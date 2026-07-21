//! Concrete local composition for the public `format` command.
//!
//! Formatting deliberately does not load a toolchain (there is no lockfile in
//! revision 0.1 either, so there is nothing else to load beyond the manifest
//! itself). The command decodes the selected root manifest, admits only
//! source files discovered by a walk of its `source_root` (modules are
//! derived, not declared), parses the exact bytes that will be replaced, and
//! publishes through a same-filesystem compare-and-replace transaction.

use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use wrela_build_model::Sha256Digest;
use wrela_diagnostics::{Diagnostic, DiagnosticSortError, Severity, canonicalize_diagnostics};
use wrela_driver::{
    Command, CommandOutput, CompilerDriver, DiagnosticReport, DriverError, DriverEvent, EventSink,
    FormatFileOutcome, FormatOutcome,
};
use wrela_format::{
    FormatError, FormatOptions, FormatOutput, FormatOutputCandidate, FormatRequest, Formatter,
    LineEnding, TextEdit, seal_format_output,
};
use wrela_package::PackageManifest;
use wrela_package_loader::{
    CanonicalPackageCodec, ContentHasher, ManifestCodecLimits, PackageCodec, SoftwareSha256,
};
use wrela_source::{FileId, SourceDatabase, SourceFile, SourceInput, TextRange};
use wrela_syntax::{
    Keyword, LexicalElement, Operator, ParseLimits, ParseRequest, ParsedFile, Punctuation,
    SyntaxParser, TokenKind, TriviaKind, WrelaSyntaxParser,
};

use crate::{CompositionError, FormatBatchLimits, PipelineLimits};

const MANIFEST_FILE_NAME: &str = "wrela.toml";
const MAX_COMMAND_PATH_BYTES: usize = 64 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;
const FORMAT_CANCELLATION_INTERVAL: usize = 256;

static PUBLICATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Production driver for local, manifest-declared source formatting.
#[derive(Debug, Clone, Copy)]
pub struct LocalFormatDriver {
    limits: PipelineLimits,
}

impl LocalFormatDriver {
    pub fn new(limits: PipelineLimits) -> Result<Self, CompositionError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    #[must_use]
    pub const fn limits(&self) -> PipelineLimits {
        self.limits
    }

    fn execute_format(
        &self,
        manifest_path: &Path,
        requested_files: &[PathBuf],
        check_only: bool,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        let workspace_root = validate_manifest_path(manifest_path)?;
        validate_directory(workspace_root).map_err(|message| {
            input_error(
                "format selection",
                format!("workspace root is not a trusted directory: {message}"),
            )
        })?;

        phase_started(events, "format-input");
        let manifest_input = read_stable_file(
            manifest_path,
            self.limits.package_load.manifest_bytes_per_package,
            false,
            is_cancelled,
        )
        .map_err(|error| map_file_error("manifest", manifest_path, error))?;
        let manifest = decode_manifest(
            &manifest_input.bytes,
            self.limits.package_load.manifest_bytes_per_package,
            is_cancelled,
        )?;
        let selected = select_declared_files(
            workspace_root,
            &manifest,
            requested_files,
            self.limits.format,
            is_cancelled,
        )?;
        let (sources, source_inputs) =
            read_selected_sources(&selected, self.limits.format, !check_only, is_cancelled)?;
        phase_finished(events, "format-input");

        phase_started(events, "format-syntax");
        let (parsed, diagnostics) =
            parse_selected_sources(&sources, &source_inputs, self.limits.parse, is_cancelled)?;
        let diagnostics =
            canonicalize_diagnostics(diagnostics, is_cancelled).map_err(|error| match error {
                DiagnosticSortError::Cancelled => DriverError::Cancelled,
                DiagnosticSortError::Allocation => input_error(
                    "format diagnostics",
                    "cannot allocate the bounded canonical diagnostic order",
                ),
            })?;
        phase_finished(events, "format-syntax");
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
        {
            let report = DiagnosticReport::rejected(
                diagnostics,
                sources,
                self.limits.parse.diagnostics,
                is_cancelled,
            )
            .map_err(|error| input_error("format diagnostics", error.to_string()))?;
            emit_diagnostics(report.diagnostics(), report.sources(), events, is_cancelled)?;
            return Err(DriverError::Rejected { report });
        }
        emit_diagnostics(&diagnostics, &sources, events, is_cancelled)?;

        phase_started(events, "formatting");
        let formatter = CanonicalSourceFormatter;
        let options = FormatOptions {
            maximum_edits: self.limits.format.edits_per_file,
            maximum_output_bytes: self.limits.format.output_bytes_per_file,
            ..FormatOptions::default()
        };
        let mut formatted = Vec::new();
        formatted
            .try_reserve_exact(source_inputs.len())
            .map_err(|_| input_error("formatting", "cannot allocate bounded format outputs"))?;
        let mut output_bytes = 0u64;
        for (index, (input, parsed)) in source_inputs.iter().zip(&parsed).enumerate() {
            check_cancelled(is_cancelled)?;
            let source = sources
                .get(input.file)
                .ok_or_else(|| input_error("formatting", "selected source identity disappeared"))?;
            let output = formatter
                .format(
                    FormatRequest {
                        parsed,
                        source,
                        options: &options,
                        range: None,
                    },
                    is_cancelled,
                )
                .map_err(map_format_error)?;
            output_bytes = checked_batch_bytes(
                output_bytes,
                output.formatted().len(),
                self.limits.format.output_bytes,
                "formatted output bytes",
            )?;
            formatted.push(FormattedSource {
                selected_index: index,
                output,
            });
        }
        phase_finished(events, "formatting");

        if !check_only && formatted.iter().any(|file| file.output.changed()) {
            phase_started(events, "format-publication");
            publish_changed_sources(
                &formatted,
                &source_inputs,
                &sources,
                self.limits.format.output_bytes_per_file,
                is_cancelled,
            )?;
            phase_finished(events, "format-publication");
        }

        let mut files = Vec::new();
        files
            .try_reserve_exact(formatted.len())
            .map_err(|_| input_error("format outcome", "cannot allocate bounded file outcomes"))?;
        for formatted in formatted {
            let input = source_inputs.get(formatted.selected_index).ok_or_else(|| {
                input_error("format outcome", "formatted source index is inconsistent")
            })?;
            files.push(
                FormatFileOutcome::new(input.path.clone(), formatted.output)
                    .map_err(|error| input_error("format outcome", error.to_string()))?,
            );
        }
        let outcome = FormatOutcome::new(
            files,
            diagnostics,
            self.limits.format.files,
            self.limits.format.edits_per_file,
            self.limits.parse.diagnostics,
            check_only,
        )
        .map_err(|error| input_error("format outcome", error.to_string()))?;
        Ok(CommandOutput::Format(outcome))
    }
}

impl CompilerDriver for LocalFormatDriver {
    fn execute(
        &self,
        command: &Command,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        let Command::Format {
            manifest,
            files,
            check_only,
        } = command
        else {
            return Err(DriverError::InvalidCommand(
                "local format driver accepts only `format` commands".to_owned(),
            ));
        };
        self.execute_format(manifest, files, *check_only, events, is_cancelled)
    }
}

/// CLI-oriented entry using standard production limits.
pub fn execute_local_format(command: &Command) -> Result<CommandOutput, DriverError> {
    LocalFormatDriver::new(PipelineLimits::standard())
        .map_err(|error| input_error("format composition", error.to_string()))?
        .execute(command, &SilentEvents, &never_cancelled)
}

struct SilentEvents;

impl EventSink for SilentEvents {
    fn emit(&self, _event: DriverEvent<'_>) {}
}

fn never_cancelled() -> bool {
    false
}

#[derive(Debug)]
struct SelectedFile {
    path: PathBuf,
    source_path: String,
}

#[derive(Debug)]
struct SelectedInput {
    path: PathBuf,
    file: FileId,
    digest: Sha256Digest,
    metadata: MetadataSnapshot,
}

fn validate_manifest_path(path: &Path) -> Result<&Path, DriverError> {
    if !normal_absolute_path(path)
        || path.as_os_str().as_encoded_bytes().len() > MAX_COMMAND_PATH_BYTES
        || path.file_name().and_then(|name| name.to_str()) != Some(MANIFEST_FILE_NAME)
    {
        return Err(DriverError::InvalidCommand(format!(
            "manifest must be a bounded normalized absolute `{MANIFEST_FILE_NAME}` path"
        )));
    }
    path.parent()
        .ok_or_else(|| DriverError::InvalidCommand("manifest has no workspace root".to_owned()))
}

fn decode_manifest(
    bytes: &[u8],
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageManifest, DriverError> {
    let entries = u32::try_from(maximum_bytes).unwrap_or(u32::MAX);
    CanonicalPackageCodec::new()
        .decode_manifest(
            bytes,
            ManifestCodecLimits {
                bytes: maximum_bytes,
                string_bytes: maximum_bytes,
                modules: entries,
                dependencies: entries,
                profiles: entries,
                images: entries,
                image_tests: entries,
            },
            is_cancelled,
        )
        .map_err(|error| match error {
            wrela_package_loader::DecodeError::Cancelled => DriverError::Cancelled,
            error => input_error("format manifest", error.to_string()),
        })
}

fn select_declared_files(
    workspace_root: &Path,
    manifest: &PackageManifest,
    requested: &[PathBuf],
    limits: FormatBatchLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<SelectedFile>, DriverError> {
    limits
        .validate()
        .map_err(|error| input_error("format selection", error.to_string()))?;
    if requested.is_empty() {
        return Err(DriverError::InvalidCommand(
            "format requires at least one source file".to_owned(),
        ));
    }
    if requested.len() > limits.files as usize {
        return Err(DriverError::InvalidCommand(format!(
            "format file count exceeds limit {}",
            limits.files
        )));
    }

    // There is no `[[module]]` list to consult: formattable files are every
    // `*.wr` file discovered by a deterministic, portable, symlink-rejecting
    // walk of `source_root`, exactly mirroring the module derivation the
    // package loader performs.
    let source_directory = join_declared_path(workspace_root, &manifest.source_root)?;
    let mut walked = Vec::new();
    walk_declared_source_files(&source_directory, "", 0, &mut walked, is_cancelled)?;
    let mut declared = Vec::new();
    declared
        .try_reserve_exact(walked.len())
        .map_err(|_| input_error("format selection", "cannot allocate declared source paths"))?;
    for relative in walked {
        wrela_package::validate_source_path(&relative)
            .map_err(|error| input_error("format selection", error.to_string()))?;
        let source_path = join_manifest_source(&manifest.source_root, &relative)?;
        let path = join_declared_path(workspace_root, &source_path)?;
        declared.push((path, source_path));
    }
    declared.sort_by(|left, right| left.0.cmp(&right.0));
    if declared.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(input_error(
            "format selection",
            "manifest declares one physical source path more than once",
        ));
    }

    let mut requested = requested.to_vec();
    requested.sort();
    if requested.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DriverError::InvalidCommand(
            "format source paths must be unique".to_owned(),
        ));
    }
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(requested.len())
        .map_err(|_| input_error("format selection", "cannot allocate selected source paths"))?;
    for path in requested {
        if !normal_absolute_path(&path)
            || path.as_os_str().as_encoded_bytes().len() > MAX_COMMAND_PATH_BYTES
        {
            return Err(DriverError::InvalidCommand(
                "format files must be bounded normalized absolute paths".to_owned(),
            ));
        }
        let index = declared
            .binary_search_by(|(declared, _)| declared.cmp(&path))
            .map_err(|_| {
                DriverError::InvalidCommand(format!(
                    "source {} is not declared by the selected root manifest",
                    path.display()
                ))
            })?;
        let (_, source_path) = declared.get(index).ok_or_else(|| {
            input_error("format selection", "declared source lookup is inconsistent")
        })?;
        selected.push(SelectedFile {
            path,
            source_path: source_path.clone(),
        });
    }
    selected.sort_by(|left, right| left.source_path.cmp(&right.source_path));
    Ok(selected)
}

/// Bound recursive directory depth for [`walk_declared_source_files`]. The
/// portable path-length ceiling (`MAX_SOURCE_PATH_BYTES`) already bounds
/// total path bytes; this additionally bounds the number of directory
/// levels the walk will recurse before failing closed.
const MAX_SOURCE_WALK_DEPTH: u32 = 64;

/// Recursively enumerate every `*.wr` regular file under `directory` in
/// sorted, portable order, appending each file's slash-separated path
/// relative to the walk root (not `directory` itself) to `output`. Rejects
/// symlinks and non-regular entries so the result cannot be steered by a
/// race outside the process; this mirrors (but does not share code with)
/// `wrela_package_loader`'s local filesystem provider, which performs the
/// equivalent walk for compilation rather than formatting.
fn walk_declared_source_files(
    directory: &Path,
    prefix: &str,
    depth: u32,
    output: &mut Vec<String>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DriverError> {
    check_cancelled(is_cancelled)?;
    if depth > MAX_SOURCE_WALK_DEPTH {
        return Err(input_error(
            "format selection",
            "source tree exceeds the maximum walk depth",
        ));
    }
    let entries = fs::read_dir(directory).map_err(|error| {
        map_file_error(
            "format source directory",
            directory,
            LocalFileError::Io(error),
        )
    })?;
    let mut names = Vec::new();
    for entry in entries {
        check_cancelled(is_cancelled)?;
        let entry = entry.map_err(|error| {
            map_file_error(
                "format source directory",
                directory,
                LocalFileError::Io(error),
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(input_error(
                "format selection",
                "source tree entry name is not portable UTF-8",
            ));
        };
        names.push(name.to_owned());
    }
    names.sort();
    for name in names {
        check_cancelled(is_cancelled)?;
        let path = directory.join(&name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            map_file_error("format source entry", &path, LocalFileError::Io(error))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(input_error(
                "format selection",
                "source tree contains a symlink",
            ));
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if metadata.is_dir() {
            walk_declared_source_files(
                &path,
                &relative,
                depth.saturating_add(1),
                output,
                is_cancelled,
            )?;
        } else if metadata.is_file() {
            if name.ends_with(".wr") {
                output.try_reserve(1).map_err(|_| {
                    input_error("format selection", "cannot allocate walked source paths")
                })?;
                output.push(relative);
            }
        } else {
            return Err(input_error(
                "format selection",
                "source tree contains a non-regular entry",
            ));
        }
    }
    Ok(())
}

fn join_manifest_source(source_root: &str, source_path: &str) -> Result<String, DriverError> {
    let length = source_root
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(source_path.len()))
        .filter(|length| *length <= wrela_source::MAX_SOURCE_PATH_BYTES)
        .ok_or_else(|| input_error("format selection", "declared source path is too long"))?;
    let mut joined = String::new();
    joined
        .try_reserve_exact(length)
        .map_err(|_| input_error("format selection", "cannot allocate declared source path"))?;
    joined.push_str(source_root);
    joined.push('/');
    joined.push_str(source_path);
    Ok(joined)
}

fn join_declared_path(root: &Path, relative: &str) -> Result<PathBuf, DriverError> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || relative
            .chars()
            .any(|character| matches!(character, '\0' | '\\' | ':') || character.is_control())
    {
        return Err(input_error(
            "format selection",
            "manifest source path is not portable",
        ));
    }
    let mut path = root.to_path_buf();
    path.try_reserve(relative.len().saturating_add(1))
        .map_err(|_| input_error("format selection", "cannot allocate host source path"))?;
    for component in relative.split('/') {
        path.push(component);
    }
    if !normal_absolute_path(&path)
        || path.as_os_str().as_encoded_bytes().len() > MAX_COMMAND_PATH_BYTES
    {
        return Err(input_error(
            "format selection",
            "declared source path exceeds the local host policy",
        ));
    }
    Ok(path)
}

fn read_selected_sources(
    selected: &[SelectedFile],
    limits: FormatBatchLimits,
    require_owner_writable: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(SourceDatabase, Vec<SelectedInput>), DriverError> {
    let mut sources = SourceDatabase::default();
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(selected.len())
        .map_err(|_| input_error("format input", "cannot allocate selected input records"))?;
    let mut total = 0u64;
    for selected in selected {
        check_cancelled(is_cancelled)?;
        let remaining = limits.input_bytes.checked_sub(total).ok_or_else(|| {
            input_error(
                "format input",
                format!("source inputs exceed {} bytes", limits.input_bytes),
            )
        })?;
        let maximum = remaining.min(u64::from(u32::MAX));
        let stable = read_stable_file(
            &selected.path,
            maximum,
            require_owner_writable,
            is_cancelled,
        )
        .map_err(|error| map_file_error("source", &selected.path, error))?;
        total = checked_batch_bytes(
            total,
            stable.bytes.len(),
            limits.input_bytes,
            "source input bytes",
        )?;
        let text = String::from_utf8(stable.bytes).map_err(|_| {
            input_error(
                "format input",
                format!("source {} is not valid UTF-8", selected.path.display()),
            )
        })?;
        let file = sources
            .add(SourceInput {
                path: selected.source_path.clone(),
                text,
                digest: stable.digest,
            })
            .map_err(|error| input_error("format input", error.to_string()))?;
        inputs.push(SelectedInput {
            path: selected.path.clone(),
            file,
            digest: stable.digest,
            metadata: stable.metadata,
        });
    }
    Ok((sources, inputs))
}

fn parse_selected_sources(
    sources: &SourceDatabase,
    inputs: &[SelectedInput],
    limits: ParseLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<ParsedFile>, Vec<Diagnostic>), DriverError> {
    limits
        .validate()
        .map_err(|error| input_error("format syntax", error.to_string()))?;
    let parser = WrelaSyntaxParser::new();
    let mut remaining = limits;
    let mut parsed = Vec::new();
    parsed
        .try_reserve_exact(inputs.len())
        .map_err(|_| input_error("format syntax", "cannot allocate parsed source outputs"))?;
    let mut diagnostics = Vec::new();
    for input in inputs {
        check_cancelled(is_cancelled)?;
        let output = parser
            .parse(
                ParseRequest {
                    sources,
                    file: input.file,
                    limits: remaining,
                },
                is_cancelled,
            )
            .map_err(|error| match error {
                wrela_syntax::ParseFailure::Cancelled => DriverError::Cancelled,
                error => input_error("format syntax", error.to_string()),
            })?;
        remaining = remaining
            .remaining_after(output.usage())
            .map_err(|error| input_error("format syntax", error.to_string()))?;
        let (file, mut file_diagnostics) = output.into_parts();
        diagnostics
            .try_reserve(file_diagnostics.len())
            .map_err(|_| input_error("format diagnostics", "cannot allocate parser diagnostics"))?;
        diagnostics.append(&mut file_diagnostics);
        parsed.push(file);
    }
    Ok((parsed, diagnostics))
}

#[derive(Debug)]
struct FormattedSource {
    selected_index: usize,
    output: FormatOutput,
}

/// Deterministic token/trivia formatter for the complete revision-0.1 lexical
/// vocabulary.  Literal and comment bytes are copied verbatim; only layout and
/// inter-token whitespace are synthesized.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalSourceFormatter;

impl Formatter for CanonicalSourceFormatter {
    fn format(
        &self,
        request: FormatRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<FormatOutput, FormatError> {
        request.options.validate()?;
        let effective_range = request.range.map_or_else(
            || Ok(request.source.full_span().range),
            |range| {
                request
                    .source
                    .slice(range)
                    .and_then(|_| request.parsed.smallest_enclosing_node(range))
                    .ok_or(FormatError::RangeOutsideFile)
            },
        )?;
        let formatted = if request.range.is_some() {
            format_effective_range(
                request.source,
                request.parsed,
                request.options,
                effective_range,
                is_cancelled,
            )?
        } else {
            SourceRenderer::new(request.source, request.options, is_cancelled)
                .render(request.parsed)?
        };
        let edits = minimal_edit(
            request.source,
            &formatted,
            request.options.maximum_output_bytes,
        )?;
        let candidate = FormatOutputCandidate {
            changed: !edits.is_empty(),
            edits,
            formatted,
            effective_range,
        };
        seal_format_output(&request, candidate, is_cancelled)
    }
}

fn format_effective_range(
    source: &SourceFile,
    parsed: &ParsedFile,
    options: &FormatOptions,
    effective_range: TextRange,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, FormatError> {
    let lexical = parsed.lexical();
    let mut first = None;
    let mut last = None;
    for (index, element) in lexical.order.iter().enumerate() {
        if index % FORMAT_CANCELLATION_INTERVAL == 0 && is_cancelled() {
            return Err(FormatError::Cancelled);
        }
        let range = lexical_element_range(lexical, *element)?;
        if range.start < range.end
            && range.start >= effective_range.start
            && range.end <= effective_range.end
        {
            first.get_or_insert(index);
            last = Some(index);
        }
    }
    let (first, last) = first.zip(last).ok_or({
        FormatError::MalformedLosslessAst("selected AST range contains no physical lexical element")
    })?;
    let prefix = PrefixState::measure(parsed, first)?;
    let column = source
        .position(effective_range.start)
        .map(|position| position.byte_column.saturating_sub(1) as usize)
        .ok_or(FormatError::RangeOutsideFile)?;
    let fragment = SourceRenderer::new_fragment(source, options, is_cancelled, prefix, column)
        .render_fragment(parsed, first, last)?;
    let original = source.text();
    let start = effective_range.start as usize;
    let end = effective_range.end as usize;
    let output_bytes = start
        .checked_add(fragment.len())
        .and_then(|length| length.checked_add(original.len().saturating_sub(end)))
        .and_then(|length| u64::try_from(length).ok())
        .filter(|length| *length <= options.maximum_output_bytes)
        .ok_or(FormatError::OutputTooLarge {
            limit: options.maximum_output_bytes,
        })?;
    let capacity = usize::try_from(output_bytes).map_err(|_| FormatError::OutputTooLarge {
        limit: options.maximum_output_bytes,
    })?;
    let mut formatted = String::new();
    formatted
        .try_reserve_exact(capacity)
        .map_err(|_| FormatError::ResourceExhausted("range format output"))?;
    formatted.push_str(original.get(..start).ok_or(FormatError::RangeOutsideFile)?);
    formatted.push_str(&fragment);
    formatted.push_str(original.get(end..).ok_or(FormatError::RangeOutsideFile)?);
    if is_cancelled() {
        return Err(FormatError::Cancelled);
    }
    Ok(formatted)
}

fn lexical_element_range(
    lexical: &wrela_syntax::LosslessLexicalTable,
    element: LexicalElement,
) -> Result<TextRange, FormatError> {
    match element {
        LexicalElement::Token(id) => lexical
            .tokens
            .get(id.0 as usize)
            .map(|token| token.span.range),
        LexicalElement::Trivia(id) => lexical
            .trivia
            .get(id.0 as usize)
            .map(|trivia| trivia.span.range),
    }
    .ok_or(FormatError::MalformedLosslessAst(
        "lexical order refers to an unknown element",
    ))
}

#[derive(Debug, Clone, Copy)]
struct PrefixState {
    indentation: u32,
    delimiter_depth: u32,
    closure_pipe_open: bool,
}

impl PrefixState {
    fn measure(parsed: &ParsedFile, end: usize) -> Result<Self, FormatError> {
        let lexical = parsed.lexical();
        let mut state = Self {
            indentation: 0,
            delimiter_depth: 0,
            closure_pipe_open: false,
        };
        let mut previous = None;
        for element in lexical
            .order
            .get(..end)
            .ok_or(FormatError::MalformedLosslessAst(
                "range prefix escapes lexical order",
            ))?
        {
            let LexicalElement::Token(id) = *element else {
                continue;
            };
            let kind = lexical
                .tokens
                .get(id.0 as usize)
                .ok_or({
                    FormatError::MalformedLosslessAst("range prefix refers to an unknown token")
                })?
                .kind;
            match kind {
                TokenKind::Indent => {
                    state.indentation = state.indentation.checked_add(1).ok_or({
                        FormatError::MalformedLosslessAst("range prefix indentation overflow")
                    })?;
                }
                TokenKind::Dedent => {
                    state.indentation = state.indentation.checked_sub(1).ok_or({
                        FormatError::MalformedLosslessAst("range prefix dedent escaped the root")
                    })?;
                }
                TokenKind::Newline => {
                    previous = None;
                    state.closure_pipe_open = false;
                }
                TokenKind::Punctuation(punctuation) if is_open(punctuation) => {
                    state.delimiter_depth = state.delimiter_depth.checked_add(1).ok_or({
                        FormatError::MalformedLosslessAst("range prefix delimiter overflow")
                    })?;
                    previous = Some(kind);
                }
                TokenKind::Punctuation(punctuation) if is_close(punctuation) => {
                    state.delimiter_depth = state.delimiter_depth.checked_sub(1).ok_or({
                        FormatError::MalformedLosslessAst(
                            "range prefix closing delimiter escaped the root",
                        )
                    })?;
                    previous = Some(kind);
                }
                TokenKind::Punctuation(Punctuation::Pipe) => {
                    if state.closure_pipe_open {
                        state.closure_pipe_open = false;
                    } else if pipe_starts_closure(previous) {
                        state.closure_pipe_open = true;
                    }
                    previous = Some(kind);
                }
                TokenKind::EndOfFile => {}
                _ => previous = Some(kind),
            }
        }
        Ok(state)
    }
}

fn minimal_edit(
    source: &SourceFile,
    formatted: &str,
    maximum_bytes: u64,
) -> Result<Vec<TextEdit>, FormatError> {
    if source.text() == formatted {
        return Ok(Vec::new());
    }
    let original = source.text().as_bytes();
    let replacement = formatted.as_bytes();
    let mut prefix = original
        .iter()
        .zip(replacement)
        .take_while(|(left, right)| left == right)
        .count();
    while !source.text().is_char_boundary(prefix) || !formatted.is_char_boundary(prefix) {
        prefix = prefix.saturating_sub(1);
    }
    let maximum_suffix = original.len().min(replacement.len()).saturating_sub(prefix);
    let mut suffix = original
        .iter()
        .rev()
        .zip(replacement.iter().rev())
        .take(maximum_suffix)
        .take_while(|(left, right)| left == right)
        .count();
    while !source.text().is_char_boundary(original.len() - suffix)
        || !formatted.is_char_boundary(replacement.len() - suffix)
    {
        suffix = suffix.saturating_sub(1);
    }
    let replacement_end = replacement.len() - suffix;
    let original_end = original.len() - suffix;
    let replacement =
        formatted
            .get(prefix..replacement_end)
            .ok_or(FormatError::MalformedLosslessAst(
                "edit boundary is not UTF-8",
            ))?;
    if u64::try_from(replacement.len()).unwrap_or(u64::MAX) > maximum_bytes {
        return Err(FormatError::OutputTooLarge {
            limit: maximum_bytes,
        });
    }
    let start = u32::try_from(prefix).map_err(|_| FormatError::OutputTooLarge {
        limit: maximum_bytes,
    })?;
    let end = u32::try_from(original_end).map_err(|_| FormatError::OutputTooLarge {
        limit: maximum_bytes,
    })?;
    let mut replacement_text = String::new();
    replacement_text
        .try_reserve_exact(replacement.len())
        .map_err(|_| FormatError::ResourceExhausted("text edit replacement"))?;
    replacement_text.push_str(replacement);
    let mut edits = Vec::new();
    edits
        .try_reserve_exact(1)
        .map_err(|_| FormatError::ResourceExhausted("text edit table"))?;
    edits.push(TextEdit {
        file: source.id(),
        range: TextRange { start, end },
        replacement: replacement_text,
    });
    Ok(edits)
}

struct SourceRenderer<'a> {
    source: &'a SourceFile,
    options: &'a FormatOptions,
    is_cancelled: &'a dyn Fn() -> bool,
    output: String,
    indentation: u32,
    delimiter_depth: u32,
    continuation_line: bool,
    at_line_start: bool,
    line_has_content: bool,
    column: usize,
    previous: Option<RenderedToken>,
    closure_pipe_open: bool,
}

#[derive(Debug, Clone, Copy)]
struct RenderedToken {
    kind: TokenKind,
    role: TokenRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenRole {
    Ordinary,
    Unary,
    CompactAssign,
    PipeOpen,
    PipeClose,
    PipeSeparator,
}

impl<'a> SourceRenderer<'a> {
    fn new(
        source: &'a SourceFile,
        options: &'a FormatOptions,
        is_cancelled: &'a dyn Fn() -> bool,
    ) -> Self {
        Self {
            source,
            options,
            is_cancelled,
            output: String::new(),
            indentation: 0,
            delimiter_depth: 0,
            continuation_line: false,
            at_line_start: true,
            line_has_content: false,
            column: 0,
            previous: None,
            closure_pipe_open: false,
        }
    }

    fn new_fragment(
        source: &'a SourceFile,
        options: &'a FormatOptions,
        is_cancelled: &'a dyn Fn() -> bool,
        prefix: PrefixState,
        column: usize,
    ) -> Self {
        Self {
            source,
            options,
            is_cancelled,
            output: String::new(),
            indentation: prefix.indentation,
            delimiter_depth: prefix.delimiter_depth,
            continuation_line: false,
            // Leading layout belongs to the unchanged prefix outside the AST
            // node.  Treat its first token as already positioned on the line.
            at_line_start: false,
            line_has_content: false,
            column,
            previous: None,
            closure_pipe_open: prefix.closure_pipe_open,
        }
    }

    fn render(mut self, parsed: &ParsedFile) -> Result<String, FormatError> {
        let lexical = parsed.lexical();
        self.render_elements(parsed, 0, lexical.order.len())?;
        if self.indentation != 0 || self.delimiter_depth != 0 {
            return Err(FormatError::MalformedLosslessAst(
                "layout or delimiter stack is unbalanced",
            ));
        }
        self.finish_line_policy()?;
        if (self.is_cancelled)() {
            return Err(FormatError::Cancelled);
        }
        Ok(self.output)
    }

    fn render_fragment(
        mut self,
        parsed: &ParsedFile,
        first: usize,
        last: usize,
    ) -> Result<String, FormatError> {
        let end = last
            .checked_add(1)
            .ok_or(FormatError::MalformedLosslessAst(
                "range lexical index overflow",
            ))?;
        self.render_elements(parsed, first, end)?;
        if (self.is_cancelled)() {
            return Err(FormatError::Cancelled);
        }
        Ok(self.output)
    }

    fn render_elements(
        &mut self,
        parsed: &ParsedFile,
        start: usize,
        end: usize,
    ) -> Result<(), FormatError> {
        let lexical = parsed.lexical();
        let elements = lexical
            .order
            .get(start..end)
            .ok_or(FormatError::MalformedLosslessAst(
                "lexical render range is invalid",
            ))?;
        for (work, element) in elements.iter().enumerate() {
            if work % FORMAT_CANCELLATION_INTERVAL == 0 && (self.is_cancelled)() {
                return Err(FormatError::Cancelled);
            }
            match *element {
                LexicalElement::Token(id) => {
                    let token = lexical.tokens.get(id.0 as usize).ok_or({
                        FormatError::MalformedLosslessAst(
                            "lexical order refers to an unknown token",
                        )
                    })?;
                    self.token(token.kind, token.spelling.as_deref())?;
                }
                LexicalElement::Trivia(id) => {
                    let trivia = lexical.trivia.get(id.0 as usize).ok_or({
                        FormatError::MalformedLosslessAst("lexical order refers to unknown trivia")
                    })?;
                    let text = self.source.slice(trivia.span.range).ok_or({
                        FormatError::MalformedLosslessAst("trivia range escapes its source")
                    })?;
                    self.trivia(trivia.kind, text)?;
                }
            }
        }
        Ok(())
    }

    fn token(&mut self, kind: TokenKind, spelling: Option<&str>) -> Result<(), FormatError> {
        match kind {
            TokenKind::Indent => {
                self.indentation =
                    self.indentation
                        .checked_add(1)
                        .ok_or(FormatError::MalformedLosslessAst(
                            "indentation depth overflow",
                        ))?;
                return Ok(());
            }
            TokenKind::Dedent => {
                self.indentation = self
                    .indentation
                    .checked_sub(1)
                    .ok_or(FormatError::MalformedLosslessAst("dedent escaped the root"))?;
                return Ok(());
            }
            TokenKind::Newline => {
                self.logical_newline()?;
                return Ok(());
            }
            TokenKind::EndOfFile => return Ok(()),
            _ => {}
        }

        let role = self.classify_role(kind);
        let text = token_text(kind, spelling)?;
        let mut space = self
            .previous
            .is_some_and(|previous| space_between(previous, kind, role, self.delimiter_depth));
        let projected = self
            .column
            .saturating_add(usize::from(space))
            .saturating_add(text.len());
        if !self.at_line_start
            && self.delimiter_depth != 0
            && space
            && projected > usize::from(self.options.maximum_line_width)
        {
            self.write_newline()?;
            self.continuation_line = true;
            space = false;
        }
        if self.at_line_start {
            self.write_indentation(matches!(kind, TokenKind::Punctuation(p) if is_close(p)))?;
        }
        if space {
            self.push(" ")?;
        }
        self.push(text)?;
        self.line_has_content = true;
        self.at_line_start = false;

        match kind {
            TokenKind::Punctuation(punctuation) if is_open(punctuation) => {
                self.delimiter_depth = self.delimiter_depth.checked_add(1).ok_or(
                    FormatError::MalformedLosslessAst("delimiter depth overflow"),
                )?;
            }
            TokenKind::Punctuation(punctuation) if is_close(punctuation) => {
                self.delimiter_depth = self.delimiter_depth.checked_sub(1).ok_or({
                    FormatError::MalformedLosslessAst("closing delimiter escaped the root")
                })?;
            }
            _ => {}
        }
        self.previous = Some(RenderedToken { kind, role });
        Ok(())
    }

    fn classify_role(&mut self, kind: TokenKind) -> TokenRole {
        match kind {
            TokenKind::Punctuation(Punctuation::Pipe) => {
                if self.closure_pipe_open {
                    self.closure_pipe_open = false;
                    TokenRole::PipeClose
                } else if pipe_starts_closure(self.previous.map(|previous| previous.kind)) {
                    self.closure_pipe_open = true;
                    TokenRole::PipeOpen
                } else {
                    TokenRole::PipeSeparator
                }
            }
            TokenKind::Operator(Operator::Add | Operator::Subtract | Operator::BitNot)
                if !self
                    .previous
                    .is_some_and(|previous| can_end_expression(previous.kind)) =>
            {
                TokenRole::Unary
            }
            TokenKind::Operator(Operator::Assign)
                if self.delimiter_depth != 0
                    && self
                        .previous
                        .is_some_and(|previous| previous.kind == TokenKind::Identifier) =>
            {
                TokenRole::CompactAssign
            }
            _ => TokenRole::Ordinary,
        }
    }

    fn trivia(&mut self, kind: TriviaKind, text: &str) -> Result<(), FormatError> {
        match kind {
            TriviaKind::Spaces => Ok(()),
            TriviaKind::Comment => {
                if self.at_line_start {
                    self.write_indentation(false)?;
                } else {
                    self.push("  ")?;
                }
                self.push(text)?;
                self.at_line_start = false;
                self.line_has_content = true;
                Ok(())
            }
            TriviaKind::SuppressedPhysicalNewline => {
                if self.line_has_content {
                    self.write_newline()?;
                }
                self.continuation_line = true;
                Ok(())
            }
            TriviaKind::BlankLine => {
                self.write_newline()?;
                self.continuation_line = false;
                Ok(())
            }
        }
    }

    fn logical_newline(&mut self) -> Result<(), FormatError> {
        if self.line_has_content {
            self.write_newline()?;
        }
        self.continuation_line = false;
        self.previous = None;
        self.closure_pipe_open = false;
        Ok(())
    }

    fn write_indentation(&mut self, closing_delimiter: bool) -> Result<(), FormatError> {
        let continuation = u32::from(self.continuation_line && !closing_delimiter);
        let levels =
            self.indentation
                .checked_add(continuation)
                .ok_or(FormatError::MalformedLosslessAst(
                    "indentation depth overflow",
                ))?;
        let width = usize::try_from(levels)
            .ok()
            .and_then(|levels| levels.checked_mul(usize::from(self.options.indentation_width)))
            .ok_or(FormatError::OutputTooLarge {
                limit: self.options.maximum_output_bytes,
            })?;
        self.push_repeated_space(width)?;
        self.at_line_start = false;
        self.continuation_line = false;
        Ok(())
    }

    fn push_repeated_space(&mut self, count: usize) -> Result<(), FormatError> {
        const SPACES: &str = "                                                                ";
        let mut remaining = count;
        while remaining != 0 {
            let take = remaining.min(SPACES.len());
            self.push(&SPACES[..take])?;
            remaining -= take;
        }
        Ok(())
    }

    fn logical_line_ending(&self) -> &'static str {
        match self.options.line_ending {
            LineEnding::Lf => "\n",
            LineEnding::CrLf => "\r\n",
        }
    }

    fn write_newline(&mut self) -> Result<(), FormatError> {
        self.push(self.logical_line_ending())?;
        self.at_line_start = true;
        self.line_has_content = false;
        self.column = 0;
        self.previous = None;
        self.closure_pipe_open = false;
        Ok(())
    }

    fn finish_line_policy(&mut self) -> Result<(), FormatError> {
        let ending = self.logical_line_ending();
        while self.output.ends_with(ending) {
            let next = self.output.len() - ending.len();
            self.output.truncate(next);
        }
        if self.options.trailing_newline {
            self.push(ending)?;
        }
        Ok(())
    }

    fn push(&mut self, value: &str) -> Result<(), FormatError> {
        let next = self
            .output
            .len()
            .checked_add(value.len())
            .and_then(|length| u64::try_from(length).ok())
            .filter(|length| *length <= self.options.maximum_output_bytes)
            .ok_or(FormatError::OutputTooLarge {
                limit: self.options.maximum_output_bytes,
            })?;
        self.output
            .try_reserve(value.len())
            .map_err(|_| FormatError::ResourceExhausted("rendered format output"))?;
        self.output.push_str(value);
        self.column = self.column.saturating_add(value.len());
        debug_assert_eq!(u64::try_from(self.output.len()).ok(), Some(next));
        Ok(())
    }
}

fn token_text(kind: TokenKind, spelling: Option<&str>) -> Result<&str, FormatError> {
    if let Some(spelling) = spelling {
        return Ok(spelling);
    }
    let text = match kind {
        TokenKind::Keyword(keyword) => keyword_text(keyword),
        TokenKind::Punctuation(punctuation) => punctuation_text(punctuation),
        TokenKind::Operator(operator) => operator_text(operator),
        TokenKind::Identifier
        | TokenKind::IntegerLiteral
        | TokenKind::FloatLiteral
        | TokenKind::StringLiteral
        | TokenKind::ByteStringLiteral
        | TokenKind::CharacterLiteral
        | TokenKind::InterpolatedStringStart
        | TokenKind::InterpolatedStringText
        | TokenKind::InterpolationFormat
        | TokenKind::InterpolatedStringEnd
        | TokenKind::Error => {
            return Err(FormatError::MalformedLosslessAst(
                "spelling-bearing token has no spelling",
            ));
        }
        TokenKind::Newline | TokenKind::Indent | TokenKind::Dedent | TokenKind::EndOfFile => {
            return Err(FormatError::MalformedLosslessAst(
                "structural token was rendered as text",
            ));
        }
    };
    Ok(text)
}

fn keyword_text(keyword: Keyword) -> &'static str {
    match keyword {
        Keyword::Module => "module",
        Keyword::Pub => "pub",
        Keyword::Import => "import",
        Keyword::From => "from",
        Keyword::As => "as",
        Keyword::Const => "const",
        Keyword::Brand => "brand",
        Keyword::Fn => "fn",
        Keyword::Init => "init",
        Keyword::Async => "async",
        Keyword::Isr => "isr",
        Keyword::Comptime => "comptime",
        Keyword::Struct => "struct",
        Keyword::Enum => "enum",
        Keyword::Iface => "interface",
        Keyword::Impl => "impl",
        Keyword::For => "for",
        Keyword::Projection => "projection",
        Keyword::Scope => "scope",
        Keyword::Implements => "implements",
        Keyword::Region => "region",
        Keyword::View => "view",
        Keyword::Mut => "mut",
        Keyword::Iso => "iso",
        Keyword::Read => "read",
        Keyword::Take => "take",
        Keyword::SelfValue => "self",
        Keyword::If => "if",
        Keyword::Elif => "elif",
        Keyword::Else => "else",
        Keyword::Match => "match",
        Keyword::Case => "case",
        Keyword::In => "in",
        Keyword::Not => "not",
        Keyword::While => "while",
        Keyword::Loop => "loop",
        Keyword::With => "with",
        Keyword::Enter => "enter",
        Keyword::Abort => "abort",
        Keyword::Exit => "exit",
        Keyword::Shadow => "shadow",
        Keyword::Return => "return",
        Keyword::Break => "break",
        Keyword::Continue => "continue",
        Keyword::Pass => "pass",
        Keyword::Assert => "assert",
        Keyword::Send => "send",
        Keyword::Try => "try",
        Keyword::Yield => "yield",
        Keyword::Await => "await",
        Keyword::Copy => "copy",
        Keyword::True => "true",
        Keyword::False => "false",
        Keyword::Unit => "unit",
        Keyword::Or => "or",
        Keyword::And => "and",
        Keyword::Is => "is",
    }
}

fn punctuation_text(punctuation: Punctuation) -> &'static str {
    match punctuation {
        Punctuation::At => "@",
        Punctuation::Dot => ".",
        Punctuation::Comma => ",",
        Punctuation::Colon => ":",
        Punctuation::Semicolon => ";",
        Punctuation::LeftParen => "(",
        Punctuation::RightParen => ")",
        Punctuation::LeftBracket => "[",
        Punctuation::RightBracket => "]",
        Punctuation::LeftBrace => "{",
        Punctuation::RightBrace => "}",
        Punctuation::Arrow => "->",
        Punctuation::Question => "?",
        Punctuation::Pipe => "|",
    }
}

fn operator_text(operator: Operator) -> &'static str {
    match operator {
        Operator::Assign => "=",
        Operator::Add => "+",
        Operator::Subtract => "-",
        Operator::Multiply => "*",
        Operator::Divide => "/",
        Operator::Remainder => "%",
        Operator::BitAnd => "&",
        Operator::BitOr => "|",
        Operator::BitXor => "^",
        Operator::ShiftLeft => "<<",
        Operator::ShiftRight => ">>",
        Operator::Equal => "==",
        Operator::NotEqual => "!=",
        Operator::Less => "<",
        Operator::LessEqual => "<=",
        Operator::Greater => ">",
        Operator::GreaterEqual => ">=",
        Operator::AddAssign => "+=",
        Operator::SubtractAssign => "-=",
        Operator::MultiplyAssign => "*=",
        Operator::DivideAssign => "/=",
        Operator::RemainderAssign => "%=",
        Operator::BitAndAssign => "&=",
        Operator::BitOrAssign => "|=",
        Operator::BitXorAssign => "^=",
        Operator::ShiftLeftAssign => "<<=",
        Operator::ShiftRightAssign => ">>=",
        Operator::AddWrapping => "+%",
        Operator::SubtractWrapping => "-%",
        Operator::MultiplyWrapping => "*%",
        Operator::BitNot => "~",
        Operator::Range => "..",
        Operator::RangeInclusive => "..=",
    }
}

fn space_between(
    previous: RenderedToken,
    current: TokenKind,
    current_role: TokenRole,
    delimiter_depth: u32,
) -> bool {
    // A `.` is ambiguous in isolation: postfix field/tuple-index access
    // (`value.field`) binds tightly with no leading space, while the
    // leading-dot variant shorthand (`.Name`, `case .Name(...)`) is a
    // primary position and wants the same space its identifier would have
    // gotten. Disambiguate using the same predicate that already decides
    // between indexing (`value[0]`) and an array literal (`[0]`).
    if current == TokenKind::Punctuation(Punctuation::Dot) && can_end_expression(previous.kind) {
        return false;
    }
    if matches!(
        current,
        TokenKind::InterpolatedStringText | TokenKind::InterpolatedStringEnd
    ) || matches!(
        previous.kind,
        TokenKind::InterpolatedStringStart | TokenKind::InterpolatedStringText
    ) || (current != TokenKind::Punctuation(Punctuation::Dot)
        && matches!(
            current,
            TokenKind::Punctuation(
                Punctuation::Comma
                    | Punctuation::Colon
                    | Punctuation::Semicolon
                    | Punctuation::RightParen
                    | Punctuation::RightBracket
                    | Punctuation::RightBrace
                    | Punctuation::Question
            )
        ))
        || matches!(
            previous.kind,
            TokenKind::Punctuation(
                Punctuation::At
                    | Punctuation::Dot
                    | Punctuation::LeftBrace
                    | Punctuation::LeftParen
                    | Punctuation::LeftBracket
            )
        )
        || current == TokenKind::InterpolationFormat
    {
        return false;
    }
    if current_role == TokenRole::PipeClose {
        return false;
    }
    if matches!(
        previous.role,
        TokenRole::PipeOpen | TokenRole::Unary | TokenRole::CompactAssign
    ) {
        return false;
    }
    if matches!(
        previous.role,
        TokenRole::PipeClose | TokenRole::PipeSeparator
    ) || current_role == TokenRole::PipeSeparator
    {
        return true;
    }
    if current_role == TokenRole::PipeOpen {
        return true;
    }
    if current_role == TokenRole::Unary {
        return !matches!(previous.kind, TokenKind::Operator(_));
    }
    if current_role == TokenRole::CompactAssign {
        return false;
    }
    if matches!(current, TokenKind::Punctuation(Punctuation::LeftParen)) {
        return !callable_before_parenthesis(previous.kind);
    }
    if matches!(current, TokenKind::Punctuation(Punctuation::LeftBracket)) {
        return !can_end_expression(previous.kind);
    }
    if current == TokenKind::Punctuation(Punctuation::LeftBrace) {
        return false;
    }
    if matches!(
        previous.kind,
        TokenKind::Punctuation(Punctuation::Comma | Punctuation::Colon | Punctuation::Semicolon)
    ) {
        return true;
    }
    if matches!(current, TokenKind::Operator(_))
        || matches!(previous.kind, TokenKind::Operator(_))
        || current == TokenKind::Punctuation(Punctuation::Arrow)
        || previous.kind == TokenKind::Punctuation(Punctuation::Arrow)
    {
        return true;
    }
    let _ = delimiter_depth;
    true
}

fn callable_before_parenthesis(kind: TokenKind) -> bool {
    can_end_expression(kind) || matches!(kind, TokenKind::Keyword(Keyword::Init))
}

fn can_end_expression(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Identifier
            | TokenKind::IntegerLiteral
            | TokenKind::FloatLiteral
            | TokenKind::StringLiteral
            | TokenKind::ByteStringLiteral
            | TokenKind::CharacterLiteral
            | TokenKind::InterpolatedStringEnd
            | TokenKind::Keyword(
                Keyword::True | Keyword::False | Keyword::Unit | Keyword::SelfValue
            )
            | TokenKind::Punctuation(
                Punctuation::RightParen
                    | Punctuation::RightBracket
                    | Punctuation::RightBrace
                    | Punctuation::Question
            )
    )
}

fn pipe_starts_closure(previous: Option<TokenKind>) -> bool {
    previous.is_none_or(|kind| {
        matches!(
            kind,
            TokenKind::Operator(Operator::Assign)
                | TokenKind::Punctuation(
                    Punctuation::Comma
                        | Punctuation::Colon
                        | Punctuation::LeftParen
                        | Punctuation::LeftBracket
                )
                | TokenKind::Keyword(
                    Keyword::Async | Keyword::Take | Keyword::Return | Keyword::Yield | Keyword::As
                )
        )
    })
}

fn is_open(punctuation: Punctuation) -> bool {
    matches!(
        punctuation,
        Punctuation::LeftParen | Punctuation::LeftBracket | Punctuation::LeftBrace
    )
}

fn is_close(punctuation: Punctuation) -> bool {
    matches!(
        punctuation,
        Punctuation::RightParen | Punctuation::RightBracket | Punctuation::RightBrace
    )
}

#[derive(Debug)]
enum LocalFileError {
    Cancelled,
    Invalid(&'static str),
    TooLarge { limit: u64 },
    Io(io::Error),
    Changed,
}

impl std::fmt::Display for LocalFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("operation was cancelled"),
            Self::Invalid(message) => formatter.write_str(message),
            Self::TooLarge { limit } => write!(formatter, "file exceeds {limit} bytes"),
            Self::Io(error) => error.fmt(formatter),
            Self::Changed => formatter.write_str("file changed while it was being measured"),
        }
    }
}

struct StableInput {
    bytes: Vec<u8>,
    digest: Sha256Digest,
    metadata: MetadataSnapshot,
}

fn read_stable_file(
    path: &Path,
    maximum_bytes: u64,
    require_owner_writable: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<StableInput, LocalFileError> {
    if is_cancelled() {
        return Err(LocalFileError::Cancelled);
    }
    let before = inspect_regular_file(path, require_owner_writable)?;
    if before.len() > maximum_bytes {
        return Err(LocalFileError::TooLarge {
            limit: maximum_bytes,
        });
    }
    let mut file = File::open(path).map_err(LocalFileError::Io)?;
    let opened_metadata = file.metadata().map_err(LocalFileError::Io)?;
    validate_regular_metadata(&opened_metadata, require_owner_writable)?;
    let opened = MetadataSnapshot::capture(&opened_metadata)?;
    if before != opened {
        return Err(LocalFileError::Changed);
    }
    let capacity = usize::try_from(before.len())
        .unwrap_or(usize::MAX)
        .min(usize::try_from(maximum_bytes).unwrap_or(usize::MAX));
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| LocalFileError::TooLarge {
            limit: maximum_bytes,
        })?;
    let mut digest = SoftwareSha256.begin_sha256();
    let mut buffer = [0u8; READ_CHUNK_BYTES];
    loop {
        if is_cancelled() {
            return Err(LocalFileError::Cancelled);
        }
        let count = file.read(&mut buffer).map_err(LocalFileError::Io)?;
        if count == 0 {
            break;
        }
        let next = bytes
            .len()
            .checked_add(count)
            .and_then(|length| u64::try_from(length).ok())
            .filter(|length| *length <= maximum_bytes)
            .ok_or(LocalFileError::TooLarge {
                limit: maximum_bytes,
            })?;
        bytes
            .try_reserve(count)
            .map_err(|_| LocalFileError::TooLarge {
                limit: maximum_bytes,
            })?;
        bytes.extend_from_slice(&buffer[..count]);
        digest.update(&buffer[..count]);
        debug_assert_eq!(u64::try_from(bytes.len()).ok(), Some(next));
    }
    if is_cancelled() {
        return Err(LocalFileError::Cancelled);
    }
    let after_handle_metadata = file.metadata().map_err(LocalFileError::Io)?;
    validate_regular_metadata(&after_handle_metadata, require_owner_writable)?;
    let after_handle = MetadataSnapshot::capture(&after_handle_metadata)?;
    let after_path = inspect_regular_file(path, require_owner_writable)?;
    if before != after_handle
        || after_handle != after_path
        || after_path.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(LocalFileError::Changed);
    }
    Ok(StableInput {
        bytes,
        digest: digest.finish(),
        metadata: after_path,
    })
}

fn inspect_regular_file(
    path: &Path,
    require_owner_writable: bool,
) -> Result<MetadataSnapshot, LocalFileError> {
    if !normal_absolute_path(path)
        || path.as_os_str().as_encoded_bytes().len() > MAX_COMMAND_PATH_BYTES
    {
        return Err(LocalFileError::Invalid(
            "file path is not bounded, normalized, and absolute",
        ));
    }
    reject_symlink_components(path)?;
    let canonical = fs::canonicalize(path).map_err(LocalFileError::Io)?;
    if canonical != path {
        return Err(LocalFileError::Invalid(
            "file path is not canonically contained",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(LocalFileError::Io)?;
    validate_regular_metadata(&metadata, require_owner_writable)?;
    MetadataSnapshot::capture(&metadata)
}

fn validate_regular_metadata(
    metadata: &Metadata,
    require_owner_writable: bool,
) -> Result<(), LocalFileError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LocalFileError::Invalid(
            "entry is not a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        let mode = metadata.mode();
        if metadata.nlink() != 1 {
            return Err(LocalFileError::Invalid("file has more than one hard link"));
        }
        if mode & 0o7022 != 0 {
            return Err(LocalFileError::Invalid(
                "file has special, group-writable, or world-writable permissions",
            ));
        }
        if require_owner_writable && mode & 0o200 == 0 {
            return Err(LocalFileError::Invalid("source file is not owner-writable"));
        }
    }
    #[cfg(not(unix))]
    if require_owner_writable && metadata.permissions().readonly() {
        return Err(LocalFileError::Invalid("source file is read-only"));
    }
    Ok(())
}

fn validate_directory(path: &Path) -> Result<(), &'static str> {
    if !normal_absolute_path(path)
        || path.as_os_str().as_encoded_bytes().len() > MAX_COMMAND_PATH_BYTES
    {
        return Err("directory path is not bounded, normalized, and absolute");
    }
    reject_symlink_components(path).map_err(|_| "directory path contains a symlink")?;
    let canonical = fs::canonicalize(path).map_err(|_| "directory cannot be canonicalized")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "directory cannot be inspected")?;
    if canonical != path || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("entry is not a canonical real directory");
    }
    #[cfg(unix)]
    if metadata.mode() & 0o7022 != 0 {
        return Err("directory has special, group-writable, or world-writable permissions");
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), LocalFileError> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor).map_err(LocalFileError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(LocalFileError::Invalid("path contains a symbolic link"));
        }
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataSnapshot {
    length: u64,
    modified: std::time::SystemTime,
}

impl MetadataSnapshot {
    #[cfg(unix)]
    fn capture(metadata: &Metadata) -> Result<Self, LocalFileError> {
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    #[cfg(not(unix))]
    fn capture(metadata: &Metadata) -> Result<Self, LocalFileError> {
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified().map_err(LocalFileError::Io)?,
        })
    }

    const fn len(&self) -> u64 {
        self.length
    }

    #[cfg(unix)]
    const fn mode(&self) -> u32 {
        self.mode
    }

    #[cfg(not(unix))]
    const fn mode(&self) -> u32 {
        0
    }
}

struct PreparedPublication {
    destination: PathBuf,
    stage: PathBuf,
    rollback: PathBuf,
    lock_path: PathBuf,
    _lock: File,
    expected_digest: Sha256Digest,
    expected_metadata: MetadataSnapshot,
    published_digest: Sha256Digest,
    published_bytes: u64,
    committed: bool,
    preserve_rollback: bool,
}

impl Drop for PreparedPublication {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.stage);
        if !self.preserve_rollback {
            let _ = fs::remove_file(&self.rollback);
        }
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn publish_changed_sources(
    formatted: &[FormattedSource],
    inputs: &[SelectedInput],
    sources: &SourceDatabase,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DriverError> {
    let changed = formatted
        .iter()
        .filter(|file| file.output.changed())
        .count();
    let mut publications = Vec::new();
    publications
        .try_reserve_exact(changed)
        .map_err(|_| input_error("format publication", "cannot allocate publication records"))?;
    for file in formatted.iter().filter(|file| file.output.changed()) {
        check_cancelled(is_cancelled)?;
        let input = inputs.get(file.selected_index).ok_or_else(|| {
            input_error(
                "format publication",
                "selected source index is inconsistent",
            )
        })?;
        let source = sources.get(input.file).ok_or_else(|| {
            input_error("format publication", "selected source identity disappeared")
        })?;
        publications.push(prepare_publication(
            input,
            source.text().as_bytes(),
            file.output.formatted().as_bytes(),
            maximum_bytes,
            is_cancelled,
        )?);
    }

    // Earlier files may have changed while later temporary files were being
    // created.  Recheck the complete set while all formatter lock files are
    // held, then observe cancellation once immediately before visibility.
    for publication in &publications {
        revalidate_publication(publication, maximum_bytes, is_cancelled)?;
    }
    check_cancelled(is_cancelled)?;
    commit_publications(&mut publications, maximum_bytes)
}

fn prepare_publication(
    input: &SelectedInput,
    original: &[u8],
    formatted: &[u8],
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PreparedPublication, DriverError> {
    check_cancelled(is_cancelled)?;
    if formatted.is_empty()
        || u64::try_from(formatted.len()).unwrap_or(u64::MAX) > maximum_bytes
        || SoftwareSha256.sha256(original) != input.digest
    {
        return Err(publication_error(
            &input.path,
            "publication bytes exceed their seal or original digest",
        ));
    }
    let parent = input
        .path
        .parent()
        .ok_or_else(|| publication_error(&input.path, "source file has no parent directory"))?;
    validate_directory(parent).map_err(|message| publication_error(parent, message))?;
    let lock_path = publication_lock_path(&input.path)?;
    let lock = create_private_new_file(&lock_path).map_err(|error| {
        publication_error(
            &input.path,
            if error.kind() == io::ErrorKind::AlreadyExists {
                "another formatter owns the source replacement lock".to_owned()
            } else {
                format!("cannot acquire source replacement lock: {error}")
            },
        )
    })?;
    let sequence = PUBLICATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let stage = parent.join(format!(
        ".wrela-format-{}-{sequence:016x}.new",
        std::process::id()
    ));
    let rollback = parent.join(format!(
        ".wrela-format-{}-{sequence:016x}.old",
        std::process::id()
    ));
    let publication = PreparedPublication {
        destination: input.path.clone(),
        stage,
        rollback,
        lock_path,
        _lock: lock,
        expected_digest: input.digest,
        expected_metadata: input.metadata,
        published_digest: SoftwareSha256.sha256(formatted),
        published_bytes: u64::try_from(formatted.len()).unwrap_or(u64::MAX),
        committed: false,
        preserve_rollback: false,
    };
    write_temporary_file(
        &publication.stage,
        formatted,
        publication.expected_metadata.mode(),
    )
    .map_err(|error| publication_error(&publication.destination, error.to_string()))?;
    if let Err(error) = write_temporary_file(
        &publication.rollback,
        original,
        publication.expected_metadata.mode(),
    ) {
        return Err(publication_error(
            &publication.destination,
            error.to_string(),
        ));
    }
    sync_directory(parent)
        .map_err(|error| publication_error(&publication.destination, error.to_string()))?;
    revalidate_publication(&publication, maximum_bytes, is_cancelled)?;
    Ok(publication)
}

fn revalidate_publication(
    publication: &PreparedPublication,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DriverError> {
    let current = read_stable_file(&publication.destination, maximum_bytes, true, is_cancelled)
        .map_err(|error| map_publication_file_error(&publication.destination, error))?;
    if current.digest != publication.expected_digest
        || current.metadata != publication.expected_metadata
    {
        return Err(publication_error(
            &publication.destination,
            "source changed after it was parsed; no replacement was published",
        ));
    }
    Ok(())
}

fn commit_publications(
    publications: &mut [PreparedPublication],
    maximum_bytes: u64,
) -> Result<(), DriverError> {
    for index in 0..publications.len() {
        let publication = publications.get_mut(index).ok_or_else(|| {
            input_error("format publication", "publication index is inconsistent")
        })?;
        if let Err(error) = fs::rename(&publication.stage, &publication.destination) {
            let failure = publication_error(&publication.destination, error.to_string());
            rollback_publications(publications, maximum_bytes)?;
            return Err(failure);
        }
        publication.committed = true;
    }
    for publication in publications.iter() {
        let parent = publication.destination.parent().ok_or_else(|| {
            publication_error(&publication.destination, "published source has no parent")
        })?;
        if let Err(error) = sync_directory(parent) {
            let failure = publication_error(&publication.destination, error.to_string());
            rollback_publications(publications, maximum_bytes)?;
            return Err(failure);
        }
    }
    for publication in publications.iter() {
        let observed = read_stable_file(
            &publication.destination,
            maximum_bytes,
            true,
            &never_cancelled,
        )
        .map_err(|error| map_publication_file_error(&publication.destination, error))?;
        if observed.digest != publication.published_digest
            || u64::try_from(observed.bytes.len()).ok() != Some(publication.published_bytes)
        {
            let failure = publication_error(
                &publication.destination,
                "published source bytes do not match the sealed formatter output",
            );
            rollback_publications(publications, maximum_bytes)?;
            return Err(failure);
        }
    }
    for publication in publications.iter_mut() {
        fs::remove_file(&publication.rollback)
            .map_err(|error| publication_error(&publication.destination, error.to_string()))?;
        publication.committed = false;
    }
    for publication in publications.iter() {
        let parent = publication.destination.parent().ok_or_else(|| {
            publication_error(&publication.destination, "published source has no parent")
        })?;
        sync_directory(parent)
            .map_err(|error| publication_error(&publication.destination, error.to_string()))?;
    }
    Ok(())
}

fn rollback_publications(
    publications: &mut [PreparedPublication],
    maximum_bytes: u64,
) -> Result<(), DriverError> {
    for publication in publications.iter_mut().rev() {
        if !publication.committed {
            continue;
        }
        let current = match read_stable_file(
            &publication.destination,
            maximum_bytes,
            true,
            &never_cancelled,
        ) {
            Ok(current) => current,
            Err(error) => {
                publication.preserve_rollback = true;
                return Err(publication_error(
                    &publication.destination,
                    format!(
                        "cannot verify failed publication for rollback ({error}); original bytes remain at {}",
                        publication.rollback.display()
                    ),
                ));
            }
        };
        if current.digest != publication.published_digest {
            publication.preserve_rollback = true;
            return Err(publication_error(
                &publication.destination,
                format!(
                    "source changed after publication failure; original bytes remain at {}",
                    publication.rollback.display()
                ),
            ));
        }
        if let Err(error) = fs::rename(&publication.rollback, &publication.destination) {
            publication.preserve_rollback = true;
            return Err(publication_error(
                &publication.destination,
                format!(
                    "cannot restore original source ({error}); original bytes remain at {}",
                    publication.rollback.display()
                ),
            ));
        }
        publication.committed = false;
    }
    for publication in publications.iter() {
        if let Some(parent) = publication.destination.parent() {
            sync_directory(parent)
                .map_err(|error| publication_error(&publication.destination, error.to_string()))?;
        }
    }
    Ok(())
}

fn publication_lock_path(destination: &Path) -> Result<PathBuf, DriverError> {
    let file_name = destination
        .file_name()
        .ok_or_else(|| publication_error(destination, "source has no file name"))?;
    let mut name = OsString::from(".");
    name.push(file_name);
    name.push(".wrela-format.lock");
    let path = destination
        .parent()
        .ok_or_else(|| publication_error(destination, "source has no parent"))?
        .join(name);
    if path.as_os_str().as_encoded_bytes().len() > MAX_COMMAND_PATH_BYTES {
        return Err(publication_error(
            destination,
            "source replacement lock path is too long",
        ));
    }
    Ok(path)
}

fn create_private_new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

fn write_temporary_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = create_private_new_file(path)?;
    if let Err(error) = file.write_all(bytes) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    #[cfg(unix)]
    {
        let canonical_mode = mode & 0o0755;
        fs::set_permissions(path, fs::Permissions::from_mode(canonical_mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    file.sync_all()
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 1
        && PathBuf::from_iter(path.components()) == path
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn checked_batch_bytes(
    total: u64,
    additional: usize,
    limit: u64,
    resource: &'static str,
) -> Result<u64, DriverError> {
    total
        .checked_add(u64::try_from(additional).unwrap_or(u64::MAX))
        .filter(|total| *total <= limit)
        .ok_or_else(|| input_error("format limits", format!("{resource} exceed limit {limit}")))
}

fn map_file_error(phase: &'static str, path: &Path, error: LocalFileError) -> DriverError {
    match error {
        LocalFileError::Cancelled => DriverError::Cancelled,
        error => input_error(phase, format!("{}: {error}", path.display())),
    }
}

fn map_publication_file_error(path: &Path, error: LocalFileError) -> DriverError {
    match error {
        LocalFileError::Cancelled => DriverError::Cancelled,
        error => publication_error(path, error.to_string()),
    }
}

fn map_format_error(error: FormatError) -> DriverError {
    match error {
        FormatError::Cancelled => DriverError::Cancelled,
        error => input_error("formatting", error.to_string()),
    }
}

fn phase_started(events: &dyn EventSink, phase: &'static str) {
    events.emit(DriverEvent::PhaseStarted { phase });
}

fn phase_finished(events: &dyn EventSink, phase: &'static str) {
    events.emit(DriverEvent::PhaseFinished {
        phase,
        reused: false,
    });
}

fn emit_diagnostics(
    diagnostics: &[Diagnostic],
    sources: &SourceDatabase,
    events: &dyn EventSink,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), DriverError> {
    for diagnostic in diagnostics {
        check_cancelled(is_cancelled)?;
        events.emit(DriverEvent::Diagnostic {
            diagnostic,
            sources,
        });
    }
    check_cancelled(is_cancelled)
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), DriverError> {
    if is_cancelled() {
        Err(DriverError::Cancelled)
    } else {
        Ok(())
    }
}

fn input_error(phase: &'static str, message: impl Into<String>) -> DriverError {
    DriverError::Input {
        phase,
        message: message.into(),
    }
}

fn publication_error(path: &Path, message: impl Into<String>) -> DriverError {
    DriverError::Publication {
        path: path.to_path_buf(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use super::*;

    const MINIMAL_MANIFEST: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/minimal.toml");
    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
            for _ in 0..128 {
                let sequence = TEST_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
                let root = base.join(format!(
                    "wrela-local-format-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        return Self {
                            root: fs::canonicalize(root).expect("canonical fixture"),
                        };
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create fixture: {error}"),
                }
            }
            panic!("cannot allocate fixture directory")
        }

        fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent");
            }
            fs::write(&path, bytes).expect("fixture write");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn format_text(text: &str) -> Result<FormatOutput, DriverError> {
        let mut sources = SourceDatabase::default();
        let digest = SoftwareSha256.sha256(text.as_bytes());
        let file = sources
            .add(SourceInput {
                path: "src/mini.wr".to_owned(),
                text: text.to_owned(),
                digest,
            })
            .expect("source");
        let output = WrelaSyntaxParser::new()
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("parse");
        assert!(
            output.diagnostics().is_empty(),
            "fixture must parse cleanly"
        );
        CanonicalSourceFormatter
            .format(
                FormatRequest {
                    parsed: output.parsed(),
                    source: sources.get(file).expect("source file"),
                    options: &FormatOptions::default(),
                    range: None,
                },
                &never_cancelled,
            )
            .map_err(map_format_error)
    }

    #[test]
    fn canonical_formatter_normalizes_layout_semicolons_and_comments() {
        let output = format_text(
            "module   mini\r\n\r\nfn  run( value:u64 ) :\r\n    pass;return  value# kept\r\n",
        )
        .expect("format");
        assert_eq!(
            output.formatted(),
            "module mini\n\nfn run(value: u64):\n    pass\n    return value  # kept\n"
        );
        assert!(output.changed());
        assert_eq!(output.edits().len(), 1);

        let second = format_text(output.formatted()).expect("idempotent format");
        assert!(!second.changed());
        assert!(second.edits().is_empty());
    }

    #[test]
    fn canonical_formatter_preserves_dedicated_init_syntax() {
        let output = format_text(
            "module mini\nstruct Cache:\n    value:u64\n    init( mut self,value:u64 ) :\n        self.value=value\n",
        )
        .expect("format init");
        assert_eq!(
            output.formatted(),
            "module mini\nstruct Cache:\n    value: u64\n    init(mut self, value: u64):\n        self.value = value\n"
        );
        assert!(
            !format_text(output.formatted())
                .expect("reparse init")
                .changed()
        );
    }

    #[test]
    fn formatter_preserves_explicit_exclusive_call_places() {
        let output = format_text(
            "module mini\nfn run(buffer: Buffer, packet: Packet):\n    sink( mut (buffer.field),payload=take packet )\n",
        )
        .expect("format exclusive call places");
        assert_eq!(
            output.formatted(),
            "module mini\nfn run(buffer: Buffer, packet: Packet):\n    sink(mut (buffer.field), payload=take packet)\n"
        );
        assert!(
            !format_text(output.formatted())
                .expect("reparse exclusive call places")
                .changed()
        );
    }

    #[test]
    fn formatter_preserves_literals_and_formats_interpolation_without_gaps() {
        let output = format_text(
            "module mini\nfn run(left:u64):\n    value=f\"raw {{brace}} {left :08x}\"\n",
        )
        .expect("format");
        assert_eq!(
            output.formatted(),
            "module mini\nfn run(left: u64):\n    value = f\"raw {{brace}} {left:08x}\"\n"
        );
    }

    #[test]
    fn canonical_formatter_reparses_and_is_idempotent_across_syntax_contracts() {
        const FIXTURES: &[(&str, &str)] = &[
            (
                "declarations-types",
                include_str!("../../../tests/contracts/syntax/v3/declarations-types.wr"),
            ),
            (
                "imports-trivia",
                include_str!("../../../tests/contracts/syntax/v3/imports-trivia.wr"),
            ),
            (
                "layout",
                include_str!("../../../tests/contracts/syntax/v3/layout.wr"),
            ),
            (
                "layout-dedent",
                include_str!("../../../tests/contracts/syntax/v3/layout-dedent.wr"),
            ),
            (
                "layout-nested-dedent",
                include_str!("../../../tests/contracts/syntax/v3/layout-nested-dedent.wr"),
            ),
            (
                "literals",
                include_str!("../../../tests/contracts/syntax/v3/literals.wr"),
            ),
            (
                "precedence",
                include_str!("../../../tests/contracts/syntax/v3/precedence.wr"),
            ),
            (
                "representative",
                include_str!("../../../tests/contracts/syntax/v3/representative.wr"),
            ),
            (
                "statements-expressions",
                include_str!("../../../tests/contracts/syntax/v3/statements-expressions.wr"),
            ),
            (
                "unicode",
                include_str!("../../../tests/contracts/syntax/v3/unicode.wr"),
            ),
        ];
        for (name, source) in FIXTURES {
            let first =
                format_text(source).unwrap_or_else(|error| panic!("format {name} failed: {error}"));
            let second = format_text(first.formatted())
                .unwrap_or_else(|error| panic!("reparse {name} failed: {error}"));
            assert!(
                !second.changed(),
                "formatted {name} was not idempotent:\n{}",
                second.formatted()
            );
        }
    }

    #[test]
    fn range_formatting_changes_only_the_smallest_enclosing_ast_node() {
        let text = "module   mini\n\nfn  run( value:u64 ) :\n    pass;return  value\n";
        let mut sources = SourceDatabase::default();
        let file = sources
            .add(SourceInput {
                path: "src/mini.wr".to_owned(),
                text: text.to_owned(),
                digest: SoftwareSha256.sha256(text.as_bytes()),
            })
            .expect("source");
        let parsed = WrelaSyntaxParser::new()
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("parse");
        assert!(parsed.diagnostics().is_empty());
        let function_start =
            u32::try_from(text.find("fn").expect("function start")).expect("function start offset");
        let function_end = u32::try_from(text.trim_end().len()).expect("function end offset");
        let output = CanonicalSourceFormatter
            .format(
                FormatRequest {
                    parsed: parsed.parsed(),
                    source: sources.get(file).expect("source file"),
                    options: &FormatOptions::default(),
                    range: Some(TextRange {
                        start: function_start,
                        end: function_end,
                    }),
                },
                &never_cancelled,
            )
            .expect("range format");
        assert_eq!(
            output.formatted(),
            "module   mini\n\nfn run(value: u64):\n    pass\n    return value\n"
        );
        assert!(output.edits().iter().all(|edit| {
            edit.range.start >= output.effective_range().start
                && edit.range.end <= output.effective_range().end
        }));
        assert_eq!(
            &output.formatted()[..function_start as usize],
            &text[..function_start as usize]
        );
    }

    #[test]
    fn check_only_reports_changes_without_writing() {
        let directory = TestDirectory::new();
        let manifest = directory.write("wrela.toml", MINIMAL_MANIFEST);
        let source = directory.write(
            "src/mini.wr",
            b"module   mini\nfn run():\n    pass;return\n",
        );
        let original = fs::read(&source).expect("original");
        let output = LocalFormatDriver::new(PipelineLimits::standard())
            .expect("driver")
            .execute(
                &Command::Format {
                    manifest,
                    files: vec![source.clone()],
                    check_only: true,
                },
                &SilentEvents,
                &never_cancelled,
            )
            .expect("check-only format");
        let CommandOutput::Format(outcome) = output else {
            panic!("format output")
        };
        assert_eq!(outcome.changed_files(), 1);
        assert_eq!(fs::read(source).expect("unchanged"), original);
    }

    #[test]
    fn publishing_formats_declared_source_and_reparses_idempotently() {
        let directory = TestDirectory::new();
        let manifest = directory.write("wrela.toml", MINIMAL_MANIFEST);
        let source = directory.write(
            "src/mini.wr",
            b"module mini\nfn run(value:u64):\n    pass;return value\n",
        );
        let driver = LocalFormatDriver::new(PipelineLimits::standard()).expect("driver");
        let command = Command::Format {
            manifest,
            files: vec![source.clone()],
            check_only: false,
        };
        let first = driver
            .execute(&command, &SilentEvents, &never_cancelled)
            .expect("published format");
        let CommandOutput::Format(first) = first else {
            panic!("format output")
        };
        assert_eq!(first.changed_files(), 1);
        assert_eq!(
            fs::read_to_string(&source).expect("formatted source"),
            "module mini\nfn run(value: u64):\n    pass\n    return value\n"
        );
        let second = driver
            .execute(&command, &SilentEvents, &never_cancelled)
            .expect("idempotent format");
        let CommandOutput::Format(second) = second else {
            panic!("format output")
        };
        assert_eq!(second.changed_files(), 0);
    }

    #[test]
    fn undeclared_duplicate_and_noncanonical_paths_are_rejected() {
        let directory = TestDirectory::new();
        let manifest = directory.write("wrela.toml", MINIMAL_MANIFEST);
        let source = directory.write("src/mini.wr", b"module mini\n");
        let other = directory.write("src/other.wr", b"module other\n");
        let outside = directory.write("outside.wr", b"module outside\n");
        let driver = LocalFormatDriver::new(PipelineLimits::standard()).expect("driver");
        // `src/other.wr` is a derived module under the source root, so
        // formatting it is an ordinary command now.
        driver
            .execute(
                &Command::Format {
                    manifest: manifest.clone(),
                    files: vec![other],
                    check_only: true,
                },
                &SilentEvents,
                &never_cancelled,
            )
            .expect("derived module source formats");
        // A path outside the source root and a duplicated path stay rejected.
        for files in [vec![outside], vec![source.clone(), source.clone()]] {
            assert!(matches!(
                driver.execute(
                    &Command::Format {
                        manifest: manifest.clone(),
                        files,
                        check_only: true,
                    },
                    &SilentEvents,
                    &never_cancelled,
                ),
                Err(DriverError::InvalidCommand(_))
            ));
        }
    }

    #[test]
    fn syntax_errors_are_canonical_rejections_and_never_publish() {
        let directory = TestDirectory::new();
        let manifest = directory.write("wrela.toml", MINIMAL_MANIFEST);
        let source = directory.write("src/mini.wr", b"module mini\nfn broken(:\n");
        let original = fs::read(&source).expect("original");
        let result = LocalFormatDriver::new(PipelineLimits::standard())
            .expect("driver")
            .execute(
                &Command::Format {
                    manifest,
                    files: vec![source.clone()],
                    check_only: false,
                },
                &SilentEvents,
                &never_cancelled,
            );
        assert!(matches!(result, Err(DriverError::Rejected { .. })));
        assert_eq!(fs::read(source).expect("unchanged"), original);
    }

    #[test]
    fn compare_and_replace_rejects_a_concurrent_edit_before_commit() {
        let directory = TestDirectory::new();
        let source = directory.write("mini.wr", b"module   mini\n");
        let initial = read_stable_file(&source, 1024, true, &never_cancelled).expect("initial");
        let input = SelectedInput {
            path: source.clone(),
            file: FileId(0),
            digest: initial.digest,
            metadata: initial.metadata,
        };
        let publication = prepare_publication(
            &input,
            &initial.bytes,
            b"module mini\n",
            1024,
            &never_cancelled,
        )
        .expect("prepared");
        fs::write(&source, b"module concurrent\n").expect("concurrent edit");
        assert!(matches!(
            revalidate_publication(&publication, 1024, &never_cancelled),
            Err(DriverError::Publication { .. })
        ));
        assert_eq!(
            fs::read_to_string(source).expect("concurrent bytes preserved"),
            "module concurrent\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_group_writable_sources_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let source = directory.write("source.wr", b"module source\n");
        let symlink_path = directory.root.join("symlink.wr");
        symlink(&source, &symlink_path).expect("symlink");
        assert!(read_stable_file(&symlink_path, 1024, true, &never_cancelled).is_err());

        let hardlink = directory.root.join("hardlink.wr");
        fs::hard_link(&source, &hardlink).expect("hard link");
        assert!(read_stable_file(&source, 1024, true, &never_cancelled).is_err());
        fs::remove_file(hardlink).expect("remove hard link");

        let mut permissions = fs::metadata(&source).expect("metadata").permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&source, permissions).expect("group writable");
        assert!(read_stable_file(&source, 1024, true, &never_cancelled).is_err());
    }

    #[test]
    fn cancellation_before_publication_leaves_every_source_unchanged() {
        let directory = TestDirectory::new();
        let manifest = directory.write("wrela.toml", MINIMAL_MANIFEST);
        let source = directory.write("src/mini.wr", b"module   mini\n");
        let original = fs::read(&source).expect("original");
        let polls = Cell::new(0usize);
        let cancelled = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 8
        };
        let result = LocalFormatDriver::new(PipelineLimits::standard())
            .expect("driver")
            .execute(
                &Command::Format {
                    manifest,
                    files: vec![source.clone()],
                    check_only: false,
                },
                &SilentEvents,
                &cancelled,
            );
        assert!(matches!(result, Err(DriverError::Cancelled)));
        assert_eq!(fs::read(source).expect("unchanged"), original);
    }
}
