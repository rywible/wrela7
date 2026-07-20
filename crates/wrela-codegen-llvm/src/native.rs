use inkwell::OptimizationLevel;
use inkwell::context::Context;
use inkwell::memory_buffer::MemoryBuffer;
use inkwell::targets::{
    CodeModel, FileType, InitializationConfig, RelocMode, Target, TargetTriple,
};

use crate::{
    CodegenError, CodegenRequest, ObjectArtifact, PINNED_LLVM_VERSION, coff, ir, seal_object,
};

pub(super) fn emit_object(
    request: CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ObjectArtifact, CodegenError> {
    check_cancelled(is_cancelled)?;
    // The backend links whatever LLVM 22.1.x is installed on the host, so the
    // gate pins the major/minor ABI series (matching inkwell's `llvm22-1`
    // feature) and accepts any patch release rather than one exact build.
    let observed_version = inkwell::support::get_llvm_version();
    if (observed_version.0, observed_version.1) != (PINNED_LLVM_VERSION.0, PINNED_LLVM_VERSION.1) {
        return Err(CodegenError::LlvmVersionMismatch {
            expected: PINNED_LLVM_VERSION,
            observed: observed_version,
        });
    }
    Target::initialize_aarch64(&InitializationConfig {
        asm_parser: true,
        asm_printer: true,
        base: true,
        disassembler: false,
        info: true,
        machine_code: true,
    });
    check_cancelled(is_cancelled)?;

    let triple = TargetTriple::create(request.target.llvm_triple());
    let llvm_target = Target::from_triple(&triple)
        .map_err(|error| CodegenError::TargetInitialization(error.to_string()))?;
    let features = join_features(
        request.target.llvm_features(),
        request.options.maximum_measurement_bytes,
        is_cancelled,
    )?;
    let target_machine = llvm_target
        .create_target_machine(
            &triple,
            request.target.llvm_cpu(),
            &features,
            OptimizationLevel::None,
            RelocMode::Static,
            CodeModel::Small,
        )
        .ok_or_else(|| {
            CodegenError::TargetInitialization(
                "LLVM could not create the pinned AArch64 target machine".to_owned(),
            )
        })?;
    let target_data = target_machine.get_target_data();
    let data_layout = target_data.get_data_layout();
    let actual_layout = data_layout.as_str().to_str().map_err(|_| {
        CodegenError::TargetInitialization("LLVM data layout is not UTF-8".to_owned())
    })?;
    if actual_layout != request.target.llvm_data_layout() {
        return Err(CodegenError::TargetMachineMismatch(format!(
            "LLVM reported {actual_layout:?}, target package pins {:?}",
            request.target.llvm_data_layout()
        )));
    }
    check_cancelled(is_cancelled)?;

    // Rendering textual IR is intentional. Inkwell 0.9 rewrites section names
    // according to the build host in `set_section`, corrupting COFF section
    // names on macOS, and its opaque-pointer GEP builder is unsafe. Parsing the
    // bounded target-owned IR keeps the crate safe and preserves exact COFF
    // sections without allowing LLVM values to cross this boundary.
    let mut llvm_ir = ir::render_module(&request, is_cancelled)?;
    let actual_ir = u64::try_from(llvm_ir.len()).unwrap_or(u64::MAX);
    check_cancelled(is_cancelled)?;
    llvm_ir
        .try_reserve_exact(1)
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "LLVM IR bytes",
            limit: request.options.maximum_ir_bytes,
            actual: actual_ir,
        })?;
    check_cancelled(is_cancelled)?;
    llvm_ir.push(0);
    let context = Context::create();
    // Keep the fallibly allocated IR vector alive while LLVM consumes a
    // non-owning view. The copy constructor would make a second input-sized
    // allocation inside LLVM, where allocation failure cannot be reported as a
    // CodegenError.
    let buffer = MemoryBuffer::create_from_memory_range(&llvm_ir, "wrela-machine.ll");
    let module = context
        .create_module_from_ir(buffer)
        .map_err(|error| CodegenError::LlvmVerification(error.to_string()))?;
    check_cancelled(is_cancelled)?;
    module
        .verify()
        .map_err(|error| CodegenError::LlvmVerification(error.to_string()))?;
    check_cancelled(is_cancelled)?;

    let buffer = target_machine
        .write_to_memory_buffer(&module, FileType::Object)
        .map_err(|error| CodegenError::ObjectEmission(error.to_string()))?;
    check_cancelled(is_cancelled)?;
    let emitted = buffer.as_slice();
    let actual = u64::try_from(emitted.len()).map_err(|_| CodegenError::ObjectTooLarge {
        limit: request.options.maximum_object_bytes,
        actual: u64::MAX,
    })?;
    if actual == 0 || actual > request.options.maximum_object_bytes {
        return Err(CodegenError::ObjectTooLarge {
            limit: request.options.maximum_object_bytes,
            actual,
        });
    }
    let bytes = copy_object_bytes(emitted, request.options.maximum_object_bytes, is_cancelled)?;
    let (sections, symbols) =
        coff::measure_object(&bytes, request.module, request.options, is_cancelled)?;
    check_cancelled(is_cancelled)?;
    seal_object(&request, bytes, sections, symbols, is_cancelled)
}

fn join_features(
    features: &[String],
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, CodegenError> {
    let mut actual = 0u64;
    for (index, feature) in features.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        actual = actual
            .checked_add(u64::try_from(feature.len()).unwrap_or(u64::MAX))
            .and_then(|bytes| bytes.checked_add(u64::from(index != 0)))
            .unwrap_or(u64::MAX);
        if actual > limit {
            return Err(CodegenError::ResourceLimit {
                resource: "LLVM target feature bytes",
                limit,
                actual,
            });
        }
    }
    let capacity = usize::try_from(actual).map_err(|_| CodegenError::ResourceLimit {
        resource: "LLVM target feature bytes",
        limit,
        actual,
    })?;
    let mut joined = String::new();
    check_cancelled(is_cancelled)?;
    joined
        .try_reserve_exact(capacity)
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "LLVM target feature bytes",
            limit,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for (index, feature) in features.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if index != 0 {
            joined.push(',');
        }
        push_text_chunks(&mut joined, feature, is_cancelled)?;
    }
    check_cancelled(is_cancelled)?;
    Ok(joined)
}

fn copy_object_bytes(
    emitted: &[u8],
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, CodegenError> {
    const CHUNK_BYTES: usize = 64 * 1024;

    let actual = u64::try_from(emitted.len()).unwrap_or(u64::MAX);
    if actual > limit {
        return Err(CodegenError::ObjectTooLarge { limit, actual });
    }
    check_cancelled(is_cancelled)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(emitted.len())
        .map_err(|_| CodegenError::ObjectTooLarge { limit, actual })?;
    check_cancelled(is_cancelled)?;
    for chunk in emitted.chunks(CHUNK_BYTES) {
        check_cancelled(is_cancelled)?;
        bytes.extend_from_slice(chunk);
    }
    check_cancelled(is_cancelled)?;
    Ok(bytes)
}

fn push_text_chunks(
    output: &mut String,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    const CHUNK_BYTES: usize = 64 * 1024;

    let mut start = 0usize;
    while start < value.len() {
        check_cancelled(is_cancelled)?;
        let mut end = start.saturating_add(CHUNK_BYTES).min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(CodegenError::TargetInitialization(
                "target feature has an invalid UTF-8 chunk boundary".to_owned(),
            ));
        }
        output.push_str(&value[start..end]);
        start = end;
    }
    check_cancelled(is_cancelled)
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), CodegenError> {
    if is_cancelled() {
        Err(CodegenError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn object_and_feature_copies_cancel_inside_large_payloads() {
        let emitted = vec![0x5a; 64 * 1024 * 3];
        let object_polls = Cell::new(0usize);
        assert_eq!(
            copy_object_bytes(&emitted, emitted.len() as u64, &|| {
                let next = object_polls.get() + 1;
                object_polls.set(next);
                next == 4
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(object_polls.get(), 4);

        let features = vec!["x".repeat(64 * 1024 * 3)];
        let feature_polls = Cell::new(0usize);
        assert_eq!(
            join_features(&features, features[0].len() as u64, &|| {
                let next = feature_polls.get() + 1;
                feature_polls.set(next);
                next == 6
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(feature_polls.get(), 6);

        let split_code_point = format!("{}é-tail", "x".repeat(64 * 1024 - 1));
        assert_eq!(
            join_features(
                std::slice::from_ref(&split_code_point),
                split_code_point.len() as u64,
                &|| false,
            )
            .expect("UTF-8 feature crossing the byte chunk boundary"),
            split_code_point
        );
    }
}
