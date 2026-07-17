use std::cmp::Ordering;
use std::fs::{self, File, Metadata};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use sha2::{Digest, Sha256};
use wrela_build_model::Sha256Digest;
use wrela_target::TargetBackendContract;

use crate::{
    CoffInspectError, CoffObjectInspector, CoffObjectMeasurements, CoffProvenanceInput,
    EFI_IMAGE_BASE, ImageInspectLimits, ImageMeasurements, InspectError, LinkedImageInspector,
    LinkedSection, LinkedSymbol, PE_SECTION_ALIGNMENT,
};

const IO_CHUNK_BYTES: usize = 64 * 1024;
const MAX_HEADER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MAP_LINE_BYTES: usize = 1024 * 1024;
const COFF_HEADER_BYTES: u64 = 20;
const COFF_SECTION_BYTES: u64 = 40;
const COFF_SECTION_NAME_BYTES: usize = 8;
const COFF_RELOCATION_BYTES: u64 = 10;
const COFF_LINE_NUMBER_BYTES: u64 = 6;
const COFF_SYMBOL_BYTES: u64 = 18;
const PE_SIGNATURE_BYTES: u64 = 4;
const PE_OPTIONAL_HEADER_BYTES: usize = 240;
const PE32_PLUS_DATA_DIRECTORY_OFFSET: usize = 112;
const PE_DATA_DIRECTORY_COUNT: usize = 16;
const PE_SECTION_BYTES: u64 = 40;
const MAX_PE_SECTIONS: usize = 96;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const IMAGE_FILE_CHARACTERISTICS_WRELA: u16 =
    IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_WRELA_TEXT: u32 = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
const IMAGE_SCN_WRELA_READ_ONLY: u32 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
const IMAGE_SCN_WRELA_DATA: u32 =
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
const IMAGE_SCN_WRELA_BSS: u32 =
    IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
const IMAGE_SCN_WRELA_RELOC: u32 =
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ;
const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
const IMAGE_SYM_DTYPE_FUNCTION: u16 = 0x20;
const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
const IMAGE_REL_ARM64_ADDR32: u16 = 0x0001;
const IMAGE_REL_ARM64_ADDR32NB: u16 = 0x0002;
const IMAGE_REL_ARM64_BRANCH26: u16 = 0x0003;
const IMAGE_REL_ARM64_PAGEBASE_REL21: u16 = 0x0004;
const IMAGE_REL_ARM64_REL21: u16 = 0x0005;
const IMAGE_REL_ARM64_PAGEOFFSET_12A: u16 = 0x0006;
const IMAGE_REL_ARM64_PAGEOFFSET_12L: u16 = 0x0007;
const IMAGE_REL_ARM64_SECREL: u16 = 0x0008;
const IMAGE_REL_ARM64_SECREL_LOW12A: u16 = 0x0009;
const IMAGE_REL_ARM64_SECREL_HIGH12A: u16 = 0x000a;
const IMAGE_REL_ARM64_SECREL_LOW12L: u16 = 0x000b;
const IMAGE_REL_ARM64_SECTION: u16 = 0x000d;
const IMAGE_REL_ARM64_ADDR64: u16 = 0x000e;
const IMAGE_REL_ARM64_BRANCH19: u16 = 0x000f;
const IMAGE_REL_ARM64_BRANCH14: u16 = 0x0010;
const IMAGE_REL_ARM64_REL32: u16 = 0x0011;
const BASE_RELOCATION_PAGE_BYTES: u64 = 4096;
const BASE_RELOCATION_BLOCK_HEADER_BYTES: u64 = 8;
const BASE_RELOCATION_ENTRY_BYTES: u64 = 2;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const PE_FILE_ALIGNMENT: u32 = 512;
const PE_MAJOR_LINKER_VERSION: u8 = 14;
const PE_MINOR_LINKER_VERSION: u8 = 0;
const PE_MAJOR_OS_VERSION: u16 = 6;
const PE_MINOR_OS_VERSION: u16 = 0;
const PE_MAJOR_IMAGE_VERSION: u16 = 0;
const PE_MINOR_IMAGE_VERSION: u16 = 0;
const PE_MAJOR_SUBSYSTEM_VERSION: u16 = 6;
const PE_MINOR_SUBSYSTEM_VERSION: u16 = 0;
const PE_DLL_CHARACTERISTICS: u16 = 0x8160;
const PE_STACK_RESERVE: u64 = 1024 * 1024;
const PE_STACK_COMMIT: u64 = 4096;
const PE_HEAP_RESERVE: u64 = 1024 * 1024;
const PE_HEAP_COMMIT: u64 = 4096;
const IMAGE_DEBUG_DIRECTORY_BYTES: u64 = 28;
const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;
const ARM64_RUNTIME_FUNCTION_BYTES: u64 = 8;
const ARM64_INSTRUCTION_BYTES: u64 = 4;
const LLD_PE_OFFSET: usize = 0x78;
const LLD_DOS_STUB: [u8; LLD_PE_OFFSET] = [
    0x4d, 0x5a, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00,
    0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
    0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x24, 0x00, 0x00,
];
const LINKER_DIRECTIVE_SECTION: &[u8; COFF_SECTION_NAME_BYTES] = b".drectve";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffEntryEvidence {
    pub defines_entry: bool,
}

/// Production ordinary-COFF inspector. It hashes the same bounded streaming
/// read from which its header and section table are captured.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalCoffObjectInspector;

impl CanonicalCoffObjectInspector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CoffObjectInspector for CanonicalCoffObjectInspector {
    fn inspect(
        &self,
        object: &Path,
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CoffObjectMeasurements, CoffInspectError> {
        inspect_coff_object(object, maximum_bytes, is_cancelled)
    }
}

/// Production PE32+/LLD-map inspector. Image bytes are hashed while the exact
/// parsed header is captured; the map is consumed incrementally with bounded
/// lines and retained measurements.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalLinkedImageInspector;

impl CanonicalLinkedImageInspector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LinkedImageInspector for CanonicalLinkedImageInspector {
    fn inspect(
        &self,
        image: &Path,
        map: &Path,
        provenance_map: &Path,
        inputs: &[CoffProvenanceInput<'_>],
        target: &TargetBackendContract,
        limits: ImageInspectLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ImageMeasurements, InspectError> {
        inspect_linked_image(
            image,
            map,
            provenance_map,
            inputs,
            target,
            limits,
            is_cancelled,
        )
    }
}

#[derive(Debug)]
enum StableReadError {
    Cancelled,
    Io(String),
    TooLarge { limit: u64, actual: u64 },
    Truncated,
    Unstable,
}

struct StableFile {
    file: File,
    identity: FileIdentity,
    bytes: u64,
}

struct DigestingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> DigestingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> Sha256Digest {
        sha256_digest(self.hasher)
    }
}

impl<R: Read> Read for DigestingReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(bytes)?;
        self.hasher.update(&bytes[..read]);
        Ok(read)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    bytes: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(windows)]
    attributes: u32,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    modified_time: u64,
}

fn inspect_coff_object(
    path: &Path,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CoffObjectMeasurements, CoffInspectError> {
    let mut stable = open_stable_file(path, maximum_bytes).map_err(map_coff_read_error)?;
    let probe = read_exact_at::<20>(&mut stable.file, 0).map_err(map_coff_read_error)?;
    let machine = le_u16(&probe, 0).ok_or(CoffInspectError::Truncated)?;
    if machine != IMAGE_FILE_MACHINE_ARM64 {
        return Err(CoffInspectError::UnsupportedMachine(machine));
    }
    let section_count = u64::from(le_u16(&probe, 2).ok_or(CoffInspectError::Truncated)?);
    let symbol_table = u64::from(le_u32(&probe, 8).ok_or(CoffInspectError::Truncated)?);
    let symbol_count = u64::from(le_u32(&probe, 12).ok_or(CoffInspectError::Truncated)?);
    let optional_header = le_u16(&probe, 16).ok_or(CoffInspectError::Truncated)?;
    if section_count == 0 || optional_header != 0 {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    let section_table_end = COFF_HEADER_BYTES
        .checked_add(
            section_count
                .checked_mul(COFF_SECTION_BYTES)
                .ok_or(CoffInspectError::InvalidCoffHeader)?,
        )
        .ok_or(CoffInspectError::InvalidCoffHeader)?;
    if section_table_end > stable.bytes || section_table_end > MAX_HEADER_BYTES {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    let symbol_table_end =
        validate_symbol_table(symbol_table, symbol_count, section_table_end, stable.bytes)?;
    let (digest, header) = hash_and_capture_prefix(
        &mut stable.file,
        stable.bytes,
        section_table_end,
        is_cancelled,
    )
    .map_err(map_coff_read_error)?;
    let section_data_end = validate_coff_sections(
        &header,
        section_count,
        stable.bytes,
        maximum_bytes,
        is_cancelled,
    )?;
    if symbol_count != 0 && symbol_table < section_data_end {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    reject_linker_directive_sections(
        &mut stable.file,
        &header,
        section_count,
        symbol_table_end,
        symbol_count,
        stable.bytes,
        is_cancelled,
    )?;
    verify_stable_path(path, &stable).map_err(map_coff_read_error)?;
    Ok(CoffObjectMeasurements {
        bytes: stable.bytes,
        digest,
        coff_machine: "arm64".to_owned(),
    })
}

pub fn inspect_coff_entry_contract(
    path: &Path,
    expected_entry: &str,
    maximum_bytes: u64,
    maximum_sections: u32,
    maximum_symbols: u32,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CoffEntryEvidence, CoffInspectError> {
    if is_cancelled() {
        return Err(CoffInspectError::Cancelled);
    }
    let mut stable = open_stable_file(path, maximum_bytes).map_err(map_coff_read_error)?;
    let probe = read_exact_at::<20>(&mut stable.file, 0).map_err(map_coff_read_error)?;
    let machine = le_u16(&probe, 0).ok_or(CoffInspectError::Truncated)?;
    if machine != IMAGE_FILE_MACHINE_ARM64 {
        return Err(CoffInspectError::UnsupportedMachine(machine));
    }
    let section_count = u64::from(le_u16(&probe, 2).ok_or(CoffInspectError::Truncated)?);
    let symbol_table = u64::from(le_u32(&probe, 8).ok_or(CoffInspectError::Truncated)?);
    let symbol_count = u64::from(le_u32(&probe, 12).ok_or(CoffInspectError::Truncated)?);
    let optional_header = le_u16(&probe, 16).ok_or(CoffInspectError::Truncated)?;
    if section_count == 0 || optional_header != 0 {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    if section_count > u64::from(maximum_sections) {
        return Err(CoffInspectError::LimitExceeded {
            resource: "COFF sections",
            limit: u64::from(maximum_sections),
            actual: section_count,
        });
    }
    if symbol_count > u64::from(maximum_symbols) {
        return Err(CoffInspectError::LimitExceeded {
            resource: "COFF symbols",
            limit: u64::from(maximum_symbols),
            actual: symbol_count,
        });
    }
    let section_table_end = COFF_HEADER_BYTES
        .checked_add(
            section_count
                .checked_mul(COFF_SECTION_BYTES)
                .ok_or(CoffInspectError::InvalidCoffHeader)?,
        )
        .ok_or(CoffInspectError::InvalidCoffHeader)?;
    if section_table_end > stable.bytes || section_table_end > MAX_HEADER_BYTES {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    let symbol_table_end =
        validate_symbol_table(symbol_table, symbol_count, section_table_end, stable.bytes)?;
    let (_, header) = hash_and_capture_prefix(
        &mut stable.file,
        stable.bytes,
        section_table_end,
        is_cancelled,
    )
    .map_err(map_coff_read_error)?;
    let section_data_end = validate_coff_sections(
        &header,
        section_count,
        stable.bytes,
        maximum_bytes,
        is_cancelled,
    )?;
    if symbol_count != 0 && symbol_table < section_data_end {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    reject_linker_directive_sections(
        &mut stable.file,
        &header,
        section_count,
        symbol_table_end,
        symbol_count,
        stable.bytes,
        is_cancelled,
    )?;
    let defines_entry = scan_entry_definition(
        &mut stable.file,
        &header,
        section_count,
        symbol_table,
        symbol_table_end,
        symbol_count,
        stable.bytes,
        expected_entry,
        is_cancelled,
    )?;
    verify_stable_path(path, &stable).map_err(map_coff_read_error)?;
    Ok(CoffEntryEvidence { defines_entry })
}

fn validate_symbol_table(
    offset: u64,
    count: u64,
    section_table_end: u64,
    file_bytes: u64,
) -> Result<u64, CoffInspectError> {
    if count == 0 {
        if offset == 0 {
            return Ok(0);
        }
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    let table_bytes = count
        .checked_mul(COFF_SYMBOL_BYTES)
        .ok_or(CoffInspectError::InvalidCoffHeader)?;
    let end = offset
        .checked_add(table_bytes)
        .ok_or(CoffInspectError::InvalidCoffHeader)?;
    if offset < section_table_end || end > file_bytes {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    Ok(end)
}

#[allow(clippy::too_many_arguments)]
fn reject_linker_directive_sections(
    file: &mut File,
    header: &[u8],
    section_count: u64,
    symbol_table_end: u64,
    symbol_count: u64,
    file_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CoffInspectError> {
    let mut string_table = None;
    for index in 0..section_count {
        if index % 1024 == 0 && is_cancelled() {
            return Err(CoffInspectError::Cancelled);
        }
        let base = COFF_HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(COFF_SECTION_BYTES)
                    .ok_or(CoffInspectError::InvalidCoffHeader)?,
            )
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(CoffInspectError::InvalidCoffHeader)?;
        let name = header
            .get(base..base + COFF_SECTION_NAME_BYTES)
            .ok_or(CoffInspectError::InvalidCoffHeader)?;
        if name == LINKER_DIRECTIVE_SECTION {
            return Err(CoffInspectError::LinkerDirectiveSection);
        }
        if name.first() != Some(&b'/') {
            continue;
        }
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        if end <= 1
            || name[end..].iter().any(|byte| *byte != 0)
            || !name[1..end].iter().all(u8::is_ascii_digit)
        {
            return Err(CoffInspectError::InvalidCoffHeader);
        }
        let offset = name[1..end]
            .iter()
            .try_fold(0u64, |value, digit| {
                value.checked_mul(10)?.checked_add(u64::from(*digit - b'0'))
            })
            .ok_or(CoffInspectError::InvalidCoffHeader)?;
        let (table_offset, table_bytes) = match string_table {
            Some(table) => table,
            None => {
                if symbol_count == 0 {
                    return Err(CoffInspectError::InvalidCoffHeader);
                }
                let encoded =
                    read_exact_at::<4>(file, symbol_table_end).map_err(map_coff_read_error)?;
                let table_bytes = u64::from(u32::from_le_bytes(encoded));
                let table_end = symbol_table_end
                    .checked_add(table_bytes)
                    .ok_or(CoffInspectError::InvalidCoffHeader)?;
                if table_bytes < 4 || table_end > file_bytes {
                    return Err(CoffInspectError::InvalidCoffHeader);
                }
                let table = (symbol_table_end, table_bytes);
                string_table = Some(table);
                table
            }
        };
        if offset < 4 || offset >= table_bytes {
            return Err(CoffInspectError::InvalidCoffHeader);
        }
        let required = u64::try_from(LINKER_DIRECTIVE_SECTION.len() + 1)
            .map_err(|_| CoffInspectError::InvalidCoffHeader)?;
        if table_bytes - offset < required {
            continue;
        }
        let section_name = read_exact_at::<9>(
            file,
            table_offset
                .checked_add(offset)
                .ok_or(CoffInspectError::InvalidCoffHeader)?,
        )
        .map_err(map_coff_read_error)?;
        if section_name[..COFF_SECTION_NAME_BYTES] == LINKER_DIRECTIVE_SECTION[..]
            && section_name[COFF_SECTION_NAME_BYTES] == 0
        {
            return Err(CoffInspectError::LinkerDirectiveSection);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_entry_definition(
    file: &mut File,
    header: &[u8],
    section_count: u64,
    symbol_table: u64,
    symbol_table_end: u64,
    symbol_count: u64,
    file_bytes: u64,
    expected_entry: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CoffInspectError> {
    if expected_entry.is_empty() || !expected_entry.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(CoffInspectError::InvalidEntryAbi);
    }
    if symbol_count == 0 {
        return Ok(false);
    }
    let string_size = read_exact_at::<4>(file, symbol_table_end).map_err(map_coff_read_error)?;
    let string_bytes = u64::from(u32::from_le_bytes(string_size));
    let string_table_end = symbol_table_end
        .checked_add(string_bytes)
        .ok_or(CoffInspectError::InvalidCoffHeader)?;
    if string_bytes < 4 || string_table_end > file_bytes {
        return Err(CoffInspectError::InvalidCoffHeader);
    }

    let mut index = 0u64;
    let mut defines_entry = false;
    while index < symbol_count {
        if index % 1024 == 0 && is_cancelled() {
            return Err(CoffInspectError::Cancelled);
        }
        let record_offset = symbol_table
            .checked_add(
                index
                    .checked_mul(COFF_SYMBOL_BYTES)
                    .ok_or(CoffInspectError::InvalidCoffHeader)?,
            )
            .ok_or(CoffInspectError::InvalidCoffHeader)?;
        let record = read_exact_at::<18>(file, record_offset).map_err(map_coff_read_error)?;
        let auxiliary = u64::from(record[17]);
        let next = index
            .checked_add(1)
            .and_then(|value| value.checked_add(auxiliary))
            .filter(|value| *value <= symbol_count)
            .ok_or(CoffInspectError::InvalidCoffHeader)?;
        if coff_symbol_name_matches(
            file,
            &record[..8],
            symbol_table_end,
            string_bytes,
            expected_entry,
        )? {
            let section = le_i16(&record, 12).ok_or(CoffInspectError::InvalidCoffHeader)?;
            if section < 0 {
                return Err(CoffInspectError::InvalidEntryAbi);
            }
            if section > 0 {
                if defines_entry
                    || u64::try_from(section).map_or(true, |value| value > section_count)
                    || le_u16(&record, 14) != Some(IMAGE_SYM_DTYPE_FUNCTION)
                    || record[16] != IMAGE_SYM_CLASS_EXTERNAL
                {
                    return Err(CoffInspectError::InvalidEntryAbi);
                }
                let section_index =
                    u64::try_from(section - 1).map_err(|_| CoffInspectError::InvalidEntryAbi)?;
                let section_base = COFF_HEADER_BYTES
                    .checked_add(
                        section_index
                            .checked_mul(COFF_SECTION_BYTES)
                            .ok_or(CoffInspectError::InvalidCoffHeader)?,
                    )
                    .and_then(|offset| usize::try_from(offset).ok())
                    .ok_or(CoffInspectError::InvalidCoffHeader)?;
                let virtual_bytes = u64::from(
                    le_u32(header, section_base + 8).ok_or(CoffInspectError::InvalidCoffHeader)?,
                );
                let raw_bytes = u64::from(
                    le_u32(header, section_base + 16).ok_or(CoffInspectError::InvalidCoffHeader)?,
                );
                let characteristics =
                    le_u32(header, section_base + 36).ok_or(CoffInspectError::InvalidCoffHeader)?;
                let value =
                    u64::from(le_u32(&record, 8).ok_or(CoffInspectError::InvalidCoffHeader)?);
                if value >= virtual_bytes.max(raw_bytes)
                    || characteristics & IMAGE_SCN_CNT_CODE == 0
                    || characteristics & IMAGE_SCN_MEM_EXECUTE == 0
                {
                    return Err(CoffInspectError::InvalidEntryAbi);
                }
                defines_entry = true;
            }
        }
        index = next;
    }
    Ok(defines_entry)
}

fn coff_symbol_name_matches(
    file: &mut File,
    name: &[u8],
    string_table: u64,
    string_bytes: u64,
    expected: &str,
) -> Result<bool, CoffInspectError> {
    let name: &[u8; 8] = name
        .try_into()
        .map_err(|_| CoffInspectError::InvalidCoffHeader)?;
    if name[..4] != [0; 4] {
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        if name[end..].iter().any(|byte| *byte != 0) {
            return Err(CoffInspectError::InvalidCoffHeader);
        }
        return Ok(&name[..end] == expected.as_bytes());
    }

    let offset = u64::from(u32::from_le_bytes(
        name[4..8]
            .try_into()
            .map_err(|_| CoffInspectError::InvalidCoffHeader)?,
    ));
    let required = u64::try_from(expected.len())
        .ok()
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(CoffInspectError::InvalidEntryAbi)?;
    if offset < 4 || offset >= string_bytes {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    if string_bytes - offset < required {
        return Ok(false);
    }
    let name_offset = string_table
        .checked_add(offset)
        .ok_or(CoffInspectError::InvalidCoffHeader)?;
    file.seek(SeekFrom::Start(name_offset))
        .map_err(|error| CoffInspectError::Io(io_kind(error)))?;
    let mut expected_offset = 0usize;
    let mut buffer = [0u8; 256];
    while expected_offset < expected.len() {
        let bytes = (expected.len() - expected_offset).min(buffer.len());
        file.read_exact(&mut buffer[..bytes]).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                CoffInspectError::Truncated
            } else {
                CoffInspectError::Io(io_kind(error))
            }
        })?;
        if buffer[..bytes] != expected.as_bytes()[expected_offset..expected_offset + bytes] {
            return Ok(false);
        }
        expected_offset += bytes;
    }
    file.read_exact(&mut buffer[..1]).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            CoffInspectError::Truncated
        } else {
            CoffInspectError::Io(io_kind(error))
        }
    })?;
    Ok(buffer[0] == 0)
}

fn validate_coff_sections(
    header: &[u8],
    section_count: u64,
    file_bytes: u64,
    maximum_uninitialized_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, CoffInspectError> {
    let mut uninitialized_bytes = 0u64;
    let mut previous_file_end = COFF_HEADER_BYTES
        .checked_add(
            section_count
                .checked_mul(COFF_SECTION_BYTES)
                .ok_or(CoffInspectError::InvalidCoffHeader)?,
        )
        .ok_or(CoffInspectError::InvalidCoffHeader)?;
    for index in 0..section_count {
        if index % 1024 == 0 && is_cancelled() {
            return Err(CoffInspectError::Cancelled);
        }
        let base = COFF_HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(COFF_SECTION_BYTES)
                    .ok_or(CoffInspectError::InvalidCoffHeader)?,
            )
            .ok_or(CoffInspectError::InvalidCoffHeader)?;
        let base = usize::try_from(base).map_err(|_| CoffInspectError::InvalidCoffHeader)?;
        let raw_bytes =
            u64::from(le_u32(header, base + 16).ok_or(CoffInspectError::InvalidCoffHeader)?);
        let raw_offset =
            u64::from(le_u32(header, base + 20).ok_or(CoffInspectError::InvalidCoffHeader)?);
        let relocation_offset =
            u64::from(le_u32(header, base + 24).ok_or(CoffInspectError::InvalidCoffHeader)?);
        let line_offset =
            u64::from(le_u32(header, base + 28).ok_or(CoffInspectError::InvalidCoffHeader)?);
        let relocations =
            u64::from(le_u16(header, base + 32).ok_or(CoffInspectError::InvalidCoffHeader)?);
        let lines =
            u64::from(le_u16(header, base + 34).ok_or(CoffInspectError::InvalidCoffHeader)?);
        let characteristics =
            le_u32(header, base + 36).ok_or(CoffInspectError::InvalidCoffHeader)?;
        let uninitialized = characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;
        if uninitialized {
            if characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA) != 0
                || raw_offset != 0
                || relocations != 0
                || relocation_offset != 0
            {
                return Err(CoffInspectError::InvalidCoffHeader);
            }
            let actual = uninitialized_bytes.checked_add(raw_bytes).ok_or(
                CoffInspectError::LimitExceeded {
                    resource: "COFF uninitialized bytes",
                    limit: maximum_uninitialized_bytes,
                    actual: u64::MAX,
                },
            )?;
            if actual > maximum_uninitialized_bytes {
                return Err(CoffInspectError::LimitExceeded {
                    resource: "COFF uninitialized bytes",
                    limit: maximum_uninitialized_bytes,
                    actual,
                });
            }
            uninitialized_bytes = actual;
        } else {
            validate_optional_range(raw_offset, raw_bytes, file_bytes)?;
            previous_file_end =
                validate_ordered_range(raw_offset, raw_bytes, previous_file_end, file_bytes)?;
        }
        let relocation_bytes = relocations
            .checked_mul(COFF_RELOCATION_BYTES)
            .ok_or(CoffInspectError::InvalidCoffHeader)?;
        validate_optional_range(relocation_offset, relocation_bytes, file_bytes)?;
        previous_file_end = validate_ordered_range(
            relocation_offset,
            relocation_bytes,
            previous_file_end,
            file_bytes,
        )?;
        let line_bytes = lines
            .checked_mul(COFF_LINE_NUMBER_BYTES)
            .ok_or(CoffInspectError::InvalidCoffHeader)?;
        validate_optional_range(line_offset, line_bytes, file_bytes)?;
        previous_file_end =
            validate_ordered_range(line_offset, line_bytes, previous_file_end, file_bytes)?;
    }
    Ok(previous_file_end)
}

fn validate_ordered_range(
    offset: u64,
    bytes: u64,
    previous_end: u64,
    file_bytes: u64,
) -> Result<u64, CoffInspectError> {
    if bytes == 0 {
        return Ok(previous_end);
    }
    let end = offset
        .checked_add(bytes)
        .filter(|end| offset >= previous_end && *end <= file_bytes)
        .ok_or(CoffInspectError::InvalidCoffHeader)?;
    Ok(end)
}

fn validate_optional_range(
    offset: u64,
    bytes: u64,
    file_bytes: u64,
) -> Result<(), CoffInspectError> {
    if bytes == 0 {
        return (offset == 0 || offset <= file_bytes)
            .then_some(())
            .ok_or(CoffInspectError::InvalidCoffHeader);
    }
    if offset == 0 || offset.checked_add(bytes).is_none_or(|end| end > file_bytes) {
        return Err(CoffInspectError::InvalidCoffHeader);
    }
    Ok(())
}

#[derive(Debug)]
struct ProvenanceObject {
    ordinal: u32,
    path: String,
    digest: Sha256Digest,
    bytes: u64,
    sections: Vec<ProvenanceSection>,
    relocations: Vec<InputAddr64Relocation>,
    definitions: Vec<ExternalDefinition>,
}

#[derive(Debug)]
struct ProvenanceSection {
    ordinal: u32,
    name: String,
    bytes: u64,
    alignment: u32,
    characteristics: u32,
    contribution_output: Option<u32>,
    contribution_rva: Option<u64>,
}

#[derive(Debug, Clone)]
enum InputRelocationTarget {
    Defined { section: u32 },
    UndefinedExternal { name: String },
}

#[derive(Debug)]
struct InputAddr64Relocation {
    source_section: u32,
    source_offset: u64,
    target: Option<InputRelocationTarget>,
}

#[derive(Debug)]
struct ExternalDefinition {
    name: String,
    section: u32,
}

#[derive(Debug, Clone, Copy)]
struct RelocationReference {
    symbol: u32,
    addr64: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedRelocation {
    source_object: u32,
    source_section: u32,
    source_offset: u64,
    target_object: u32,
    target_section: u32,
    output_rva: u64,
}

#[derive(Default)]
struct ProvenanceBudget {
    sections: u64,
    symbols: u64,
    relocations: u64,
    measurement_bytes: u64,
}

impl ProvenanceBudget {
    fn add(
        current: &mut u64,
        amount: u64,
        limit: u64,
        resource: &'static str,
    ) -> Result<(), InspectError> {
        let actual = current
            .checked_add(amount)
            .ok_or(InspectError::LimitExceeded {
                resource,
                limit,
                actual: u64::MAX,
            })?;
        if actual > limit {
            return Err(InspectError::LimitExceeded {
                resource,
                limit,
                actual,
            });
        }
        *current = actual;
        Ok(())
    }

    fn add_measurement(
        &mut self,
        bytes: usize,
        limits: ImageInspectLimits,
    ) -> Result<(), InspectError> {
        Self::add(
            &mut self.measurement_bytes,
            u64::try_from(bytes).unwrap_or(u64::MAX),
            limits.measurement_bytes,
            "relocation provenance measurement bytes",
        )
    }
}

fn inspect_provenance_inputs(
    inputs: &[CoffProvenanceInput<'_>],
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ProvenanceObject>, InspectError> {
    if inputs.is_empty() || inputs.len() > limits.sections as usize {
        return Err(InspectError::InvalidRelocationProvenance(
            "relocation provenance input count is empty or unbounded",
        ));
    }
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(inputs.len())
        .map_err(|_| InspectError::LimitExceeded {
            resource: "relocation provenance inputs",
            limit: u64::from(limits.sections),
            actual: inputs.len() as u64,
        })?;
    let mut budget = ProvenanceBudget::default();
    for (index, input) in inputs.iter().copied().enumerate() {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if input.ordinal() as usize != index
            || input.expected_bytes() == 0
            || input.expected_bytes() > limits.image_bytes
            || input
                .expected_digest()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(InspectError::InvalidRelocationProvenance(
                "sealed input identity is noncanonical",
            ));
        }
        objects.push(inspect_provenance_input(
            input,
            &mut budget,
            limits,
            is_cancelled,
        )?);
    }
    Ok(objects)
}

#[allow(clippy::too_many_lines)]
fn inspect_provenance_input(
    input: CoffProvenanceInput<'_>,
    budget: &mut ProvenanceBudget,
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ProvenanceObject, InspectError> {
    let path = input
        .path()
        .to_str()
        .ok_or(InspectError::InvalidRelocationProvenance(
            "input path is not UTF-8 and cannot match LLD's contribution map",
        ))?;
    budget.add_measurement(path.len(), limits)?;
    let path = copy_string(path, limits.measurement_bytes)?;
    let mut stable = open_stable_file(input.path(), input.expected_bytes())
        .map_err(|error| map_image_read_error(error, "input provenance bytes"))?;
    if stable.bytes != input.expected_bytes() {
        return Err(InspectError::InvalidRelocationProvenance(
            "input byte length differs from its sealed identity",
        ));
    }
    let probe = read_exact_at::<20>(&mut stable.file, 0)
        .map_err(|error| map_image_read_error(error, "input provenance bytes"))?;
    if le_u16(&probe, 0) != Some(IMAGE_FILE_MACHINE_ARM64) || le_u16(&probe, 16) != Some(0) {
        return Err(InspectError::InvalidRelocationProvenance(
            "input is not ordinary ARM64 COFF",
        ));
    }
    let section_count = u64::from(le_u16(&probe, 2).ok_or(InspectError::Truncated)?);
    let symbol_table = u64::from(le_u32(&probe, 8).ok_or(InspectError::Truncated)?);
    let symbol_count = u64::from(le_u32(&probe, 12).ok_or(InspectError::Truncated)?);
    if section_count == 0 {
        return Err(InspectError::InvalidRelocationProvenance(
            "input COFF contains no sections",
        ));
    }
    ProvenanceBudget::add(
        &mut budget.sections,
        section_count,
        u64::from(limits.sections),
        "input COFF sections",
    )?;
    ProvenanceBudget::add(
        &mut budget.symbols,
        symbol_count,
        u64::from(limits.symbols),
        "input COFF symbols",
    )?;
    let section_table_end = COFF_HEADER_BYTES
        .checked_add(section_count.checked_mul(COFF_SECTION_BYTES).ok_or(
            InspectError::InvalidRelocationProvenance("input COFF section table overflows"),
        )?)
        .filter(|end| *end <= stable.bytes && *end <= MAX_HEADER_BYTES)
        .ok_or(InspectError::InvalidRelocationProvenance(
            "input COFF section table is out of bounds",
        ))?;
    let symbol_table_end =
        validate_symbol_table(symbol_table, symbol_count, section_table_end, stable.bytes)
            .map_err(map_coff_provenance_error)?;
    let (digest, header) = hash_and_capture_prefix(
        &mut stable.file,
        stable.bytes,
        section_table_end,
        is_cancelled,
    )
    .map_err(|error| map_image_read_error(error, "input provenance bytes"))?;
    if digest != input.expected_digest() {
        return Err(InspectError::InvalidRelocationProvenance(
            "input digest differs from its sealed identity",
        ));
    }
    let section_data_end = validate_coff_sections(
        &header,
        section_count,
        stable.bytes,
        limits.image_bytes,
        is_cancelled,
    )
    .map_err(map_coff_provenance_error)?;
    if symbol_count != 0 && symbol_table < section_data_end {
        return Err(InspectError::InvalidRelocationProvenance(
            "input symbol table overlaps section data",
        ));
    }
    reject_linker_directive_sections(
        &mut stable.file,
        &header,
        section_count,
        symbol_table_end,
        symbol_count,
        stable.bytes,
        is_cancelled,
    )
    .map_err(map_coff_provenance_error)?;
    let string_bytes = if symbol_count == 0 {
        0
    } else {
        let encoded = read_exact_at::<4>(&mut stable.file, symbol_table_end)
            .map_err(|error| map_image_read_error(error, "input provenance bytes"))?;
        let bytes = u64::from(u32::from_le_bytes(encoded));
        if bytes < 4
            || symbol_table_end
                .checked_add(bytes)
                .is_none_or(|end| end > stable.bytes)
        {
            return Err(InspectError::InvalidRelocationProvenance(
                "input COFF string table is out of bounds",
            ));
        }
        bytes
    };

    let section_capacity =
        usize::try_from(section_count).map_err(|_| InspectError::LimitExceeded {
            resource: "input COFF sections",
            limit: u64::from(limits.sections),
            actual: section_count,
        })?;
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(section_capacity)
        .map_err(|_| InspectError::LimitExceeded {
            resource: "input COFF sections",
            limit: u64::from(limits.sections),
            actual: section_count,
        })?;
    let mut total_relocations = 0u64;
    for index in 0..section_count {
        if index % 1024 == 0 && is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let base = usize::try_from(
            COFF_HEADER_BYTES
                .checked_add(index.checked_mul(COFF_SECTION_BYTES).ok_or(
                    InspectError::InvalidRelocationProvenance("input section index overflows"),
                )?)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "input section offset overflows",
                ))?,
        )
        .map_err(|_| InspectError::Truncated)?;
        let name = read_coff_section_name(
            &mut stable.file,
            header
                .get(base..base + COFF_SECTION_NAME_BYTES)
                .ok_or(InspectError::Truncated)?,
            symbol_table_end,
            string_bytes,
            limits,
            is_cancelled,
        )?;
        budget.add_measurement(name.len(), limits)?;
        let bytes = u64::from(le_u32(&header, base + 16).ok_or(InspectError::Truncated)?);
        let characteristics = le_u32(&header, base + 36).ok_or(InspectError::Truncated)?;
        if characteristics & (IMAGE_SCN_LNK_COMDAT | IMAGE_SCN_LNK_NRELOC_OVFL) != 0 {
            return Err(InspectError::InvalidRelocationProvenance(
                "COMDAT or relocation-overflow input sections are unsupported",
            ));
        }
        let alignment = coff_section_alignment(characteristics)?;
        let relocations = u64::from(le_u16(&header, base + 32).ok_or(InspectError::Truncated)?);
        total_relocations =
            total_relocations
                .checked_add(relocations)
                .ok_or(InspectError::LimitExceeded {
                    resource: "input COFF relocations",
                    limit: u64::from(limits.base_relocations),
                    actual: u64::MAX,
                })?;
        sections.push(ProvenanceSection {
            ordinal: u32::try_from(index).map_err(|_| InspectError::LimitExceeded {
                resource: "input COFF sections",
                limit: u64::from(limits.sections),
                actual: section_count,
            })?,
            name,
            bytes,
            alignment,
            characteristics,
            contribution_output: None,
            contribution_rva: None,
        });
    }
    ProvenanceBudget::add(
        &mut budget.relocations,
        total_relocations,
        u64::from(limits.base_relocations),
        "input COFF relocations",
    )?;
    let mut names: Vec<&str> = sections
        .iter()
        .map(|section| section.name.as_str())
        .collect();
    names = cancellable_sort(
        names,
        Ord::cmp,
        "input COFF sections",
        u64::from(limits.sections),
        is_cancelled,
    )?;
    for pair in names.windows(2) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if pair[0] == pair[1] && !repeated_provenance_section_name_is_supported(pair[0]) {
            return Err(InspectError::InvalidRelocationProvenance(
                "duplicate input section names make LLD contributions ambiguous",
            ));
        }
    }

    let relocation_capacity =
        usize::try_from(total_relocations).map_err(|_| InspectError::LimitExceeded {
            resource: "input COFF relocations",
            limit: u64::from(limits.base_relocations),
            actual: total_relocations,
        })?;
    let mut references = Vec::new();
    references
        .try_reserve_exact(relocation_capacity)
        .map_err(|_| InspectError::LimitExceeded {
            resource: "input COFF relocations",
            limit: u64::from(limits.base_relocations),
            actual: total_relocations,
        })?;
    let mut sites = Vec::new();
    sites
        .try_reserve_exact(relocation_capacity)
        .map_err(|_| InspectError::LimitExceeded {
            resource: "input COFF relocations",
            limit: u64::from(limits.base_relocations),
            actual: total_relocations,
        })?;
    let mut relocations = Vec::new();
    relocations
        .try_reserve_exact(relocation_capacity.min(limits.base_relocations as usize))
        .map_err(|_| InspectError::LimitExceeded {
            resource: "input COFF relocations",
            limit: u64::from(limits.base_relocations),
            actual: total_relocations,
        })?;
    for (section_index, section) in sections.iter().enumerate() {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let base = 20 + section_index * 40;
        let relocation_offset =
            u64::from(le_u32(&header, base + 24).ok_or(InspectError::Truncated)?);
        let count = u64::from(le_u16(&header, base + 32).ok_or(InspectError::Truncated)?);
        for index in 0..count {
            if index % 1024 == 0 && is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            let offset = relocation_offset
                .checked_add(index.checked_mul(COFF_RELOCATION_BYTES).ok_or(
                    InspectError::InvalidRelocationProvenance("input relocation table overflows"),
                )?)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "input relocation offset overflows",
                ))?;
            let record = read_exact_at::<10>(&mut stable.file, offset)
                .map_err(|error| map_image_read_error(error, "input provenance bytes"))?;
            let source_offset = u64::from(le_u32(&record, 0).ok_or(InspectError::Truncated)?);
            let symbol = le_u32(&record, 4).ok_or(InspectError::Truncated)?;
            let kind = le_u16(&record, 8).ok_or(InspectError::Truncated)?;
            let width =
                arm64_relocation_width(kind).ok_or(InspectError::InvalidRelocationProvenance(
                    "input contains an unsupported ARM64 COFF relocation type",
                ))?;
            if u64::from(symbol) >= symbol_count
                || source_offset
                    .checked_add(width)
                    .is_none_or(|end| end > section.bytes)
            {
                return Err(InspectError::InvalidRelocationProvenance(
                    "input relocation site or target is out of bounds",
                ));
            }
            let addr64 = if kind == IMAGE_REL_ARM64_ADDR64 {
                if source_offset % 8 != 0
                    || section.characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0
                {
                    return Err(InspectError::InvalidRelocationProvenance(
                        "input ADDR64 site is unaligned or discardable",
                    ));
                }
                let index = relocations.len();
                relocations.push(InputAddr64Relocation {
                    source_section: u32::try_from(section_index).map_err(|_| {
                        InspectError::LimitExceeded {
                            resource: "input COFF sections",
                            limit: u64::from(limits.sections),
                            actual: section_count,
                        }
                    })?,
                    source_offset,
                    target: None,
                });
                Some(index)
            } else {
                None
            };
            references.push(RelocationReference { symbol, addr64 });
            sites.push((
                u32::try_from(section_index).unwrap_or(u32::MAX),
                source_offset,
            ));
        }
    }
    sites = cancellable_sort(
        sites,
        Ord::cmp,
        "input COFF relocations",
        u64::from(limits.base_relocations),
        is_cancelled,
    )?;
    for pair in sites.windows(2) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if pair[0] == pair[1] {
            return Err(InspectError::InvalidRelocationProvenance(
                "duplicate input relocation sites are ambiguous",
            ));
        }
    }
    references = cancellable_sort(
        references,
        |left, right| left.symbol.cmp(&right.symbol),
        "input COFF relocations",
        u64::from(limits.base_relocations),
        is_cancelled,
    )?;
    let mut definitions = Vec::new();
    let mut reference_index = 0usize;
    let mut symbol_index = 0u64;
    while symbol_index < symbol_count {
        if symbol_index % 1024 == 0 && is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if references
            .get(reference_index)
            .is_some_and(|reference| u64::from(reference.symbol) < symbol_index)
        {
            return Err(InspectError::InvalidRelocationProvenance(
                "input relocation targets an auxiliary symbol record",
            ));
        }
        let record_offset = symbol_table
            .checked_add(symbol_index.checked_mul(COFF_SYMBOL_BYTES).ok_or(
                InspectError::InvalidRelocationProvenance("input symbol table overflows"),
            )?)
            .ok_or(InspectError::InvalidRelocationProvenance(
                "input symbol offset overflows",
            ))?;
        let record = read_exact_at::<18>(&mut stable.file, record_offset)
            .map_err(|error| map_image_read_error(error, "input provenance bytes"))?;
        let auxiliary = u64::from(record[17]);
        let next = symbol_index
            .checked_add(1)
            .and_then(|value| value.checked_add(auxiliary))
            .filter(|value| *value <= symbol_count)
            .ok_or(InspectError::InvalidRelocationProvenance(
                "input symbol auxiliary records are out of bounds",
            ))?;
        let section_number = le_i16(&record, 12).ok_or(InspectError::Truncated)?;
        let value = u64::from(le_u32(&record, 8).ok_or(InspectError::Truncated)?);
        let storage_class = record[16];
        let referenced = references
            .get(reference_index)
            .is_some_and(|reference| u64::from(reference.symbol) == symbol_index);
        let externally_defined = storage_class == IMAGE_SYM_CLASS_EXTERNAL && section_number > 0;
        let mut name = None;
        if referenced && section_number == 0 || externally_defined {
            let decoded = read_coff_symbol_name(
                &mut stable.file,
                &record[..8],
                symbol_table_end,
                string_bytes,
                limits,
                is_cancelled,
            )?;
            budget.add_measurement(decoded.len(), limits)?;
            name = Some(decoded);
        }
        if externally_defined {
            let section = u32::try_from(section_number - 1).map_err(|_| {
                InspectError::InvalidRelocationProvenance(
                    "external definition has an invalid section",
                )
            })?;
            if sections
                .get(section as usize)
                .is_none_or(|input_section| value > input_section.bytes)
            {
                return Err(InspectError::InvalidRelocationProvenance(
                    "external definition escapes its input section",
                ));
            }
            definitions
                .try_reserve(1)
                .map_err(|_| InspectError::LimitExceeded {
                    resource: "input COFF symbols",
                    limit: u64::from(limits.symbols),
                    actual: budget.symbols,
                })?;
            definitions.push(ExternalDefinition {
                name: name
                    .clone()
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "external definition has no canonical name",
                    ))?,
                section,
            });
        }
        while references
            .get(reference_index)
            .is_some_and(|reference| u64::from(reference.symbol) == symbol_index)
        {
            if let Some(addr64) = references[reference_index].addr64 {
                let target = if section_number > 0 {
                    let section = u32::try_from(section_number - 1).map_err(|_| {
                        InspectError::InvalidRelocationProvenance(
                            "ADDR64 target section is invalid",
                        )
                    })?;
                    if sections
                        .get(section as usize)
                        .is_none_or(|target_section| value > target_section.bytes)
                    {
                        return Err(InspectError::InvalidRelocationProvenance(
                            "ADDR64 target escapes its input section",
                        ));
                    }
                    InputRelocationTarget::Defined { section }
                } else if section_number == 0
                    && value == 0
                    && storage_class == IMAGE_SYM_CLASS_EXTERNAL
                {
                    InputRelocationTarget::UndefinedExternal {
                        name: name
                            .clone()
                            .ok_or(InspectError::InvalidRelocationProvenance(
                                "undefined ADDR64 target has no canonical external name",
                            ))?,
                    }
                } else {
                    return Err(InspectError::InvalidRelocationProvenance(
                        "ADDR64 target is absolute, common, weak, or otherwise unsupported",
                    ));
                };
                relocations
                    .get_mut(addr64)
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "ADDR64 target index is inconsistent",
                    ))?
                    .target = Some(target);
            }
            reference_index += 1;
        }
        symbol_index = next;
    }
    if reference_index != references.len()
        || relocations
            .iter()
            .any(|relocation| relocation.target.is_none())
    {
        return Err(InspectError::InvalidRelocationProvenance(
            "input relocation target is missing or auxiliary",
        ));
    }
    verify_stable_path(input.path(), &stable)
        .map_err(|error| map_image_read_error(error, "input provenance bytes"))?;
    Ok(ProvenanceObject {
        ordinal: input.ordinal(),
        path,
        digest,
        bytes: stable.bytes,
        sections,
        relocations,
        definitions,
    })
}

fn repeated_provenance_section_name_is_supported(name: &str) -> bool {
    matches!(name, ".pdata" | ".xdata")
}

const fn arm64_relocation_width(kind: u16) -> Option<u64> {
    match kind {
        IMAGE_REL_ARM64_SECTION => Some(2),
        IMAGE_REL_ARM64_ADDR64 => Some(8),
        IMAGE_REL_ARM64_ADDR32
        | IMAGE_REL_ARM64_ADDR32NB
        | IMAGE_REL_ARM64_BRANCH26
        | IMAGE_REL_ARM64_PAGEBASE_REL21
        | IMAGE_REL_ARM64_REL21
        | IMAGE_REL_ARM64_PAGEOFFSET_12A
        | IMAGE_REL_ARM64_PAGEOFFSET_12L
        | IMAGE_REL_ARM64_SECREL
        | IMAGE_REL_ARM64_SECREL_LOW12A
        | IMAGE_REL_ARM64_SECREL_HIGH12A
        | IMAGE_REL_ARM64_SECREL_LOW12L
        | IMAGE_REL_ARM64_BRANCH19
        | IMAGE_REL_ARM64_BRANCH14
        | IMAGE_REL_ARM64_REL32 => Some(4),
        _ => None,
    }
}

fn coff_section_alignment(characteristics: u32) -> Result<u32, InspectError> {
    match (characteristics >> 20) & 0x0f {
        0 => Ok(1),
        value @ 1..=14 => Ok(1u32 << (value - 1)),
        _ => Err(InspectError::InvalidRelocationProvenance(
            "input section alignment encoding is reserved",
        )),
    }
}

fn read_coff_section_name(
    file: &mut File,
    encoded: &[u8],
    string_table: u64,
    string_bytes: u64,
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, InspectError> {
    let encoded: &[u8; 8] = encoded.try_into().map_err(|_| InspectError::Truncated)?;
    if encoded[0] != b'/' {
        return canonical_coff_short_name(encoded, limits.measurement_bytes);
    }
    let end = encoded
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(encoded.len());
    if end <= 1
        || encoded[end..].iter().any(|byte| *byte != 0)
        || !encoded[1..end].iter().all(u8::is_ascii_digit)
    {
        return Err(InspectError::InvalidRelocationProvenance(
            "input section name encoding is noncanonical",
        ));
    }
    let offset = encoded[1..end]
        .iter()
        .try_fold(0u64, |value, digit| {
            value.checked_mul(10)?.checked_add(u64::from(*digit - b'0'))
        })
        .ok_or(InspectError::InvalidRelocationProvenance(
            "input section name offset overflows",
        ))?;
    read_coff_string(
        file,
        string_table,
        string_bytes,
        offset,
        limits,
        is_cancelled,
    )
}

fn read_coff_symbol_name(
    file: &mut File,
    encoded: &[u8],
    string_table: u64,
    string_bytes: u64,
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, InspectError> {
    let encoded: &[u8; 8] = encoded.try_into().map_err(|_| InspectError::Truncated)?;
    if encoded[..4] != [0; 4] {
        return canonical_coff_short_name(encoded, limits.measurement_bytes);
    }
    let offset = u64::from(u32::from_le_bytes(
        encoded[4..8]
            .try_into()
            .map_err(|_| InspectError::Truncated)?,
    ));
    read_coff_string(
        file,
        string_table,
        string_bytes,
        offset,
        limits,
        is_cancelled,
    )
}

fn canonical_coff_short_name(encoded: &[u8; 8], limit: u64) -> Result<String, InspectError> {
    let end = encoded
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(encoded.len());
    if end == 0
        || encoded[end..].iter().any(|byte| *byte != 0)
        || !encoded[..end].iter().all(u8::is_ascii_graphic)
    {
        return Err(InspectError::InvalidRelocationProvenance(
            "input COFF name is noncanonical ASCII",
        ));
    }
    let name = std::str::from_utf8(&encoded[..end])
        .map_err(|_| InspectError::InvalidRelocationProvenance("input COFF name is not UTF-8"))?;
    copy_string(name, limit)
}

fn read_coff_string(
    file: &mut File,
    string_table: u64,
    string_bytes: u64,
    offset: u64,
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, InspectError> {
    if offset < 4 || offset >= string_bytes {
        return Err(InspectError::InvalidRelocationProvenance(
            "input COFF string offset is out of bounds",
        ));
    }
    let maximum = (string_bytes - offset).min(MAX_MAP_LINE_BYTES as u64 + 1);
    file.seek(SeekFrom::Start(string_table.checked_add(offset).ok_or(
        InspectError::InvalidRelocationProvenance("input COFF string offset overflows"),
    )?))
    .map_err(|error| InspectError::Io(io_kind(error)))?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut consumed = 0u64;
    while consumed < maximum {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let take = usize::try_from((maximum - consumed).min(buffer.len() as u64))
            .map_err(|_| InspectError::Truncated)?;
        let read = file
            .read(&mut buffer[..take])
            .map_err(|error| InspectError::Io(io_kind(error)))?;
        if read == 0 {
            break;
        }
        if let Some(end) = buffer[..read].iter().position(|byte| *byte == 0) {
            bytes
                .try_reserve(end)
                .map_err(|_| InspectError::LimitExceeded {
                    resource: "relocation provenance measurement bytes",
                    limit: limits.measurement_bytes,
                    actual: limits.measurement_bytes.saturating_add(1),
                })?;
            bytes.extend_from_slice(&buffer[..end]);
            if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_graphic) {
                return Err(InspectError::InvalidRelocationProvenance(
                    "input COFF string is empty or noncanonical ASCII",
                ));
            }
            let value = std::str::from_utf8(&bytes).map_err(|_| {
                InspectError::InvalidRelocationProvenance("input COFF string is not UTF-8")
            })?;
            return copy_string(value, limits.measurement_bytes);
        }
        let next = bytes
            .len()
            .checked_add(read)
            .ok_or(InspectError::LimitExceeded {
                resource: "relocation provenance measurement bytes",
                limit: limits.measurement_bytes,
                actual: u64::MAX,
            })?;
        if next > MAX_MAP_LINE_BYTES || next as u64 > limits.measurement_bytes {
            return Err(InspectError::LimitExceeded {
                resource: "relocation provenance measurement bytes",
                limit: limits.measurement_bytes.min(MAX_MAP_LINE_BYTES as u64),
                actual: next as u64,
            });
        }
        bytes
            .try_reserve(read)
            .map_err(|_| InspectError::LimitExceeded {
                resource: "relocation provenance measurement bytes",
                limit: limits.measurement_bytes,
                actual: next as u64,
            })?;
        bytes.extend_from_slice(&buffer[..read]);
        consumed = consumed
            .checked_add(read as u64)
            .ok_or(InspectError::Truncated)?;
    }
    Err(InspectError::InvalidRelocationProvenance(
        "input COFF string is unterminated or exceeds its bound",
    ))
}

fn map_coff_provenance_error(error: CoffInspectError) -> InspectError {
    match error {
        CoffInspectError::Cancelled => InspectError::Cancelled,
        CoffInspectError::Io(message) => InspectError::Io(message),
        CoffInspectError::TooLarge { limit, actual } => InspectError::LimitExceeded {
            resource: "input provenance bytes",
            limit,
            actual,
        },
        CoffInspectError::LimitExceeded {
            resource,
            limit,
            actual,
        } => InspectError::LimitExceeded {
            resource,
            limit,
            actual,
        },
        _ => InspectError::InvalidRelocationProvenance(
            "input COFF structure is invalid for relocation provenance",
        ),
    }
}

#[derive(Debug)]
struct ContributionKey {
    key: String,
    object: usize,
    section: usize,
    object_ordinal: u32,
    section_ordinal: u32,
    bytes: u64,
    alignment: u32,
    characteristics: u32,
    repeated_name_is_supported: bool,
    retired: bool,
    matched: bool,
}

struct ContributionMapState {
    saw_header: bool,
    output_index: usize,
    current_output: Option<usize>,
    previous_contribution_end: Option<u64>,
    keys: Vec<ContributionKey>,
}

#[allow(clippy::large_stack_arrays)]
fn parse_lld_contribution_map(
    file: &mut File,
    map_bytes: u64,
    pe: &ParsedPe,
    objects: &mut [ProvenanceObject],
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), InspectError> {
    let keys = contribution_keys(objects, limits, is_cancelled)?;
    let mut state = ContributionMapState {
        saw_header: false,
        output_index: 0,
        current_output: None,
        previous_contribution_end: None,
        keys,
    };
    file.seek(SeekFrom::Start(0))
        .map_err(|error| InspectError::Io(io_kind(error)))?;
    let mut chunk = [0u8; IO_CHUNK_BYTES];
    let mut line = Vec::new();
    let mut consumed = 0u64;
    let mut ended_with_lf = false;
    loop {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let read = file
            .read(&mut chunk)
            .map_err(|error| InspectError::Io(io_kind(error)))?;
        if read == 0 {
            break;
        }
        consumed = consumed
            .checked_add(read as u64)
            .ok_or(InspectError::LimitExceeded {
                resource: "relocation provenance map bytes",
                limit: limits.map_bytes,
                actual: u64::MAX,
            })?;
        if consumed > map_bytes || consumed > limits.map_bytes {
            return Err(InspectError::LimitExceeded {
                resource: "relocation provenance map bytes",
                limit: limits.map_bytes,
                actual: consumed,
            });
        }
        let mut start = 0usize;
        for (index, byte) in chunk[..read].iter().copied().enumerate() {
            if byte != b'\n' {
                continue;
            }
            append_provenance_line(&mut line, &chunk[start..index], limits)?;
            process_contribution_map_line(&line, &mut state, pe, objects, is_cancelled)?;
            line.clear();
            start = index + 1;
        }
        append_provenance_line(&mut line, &chunk[start..read], limits)?;
        ended_with_lf = chunk[read - 1] == b'\n';
    }
    if consumed != map_bytes || consumed == 0 {
        return Err(InspectError::Truncated);
    }
    if !line.is_empty() || !ended_with_lf {
        return Err(InspectError::InvalidRelocationProvenance(
            "LLD contribution map is not canonically LF-terminated",
        ));
    }
    if !state.saw_header || state.output_index != pe.sections.len() {
        return Err(InspectError::InvalidRelocationProvenance(
            "LLD contribution map has missing or extra output sections",
        ));
    }
    validate_repeated_contribution_completion(&state.keys, is_cancelled)?;
    Ok(())
}

fn append_provenance_line(
    line: &mut Vec<u8>,
    bytes: &[u8],
    limits: ImageInspectLimits,
) -> Result<(), InspectError> {
    let next = line
        .len()
        .checked_add(bytes.len())
        .ok_or(InspectError::LimitExceeded {
            resource: "relocation provenance map line bytes",
            limit: limits.measurement_bytes.min(MAX_MAP_LINE_BYTES as u64),
            actual: u64::MAX,
        })?;
    let limit = limits.measurement_bytes.min(MAX_MAP_LINE_BYTES as u64);
    if next as u64 > limit {
        return Err(InspectError::LimitExceeded {
            resource: "relocation provenance map line bytes",
            limit,
            actual: next as u64,
        });
    }
    line.try_reserve(bytes.len())
        .map_err(|_| InspectError::LimitExceeded {
            resource: "relocation provenance map line bytes",
            limit,
            actual: next as u64,
        })?;
    line.extend_from_slice(bytes);
    Ok(())
}

fn contribution_keys(
    objects: &[ProvenanceObject],
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ContributionKey>, InspectError> {
    let count = objects.iter().try_fold(0usize, |total, object| {
        total.checked_add(object.sections.len())
    });
    let count = count.ok_or(InspectError::LimitExceeded {
        resource: "input COFF sections",
        limit: u64::from(limits.sections),
        actual: u64::MAX,
    })?;
    if count > limits.sections as usize {
        return Err(InspectError::LimitExceeded {
            resource: "input COFF sections",
            limit: u64::from(limits.sections),
            actual: count as u64,
        });
    }
    let mut keys = Vec::new();
    keys.try_reserve_exact(count)
        .map_err(|_| InspectError::LimitExceeded {
            resource: "input COFF sections",
            limit: u64::from(limits.sections),
            actual: count as u64,
        })?;
    for (object_index, object) in objects.iter().enumerate() {
        for (section_index, section) in object.sections.iter().enumerate() {
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            let capacity = object
                .path
                .len()
                .checked_add(section.name.len())
                .and_then(|value| value.checked_add(3))
                .ok_or(InspectError::LimitExceeded {
                    resource: "relocation provenance contribution key bytes",
                    limit: limits.measurement_bytes,
                    actual: u64::MAX,
                })?;
            if capacity as u64 > limits.measurement_bytes {
                return Err(InspectError::LimitExceeded {
                    resource: "relocation provenance contribution key bytes",
                    limit: limits.measurement_bytes,
                    actual: capacity as u64,
                });
            }
            let mut key = String::new();
            key.try_reserve_exact(capacity)
                .map_err(|_| InspectError::LimitExceeded {
                    resource: "relocation provenance contribution key bytes",
                    limit: limits.measurement_bytes,
                    actual: capacity as u64,
                })?;
            key.push_str(&object.path);
            key.push_str(":(");
            key.push_str(&section.name);
            key.push(')');
            keys.push(ContributionKey {
                key,
                object: object_index,
                section: section_index,
                object_ordinal: object.ordinal,
                section_ordinal: section.ordinal,
                bytes: section.bytes,
                alignment: section.alignment,
                characteristics: section.characteristics,
                repeated_name_is_supported: repeated_provenance_section_name_is_supported(
                    &section.name,
                ),
                retired: false,
                matched: false,
            });
        }
    }
    keys = cancellable_sort(
        keys,
        |left, right| {
            left.key
                .cmp(&right.key)
                .then_with(|| left.object_ordinal.cmp(&right.object_ordinal))
                .then_with(|| left.section_ordinal.cmp(&right.section_ordinal))
        },
        "input COFF sections",
        u64::from(limits.sections),
        is_cancelled,
    )?;
    for pair in keys.windows(2) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if pair[0].key == pair[1].key {
            if pair[0].object_ordinal != pair[1].object_ordinal {
                return Err(InspectError::InvalidRelocationProvenance(
                    "duplicate input contribution identity spans reviewed objects",
                ));
            }
            if !pair[0].repeated_name_is_supported || !pair[1].repeated_name_is_supported {
                return Err(InspectError::InvalidRelocationProvenance(
                    "duplicate input contribution identities are ambiguous",
                ));
            }
        }
    }
    Ok(keys)
}

fn validate_repeated_contribution_completion(
    keys: &[ContributionKey],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), InspectError> {
    let mut first = 0usize;
    while first < keys.len() {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let remaining = keys
            .get(first..)
            .ok_or(InspectError::InvalidRelocationProvenance(
                "LLD contribution candidate range is invalid",
            ))?;
        let key = remaining
            .first()
            .ok_or(InspectError::InvalidRelocationProvenance(
                "LLD contribution candidate index is invalid",
            ))?
            .key
            .as_str();
        let relative_end = remaining.partition_point(|candidate| candidate.key == key);
        let end =
            first
                .checked_add(relative_end)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "LLD contribution candidate range overflows",
                ))?;
        if end - first > 1 {
            for candidate in
                keys.get(first..end)
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "LLD contribution candidate range is invalid",
                    ))?
            {
                if is_cancelled() {
                    return Err(InspectError::Cancelled);
                }
                if candidate.repeated_name_is_supported
                    && candidate.bytes != 0
                    && !candidate.matched
                {
                    return Err(InspectError::InvalidRelocationProvenance(
                        "nonempty repeated unwind section is missing from LLD contributions",
                    ));
                }
            }
        }
        first = end;
    }
    Ok(())
}

fn resolve_contribution_key(
    state: &mut ContributionMapState,
    objects: &[ProvenanceObject],
    key: &str,
    bytes: u64,
    alignment: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(usize, usize), InspectError> {
    let first = state
        .keys
        .partition_point(|candidate| candidate.key.as_str() < key);
    let end = state
        .keys
        .partition_point(|candidate| candidate.key.as_str() <= key);
    if first == end {
        return Err(InspectError::InvalidRelocationProvenance(
            "LLD contribution does not name a reviewed input section",
        ));
    }

    // Pinned LLD emits same-named unwind sections from one input in original
    // COFF section order. Each examined candidate is retired, so a row that
    // selects a later distinguishable ordinal cannot be followed by an earlier
    // one. Completion rejects every skipped nonempty candidate; only a
    // zero-byte duplicate may be absent. This resolves repeated textual
    // `path:(name)` rows without erasing the sealed ordinal, extent, alignment,
    // or characteristics that distinguish their provenance identities.
    for index in first..end {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let (
            retired,
            object_index,
            section_index,
            object_ordinal,
            section_ordinal,
            candidate_bytes,
            candidate_alignment,
            candidate_characteristics,
        ) = {
            let candidate =
                state
                    .keys
                    .get(index)
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "LLD contribution candidate index is invalid",
                    ))?;
            (
                candidate.retired,
                candidate.object,
                candidate.section,
                candidate.object_ordinal,
                candidate.section_ordinal,
                candidate.bytes,
                candidate.alignment,
                candidate.characteristics,
            )
        };
        if retired {
            continue;
        }
        let object = objects
            .get(object_index)
            .ok_or(InspectError::InvalidRelocationProvenance(
                "LLD contribution identity resolves outside reviewed inputs",
            ))?;
        let section =
            object
                .sections
                .get(section_index)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "LLD contribution identity resolves outside reviewed inputs",
                ))?;
        if object.ordinal != object_ordinal
            || section.ordinal != section_ordinal
            || section.bytes != candidate_bytes
            || section.alignment != candidate_alignment
            || section.characteristics != candidate_characteristics
        {
            return Err(InspectError::InvalidRelocationProvenance(
                "LLD contribution candidate differs from sealed COFF identity",
            ));
        }
        let matches = section.contribution_output.is_none()
            && section.contribution_rva.is_none()
            && bytes == candidate_bytes
            && alignment == u64::from(candidate_alignment);
        let candidate =
            state
                .keys
                .get_mut(index)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "LLD contribution candidate index is invalid",
                ))?;
        candidate.retired = true;
        candidate.matched = matches;
        if matches {
            return Ok((object_index, section_index));
        }
    }
    Err(InspectError::InvalidRelocationProvenance(
        "LLD contribution does not resolve in original COFF section order",
    ))
}

fn process_contribution_map_line(
    line: &[u8],
    state: &mut ContributionMapState,
    pe: &ParsedPe,
    objects: &mut [ProvenanceObject],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), InspectError> {
    if is_cancelled() {
        return Err(InspectError::Cancelled);
    }
    if line.contains(&b'\r') || !line.is_ascii() {
        return Err(InspectError::InvalidRelocationProvenance(
            "LLD contribution map is not canonical ASCII",
        ));
    }
    if !state.saw_header {
        if line != b"Address  Size     Align Out     In      Symbol" {
            return Err(InspectError::InvalidRelocationProvenance(
                "LLD contribution map header is missing or unsupported",
            ));
        }
        state.saw_header = true;
        return Ok(());
    }
    let (address, bytes, alignment, rest) = parse_lld_contribution_row(line)?;
    let indentation = rest.iter().take_while(|byte| **byte == b' ').count();
    match indentation {
        0 => {
            let expected = pe.sections.get(state.output_index).ok_or(
                InspectError::InvalidRelocationProvenance(
                    "LLD contribution map contains an extra output section",
                ),
            )?;
            if rest != expected.name.as_bytes()
                || address != expected.virtual_address
                || bytes != expected.virtual_bytes
                || alignment != u64::from(pe.section_alignment)
            {
                return Err(InspectError::InvalidRelocationProvenance(
                    "LLD output-section layout disagrees with PE32+",
                ));
            }
            state.current_output = Some(state.output_index);
            state.output_index += 1;
            state.previous_contribution_end = None;
        }
        8 => {
            let output_index =
                state
                    .current_output
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "LLD contribution appears before its output section",
                    ))?;
            let output =
                pe.sections
                    .get(output_index)
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "LLD contribution output index is invalid",
                    ))?;
            let output_ordinal = u32::try_from(output_index).map_err(|_| {
                InspectError::InvalidRelocationProvenance(
                    "LLD contribution output-section ordinal overflows",
                )
            })?;
            let key = std::str::from_utf8(&rest[8..]).map_err(|_| {
                InspectError::InvalidRelocationProvenance("LLD contribution identity is not UTF-8")
            })?;
            if key.is_empty() {
                return Err(InspectError::InvalidRelocationProvenance(
                    "LLD contribution identity is empty",
                ));
            }
            let (contribution_object, contribution_section) =
                resolve_contribution_key(state, objects, key, bytes, alignment, is_cancelled)?;
            let section = objects
                .get_mut(contribution_object)
                .and_then(|object| object.sections.get_mut(contribution_section))
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "LLD contribution identity resolves outside reviewed inputs",
                ))?;
            let end =
                address
                    .checked_add(bytes)
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "LLD contribution range overflows",
                    ))?;
            let output_end = output
                .virtual_address
                .checked_add(output.virtual_bytes)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "PE output-section range overflows",
                ))?;
            if section.contribution_output.is_some()
                || section.contribution_rva.is_some()
                || bytes != section.bytes
                || alignment != u64::from(section.alignment)
                || alignment == 0
                || address % alignment != 0
                || address < output.virtual_address
                || end > output_end
                || state
                    .previous_contribution_end
                    .is_some_and(|previous| address < previous)
            {
                return Err(InspectError::InvalidRelocationProvenance(
                    "LLD input contribution is duplicate, substituted, or out of bounds",
                ));
            }
            section.contribution_output = Some(output_ordinal);
            section.contribution_rva = Some(address);
            state.previous_contribution_end = Some(end);
        }
        16 => {
            let output = pe
                .sections
                .get(
                    state
                        .current_output
                        .ok_or(InspectError::InvalidRelocationProvenance(
                            "LLD symbol appears before its output section",
                        ))?,
                )
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "LLD symbol output index is invalid",
                ))?;
            let output_end = output
                .virtual_address
                .checked_add(output.virtual_bytes)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "PE output-section range overflows",
                ))?;
            if bytes != 0
                || alignment != 0
                || rest.len() == 16
                || address < output.virtual_address
                || address > output_end
            {
                return Err(InspectError::InvalidRelocationProvenance(
                    "LLD contribution-map symbol record is malformed",
                ));
            }
        }
        _ => {
            return Err(InspectError::InvalidRelocationProvenance(
                "LLD contribution map contains an unsupported record",
            ));
        }
    }
    Ok(())
}

fn parse_lld_contribution_row(line: &[u8]) -> Result<(u64, u64, u64, &[u8]), InspectError> {
    if line.len() < 25
        || line.get(8) != Some(&b' ')
        || line.get(17) != Some(&b' ')
        || line.get(23) != Some(&b' ')
    {
        return Err(InspectError::InvalidRelocationProvenance(
            "LLD contribution-map row has unsupported columns",
        ));
    }
    let address = parse_lld_hex(&line[..8])?;
    let bytes = parse_lld_hex(&line[9..17])?;
    let alignment_field = &line[18..23];
    let first_digit = alignment_field
        .iter()
        .position(|byte| *byte != b' ')
        .ok_or(InspectError::InvalidRelocationProvenance(
            "LLD contribution-map alignment is empty",
        ))?;
    if !alignment_field[..first_digit]
        .iter()
        .all(|byte| *byte == b' ')
        || !alignment_field[first_digit..]
            .iter()
            .all(u8::is_ascii_digit)
        || (alignment_field[first_digit] == b'0' && first_digit + 1 != alignment_field.len())
    {
        return Err(InspectError::InvalidRelocationProvenance(
            "LLD contribution-map alignment is noncanonical",
        ));
    }
    let alignment = std::str::from_utf8(&alignment_field[first_digit..])
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(InspectError::InvalidRelocationProvenance(
            "LLD contribution-map alignment overflows",
        ))?;
    Ok((address, bytes, alignment, &line[24..]))
}

fn parse_lld_hex(value: &[u8]) -> Result<u64, InspectError> {
    if value.len() != 8
        || !value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(InspectError::InvalidRelocationProvenance(
            "LLD contribution-map hexadecimal field is noncanonical",
        ));
    }
    let value = std::str::from_utf8(value).map_err(|_| {
        InspectError::InvalidRelocationProvenance(
            "LLD contribution-map hexadecimal field is not UTF-8",
        )
    })?;
    u64::from_str_radix(value, 16).map_err(|_| {
        InspectError::InvalidRelocationProvenance(
            "LLD contribution-map hexadecimal field overflows",
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XdataContribution {
    output_section: usize,
    rva: u64,
    file_offset: u64,
    bytes: u64,
}

fn reviewed_xdata_contributions(
    objects: &[ProvenanceObject],
    pe: &ParsedPe,
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<XdataContribution>, InspectError> {
    let mut count = 0usize;
    for object in objects {
        for section in &object.sections {
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            if section.name == ".xdata" && section.bytes != 0 {
                count = count.checked_add(1).ok_or(InspectError::LimitExceeded {
                    resource: "ARM64 unwind-data contributions",
                    limit: u64::from(limits.sections),
                    actual: u64::MAX,
                })?;
            }
        }
    }
    if count > limits.sections as usize {
        return Err(InspectError::LimitExceeded {
            resource: "ARM64 unwind-data contributions",
            limit: u64::from(limits.sections),
            actual: u64::try_from(count).unwrap_or(u64::MAX),
        });
    }
    for section in &pe.sections {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if section.name == ".xdata" {
            return Err(InspectError::InvalidRelocationProvenance(
                "pinned LLD must merge input .xdata into output .rdata",
            ));
        }
    }
    let mut contributions = Vec::new();
    contributions
        .try_reserve_exact(count)
        .map_err(|_| InspectError::LimitExceeded {
            resource: "ARM64 unwind-data contributions",
            limit: u64::from(limits.sections),
            actual: u64::try_from(count).unwrap_or(u64::MAX),
        })?;
    for object in objects {
        for section in &object.sections {
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            if section.name != ".xdata" || section.bytes == 0 {
                continue;
            }
            let output_section = usize::try_from(section.contribution_output.ok_or(
                InspectError::InvalidRelocationProvenance(
                    "reviewed .xdata input is absent from LLD's live contributions",
                ),
            )?)
            .map_err(|_| {
                InspectError::InvalidRelocationProvenance(
                    "reviewed .xdata output-section ordinal overflows",
                )
            })?;
            let rva = section
                .contribution_rva
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "reviewed .xdata input is absent from LLD's live contributions",
                ))?;
            let output = pe.sections.get(output_section).ok_or(
                InspectError::InvalidRelocationProvenance(
                    "reviewed .xdata contribution resolves outside PE sections",
                ),
            )?;
            let relative = rva.checked_sub(output.virtual_address).ok_or(
                InspectError::InvalidRelocationProvenance(
                    "reviewed .xdata contribution precedes its PE section",
                ),
            )?;
            let file_offset = output.file_offset.checked_add(relative).ok_or(
                InspectError::InvalidRelocationProvenance(
                    "reviewed .xdata contribution file offset overflows",
                ),
            )?;
            let contribution_end =
                rva.checked_add(section.bytes)
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "reviewed .xdata contribution range overflows",
                    ))?;
            let output_end = output
                .virtual_address
                .checked_add(output.virtual_bytes)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "PE output-section range overflows",
                ))?;
            let contribution_file_end = file_offset.checked_add(section.bytes).ok_or(
                InspectError::InvalidRelocationProvenance(
                    "reviewed .xdata contribution file range overflows",
                ),
            )?;
            let output_file_end = output.file_offset.checked_add(output.file_bytes).ok_or(
                InspectError::InvalidRelocationProvenance("PE output-section file range overflows"),
            )?;
            if output.name != ".rdata"
                || section.bytes % ARM64_INSTRUCTION_BYTES != 0
                || u64::from(section.alignment) != ARM64_INSTRUCTION_BYTES
                || rva % ARM64_INSTRUCTION_BYTES != 0
                || contribution_end > output_end
                || contribution_file_end > output_file_end
            {
                return Err(InspectError::InvalidRelocationProvenance(
                    "reviewed .xdata contribution does not match pinned LLD's merged .rdata layout",
                ));
            }
            contributions.push(XdataContribution {
                output_section,
                rva,
                file_offset,
                bytes: section.bytes,
            });
        }
    }
    contributions = cancellable_sort(
        contributions,
        |left, right| {
            (left.output_section, left.rva, left.bytes).cmp(&(
                right.output_section,
                right.rva,
                right.bytes,
            ))
        },
        "ARM64 unwind-data contributions",
        u64::from(limits.sections),
        is_cancelled,
    )?;
    for pair in contributions.windows(2) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let previous_end = pair[0].rva.checked_add(pair[0].bytes).ok_or(
            InspectError::InvalidRelocationProvenance(
                "reviewed .xdata contribution range overflows",
            ),
        )?;
        if pair[0].output_section == pair[1].output_section && previous_end > pair[1].rva {
            return Err(InspectError::InvalidRelocationProvenance(
                "reviewed .xdata contributions overlap",
            ));
        }
    }
    Ok(contributions)
}

fn resolve_relocation_provenance(
    objects: &[ProvenanceObject],
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ResolvedRelocation>, InspectError> {
    let mut definitions = Vec::new();
    for object in objects {
        for definition in &object.definitions {
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            definitions
                .try_reserve(1)
                .map_err(|_| InspectError::LimitExceeded {
                    resource: "input COFF symbols",
                    limit: u64::from(limits.symbols),
                    actual: limits.symbols as u64,
                })?;
            definitions.push((definition.name.as_str(), object.ordinal, definition.section));
        }
    }
    definitions = cancellable_sort(
        definitions,
        |left, right| left.0.cmp(right.0),
        "input COFF symbols",
        u64::from(limits.symbols),
        is_cancelled,
    )?;
    for pair in definitions.windows(2) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if pair[0].0 == pair[1].0 {
            return Err(InspectError::InvalidRelocationProvenance(
                "duplicate external definitions make ADDR64 resolution ambiguous",
            ));
        }
    }

    let relocation_count = objects.iter().try_fold(0usize, |total, object| {
        total.checked_add(object.relocations.len())
    });
    let relocation_count = relocation_count.ok_or(InspectError::LimitExceeded {
        resource: "input ADDR64 relocations",
        limit: u64::from(limits.base_relocations),
        actual: u64::MAX,
    })?;
    if relocation_count == 0 || relocation_count > limits.base_relocations as usize {
        return Err(InspectError::InvalidRelocationProvenance(
            "reviewed inputs contain no bounded ADDR64 relocation provenance",
        ));
    }
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(relocation_count)
        .map_err(|_| InspectError::LimitExceeded {
            resource: "input ADDR64 relocations",
            limit: u64::from(limits.base_relocations),
            actual: relocation_count as u64,
        })?;
    for object in objects {
        for relocation in &object.relocations {
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            let source = object
                .sections
                .get(relocation.source_section as usize)
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "ADDR64 source section is missing",
                ))?;
            let source_rva =
                source
                    .contribution_rva
                    .ok_or(InspectError::InvalidRelocationProvenance(
                        "ADDR64 source section is missing from LLD's live contributions",
                    ))?;
            let (target_object, target_section) = match relocation.target.as_ref().ok_or(
                InspectError::InvalidRelocationProvenance("ADDR64 target is unresolved"),
            )? {
                InputRelocationTarget::Defined { section } => (object.ordinal, *section),
                InputRelocationTarget::UndefinedExternal { name } => {
                    let index = definitions
                        .binary_search_by(|candidate| candidate.0.cmp(name.as_str()))
                        .map_err(|_| {
                            InspectError::InvalidRelocationProvenance(
                                "undefined ADDR64 external has no exact reviewed definition",
                            )
                        })?;
                    (definitions[index].1, definitions[index].2)
                }
            };
            let target = objects
                .get(target_object as usize)
                .and_then(|target_object| target_object.sections.get(target_section as usize))
                .ok_or(InspectError::InvalidRelocationProvenance(
                    "ADDR64 target resolves outside reviewed inputs",
                ))?;
            if target.contribution_rva.is_none() {
                return Err(InspectError::InvalidRelocationProvenance(
                    "ADDR64 target section is missing from LLD's live contributions",
                ));
            }
            let output_rva = source_rva.checked_add(relocation.source_offset).ok_or(
                InspectError::InvalidRelocationProvenance("ADDR64 output RVA overflows"),
            )?;
            if relocation
                .source_offset
                .checked_add(8)
                .is_none_or(|end| end > source.bytes)
            {
                return Err(InspectError::InvalidRelocationProvenance(
                    "ADDR64 source escapes its exact LLD contribution",
                ));
            }
            evidence.push(ResolvedRelocation {
                source_object: object.ordinal,
                source_section: relocation.source_section,
                source_offset: relocation.source_offset,
                target_object,
                target_section,
                output_rva,
            });
        }
    }
    evidence = cancellable_sort(
        evidence,
        |left, right| left.output_rva.cmp(&right.output_rva),
        "input ADDR64 relocations",
        u64::from(limits.base_relocations),
        is_cancelled,
    )?;
    for pair in evidence.windows(2) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if pair[0]
            .output_rva
            .checked_add(8)
            .is_none_or(|end| end > pair[1].output_rva)
        {
            return Err(InspectError::InvalidRelocationProvenance(
                "translated ADDR64 output sites are duplicate or overlapping",
            ));
        }
    }
    Ok(evidence)
}

fn relocation_provenance_digest(
    artifact: Sha256Digest,
    objects: &[ProvenanceObject],
    evidence: &[ResolvedRelocation],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, InspectError> {
    let mut hasher = Sha256::new();
    // The authenticated LLD map contains absolute input spellings used only
    // to resolve each row to a sealed object/section identity. Digest the
    // resolved, typed contribution graph so equivalent private roots retain
    // identical evidence without discarding any layout or relocation fact.
    hasher.update(b"wrela.pe.arm64.relocation-provenance.v2\0");
    hasher.update(artifact.as_bytes());
    hasher.update(
        u64::try_from(objects.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for object in objects {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        hasher.update(object.ordinal.to_le_bytes());
        hasher.update(object.bytes.to_le_bytes());
        hasher.update(object.digest.as_bytes());
        hasher.update(
            u64::try_from(object.sections.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for section in &object.sections {
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            hasher.update(section.ordinal.to_le_bytes());
            hasher.update(section.bytes.to_le_bytes());
            hasher.update(section.alignment.to_le_bytes());
            hasher.update(section.characteristics.to_le_bytes());
            hasher.update(
                section
                    .contribution_output
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            hasher.update(section.contribution_rva.unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(
                u64::try_from(section.name.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            hasher.update(section.name.as_bytes());
        }
    }
    hasher.update(
        u64::try_from(evidence.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for item in evidence {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        hasher.update(item.source_object.to_le_bytes());
        hasher.update(item.source_section.to_le_bytes());
        hasher.update(item.source_offset.to_le_bytes());
        hasher.update(item.target_object.to_le_bytes());
        hasher.update(item.target_section.to_le_bytes());
        hasher.update(item.output_rva.to_le_bytes());
    }
    Ok(sha256_digest(hasher))
}

fn inspect_linked_image(
    image_path: &Path,
    map_path: &Path,
    provenance_map_path: &Path,
    inputs: &[CoffProvenanceInput<'_>],
    target: &TargetBackendContract,
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ImageMeasurements, InspectError> {
    validate_image_limits(limits)?;
    if is_cancelled() {
        return Err(InspectError::Cancelled);
    }
    let mut image = open_stable_file(image_path, limits.image_bytes)
        .map_err(|error| map_image_read_error(error, "image bytes"))?;
    let dos = read_exact_at::<64>(&mut image.file, 0)
        .map_err(|error| map_image_read_error(error, "image bytes"))?;
    if dos.get(..2) != Some(b"MZ") {
        return Err(InspectError::InvalidDosHeader);
    }
    let pe_offset = u64::from(le_u32(&dos, 0x3c).ok_or(InspectError::Truncated)?);
    let coff_offset = pe_offset
        .checked_add(PE_SIGNATURE_BYTES)
        .ok_or(InspectError::Truncated)?;
    let coff = read_exact_at::<20>(&mut image.file, coff_offset)
        .map_err(|error| map_image_read_error(error, "image bytes"))?;
    let section_count = u32::from(le_u16(&coff, 2).ok_or(InspectError::Truncated)?);
    let optional_bytes = usize::from(le_u16(&coff, 16).ok_or(InspectError::Truncated)?);
    let section_table_end = coff_offset
        .checked_add(COFF_HEADER_BYTES)
        .and_then(|value| value.checked_add(u64::try_from(optional_bytes).ok()?))
        .and_then(|value| {
            value.checked_add(u64::from(section_count).checked_mul(PE_SECTION_BYTES)?)
        })
        .ok_or(InspectError::Truncated)?;
    if section_count == 0
        || section_count > limits.sections
        || optional_bytes != PE_OPTIONAL_HEADER_BYTES
        || section_table_end > image.bytes
        || section_table_end > MAX_HEADER_BYTES
    {
        return Err(InspectError::NonCanonical(
            "PE header or section count is outside the revision-0.1 contract",
        ));
    }
    let preflight_header = read_prefix(
        &mut image.file,
        image.bytes,
        section_table_end,
        is_cancelled,
    )
    .map_err(|error| map_image_read_error(error, "image bytes"))?;
    let pe = parse_pe_header(&preflight_header, image.bytes, limits, target, is_cancelled)?;
    let (artifact_digest, hashed_header, hashed_relocations) = hash_and_capture_prefix_and_range(
        &mut image.file,
        image.bytes,
        section_table_end,
        pe.relocation_file_offset,
        pe.relocation_bytes,
        is_cancelled,
    )
    .map_err(|error| map_image_read_error(error, "image bytes"))?;
    if hashed_header != preflight_header {
        return Err(InspectError::NonCanonical(
            "image header changed between structural and digest inspection",
        ));
    }
    let mut map = open_stable_file(map_path, limits.map_bytes)
        .map_err(|error| map_image_read_error(error, "map bytes"))?;
    let symbols = parse_lld_map(
        &mut map.file,
        map.bytes,
        MapContext {
            sections: &pe.sections,
            image_base: pe.image_base,
            entry_rva: pe.entry_rva,
            expected_entry: target.entry_symbol(),
        },
        limits,
        is_cancelled,
    )?;
    verify_stable_path(map_path, &map).map_err(|error| map_image_read_error(error, "map bytes"))?;

    let mut provenance_inputs = inspect_provenance_inputs(inputs, limits, is_cancelled)?;
    let mut provenance_map = open_stable_file(provenance_map_path, limits.map_bytes)
        .map_err(|error| map_image_read_error(error, "relocation provenance map bytes"))?;
    parse_lld_contribution_map(
        &mut provenance_map.file,
        provenance_map.bytes,
        &pe,
        &mut provenance_inputs,
        limits,
        is_cancelled,
    )?;
    verify_stable_path(provenance_map_path, &provenance_map)
        .map_err(|error| map_image_read_error(error, "relocation provenance map bytes"))?;
    let xdata_contributions =
        reviewed_xdata_contributions(&provenance_inputs, &pe, limits, is_cancelled)?;
    validate_pe_contents(
        &mut image.file,
        section_table_end,
        &pe,
        &xdata_contributions,
        limits,
        is_cancelled,
    )?;
    let evidence = resolve_relocation_provenance(&provenance_inputs, limits, is_cancelled)?;
    let expected_sites: Vec<u64> = evidence.iter().map(|item| item.output_rva).collect();

    image
        .file
        .seek(SeekFrom::Start(pe.relocation_file_offset))
        .map_err(|error| InspectError::Io(io_kind(error)))?;
    let relocation_reader =
        BufReader::with_capacity(IO_CHUNK_BYTES, (&mut image.file).take(pe.relocation_bytes));
    let mut relocation_reader = DigestingReader::new(relocation_reader);
    let relocations = parse_base_relocations(
        &mut relocation_reader,
        pe.relocation_bytes,
        &pe.sections,
        Some(&expected_sites),
        limits,
        is_cancelled,
    )?;
    if relocation_reader.finish() != hashed_relocations {
        return Err(InspectError::NonCanonical(
            "base-relocation bytes changed during image inspection",
        ));
    }
    verify_stable_path(image_path, &image)
        .map_err(|error| map_image_read_error(error, "image bytes"))?;
    let provenance_digest =
        relocation_provenance_digest(artifact_digest, &provenance_inputs, &evidence, is_cancelled)?;
    Ok(ImageMeasurements {
        artifact_bytes: image.bytes,
        artifact_digest,
        coff_machine: "arm64".to_owned(),
        subsystem: "efi_application".to_owned(),
        image_base: pe.image_base,
        entry_symbol: copy_string(target.entry_symbol(), limits.measurement_bytes)?,
        entry_virtual_address: pe.entry_rva,
        relocation_directory_bytes: pe.relocation_bytes,
        base_relocation_blocks: relocations.blocks,
        base_relocations: relocations.entries,
        base_relocation_provenance_digest: provenance_digest,
        sections: pe.sections,
        symbols,
    })
}

const fn validate_image_limits(limits: ImageInspectLimits) -> Result<(), InspectError> {
    if limits.image_bytes == 0
        || limits.map_bytes == 0
        || limits.sections == 0
        || limits.symbols == 0
        || limits.base_relocations == 0
        || limits.exception_records == 0
        || limits.measurement_bytes == 0
    {
        Err(InspectError::NonCanonical(
            "PE inspection limits must be nonzero",
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct ParsedPe {
    image_base: u64,
    entry_rva: u64,
    section_alignment: u32,
    timestamp: u32,
    header_bytes: u64,
    debug: MappedDirectory,
    exception: Option<MappedDirectory>,
    relocation_file_offset: u64,
    relocation_bytes: u64,
    sections: Vec<LinkedSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataDirectory {
    rva: u64,
    bytes: u64,
}

impl DataDirectory {
    const EMPTY: Self = Self { rva: 0, bytes: 0 };

    const fn is_empty(self) -> bool {
        self.rva == 0 && self.bytes == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MappedDirectory {
    rva: u64,
    bytes: u64,
    file_offset: u64,
    section_index: usize,
}

#[allow(clippy::too_many_lines)]
fn parse_pe_header(
    header: &[u8],
    file_bytes: u64,
    limits: ImageInspectLimits,
    target: &TargetBackendContract,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ParsedPe, InspectError> {
    if header.get(..LLD_PE_OFFSET) != Some(&LLD_DOS_STUB) {
        return Err(InspectError::InvalidDosHeader);
    }
    let pe_offset = usize::try_from(
        le_u32(header, 0x3c)
            .map(u64::from)
            .ok_or(InspectError::Truncated)?,
    )
    .map_err(|_| InspectError::Truncated)?;
    if pe_offset != LLD_PE_OFFSET
        || header.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0")
    {
        return Err(InspectError::InvalidPeSignature);
    }
    let coff = pe_offset.checked_add(4).ok_or(InspectError::Truncated)?;
    let machine = le_u16(header, coff).ok_or(InspectError::Truncated)?;
    if machine != IMAGE_FILE_MACHINE_ARM64 || target.coff_machine() != "arm64" {
        return Err(InspectError::NonCanonical(
            "PE machine is not the selected ARM64 target",
        ));
    }
    let sections = usize::from(le_u16(header, coff + 2).ok_or(InspectError::Truncated)?);
    if sections == 0 || sections > usize::try_from(limits.sections).unwrap_or(usize::MAX) {
        return Err(InspectError::LimitExceeded {
            resource: "sections",
            limit: u64::from(limits.sections),
            actual: sections as u64,
        });
    }
    if sections > MAX_PE_SECTIONS {
        return Err(InspectError::NonCanonical(
            "PE section count exceeds the loader's canonical maximum",
        ));
    }
    let timestamp = le_u32(header, coff + 4).ok_or(InspectError::Truncated)?;
    let symbol_table = le_u32(header, coff + 8).ok_or(InspectError::Truncated)?;
    let symbol_count = le_u32(header, coff + 12).ok_or(InspectError::Truncated)?;
    let optional_bytes = usize::from(le_u16(header, coff + 16).ok_or(InspectError::Truncated)?);
    let characteristics = le_u16(header, coff + 18).ok_or(InspectError::Truncated)?;
    if symbol_table != 0
        || symbol_count != 0
        || optional_bytes != PE_OPTIONAL_HEADER_BYTES
        || characteristics != IMAGE_FILE_CHARACTERISTICS_WRELA
        || characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0
    {
        return Err(InspectError::NonCanonical(
            "PE COFF header is not the canonical stripped ARM64 image header",
        ));
    }
    let optional = coff.checked_add(20).ok_or(InspectError::Truncated)?;
    let magic = le_u16(header, optional).ok_or(InspectError::Truncated)?;
    if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(InspectError::UnsupportedOptionalHeader(magic));
    }
    let linker_major = *header.get(optional + 2).ok_or(InspectError::Truncated)?;
    let linker_minor = *header.get(optional + 3).ok_or(InspectError::Truncated)?;
    let size_of_code = u64::from(le_u32(header, optional + 4).ok_or(InspectError::Truncated)?);
    let size_of_initialized_data =
        u64::from(le_u32(header, optional + 8).ok_or(InspectError::Truncated)?);
    let size_of_uninitialized_data =
        le_u32(header, optional + 12).ok_or(InspectError::Truncated)?;
    let entry_rva = u64::from(le_u32(header, optional + 16).ok_or(InspectError::Truncated)?);
    let base_of_code = u64::from(le_u32(header, optional + 20).ok_or(InspectError::Truncated)?);
    let image_base = le_u64(header, optional + 24).ok_or(InspectError::Truncated)?;
    let section_alignment = le_u32(header, optional + 32).ok_or(InspectError::Truncated)?;
    let file_alignment = le_u32(header, optional + 36).ok_or(InspectError::Truncated)?;
    let major_os_version = le_u16(header, optional + 40).ok_or(InspectError::Truncated)?;
    let minor_os_version = le_u16(header, optional + 42).ok_or(InspectError::Truncated)?;
    let major_image_version = le_u16(header, optional + 44).ok_or(InspectError::Truncated)?;
    let minor_image_version = le_u16(header, optional + 46).ok_or(InspectError::Truncated)?;
    let major_subsystem_version = le_u16(header, optional + 48).ok_or(InspectError::Truncated)?;
    let minor_subsystem_version = le_u16(header, optional + 50).ok_or(InspectError::Truncated)?;
    let win32_version = le_u32(header, optional + 52).ok_or(InspectError::Truncated)?;
    let size_of_image = u64::from(le_u32(header, optional + 56).ok_or(InspectError::Truncated)?);
    let header_bytes = u64::from(le_u32(header, optional + 60).ok_or(InspectError::Truncated)?);
    let checksum = le_u32(header, optional + 64).ok_or(InspectError::Truncated)?;
    let subsystem = le_u16(header, optional + 68).ok_or(InspectError::Truncated)?;
    let dll_characteristics = le_u16(header, optional + 70).ok_or(InspectError::Truncated)?;
    let stack_reserve = le_u64(header, optional + 72).ok_or(InspectError::Truncated)?;
    let stack_commit = le_u64(header, optional + 80).ok_or(InspectError::Truncated)?;
    let heap_reserve = le_u64(header, optional + 88).ok_or(InspectError::Truncated)?;
    let heap_commit = le_u64(header, optional + 96).ok_or(InspectError::Truncated)?;
    let loader_flags = le_u32(header, optional + 104).ok_or(InspectError::Truncated)?;
    let directory_count = le_u32(header, optional + 108).ok_or(InspectError::Truncated)?;
    if size_of_image > limits.image_bytes {
        return Err(InspectError::LimitExceeded {
            resource: "image virtual bytes",
            limit: limits.image_bytes,
            actual: size_of_image,
        });
    }
    if entry_rva == 0
        || entry_rva % ARM64_INSTRUCTION_BYTES != 0
        || image_base != EFI_IMAGE_BASE
        || linker_major != PE_MAJOR_LINKER_VERSION
        || linker_minor != PE_MINOR_LINKER_VERSION
        || section_alignment != PE_SECTION_ALIGNMENT
        || file_alignment != PE_FILE_ALIGNMENT
        || major_os_version != PE_MAJOR_OS_VERSION
        || minor_os_version != PE_MINOR_OS_VERSION
        || major_image_version != PE_MAJOR_IMAGE_VERSION
        || minor_image_version != PE_MINOR_IMAGE_VERSION
        || major_subsystem_version != PE_MAJOR_SUBSYSTEM_VERSION
        || minor_subsystem_version != PE_MINOR_SUBSYSTEM_VERSION
        || win32_version != 0
        || size_of_image == 0
        || header_bytes == 0
        || header_bytes > file_bytes
        || checksum != 0
        || subsystem != IMAGE_SUBSYSTEM_EFI_APPLICATION
        || target.subsystem() != "efi_application"
        || dll_characteristics != PE_DLL_CHARACTERISTICS
        || stack_reserve != PE_STACK_RESERVE
        || stack_commit != PE_STACK_COMMIT
        || heap_reserve != PE_HEAP_RESERVE
        || heap_commit != PE_HEAP_COMMIT
        || loader_flags != 0
        || directory_count != PE_DATA_DIRECTORY_COUNT as u32
    {
        return Err(InspectError::NonCanonical(
            "PE32+ optional header is not canonical EFI application metadata",
        ));
    }
    let mut directories = [DataDirectory::EMPTY; PE_DATA_DIRECTORY_COUNT];
    for (index, slot) in directories.iter_mut().enumerate() {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let directory = optional
            .checked_add(PE32_PLUS_DATA_DIRECTORY_OFFSET)
            .and_then(|value| value.checked_add(index.checked_mul(8)?))
            .ok_or(InspectError::Truncated)?;
        let rva = u64::from(le_u32(header, directory).ok_or(InspectError::Truncated)?);
        let bytes = u64::from(le_u32(header, directory + 4).ok_or(InspectError::Truncated)?);
        if (rva == 0) != (bytes == 0) {
            return Err(InspectError::NonCanonical(
                "PE data directory has a one-sided zero range",
            ));
        }
        if !matches!(
            index,
            IMAGE_DIRECTORY_ENTRY_EXCEPTION
                | IMAGE_DIRECTORY_ENTRY_BASERELOC
                | IMAGE_DIRECTORY_ENTRY_DEBUG
        ) && (rva != 0 || bytes != 0)
        {
            return Err(InspectError::NonCanonical(
                if index == IMAGE_DIRECTORY_ENTRY_SECURITY {
                    "PE image declares a forbidden certificate table or file overlay"
                } else {
                    "PE image declares a forbidden data directory"
                },
            ));
        }
        *slot = DataDirectory { rva, bytes };
    }
    let relocation_directory = directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    let debug_directory = directories[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if relocation_directory.is_empty() || debug_directory.is_empty() {
        return Err(InspectError::NonCanonical(
            "PE base-relocation or reproducibility directory is absent",
        ));
    }
    let section_table = optional
        .checked_add(PE_OPTIONAL_HEADER_BYTES)
        .ok_or(InspectError::Truncated)?;
    let table_end = section_table
        .checked_add(
            sections
                .checked_mul(usize::try_from(PE_SECTION_BYTES).unwrap_or(40))
                .ok_or(InspectError::Truncated)?,
        )
        .ok_or(InspectError::Truncated)?;
    let expected_header_bytes = align_up(
        u64::try_from(table_end).map_err(|_| InspectError::Truncated)?,
        u64::from(PE_FILE_ALIGNMENT),
    )?;
    if table_end > header.len() {
        return Err(InspectError::Truncated);
    }
    if table_end as u64 > header_bytes {
        return Err(InspectError::NonCanonical(
            "PE section table escapes SizeOfHeaders",
        ));
    }
    // LLD assigns addresses before its final empty-output-section removal.
    // The production backend exercises that path and therefore legitimately
    // retains one otherwise empty 512-byte header page even though only three
    // section records remain. No other slack is emitted by the pinned linker.
    let retained_empty_section_page = expected_header_bytes == u64::from(PE_FILE_ALIGNMENT)
        && header_bytes == u64::from(PE_FILE_ALIGNMENT) * 2;
    if header_bytes != expected_header_bytes && !retained_empty_section_page {
        return Err(InspectError::NonCanonical(
            "PE SizeOfHeaders is not a pinned LLD section-table extent",
        ));
    }
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(sections)
        .map_err(|_| InspectError::LimitExceeded {
            resource: "sections",
            limit: u64::from(limits.sections),
            actual: sections as u64,
        })?;
    let mut measurement_bytes = 0u64;
    let mut previous_virtual_end = 0u64;
    let mut next_virtual_address = u64::from(PE_SECTION_ALIGNMENT);
    let mut next_file_offset = header_bytes;
    let mut entry_executable = false;
    let mut text_raw_bytes = None;
    let mut initialized_raw_bytes = 0u64;
    for index in 0..sections {
        if index % 1024 == 0 && is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let base = section_table + index * 40;
        let name = pe_section_name(
            header.get(base..base + 8).ok_or(InspectError::Truncated)?,
            limits.measurement_bytes,
        )?;
        measurement_bytes = add_measurement(measurement_bytes, name.len(), limits)?;
        let virtual_bytes = u64::from(le_u32(header, base + 8).ok_or(InspectError::Truncated)?);
        let virtual_address = u64::from(le_u32(header, base + 12).ok_or(InspectError::Truncated)?);
        let file_section_bytes =
            u64::from(le_u32(header, base + 16).ok_or(InspectError::Truncated)?);
        let file_offset = u64::from(le_u32(header, base + 20).ok_or(InspectError::Truncated)?);
        let relocation_pointer = le_u32(header, base + 24).ok_or(InspectError::Truncated)?;
        let line_number_pointer = le_u32(header, base + 28).ok_or(InspectError::Truncated)?;
        let relocation_count = le_u16(header, base + 32).ok_or(InspectError::Truncated)?;
        let line_number_count = le_u16(header, base + 34).ok_or(InspectError::Truncated)?;
        let characteristics = le_u32(header, base + 36).ok_or(InspectError::Truncated)?;
        let virtual_end = virtual_address
            .checked_add(virtual_bytes)
            .ok_or(InspectError::NonCanonical("PE section range overflows"))?;
        let raw_end = file_offset
            .checked_add(file_section_bytes)
            .ok_or(InspectError::NonCanonical("PE section range overflows"))?;
        let expected_characteristics = canonical_section_characteristics(&name)?;
        let canonical_virtual_size = match name.as_str() {
            ".text" | ".xdata" => virtual_bytes % ARM64_INSTRUCTION_BYTES == 0,
            ".pdata" => virtual_bytes % ARM64_RUNTIME_FUNCTION_BYTES == 0,
            _ => true,
        };
        let aligned_virtual_bytes = align_up(virtual_bytes, u64::from(PE_FILE_ALIGNMENT))?;
        // Pinned LLD merges input `.bss` last into the output `.data`. The
        // resulting section can therefore be wholly zero-filled or have an
        // initialized, file-aligned prefix followed by a zero-filled virtual
        // tail. Constrain that relaxation to exact `.data` permissions; every
        // other initialized section retains an exact aligned file extent, and
        // a standalone `.bss` retains a zero/zero raw layout.
        let canonical_file_layout = match name.as_str() {
            ".bss" => file_section_bytes == 0 && file_offset == 0,
            ".data" => {
                file_section_bytes <= aligned_virtual_bytes
                    && file_section_bytes % u64::from(PE_FILE_ALIGNMENT) == 0
                    && if file_section_bytes == 0 {
                        file_offset == 0
                    } else {
                        file_offset == next_file_offset && raw_end <= file_bytes
                    }
            }
            _ => {
                file_section_bytes == aligned_virtual_bytes
                    && file_offset == next_file_offset
                    && raw_end <= file_bytes
            }
        };
        if virtual_bytes == 0
            || virtual_address == 0
            || virtual_address != next_virtual_address
            || virtual_address < previous_virtual_end
            || virtual_end > size_of_image
            || characteristics != expected_characteristics
            || !canonical_virtual_size
            || characteristics & IMAGE_SCN_MEM_READ == 0
            || characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                && characteristics & IMAGE_SCN_MEM_WRITE != 0
            || relocation_pointer != 0
            || line_number_pointer != 0
            || relocation_count != 0
            || line_number_count != 0
            || !canonical_file_layout
        {
            return Err(InspectError::NonCanonical(
                "PE section layout is duplicate, overlapping, unaligned, or out of range",
            ));
        }
        if file_section_bytes != 0 {
            next_file_offset = raw_end;
        }
        if characteristics & IMAGE_SCN_CNT_CODE != 0
            && (text_raw_bytes.replace(file_section_bytes).is_some() || name != ".text")
        {
            return Err(InspectError::NonCanonical(
                "PE image contains more than one code section",
            ));
        }
        if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            initialized_raw_bytes = initialized_raw_bytes
                .checked_add(file_section_bytes)
                .ok_or(InspectError::NonCanonical(
                    "PE initialized-data size overflows",
                ))?;
        }
        entry_executable |= entry_rva >= virtual_address
            && entry_rva < virtual_end
            && characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        previous_virtual_end = virtual_end;
        next_virtual_address = align_up(virtual_end, u64::from(PE_SECTION_ALIGNMENT))?;
        decoded.push(LinkedSection {
            name,
            virtual_address,
            virtual_bytes,
            file_offset,
            file_bytes: file_section_bytes,
            characteristics,
        });
    }
    let mut section_names = Vec::new();
    section_names
        .try_reserve_exact(decoded.len())
        .map_err(|_| InspectError::LimitExceeded {
            resource: "sections",
            limit: u64::from(limits.sections),
            actual: decoded.len() as u64,
        })?;
    for section in &decoded {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        section_names.push(section.name.as_str());
    }
    let section_names = cancellable_sort(
        section_names,
        Ord::cmp,
        "sections",
        u64::from(limits.sections),
        is_cancelled,
    )?;
    for pair in section_names.windows(2) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if pair[0] == pair[1] {
            return Err(InspectError::NonCanonical(
                "PE section layout is duplicate, overlapping, unaligned, or out of range",
            ));
        }
    }
    let Some(text_raw_bytes) = text_raw_bytes else {
        return Err(InspectError::NonCanonical(
            "PE image has no canonical code section",
        ));
    };
    let expected_image_bytes = align_up(previous_virtual_end, u64::from(PE_SECTION_ALIGNMENT))?;
    if !entry_executable
        || base_of_code
            != decoded
                .iter()
                .find(|section| section.name == ".text")
                .map_or(u64::MAX, |section| section.virtual_address)
        || size_of_code != text_raw_bytes
        || size_of_initialized_data != initialized_raw_bytes
        || size_of_uninitialized_data != 0
        || size_of_image != expected_image_bytes
        || next_file_offset != file_bytes
        || decoded
            .last()
            .is_none_or(|section| section.name != ".reloc")
    {
        return Err(InspectError::NonCanonical(
            "PE aggregate sizes, entry point, or terminal relocation section are noncanonical",
        ));
    }
    let relocation = map_directory(relocation_directory, &decoded, file_bytes)?;
    let debug = map_directory(debug_directory, &decoded, file_bytes)?;
    let exception = if directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].is_empty() {
        None
    } else {
        Some(map_directory(
            directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION],
            &decoded,
            file_bytes,
        )?)
    };
    let relocation_section = &decoded[relocation.section_index];
    if relocation_section.name != ".reloc"
        || relocation.rva != relocation_section.virtual_address
        || relocation.bytes != relocation_section.virtual_bytes
        || relocation.file_offset != relocation_section.file_offset
    {
        return Err(InspectError::NonCanonical(
            "base-relocation directory is not the exact .reloc payload",
        ));
    }
    let debug_section = &decoded[debug.section_index];
    if debug_section.name != ".rdata"
        || debug.bytes != IMAGE_DEBUG_DIRECTORY_BYTES
        || debug.rva % 4 != 0
        || debug.file_offset % 4 != 0
    {
        return Err(InspectError::NonCanonical(
            "debug directory is not one aligned REPRO record in .rdata",
        ));
    }
    match exception {
        Some(directory) => {
            let section = &decoded[directory.section_index];
            if section.name != ".pdata"
                || directory.rva != section.virtual_address
                || directory.bytes != section.virtual_bytes
                || directory.file_offset != section.file_offset
                || directory.bytes % ARM64_RUNTIME_FUNCTION_BYTES != 0
            {
                return Err(InspectError::NonCanonical(
                    "exception directory is not the exact ARM64 .pdata payload",
                ));
            }
        }
        None if decoded
            .iter()
            .any(|section| matches!(section.name.as_str(), ".pdata" | ".xdata")) =>
        {
            return Err(InspectError::NonCanonical(
                "ARM64 unwind sections exist without an exception directory",
            ));
        }
        None => {}
    }
    let mut declared_ranges = [
        Some((relocation.rva, relocation.rva + relocation.bytes)),
        Some((debug.rva, debug.rva + debug.bytes)),
        exception.map(|directory| (directory.rva, directory.rva + directory.bytes)),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    declared_ranges.sort_unstable();
    if declared_ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(InspectError::NonCanonical(
            "allowed PE data directories overlap",
        ));
    }
    Ok(ParsedPe {
        image_base,
        entry_rva,
        section_alignment,
        timestamp,
        header_bytes,
        debug,
        exception,
        relocation_file_offset: relocation.file_offset,
        relocation_bytes: relocation.bytes,
        sections: decoded,
    })
}

fn canonical_section_characteristics(name: &str) -> Result<u32, InspectError> {
    match name {
        ".text" => Ok(IMAGE_SCN_WRELA_TEXT),
        ".rdata" | ".pdata" | ".xdata" => Ok(IMAGE_SCN_WRELA_READ_ONLY),
        ".data" => Ok(IMAGE_SCN_WRELA_DATA),
        ".bss" => Ok(IMAGE_SCN_WRELA_BSS),
        ".reloc" => Ok(IMAGE_SCN_WRELA_RELOC),
        _ => Err(InspectError::NonCanonical(
            "PE image contains an undeclared output section",
        )),
    }
}

fn map_directory(
    directory: DataDirectory,
    sections: &[LinkedSection],
    file_bytes: u64,
) -> Result<MappedDirectory, InspectError> {
    if directory.is_empty() {
        return Err(InspectError::NonCanonical("PE data directory is absent"));
    }
    let directory_end = directory
        .rva
        .checked_add(directory.bytes)
        .ok_or(InspectError::NonCanonical("PE data directory overflows"))?;
    let mut mapped = None;
    for (section_index, section) in sections.iter().enumerate() {
        let virtual_end = section
            .virtual_address
            .checked_add(section.virtual_bytes)
            .ok_or(InspectError::NonCanonical("PE section range overflows"))?;
        if directory.rva < section.virtual_address || directory_end > virtual_end {
            continue;
        }
        let relative = directory.rva - section.virtual_address;
        let raw_end = relative
            .checked_add(directory.bytes)
            .ok_or(InspectError::NonCanonical("PE data directory overflows"))?;
        if raw_end > section.file_bytes {
            return Err(InspectError::NonCanonical(
                "PE data directory escapes initialized section bytes",
            ));
        }
        let file_offset = section
            .file_offset
            .checked_add(relative)
            .filter(|offset| {
                offset
                    .checked_add(directory.bytes)
                    .is_some_and(|end| end <= file_bytes)
            })
            .ok_or(InspectError::NonCanonical(
                "PE data directory escapes the image file",
            ))?;
        if mapped.is_some() {
            return Err(InspectError::NonCanonical(
                "PE data directory maps to multiple sections",
            ));
        }
        mapped = Some(MappedDirectory {
            rva: directory.rva,
            bytes: directory.bytes,
            file_offset,
            section_index,
        });
    }
    mapped.ok_or(InspectError::NonCanonical(
        "PE data directory does not map to a section",
    ))
}

fn align_up(value: u64, alignment: u64) -> Result<u64, InspectError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(InspectError::NonCanonical("PE alignment is invalid"));
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or(InspectError::NonCanonical("PE aligned size overflows"))
}

fn validate_pe_contents(
    file: &mut File,
    section_table_end: u64,
    pe: &ParsedPe,
    xdata_contributions: &[XdataContribution],
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), InspectError> {
    if is_cancelled() {
        return Err(InspectError::Cancelled);
    }
    ensure_zero_range(
        file,
        section_table_end,
        pe.header_bytes
            .checked_sub(section_table_end)
            .ok_or(InspectError::NonCanonical("PE header range underflows"))?,
        "PE header padding contains nonzero bytes",
        is_cancelled,
    )?;
    for section in &pe.sections {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if section.file_bytes > section.virtual_bytes {
            ensure_zero_range(
                file,
                section
                    .file_offset
                    .checked_add(section.virtual_bytes)
                    .ok_or(InspectError::NonCanonical("PE section padding overflows"))?,
                section.file_bytes - section.virtual_bytes,
                "PE section padding contains nonzero bytes",
                is_cancelled,
            )?;
        }
    }
    validate_repro_debug(file, pe)?;
    validate_arm64_exceptions(file, pe, xdata_contributions, limits, is_cancelled)
}

fn validate_repro_debug(file: &mut File, pe: &ParsedPe) -> Result<(), InspectError> {
    let record = read_exact_at::<28>(file, pe.debug.file_offset)
        .map_err(|error| map_image_read_error(error, "debug directory bytes"))?;
    let characteristics = le_u32(&record, 0).ok_or(InspectError::Truncated)?;
    let timestamp = le_u32(&record, 4).ok_or(InspectError::Truncated)?;
    let major_version = le_u16(&record, 8).ok_or(InspectError::Truncated)?;
    let minor_version = le_u16(&record, 10).ok_or(InspectError::Truncated)?;
    let debug_type = le_u32(&record, 12).ok_or(InspectError::Truncated)?;
    let data_bytes = le_u32(&record, 16).ok_or(InspectError::Truncated)?;
    let data_rva = le_u32(&record, 20).ok_or(InspectError::Truncated)?;
    let data_file_offset = le_u32(&record, 24).ok_or(InspectError::Truncated)?;
    if characteristics != 0
        || timestamp != pe.timestamp
        || major_version != 0
        || minor_version != 0
        || debug_type != IMAGE_DEBUG_TYPE_REPRO
        || data_bytes != 0
        || data_rva != 0
        || data_file_offset != 0
    {
        return Err(InspectError::NonCanonical(
            "debug directory is not LLD's exact deterministic REPRO record",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XdataRecordRange {
    contribution: usize,
    rva: u64,
    file_offset: u64,
    bytes: u64,
}

fn validate_arm64_exceptions(
    file: &mut File,
    pe: &ParsedPe,
    xdata_contributions: &[XdataContribution],
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), InspectError> {
    let Some(exception) = pe.exception else {
        return if xdata_contributions.is_empty() {
            Ok(())
        } else {
            Err(invalid_arm64_exceptions(
                "reviewed ARM64 unwind data exists without an exception directory",
            ))
        };
    };
    let records = exception.bytes / ARM64_RUNTIME_FUNCTION_BYTES;
    if records == 0 || records > u64::from(limits.exception_records) {
        return Err(InspectError::LimitExceeded {
            resource: "ARM64 exception records",
            limit: u64::from(limits.exception_records),
            actual: records,
        });
    }
    let text = pe
        .sections
        .iter()
        .find(|section| section.name == ".text")
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 executable code section is absent"))?;
    let text_end = text
        .virtual_address
        .checked_add(text.virtual_bytes)
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 executable code range overflows"))?;
    let mut xdata_ranges = Vec::new();
    xdata_ranges
        .try_reserve_exact(
            usize::try_from(records).map_err(|_| InspectError::LimitExceeded {
                resource: "ARM64 exception records",
                limit: u64::from(limits.exception_records),
                actual: records,
            })?,
        )
        .map_err(|_| InspectError::LimitExceeded {
            resource: "ARM64 exception records",
            limit: u64::from(limits.exception_records),
            actual: records,
        })?;
    let mut previous_function_start = None;
    let mut previous_function_end = None;
    for index in 0..records {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let record_offset = exception
            .file_offset
            .checked_add(index.checked_mul(ARM64_RUNTIME_FUNCTION_BYTES).ok_or(
                InspectError::NonCanonical("ARM64 exception cursor overflows"),
            )?)
            .ok_or(InspectError::NonCanonical(
                "ARM64 exception cursor overflows",
            ))?;
        let record = read_exact_at::<8>(file, record_offset)
            .map_err(|error| map_image_read_error(error, "ARM64 exception directory bytes"))?;
        let function_start = u64::from(le_u32(&record, 0).ok_or(InspectError::Truncated)?);
        let unwind = le_u32(&record, 4).ok_or(InspectError::Truncated)?;
        let flag = unwind & 0x3;
        if function_start == 0
            || function_start % ARM64_INSTRUCTION_BYTES != 0
            || flag == 3
            || previous_function_start.is_some_and(|previous| function_start <= previous)
        {
            return Err(invalid_arm64_exceptions(
                "ARM64 .pdata record is unaligned, unordered, or reserved",
            ));
        }
        let function_bytes = if flag == 0 {
            let xdata = parse_xdata_record(
                file,
                u64::from(unwind),
                pe,
                xdata_contributions,
                is_cancelled,
            )?;
            xdata_ranges.push(xdata.range);
            xdata.function_bytes
        } else {
            validate_packed_unwind(unwind)?
        };
        let function_end = function_start
            .checked_add(function_bytes)
            .ok_or_else(|| invalid_arm64_exceptions("ARM64 unwind function range overflows"))?;
        if previous_function_end.is_some_and(|previous| function_start < previous)
            || function_start < text.virtual_address
            || function_end <= function_start
            || function_end > text_end
        {
            return Err(invalid_arm64_exceptions(
                "ARM64 unwind function range overlaps or escapes executable code",
            ));
        }
        previous_function_start = Some(function_start);
        previous_function_end = Some(function_end);
    }
    validate_xdata_coverage(
        file,
        xdata_contributions,
        &mut xdata_ranges,
        u64::from(limits.exception_records),
        is_cancelled,
    )
}

fn validate_packed_unwind(unwind: u32) -> Result<u64, InspectError> {
    let flag = u64::from(unwind & 0x3);
    let function_words = u64::from((unwind >> 2) & 0x7ff);
    let reg_f = u64::from((unwind >> 13) & 0x7);
    let reg_i = u64::from((unwind >> 16) & 0xf);
    let homes_parameters = u64::from((unwind >> 20) & 1);
    let chain_return = u64::from((unwind >> 21) & 0x3);
    let frame_words = u64::from((unwind >> 23) & 0x1ff);
    let integer_save_bytes = reg_i
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(u64::from(chain_return == 1) * 8))
        .ok_or_else(|| invalid_arm64_exceptions("packed unwind save size overflows"))?;
    let floating_save_bytes = reg_f
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(u64::from(reg_f != 0) * 8))
        .ok_or_else(|| invalid_arm64_exceptions("packed unwind save size overflows"))?;
    let minimum_frame = align_up(
        integer_save_bytes
            .checked_add(floating_save_bytes)
            .and_then(|bytes| bytes.checked_add(homes_parameters * 64))
            .ok_or_else(|| invalid_arm64_exceptions("packed unwind save size overflows"))?,
        16,
    )?;
    let frame_bytes = frame_words * 16;
    let describes_frame =
        frame_words != 0 || reg_f != 0 || reg_i != 0 || homes_parameters != 0 || chain_return != 0;
    if function_words == 0
        || reg_i > 10
        || minimum_frame > frame_bytes
        || flag == 1 && !describes_frame
    {
        return Err(invalid_arm64_exceptions(
            "packed ARM64 unwind fields are noncanonical",
        ));
    }
    Ok(function_words * ARM64_INSTRUCTION_BYTES)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedXdataRecord {
    function_bytes: u64,
    range: XdataRecordRange,
}

fn parse_xdata_record(
    file: &mut File,
    xdata_rva: u64,
    pe: &ParsedPe,
    xdata_contributions: &[XdataContribution],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ParsedXdataRecord, InspectError> {
    if is_cancelled() {
        return Err(InspectError::Cancelled);
    }
    if xdata_rva == 0 || xdata_rva % 4 != 0 {
        return Err(invalid_arm64_exceptions(
            "ARM64 .xdata RVA is absent or unaligned",
        ));
    }
    let contribution_index = xdata_contributions
        .partition_point(|contribution| contribution.rva <= xdata_rva)
        .checked_sub(1)
        .ok_or_else(|| {
            invalid_arm64_exceptions(
                "ARM64 .xdata RVA does not target a reviewed input contribution",
            )
        })?;
    let contribution = &xdata_contributions[contribution_index];
    if xdata_rva - contribution.rva >= contribution.bytes {
        return Err(invalid_arm64_exceptions(
            "ARM64 .xdata RVA does not target a reviewed input contribution",
        ));
    }
    pe.sections
        .get(contribution.output_section)
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata contribution escapes PE sections"))?;
    let relative = xdata_rva - contribution.rva;
    let file_offset = contribution
        .file_offset
        .checked_add(relative)
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata file offset overflows"))?;
    if relative
        .checked_add(8)
        .is_none_or(|end| end > contribution.bytes)
    {
        return Err(invalid_arm64_exceptions(
            "ARM64 .xdata header escapes its reviewed contribution",
        ));
    }
    let first = read_exact_at::<8>(file, file_offset)
        .map_err(|error| map_image_read_error(error, "ARM64 .xdata bytes"))?;
    let header = le_u32(&first, 0).ok_or(InspectError::Truncated)?;
    let function_words = u64::from(header & 0x3ffff);
    let version = (header >> 18) & 0x3;
    let has_handler = header & (1 << 20) != 0;
    let single_epilog = header & (1 << 21) != 0;
    let inline_epilog_field = u64::from((header >> 22) & 0x1f);
    let inline_code_words = u64::from((header >> 27) & 0x1f);
    if function_words == 0 || version != 0 || has_handler {
        return Err(invalid_arm64_exceptions(
            "ARM64 .xdata header has invalid length, version, or handler data",
        ));
    }
    let extended = header >> 22 == 0;
    let (header_bytes, epilog_field, code_words) = if extended {
        let extension = le_u32(&first, 4).ok_or(InspectError::Truncated)?;
        if extension >> 24 != 0 {
            return Err(invalid_arm64_exceptions(
                "ARM64 .xdata extended header has nonzero reserved bits",
            ));
        }
        (
            8u64,
            u64::from(extension & 0xffff),
            u64::from((extension >> 16) & 0xff),
        )
    } else {
        (4u64, inline_epilog_field, inline_code_words)
    };
    if code_words == 0 {
        return Err(invalid_arm64_exceptions(
            "ARM64 .xdata has no unwind-code words",
        ));
    }
    let scope_count = if single_epilog { 0 } else { epilog_field };
    let scope_bytes = scope_count
        .checked_mul(4)
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata scope size overflows"))?;
    let code_bytes = code_words
        .checked_mul(4)
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata code size overflows"))?;
    let record_bytes = header_bytes
        .checked_add(scope_bytes)
        .and_then(|bytes| bytes.checked_add(code_bytes))
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata record size overflows"))?;
    let contribution_relative = xdata_rva - contribution.rva;
    if contribution_relative
        .checked_add(record_bytes)
        .is_none_or(|end| end > contribution.bytes)
    {
        return Err(invalid_arm64_exceptions(
            "ARM64 .xdata record escapes its reviewed contribution",
        ));
    }
    let record = read_image_vec_at(file, file_offset, record_bytes, "ARM64 .xdata bytes")?;
    let code_start = usize::try_from(header_bytes + scope_bytes)
        .map_err(|_| invalid_arm64_exceptions("ARM64 .xdata code offset overflows"))?;
    let code_end = usize::try_from(record_bytes)
        .map_err(|_| invalid_arm64_exceptions("ARM64 .xdata code range overflows"))?;
    let codes = record
        .get(code_start..code_end)
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata code range is truncated"))?;
    let layout = validate_unwind_codes(codes, is_cancelled)?;
    let mut code_coverage = Vec::new();
    code_coverage
        .try_reserve_exact(layout.meaningful_bytes)
        .map_err(|_| invalid_arm64_exceptions("ARM64 unwind-code allocation failed"))?;
    code_coverage.resize(layout.meaningful_bytes, false);
    mark_unwind_sequence(codes, &layout, 0, &mut code_coverage)?;
    if single_epilog {
        let index = usize::try_from(epilog_field).map_err(|_| {
            invalid_arm64_exceptions("ARM64 .xdata embedded epilog index overflows")
        })?;
        mark_unwind_sequence(codes, &layout, index, &mut code_coverage)?;
    } else {
        let scope_start = usize::try_from(header_bytes)
            .map_err(|_| invalid_arm64_exceptions("ARM64 .xdata scope offset overflows"))?;
        let mut previous_offset = None;
        for index in 0..scope_count {
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            let offset = scope_start
                .checked_add(
                    usize::try_from(index * 4).map_err(|_| {
                        invalid_arm64_exceptions("ARM64 .xdata scope cursor overflows")
                    })?,
                )
                .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata scope cursor overflows"))?;
            let scope = le_u32(&record, offset).ok_or(InspectError::Truncated)?;
            let epilog_offset_words = u64::from(scope & 0x3ffff);
            let reserved = (scope >> 18) & 0xf;
            let unwind_index = usize::try_from((scope >> 22) & 0x3ff)
                .map_err(|_| invalid_arm64_exceptions("ARM64 .xdata epilog index overflows"))?;
            if reserved != 0
                || epilog_offset_words >= function_words
                || previous_offset.is_some_and(|previous| epilog_offset_words <= previous)
            {
                return Err(invalid_arm64_exceptions(
                    "ARM64 .xdata epilog scopes are reserved, unordered, or out of range",
                ));
            }
            mark_unwind_sequence(codes, &layout, unwind_index, &mut code_coverage)?;
            previous_offset = Some(epilog_offset_words);
        }
    }
    if code_coverage.iter().any(|covered| !covered) {
        return Err(invalid_arm64_exceptions(
            "ARM64 .xdata contains an unreferenced unwind-code sequence",
        ));
    }
    Ok(ParsedXdataRecord {
        function_bytes: function_words * ARM64_INSTRUCTION_BYTES,
        range: XdataRecordRange {
            contribution: contribution_index,
            rva: xdata_rva,
            file_offset,
            bytes: record_bytes,
        },
    })
}

struct UnwindCodeLayout {
    boundaries: Vec<bool>,
    meaningful_bytes: usize,
}

fn validate_unwind_codes(
    codes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<UnwindCodeLayout, InspectError> {
    let mut boundaries = Vec::new();
    boundaries
        .try_reserve_exact(codes.len().saturating_add(1))
        .map_err(|_| invalid_arm64_exceptions("ARM64 unwind-code allocation failed"))?;
    boundaries.resize(codes.len().saturating_add(1), false);
    let mut cursor = 0usize;
    let mut saw_end = false;
    let mut last_sequence_ended = false;
    let mut meaningful_bytes = codes.len();
    let mut allows_save_next = false;
    while cursor < codes.len() {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        boundaries[cursor] = true;
        let opcode = codes[cursor];
        let opcode_bytes = unwind_opcode_bytes(codes, cursor)?;
        let end = cursor
            .checked_add(opcode_bytes)
            .ok_or_else(|| invalid_arm64_exceptions("ARM64 unwind-code cursor overflows"))?;
        if end > codes.len() {
            return Err(invalid_arm64_exceptions("ARM64 unwind opcode is truncated"));
        }
        if opcode == 0xe6 && !allows_save_next {
            return Err(invalid_arm64_exceptions(
                "ARM64 save_next does not follow a register-pair save",
            ));
        }
        allows_save_next = matches!(opcode, 0x20..=0x3f | 0xc8..=0xcf | 0xd8..=0xdb | 0xe6)
            || opcode == 0xe7 && codes.get(cursor + 1).is_some_and(|byte| byte & 0x40 != 0);
        if opcode == 0xe4 {
            saw_end = true;
            last_sequence_ended = true;
            if codes.len() - end <= 3 && codes[end..].iter().all(|byte| *byte == 0) {
                meaningful_bytes = end;
                break;
            }
            allows_save_next = false;
        } else if opcode == 0xe5 {
            last_sequence_ended = false;
            allows_save_next = false;
        } else {
            last_sequence_ended = false;
        }
        cursor = end;
    }
    if !saw_end || !last_sequence_ended {
        return Err(invalid_arm64_exceptions(
            "ARM64 unwind-code array has an unterminated sequence",
        ));
    }
    boundaries[meaningful_bytes] = true;
    Ok(UnwindCodeLayout {
        boundaries,
        meaningful_bytes,
    })
}

fn unwind_opcode_bytes(codes: &[u8], cursor: usize) -> Result<usize, InspectError> {
    let opcode = *codes
        .get(cursor)
        .ok_or_else(|| invalid_arm64_exceptions("ARM64 unwind opcode is truncated"))?;
    match opcode {
        0x00..=0xbf | 0xe1 | 0xe3..=0xe6 | 0xfc => Ok(1),
        0xc0..=0xdf | 0xe2 => Ok(2),
        0xe0 => Ok(4),
        0xe7 => {
            let fields = *codes
                .get(cursor + 1)
                .ok_or_else(|| invalid_arm64_exceptions("ARM64 save_any opcode is truncated"))?;
            let kind =
                codes.get(cursor + 2).copied().ok_or_else(|| {
                    invalid_arm64_exceptions("ARM64 save_any opcode is truncated")
                })? >> 6;
            let register = fields & 0x1f;
            let pair = fields & 0x40 != 0;
            if fields & 0x80 != 0
                || (kind <= 2 && pair && register == 31)
                || (kind == 3 && fields & 0x10 != 0 && fields & 0x0f < 4)
            {
                return Err(invalid_arm64_exceptions(
                    "ARM64 save_any opcode uses reserved register fields",
                ));
            }
            Ok(3)
        }
        _ => Err(invalid_arm64_exceptions(
            "ARM64 unwind-code array contains a reserved opcode",
        )),
    }
}

fn mark_unwind_sequence(
    codes: &[u8],
    layout: &UnwindCodeLayout,
    index: usize,
    coverage: &mut [bool],
) -> Result<(), InspectError> {
    if index >= layout.meaningful_bytes || !layout.boundaries.get(index).copied().unwrap_or(false) {
        return Err(invalid_arm64_exceptions(
            "ARM64 epilog index is not an unwind-sequence boundary",
        ));
    }
    let mut cursor = index;
    while cursor < layout.meaningful_bytes {
        let opcode = codes
            .get(cursor)
            .copied()
            .ok_or_else(|| invalid_arm64_exceptions("ARM64 unwind sequence is truncated"))?;
        let bytes = unwind_opcode_bytes(codes, cursor)?;
        let next = cursor
            .checked_add(bytes)
            .ok_or_else(|| invalid_arm64_exceptions("ARM64 unwind sequence cursor overflows"))?;
        let covered = coverage.get_mut(cursor..next).ok_or_else(|| {
            invalid_arm64_exceptions("ARM64 unwind sequence escapes its code words")
        })?;
        covered.fill(true);
        if opcode == 0xe4 {
            return Ok(());
        }
        cursor = next;
    }
    Err(invalid_arm64_exceptions(
        "ARM64 unwind sequence has no end opcode",
    ))
}

fn validate_xdata_coverage(
    file: &mut File,
    contributions: &[XdataContribution],
    ranges: &mut Vec<XdataRecordRange>,
    range_limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), InspectError> {
    if ranges.is_empty() {
        return if contributions.is_empty() {
            Ok(())
        } else {
            Err(invalid_arm64_exceptions(
                "reviewed .xdata contribution is unreferenced",
            ))
        };
    }
    if contributions.is_empty() {
        return Err(invalid_arm64_exceptions(
            "full ARM64 unwind records require reviewed .xdata contributions",
        ));
    }
    *ranges = cancellable_sort(
        std::mem::take(ranges),
        |left, right| {
            (left.contribution, left.rva, left.bytes).cmp(&(
                right.contribution,
                right.rva,
                right.bytes,
            ))
        },
        "ARM64 exception records",
        range_limit,
        is_cancelled,
    )?;
    let mut unique = 0usize;
    for index in 0..ranges.len() {
        if index % 1024 == 0 && is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let range = ranges[index];
        if unique == 0 || ranges[unique - 1] != range {
            ranges[unique] = range;
            unique += 1;
        }
    }
    ranges.truncate(unique);
    let mut range_index = 0usize;
    for (contribution_index, contribution) in contributions.iter().enumerate() {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let contribution_rva_end = contribution
            .rva
            .checked_add(contribution.bytes)
            .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata contribution overflows"))?;
        let contribution_file_end = contribution
            .file_offset
            .checked_add(contribution.bytes)
            .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata contribution overflows"))?;
        let mut cursor_rva = contribution.rva;
        let mut cursor_file = contribution.file_offset;
        let first_range = range_index;
        while let Some(range) = ranges.get(range_index) {
            if range.contribution != contribution_index {
                break;
            }
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            let range_rva_end = range
                .rva
                .checked_add(range.bytes)
                .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata range overflows"))?;
            let range_file_end = range
                .file_offset
                .checked_add(range.bytes)
                .ok_or_else(|| invalid_arm64_exceptions("ARM64 .xdata range overflows"))?;
            if range.rva < cursor_rva
                || range.file_offset < cursor_file
                || range_rva_end > contribution_rva_end
                || range_file_end > contribution_file_end
                || range.rva - cursor_rva != range.file_offset - cursor_file
            {
                return Err(invalid_arm64_exceptions(
                    "ARM64 .xdata records overlap or escape their reviewed contribution",
                ));
            }
            ensure_zero_range(
                file,
                cursor_file,
                range.file_offset - cursor_file,
                "unreferenced ARM64 .xdata bytes are nonzero",
                is_cancelled,
            )?;
            cursor_rva = range_rva_end;
            cursor_file = range_file_end;
            range_index += 1;
        }
        if range_index == first_range {
            return Err(invalid_arm64_exceptions(
                "reviewed .xdata contribution is unreferenced",
            ));
        }
        ensure_zero_range(
            file,
            cursor_file,
            contribution_file_end - cursor_file,
            "unreferenced ARM64 .xdata bytes are nonzero",
            is_cancelled,
        )?;
    }
    if range_index != ranges.len() {
        return Err(invalid_arm64_exceptions(
            "ARM64 .xdata record names an unknown reviewed contribution",
        ));
    }
    Ok(())
}

fn read_image_vec_at(
    file: &mut File,
    offset: u64,
    bytes: u64,
    resource: &'static str,
) -> Result<Vec<u8>, InspectError> {
    let length = usize::try_from(bytes).map_err(|_| InspectError::LimitExceeded {
        resource,
        limit: usize::MAX as u64,
        actual: bytes,
    })?;
    let mut contents = Vec::new();
    contents
        .try_reserve_exact(length)
        .map_err(|_| InspectError::LimitExceeded {
            resource,
            limit: bytes,
            actual: bytes,
        })?;
    contents.resize(length, 0);
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| InspectError::Io(io_kind(error)))?;
    file.read_exact(&mut contents).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            InspectError::Truncated
        } else {
            InspectError::Io(io_kind(error))
        }
    })?;
    Ok(contents)
}

fn ensure_zero_range(
    file: &mut File,
    offset: u64,
    bytes: u64,
    reason: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), InspectError> {
    if bytes == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| InspectError::Io(io_kind(error)))?;
    let mut remaining = bytes;
    let mut buffer = [0u8; IO_CHUNK_BYTES];
    while remaining != 0 {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let take = usize::try_from(remaining.min(IO_CHUNK_BYTES as u64))
            .map_err(|_| InspectError::Truncated)?;
        file.read_exact(&mut buffer[..take]).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                InspectError::Truncated
            } else {
                InspectError::Io(io_kind(error))
            }
        })?;
        if buffer[..take].iter().any(|byte| *byte != 0) {
            return Err(InspectError::NonCanonical(reason));
        }
        remaining -= take as u64;
    }
    Ok(())
}

const fn invalid_arm64_exceptions(reason: &'static str) -> InspectError {
    InspectError::NonCanonical(reason)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaseRelocationMeasurements {
    blocks: u32,
    entries: u32,
}

/// Decode the complete base-relocation directory without retaining attacker-
/// controlled entries. Revision 0.1 ARM64 images use only aligned `DIR64`
/// fixups; a zero `ABSOLUTE` entry is permitted solely as LLD's final
/// four-byte block-alignment pad.
fn parse_base_relocations(
    reader: &mut impl Read,
    directory_bytes: u64,
    sections: &[LinkedSection],
    expected_sites: Option<&[u64]>,
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BaseRelocationMeasurements, InspectError> {
    if directory_bytes < BASE_RELOCATION_BLOCK_HEADER_BYTES + 4 || directory_bytes % 4 != 0 {
        return Err(invalid_base_relocations(
            "base-relocation directory size is not canonical",
        ));
    }
    let mut consumed = 0u64;
    let mut blocks = 0u32;
    let mut entries = 0u64;
    let mut previous_page_end = None;
    let mut previous_target_end = None;
    let mut section_index = 0usize;
    while consumed < directory_bytes {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let remaining = directory_bytes
            .checked_sub(consumed)
            .ok_or_else(|| invalid_base_relocations("base-relocation cursor overflowed"))?;
        if remaining < BASE_RELOCATION_BLOCK_HEADER_BYTES {
            return Err(invalid_base_relocations(
                "base-relocation directory ends inside a block header",
            ));
        }
        let header = read_relocation_exact::<8>(reader)?;
        let page_rva = u64::from(
            le_u32(&header, 0)
                .ok_or_else(|| invalid_base_relocations("base-relocation page is truncated"))?,
        );
        let block_bytes = u64::from(
            le_u32(&header, 4)
                .ok_or_else(|| invalid_base_relocations("base-relocation size is truncated"))?,
        );
        if page_rva % BASE_RELOCATION_PAGE_BYTES != 0
            || block_bytes < BASE_RELOCATION_BLOCK_HEADER_BYTES + 4
            || block_bytes % 4 != 0
            || block_bytes > remaining
            || previous_page_end.is_some_and(|end| page_rva < end)
        {
            return Err(invalid_base_relocations(
                "base-relocation block is unaligned, unordered, or out of bounds",
            ));
        }
        let block_entries = block_bytes
            .checked_sub(BASE_RELOCATION_BLOCK_HEADER_BYTES)
            .and_then(|bytes| bytes.checked_div(BASE_RELOCATION_ENTRY_BYTES))
            .ok_or_else(|| invalid_base_relocations("base-relocation block size overflowed"))?;
        consumed = consumed
            .checked_add(BASE_RELOCATION_BLOCK_HEADER_BYTES)
            .ok_or_else(|| invalid_base_relocations("base-relocation cursor overflowed"))?;
        let mut block_relocations = 0u64;
        let mut saw_padding = false;
        for index in 0..block_entries {
            if is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            let encoded = u16::from_le_bytes(read_relocation_exact::<2>(reader)?);
            consumed = consumed
                .checked_add(BASE_RELOCATION_ENTRY_BYTES)
                .ok_or_else(|| invalid_base_relocations("base-relocation cursor overflowed"))?;
            let relocation_type = encoded >> 12;
            let page_offset = u64::from(encoded & 0x0fff);
            if relocation_type == IMAGE_REL_BASED_ABSOLUTE {
                if encoded != 0 || saw_padding || index + 1 != block_entries {
                    return Err(invalid_base_relocations(
                        "base-relocation padding is not one final zero entry",
                    ));
                }
                saw_padding = true;
                continue;
            }
            if relocation_type != IMAGE_REL_BASED_DIR64 {
                return Err(invalid_base_relocations(
                    "base-relocation type is not ARM64 DIR64",
                ));
            }
            let target = page_rva
                .checked_add(page_offset)
                .ok_or_else(|| invalid_base_relocations("base-relocation target overflowed"))?;
            let target_end = target
                .checked_add(8)
                .ok_or_else(|| invalid_base_relocations("base-relocation target overflowed"))?;
            if target % 8 != 0
                || previous_target_end.is_some_and(|end| target < end)
                || !relocation_target_is_mapped(sections, &mut section_index, target, target_end)?
            {
                return Err(invalid_base_relocations(
                    "base-relocation target is unaligned, overlapping, or unmapped",
                ));
            }
            if expected_sites.is_some_and(|expected| {
                expected.get(usize::try_from(entries).unwrap_or(usize::MAX)) != Some(&target)
            }) {
                return Err(InspectError::InvalidRelocationProvenance(
                    "output DIR64 target does not match its reviewed input relocation site",
                ));
            }
            entries = entries.checked_add(1).ok_or(InspectError::LimitExceeded {
                resource: "base relocations",
                limit: u64::from(limits.base_relocations),
                actual: u64::MAX,
            })?;
            if entries > u64::from(limits.base_relocations) {
                return Err(InspectError::LimitExceeded {
                    resource: "base relocations",
                    limit: u64::from(limits.base_relocations),
                    actual: entries,
                });
            }
            block_relocations = block_relocations
                .checked_add(1)
                .ok_or_else(|| invalid_base_relocations("base-relocation count overflowed"))?;
            previous_target_end = Some(target_end);
        }
        if block_relocations == 0 || (block_relocations % 2 == 1) != saw_padding {
            return Err(invalid_base_relocations(
                "base-relocation block has noncanonical entries or padding",
            ));
        }
        blocks = blocks
            .checked_add(1)
            .ok_or_else(|| invalid_base_relocations("base-relocation block count overflowed"))?;
        previous_page_end = Some(
            page_rva
                .checked_add(BASE_RELOCATION_PAGE_BYTES)
                .ok_or_else(|| invalid_base_relocations("base-relocation page overflowed"))?,
        );
    }
    if consumed != directory_bytes || blocks == 0 || entries == 0 {
        return Err(invalid_base_relocations(
            "base-relocation directory is empty or not consumed exactly",
        ));
    }
    if expected_sites.is_some_and(|expected| expected.len() != entries as usize) {
        return Err(InspectError::InvalidRelocationProvenance(
            "input and output DIR64 relocation counts differ",
        ));
    }
    Ok(BaseRelocationMeasurements {
        blocks,
        entries: u32::try_from(entries).map_err(|_| InspectError::LimitExceeded {
            resource: "base relocations",
            limit: u64::from(limits.base_relocations),
            actual: entries,
        })?,
    })
}

fn relocation_target_is_mapped(
    sections: &[LinkedSection],
    section_index: &mut usize,
    target: u64,
    target_end: u64,
) -> Result<bool, InspectError> {
    while let Some(section) = sections.get(*section_index) {
        let section_end = section
            .virtual_address
            .checked_add(section.virtual_bytes)
            .ok_or_else(|| invalid_base_relocations("PE section range overflowed"))?;
        if target < section_end {
            return Ok(target >= section.virtual_address
                && target_end <= section_end
                && section.characteristics & IMAGE_SCN_MEM_DISCARDABLE == 0
                && section.characteristics
                    & (IMAGE_SCN_CNT_CODE
                        | IMAGE_SCN_CNT_INITIALIZED_DATA
                        | IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                    != 0);
        }
        *section_index = section_index
            .checked_add(1)
            .ok_or_else(|| invalid_base_relocations("PE section cursor overflowed"))?;
    }
    Ok(false)
}

fn read_relocation_exact<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], InspectError> {
    let mut bytes = [0u8; N];
    reader.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            InspectError::Truncated
        } else {
            InspectError::Io(io_kind(error))
        }
    })?;
    Ok(bytes)
}

const fn invalid_base_relocations(reason: &'static str) -> InspectError {
    InspectError::InvalidBaseRelocations(reason)
}

#[derive(Debug)]
struct RawMapSymbol {
    name: String,
    section: usize,
    virtual_address: u64,
    public: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MapMode {
    Header,
    Public,
    Static,
}

#[allow(clippy::struct_excessive_bools)]
struct MapState<'a> {
    sections: &'a [LinkedSection],
    image_base: u64,
    entry_rva: u64,
    expected_entry: &'a str,
    limits: ImageInspectLimits,
    mode: MapMode,
    saw_repro: bool,
    saw_preferred_base: bool,
    saw_public_header: bool,
    saw_static_header: bool,
    saw_entry_record: bool,
    map_symbol_lines: u32,
    measurement_bytes: u64,
    symbols: Vec<RawMapSymbol>,
}

#[derive(Debug, Clone, Copy)]
struct MapContext<'a> {
    sections: &'a [LinkedSection],
    image_base: u64,
    entry_rva: u64,
    expected_entry: &'a str,
}

#[allow(clippy::large_stack_arrays)]
fn parse_lld_map(
    file: &mut File,
    map_bytes: u64,
    context: MapContext<'_>,
    limits: ImageInspectLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<LinkedSymbol>, InspectError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| InspectError::Io(io_kind(error)))?;
    let mut state = MapState {
        sections: context.sections,
        image_base: context.image_base,
        entry_rva: context.entry_rva,
        expected_entry: context.expected_entry,
        limits,
        mode: MapMode::Header,
        saw_repro: false,
        saw_preferred_base: false,
        saw_public_header: false,
        saw_static_header: false,
        saw_entry_record: false,
        map_symbol_lines: 0,
        measurement_bytes: context.sections.iter().try_fold(0u64, |total, section| {
            add_measurement(total, section.name.len(), limits)
        })?,
        symbols: Vec::new(),
    };
    let mut chunk = [0u8; IO_CHUNK_BYTES];
    let mut line = Vec::new();
    let mut consumed = 0u64;
    loop {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let read = file
            .read(&mut chunk)
            .map_err(|error| InspectError::Io(io_kind(error)))?;
        if read == 0 {
            break;
        }
        consumed = consumed
            .checked_add(read as u64)
            .ok_or(InspectError::LimitExceeded {
                resource: "map bytes",
                limit: limits.map_bytes,
                actual: u64::MAX,
            })?;
        if consumed > map_bytes || consumed > limits.map_bytes {
            return Err(InspectError::LimitExceeded {
                resource: "map bytes",
                limit: limits.map_bytes,
                actual: consumed,
            });
        }
        let mut start = 0usize;
        for (index, byte) in chunk[..read].iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            append_line(&mut line, &chunk[start..index])?;
            process_map_line(&line, &mut state, is_cancelled)?;
            line.clear();
            start = index + 1;
        }
        append_line(&mut line, &chunk[start..read])?;
    }
    if consumed != map_bytes {
        return Err(InspectError::Truncated);
    }
    if !line.is_empty() {
        process_map_line(&line, &mut state, is_cancelled)?;
    }
    finish_map(state, is_cancelled)
}

fn append_line(line: &mut Vec<u8>, bytes: &[u8]) -> Result<(), InspectError> {
    let new_len = line
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| invalid_map("map line length overflows"))?;
    if new_len > MAX_MAP_LINE_BYTES {
        return Err(invalid_map("map line exceeds the fixed parser ceiling"));
    }
    line.try_reserve(bytes.len())
        .map_err(|_| invalid_map("cannot reserve bounded map line"))?;
    line.extend_from_slice(bytes);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn process_map_line(
    line: &[u8],
    state: &mut MapState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), InspectError> {
    for chunk in line.chunks(4096) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if chunk.contains(&b'\r') || !chunk.is_ascii() {
            return Err(invalid_map("map is not canonical LF-terminated ASCII"));
        }
    }
    let line = std::str::from_utf8(line).map_err(|_| invalid_map("map is not UTF-8"))?;
    if let Some(value) = line.strip_prefix(" Timestamp is ") {
        let Some((timestamp, suffix)) = value.split_once(' ') else {
            return Err(invalid_map("map timestamp record is malformed"));
        };
        let timestamp = parse_fixed_hex(timestamp, 8)?;
        if state.mode != MapMode::Header
            || timestamp != 0
            || suffix != "(Repro mode)"
            || std::mem::replace(&mut state.saw_repro, true)
        {
            return Err(invalid_map("map is not uniquely marked as reproducible"));
        }
        return Ok(());
    }
    if let Some(value) = line.strip_prefix(" Preferred load address is ") {
        let observed = parse_fixed_hex(value, 16)?;
        if state.mode != MapMode::Header
            || observed != state.image_base
            || std::mem::replace(&mut state.saw_preferred_base, true)
        {
            return Err(invalid_map("map preferred image base disagrees with PE32+"));
        }
        return Ok(());
    }
    if line.starts_with("  Address") && line.contains("Publics by Value") {
        if state.mode != MapMode::Header
            || !state.saw_repro
            || !state.saw_preferred_base
            || std::mem::replace(&mut state.saw_public_header, true)
        {
            return Err(invalid_map("map contains duplicate public symbol headers"));
        }
        state.mode = MapMode::Public;
        return Ok(());
    }
    if line == " Static symbols" {
        if state.mode != MapMode::Public || std::mem::replace(&mut state.saw_static_header, true) {
            return Err(invalid_map("map static symbol header is out of order"));
        }
        state.mode = MapMode::Static;
        return Ok(());
    }
    if let Some(value) = line.strip_prefix(" entry point at         ") {
        let (section, offset) = parse_section_address(value)?;
        let observed = map_virtual_address(state.sections, section, offset)?;
        if state.mode != MapMode::Public
            || observed != state.entry_rva
            || std::mem::replace(&mut state.saw_entry_record, true)
        {
            return Err(invalid_map("map entry record disagrees with PE32+"));
        }
        return Ok(());
    }
    if state.mode == MapMode::Header || line.trim().is_empty() {
        return Ok(());
    }
    let mut fields = line.split_whitespace();
    let Some(address) = fields.next() else {
        return Ok(());
    };
    if address.len() != 13 || address.as_bytes().get(4) != Some(&b':') {
        return Err(invalid_map(
            "map symbol region contains an unrecognized nonempty record",
        ));
    }
    let Some(name) = fields.next() else {
        return Err(invalid_map("map symbol record omits a name"));
    };
    let Some(absolute) = fields.next() else {
        return Err(invalid_map("map symbol record omits an absolute address"));
    };
    state.map_symbol_lines =
        state
            .map_symbol_lines
            .checked_add(1)
            .ok_or_else(|| InspectError::LimitExceeded {
                resource: "symbols",
                limit: u64::from(state.limits.symbols),
                actual: u64::MAX,
            })?;
    if state.map_symbol_lines > state.limits.symbols {
        return Err(InspectError::LimitExceeded {
            resource: "symbols",
            limit: u64::from(state.limits.symbols),
            actual: u64::from(state.map_symbol_lines),
        });
    }
    let (section, offset) = parse_section_address(address)?;
    let absolute = parse_fixed_hex(absolute, 16)?;
    if section == 0 {
        return Ok(());
    }
    let virtual_address = map_virtual_address(state.sections, section, offset)?;
    if state
        .image_base
        .checked_add(virtual_address)
        .is_none_or(|expected| expected != absolute)
        || name.is_empty()
        || !canonical_map_name(name, is_cancelled)?
    {
        return Err(invalid_map(
            "map symbol address or spelling is noncanonical",
        ));
    }
    state.measurement_bytes = add_measurement(state.measurement_bytes, name.len(), state.limits)?;
    state
        .symbols
        .try_reserve(1)
        .map_err(|_| InspectError::LimitExceeded {
            resource: "symbols",
            limit: u64::from(state.limits.symbols),
            actual: u64::from(state.map_symbol_lines),
        })?;
    state.symbols.push(RawMapSymbol {
        name: copy_string(name, state.limits.measurement_bytes)?,
        section: section - 1,
        virtual_address,
        public: state.mode == MapMode::Public,
    });
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn finish_map(
    mut state: MapState<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<LinkedSymbol>, InspectError> {
    if !state.saw_repro
        || !state.saw_preferred_base
        || !state.saw_public_header
        || !state.saw_static_header
        || !state.saw_entry_record
    {
        return Err(invalid_map(
            "map omits reproducibility, image-base, symbol, or entry evidence",
        ));
    }
    let mut entry_matches = 0usize;
    for (index, symbol) in state.symbols.iter().enumerate() {
        if index % 1024 == 0 && is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        entry_matches += usize::from(
            symbol.public
                && symbol.name == state.expected_entry
                && symbol.virtual_address == state.entry_rva,
        );
    }
    if entry_matches != 1 {
        return Err(invalid_map(
            "map does not bind exactly one selected entry symbol to AddressOfEntryPoint",
        ));
    }
    let symbols = cancellable_sort(
        std::mem::take(&mut state.symbols),
        |left, right| {
            (left.section, left.virtual_address, left.name.as_str()).cmp(&(
                right.section,
                right.virtual_address,
                right.name.as_str(),
            ))
        },
        "symbols",
        u64::from(state.limits.symbols),
        is_cancelled,
    )?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(symbols.len())
        .map_err(|_| InspectError::LimitExceeded {
            resource: "symbols",
            limit: u64::from(state.limits.symbols),
            actual: symbols.len() as u64,
        })?;
    let mut index = 0usize;
    while index < symbols.len() {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let first = &symbols[index];
        let section = state
            .sections
            .get(first.section)
            .ok_or_else(|| invalid_map("map symbol names a nonexistent section"))?;
        let section_end = section
            .virtual_address
            .checked_add(section.virtual_bytes)
            .ok_or_else(|| invalid_map("PE section range overflows"))?;
        let mut group_end = index + 1;
        while group_end < symbols.len()
            && symbols[group_end].section == first.section
            && symbols[group_end].virtual_address == first.virtual_address
        {
            group_end += 1;
        }
        let next = symbols.get(group_end).map_or(section_end, |candidate| {
            if candidate.section == first.section {
                candidate.virtual_address
            } else {
                section_end
            }
        });
        if first.virtual_address < section.virtual_address
            || first.virtual_address >= section_end
            || next > section_end
        {
            return Err(invalid_map("map symbol escapes its PE section"));
        }
        for symbol in &symbols[index..group_end] {
            if output.len() % 1024 == 0 && is_cancelled() {
                return Err(InspectError::Cancelled);
            }
            state.measurement_bytes =
                add_measurement(state.measurement_bytes, section.name.len(), state.limits)?;
            output.push(LinkedSymbol {
                name: copy_string(&symbol.name, state.limits.measurement_bytes)?,
                section: copy_string(&section.name, state.limits.measurement_bytes)?,
                virtual_address: symbol.virtual_address,
                bytes: next - symbol.virtual_address,
            });
        }
        index = group_end;
    }
    let output = cancellable_sort(
        output,
        |left, right| {
            (
                left.name.as_str(),
                left.section.as_str(),
                left.virtual_address,
                left.bytes,
            )
                .cmp(&(
                    right.name.as_str(),
                    right.section.as_str(),
                    right.virtual_address,
                    right.bytes,
                ))
        },
        "symbols",
        u64::from(state.limits.symbols),
        is_cancelled,
    )?;
    if output.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(invalid_map("map contains duplicate symbol names"));
    }
    let fixed = "arm64".len() + "efi_application".len() + state.expected_entry.len();
    add_measurement(state.measurement_bytes, fixed, state.limits)?;
    Ok(output)
}

fn cancellable_sort<T>(
    values: Vec<T>,
    compare: impl Fn(&T, &T) -> Ordering,
    resource: &'static str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<T>, InspectError> {
    const RUN_ITEMS: usize = 256;
    if is_cancelled() {
        return Err(InspectError::Cancelled);
    }
    if values.len() <= 1 {
        return Ok(values);
    }
    if values.len() <= RUN_ITEMS {
        let mut values = values;
        values.sort_unstable_by(&compare);
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        return Ok(values);
    }

    let actual = values.len() as u64;
    let run_count = values.len().div_ceil(RUN_ITEMS);
    let mut runs = Vec::new();
    runs.try_reserve_exact(run_count)
        .map_err(|_| InspectError::LimitExceeded {
            resource,
            limit,
            actual,
        })?;
    let mut remaining = values.len();
    let mut values = values.into_iter();
    while remaining != 0 {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let capacity = remaining.min(RUN_ITEMS);
        let mut run = Vec::new();
        run.try_reserve_exact(capacity)
            .map_err(|_| InspectError::LimitExceeded {
                resource,
                limit,
                actual,
            })?;
        for _ in 0..capacity {
            let Some(value) = values.next() else {
                return Err(invalid_map("sort input ended before its measured length"));
            };
            run.push(value);
        }
        remaining -= capacity;
        run.sort_unstable_by(&compare);
        runs.push(run);
    }

    while runs.len() > 1 {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let mut merged = Vec::new();
        merged
            .try_reserve_exact(runs.len().div_ceil(2))
            .map_err(|_| InspectError::LimitExceeded {
                resource,
                limit,
                actual,
            })?;
        let mut previous = std::mem::take(&mut runs).into_iter();
        while let Some(left) = previous.next() {
            let Some(right) = previous.next() else {
                merged.push(left);
                break;
            };
            merged.push(merge_sorted_runs(
                left,
                right,
                &compare,
                resource,
                limit,
                actual,
                is_cancelled,
            )?);
        }
        runs = merged;
    }
    runs.pop()
        .ok_or_else(|| invalid_map("sort produced no result"))
}

fn merge_sorted_runs<T>(
    left: Vec<T>,
    right: Vec<T>,
    compare: &impl Fn(&T, &T) -> Ordering,
    resource: &'static str,
    limit: u64,
    actual: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<T>, InspectError> {
    let capacity = left
        .len()
        .checked_add(right.len())
        .ok_or(InspectError::LimitExceeded {
            resource,
            limit,
            actual: u64::MAX,
        })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| InspectError::LimitExceeded {
            resource,
            limit,
            actual,
        })?;
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    while left.peek().is_some() || right.peek().is_some() {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        let next = match (left.peek(), right.peek()) {
            (Some(left_value), Some(right_value))
                if compare(left_value, right_value) != Ordering::Greater =>
            {
                left.next()
            }
            (Some(_) | None, Some(_)) => right.next(),
            (Some(_), None) => left.next(),
            (None, None) => None,
        }
        .ok_or_else(|| invalid_map("sort merge lost a measured item"))?;
        output.push(next);
    }
    Ok(output)
}

fn map_virtual_address(
    sections: &[LinkedSection],
    section: usize,
    offset: u64,
) -> Result<u64, InspectError> {
    if section == 0 {
        return Ok(offset);
    }
    let section = sections
        .get(section - 1)
        .ok_or_else(|| invalid_map("map section index is outside PE section table"))?;
    let address = section
        .virtual_address
        .checked_add(offset)
        .ok_or_else(|| invalid_map("map symbol address overflows"))?;
    if address
        >= section
            .virtual_address
            .checked_add(section.virtual_bytes)
            .ok_or_else(|| invalid_map("PE section range overflows"))?
    {
        return Err(invalid_map("map symbol offset escapes its PE section"));
    }
    Ok(address)
}

fn parse_section_address(value: &str) -> Result<(usize, u64), InspectError> {
    let Some((section, offset)) = value.split_once(':') else {
        return Err(invalid_map("map section address is malformed"));
    };
    let section = usize::try_from(parse_fixed_hex(section, 4)?)
        .map_err(|_| invalid_map("map section index does not fit the host"))?;
    let offset = parse_fixed_hex(offset, 8)?;
    Ok((section, offset))
}

fn parse_fixed_hex(value: &str, digits: usize) -> Result<u64, InspectError> {
    if value.len() != digits || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_map("map hexadecimal field is malformed"));
    }
    u64::from_str_radix(value, 16).map_err(|_| invalid_map("map hexadecimal field overflows"))
}

fn canonical_map_name(value: &str, is_cancelled: &dyn Fn() -> bool) -> Result<bool, InspectError> {
    if value.is_empty() || value.len() > MAX_MAP_LINE_BYTES {
        return Ok(false);
    }
    for chunk in value.as_bytes().chunks(4096) {
        if is_cancelled() {
            return Err(InspectError::Cancelled);
        }
        if !chunk.iter().all(u8::is_ascii_graphic) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn pe_section_name(bytes: &[u8], limit: u64) -> Result<String, InspectError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0
        || bytes[end..].iter().any(|byte| *byte != 0)
        || bytes[0] == b'/'
        || !bytes[..end].iter().all(u8::is_ascii_graphic)
    {
        return Err(InspectError::NonCanonical(
            "PE section name is empty, long-form, or noncanonical ASCII",
        ));
    }
    let name = std::str::from_utf8(&bytes[..end])
        .map_err(|_| InspectError::NonCanonical("PE section name is not canonical ASCII"))?;
    copy_string(name, limit)
}

fn add_measurement(
    total: u64,
    bytes: usize,
    limits: ImageInspectLimits,
) -> Result<u64, InspectError> {
    let actual = total
        .checked_add(u64::try_from(bytes).unwrap_or(u64::MAX))
        .ok_or(InspectError::LimitExceeded {
            resource: "measurement bytes",
            limit: limits.measurement_bytes,
            actual: u64::MAX,
        })?;
    if actual > limits.measurement_bytes {
        return Err(InspectError::LimitExceeded {
            resource: "measurement bytes",
            limit: limits.measurement_bytes,
            actual,
        });
    }
    Ok(actual)
}

fn copy_string(value: &str, limit: u64) -> Result<String, InspectError> {
    if u64::try_from(value.len()).unwrap_or(u64::MAX) > limit {
        return Err(InspectError::LimitExceeded {
            resource: "measurement bytes",
            limit,
            actual: value.len() as u64,
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| InspectError::LimitExceeded {
            resource: "measurement bytes",
            limit,
            actual: value.len() as u64,
        })?;
    output.push_str(value);
    Ok(output)
}

fn invalid_map(reason: &'static str) -> InspectError {
    InspectError::InvalidMap(reason.to_owned())
}

fn open_stable_file(path: &Path, maximum_bytes: u64) -> Result<StableFile, StableReadError> {
    let canonical = fs::canonicalize(path).map_err(|error| StableReadError::Io(io_kind(error)))?;
    if canonical != path {
        return Err(StableReadError::Unstable);
    }
    let before = fs::symlink_metadata(path).map_err(|error| StableReadError::Io(io_kind(error)))?;
    validate_regular_metadata(&before)?;
    let before = file_identity(&before);
    if before.bytes > maximum_bytes {
        return Err(StableReadError::TooLarge {
            limit: maximum_bytes,
            actual: before.bytes,
        });
    }
    let file = File::open(path).map_err(|error| StableReadError::Io(io_kind(error)))?;
    let opened = file
        .metadata()
        .map_err(|error| StableReadError::Io(io_kind(error)))?;
    validate_regular_metadata(&opened)?;
    if file_identity(&opened) != before {
        return Err(StableReadError::Unstable);
    }
    Ok(StableFile {
        file,
        identity: before,
        bytes: before.bytes,
    })
}

fn verify_stable_path(path: &Path, stable: &StableFile) -> Result<(), StableReadError> {
    let opened = stable
        .file
        .metadata()
        .map_err(|error| StableReadError::Io(io_kind(error)))?;
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| StableReadError::Io(io_kind(error)))?;
    validate_regular_metadata(&opened)?;
    validate_regular_metadata(&path_metadata)?;
    if file_identity(&opened) != stable.identity || file_identity(&path_metadata) != stable.identity
    {
        return Err(StableReadError::Unstable);
    }
    Ok(())
}

fn validate_regular_metadata(metadata: &Metadata) -> Result<(), StableReadError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StableReadError::Unstable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return Err(StableReadError::Unstable);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        bytes: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

#[cfg(windows)]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    use std::os::windows::fs::MetadataExt;

    FileIdentity {
        bytes: metadata.len(),
        attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        modified_time: metadata.last_write_time(),
    }
}

#[cfg(not(any(unix, windows)))]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        bytes: metadata.len(),
    }
}

#[allow(clippy::large_stack_arrays)]
fn hash_and_capture_prefix(
    file: &mut File,
    expected_bytes: u64,
    prefix_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Sha256Digest, Vec<u8>), StableReadError> {
    let (digest, prefix, _) =
        hash_and_capture(file, expected_bytes, prefix_bytes, None, is_cancelled)?;
    Ok((digest, prefix))
}

#[allow(clippy::large_stack_arrays)]
fn hash_and_capture_prefix_and_range(
    file: &mut File,
    expected_bytes: u64,
    prefix_bytes: u64,
    range_offset: u64,
    range_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Sha256Digest, Vec<u8>, Sha256Digest), StableReadError> {
    let (digest, prefix, range_digest) = hash_and_capture(
        file,
        expected_bytes,
        prefix_bytes,
        Some((range_offset, range_bytes)),
        is_cancelled,
    )?;
    Ok((
        digest,
        prefix,
        range_digest.ok_or(StableReadError::Truncated)?,
    ))
}

#[allow(clippy::large_stack_arrays)]
fn hash_and_capture(
    file: &mut File,
    expected_bytes: u64,
    prefix_bytes: u64,
    range: Option<(u64, u64)>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Sha256Digest, Vec<u8>, Option<Sha256Digest>), StableReadError> {
    if prefix_bytes > expected_bytes || prefix_bytes > MAX_HEADER_BYTES {
        return Err(StableReadError::Truncated);
    }
    let range_end = match range {
        Some((offset, bytes)) if bytes != 0 => Some(
            offset
                .checked_add(bytes)
                .filter(|end| *end <= expected_bytes)
                .ok_or(StableReadError::Truncated)?,
        ),
        Some(_) => return Err(StableReadError::Truncated),
        None => None,
    };
    file.seek(SeekFrom::Start(0))
        .map_err(|error| StableReadError::Io(io_kind(error)))?;
    let prefix_capacity = usize::try_from(prefix_bytes).map_err(|_| StableReadError::Truncated)?;
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(prefix_capacity)
        .map_err(|_| StableReadError::TooLarge {
            limit: prefix_bytes,
            actual: prefix_bytes,
        })?;
    let mut hasher = Sha256::new();
    let mut range_hasher = range.map(|_| Sha256::new());
    let mut range_total = 0u64;
    let mut buffer = [0u8; IO_CHUNK_BYTES];
    let mut total = 0u64;
    loop {
        if is_cancelled() {
            return Err(StableReadError::Cancelled);
        }
        let read = file
            .read(&mut buffer)
            .map_err(|error| StableReadError::Io(io_kind(error)))?;
        if read == 0 {
            break;
        }
        let chunk_start = total;
        total = chunk_start
            .checked_add(read as u64)
            .ok_or(StableReadError::Truncated)?;
        if total > expected_bytes {
            return Err(StableReadError::Unstable);
        }
        hasher.update(&buffer[..read]);
        if let (Some((range_offset, _)), Some(range_end), Some(range_hasher)) =
            (range, range_end, range_hasher.as_mut())
        {
            let overlap_start = chunk_start.max(range_offset);
            let overlap_end = total.min(range_end);
            if overlap_start < overlap_end {
                let start = usize::try_from(overlap_start - chunk_start)
                    .map_err(|_| StableReadError::Truncated)?;
                let end = usize::try_from(overlap_end - chunk_start)
                    .map_err(|_| StableReadError::Truncated)?;
                range_hasher.update(&buffer[start..end]);
                range_total = range_total
                    .checked_add(overlap_end - overlap_start)
                    .ok_or(StableReadError::Truncated)?;
            }
        }
        if prefix.len() < prefix_capacity {
            let retain = (prefix_capacity - prefix.len()).min(read);
            prefix.extend_from_slice(&buffer[..retain]);
        }
    }
    if total != expected_bytes
        || prefix.len() != prefix_capacity
        || range.is_some_and(|(_, bytes)| range_total != bytes)
    {
        return Err(StableReadError::Truncated);
    }
    Ok((
        sha256_digest(hasher),
        prefix,
        range_hasher.map(sha256_digest),
    ))
}

#[allow(clippy::large_stack_arrays)]
fn read_prefix(
    file: &mut File,
    expected_bytes: u64,
    prefix_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, StableReadError> {
    if prefix_bytes > expected_bytes || prefix_bytes > MAX_HEADER_BYTES {
        return Err(StableReadError::Truncated);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| StableReadError::Io(io_kind(error)))?;
    let prefix_capacity = usize::try_from(prefix_bytes).map_err(|_| StableReadError::Truncated)?;
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(prefix_capacity)
        .map_err(|_| StableReadError::TooLarge {
            limit: prefix_bytes,
            actual: prefix_bytes,
        })?;
    let mut buffer = [0u8; IO_CHUNK_BYTES];
    while prefix.len() < prefix_capacity {
        if is_cancelled() {
            return Err(StableReadError::Cancelled);
        }
        let remaining = prefix_capacity - prefix.len();
        let read = file
            .read(&mut buffer[..remaining.min(IO_CHUNK_BYTES)])
            .map_err(|error| StableReadError::Io(io_kind(error)))?;
        if read == 0 {
            return Err(StableReadError::Truncated);
        }
        prefix.extend_from_slice(&buffer[..read]);
    }
    Ok(prefix)
}

fn sha256_digest(hasher: Sha256) -> Sha256Digest {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    Sha256Digest::from_bytes(digest)
}

fn read_exact_at<const N: usize>(file: &mut File, offset: u64) -> Result<[u8; N], StableReadError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| StableReadError::Io(io_kind(error)))?;
    let mut bytes = [0u8; N];
    file.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            StableReadError::Truncated
        } else {
            StableReadError::Io(io_kind(error))
        }
    })?;
    Ok(bytes)
}

fn map_coff_read_error(error: StableReadError) -> CoffInspectError {
    match error {
        StableReadError::Cancelled => CoffInspectError::Cancelled,
        StableReadError::Io(message) => CoffInspectError::Io(message),
        StableReadError::TooLarge { limit, actual } => CoffInspectError::TooLarge { limit, actual },
        StableReadError::Truncated => CoffInspectError::Truncated,
        StableReadError::Unstable => CoffInspectError::InvalidCoffHeader,
    }
}

fn map_image_read_error(error: StableReadError, resource: &'static str) -> InspectError {
    match error {
        StableReadError::Cancelled => InspectError::Cancelled,
        StableReadError::Io(message) => InspectError::Io(message),
        StableReadError::TooLarge { limit, actual } => InspectError::LimitExceeded {
            resource,
            limit,
            actual,
        },
        StableReadError::Truncated => InspectError::Truncated,
        StableReadError::Unstable => {
            InspectError::NonCanonical("artifact path or file identity changed during inspection")
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn io_kind(error: std::io::Error) -> String {
    format!("{:?}", error.kind())
}

fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(value))
}

fn le_i16(bytes: &[u8], offset: usize) -> Option<i16> {
    let value: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(i16::from_le_bytes(value))
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(value))
}

fn le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let value: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use wrela_target::TargetPackage;

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const TEST_PE: usize = LLD_PE_OFFSET;
    const TEST_OPTIONAL: usize = TEST_PE + 24;
    const TEST_SECTIONS: usize = TEST_OPTIONAL + PE_OPTIONAL_HEADER_BYTES;

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary base");
            for _ in 0..128 {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = base.join(format!(
                    "wrela-link-inspect-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        return Self {
                            root: fs::canonicalize(root).expect("canonical fixture directory"),
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create inspector fixture: {error}"),
                }
            }
            panic!("cannot allocate inspector fixture directory")
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(name);
            fs::write(&path, bytes).expect("bounded fixture write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("private fixture mode");
            }
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn target() -> TargetPackage {
        let target = TargetPackage::aarch64_qemu_virt_uefi(Sha256Digest::from_bytes([0x51; 32]));
        target.validate().expect("valid target fixture");
        target
    }

    fn limits() -> ImageInspectLimits {
        ImageInspectLimits {
            image_bytes: 1024 * 1024,
            map_bytes: 1024 * 1024,
            sections: 16,
            symbols: 16,
            base_relocations: 16,
            exception_records: 16,
            measurement_bytes: 1024 * 1024,
        }
    }

    fn ordinary_coff() -> Vec<u8> {
        let mut bytes = vec![0u8; 68];
        put_u16(&mut bytes, 0, IMAGE_FILE_MACHINE_ARM64);
        put_u16(&mut bytes, 2, 1);
        bytes[20..25].copy_from_slice(b".text");
        put_u32(&mut bytes, 20 + 16, 8);
        put_u32(&mut bytes, 20 + 20, 60);
        put_u32(&mut bytes, 20 + 36, 0x6050_0020);
        bytes[60..68].copy_from_slice(&[0xe0, 0x03, 0x1f, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
        bytes
    }

    fn coff_with_entry_definition() -> Vec<u8> {
        const SYMBOL_TABLE: usize = 68;
        const STRING_TABLE: usize = SYMBOL_TABLE + 18;
        const ENTRY: &[u8] = b"wrela_image_entry";
        let mut bytes = ordinary_coff();
        bytes.resize(STRING_TABLE + 4 + ENTRY.len() + 1, 0);
        put_u32(
            &mut bytes,
            8,
            u32::try_from(SYMBOL_TABLE).expect("symbol table offset"),
        );
        put_u32(&mut bytes, 12, 1);
        put_u32(&mut bytes, SYMBOL_TABLE + 4, 4);
        put_u32(&mut bytes, SYMBOL_TABLE + 8, 0);
        put_u16(&mut bytes, SYMBOL_TABLE + 12, 1);
        put_u16(&mut bytes, SYMBOL_TABLE + 14, IMAGE_SYM_DTYPE_FUNCTION);
        bytes[SYMBOL_TABLE + 16] = IMAGE_SYM_CLASS_EXTERNAL;
        put_u32(
            &mut bytes,
            STRING_TABLE,
            u32::try_from(4 + ENTRY.len() + 1).expect("string table bytes"),
        );
        bytes[STRING_TABLE + 4..STRING_TABLE + 4 + ENTRY.len()].copy_from_slice(ENTRY);
        bytes
    }

    fn coff_with_long_directive_section_name() -> Vec<u8> {
        const STRING_TABLE: usize = 68 + 18;
        let mut bytes = coff_with_entry_definition();
        let directive_offset =
            usize::try_from(le_u32(&bytes, STRING_TABLE).expect("string table bytes"))
                .expect("string table offset");
        let encoded = format!("/{directive_offset}");
        assert!(encoded.len() <= COFF_SECTION_NAME_BYTES);
        bytes[20..20 + COFF_SECTION_NAME_BYTES].fill(0);
        bytes[20..20 + encoded.len()].copy_from_slice(encoded.as_bytes());
        bytes.extend_from_slice(b".drectve\0");
        put_u32(
            &mut bytes,
            STRING_TABLE,
            u32::try_from(directive_offset + LINKER_DIRECTIVE_SECTION.len() + 1)
                .expect("extended string table bytes"),
        );
        bytes
    }

    fn coff_with_bss() -> Vec<u8> {
        let mut bytes = vec![0u8; 108];
        put_u16(&mut bytes, 0, IMAGE_FILE_MACHINE_ARM64);
        put_u16(&mut bytes, 2, 2);
        bytes[20..25].copy_from_slice(b".text");
        put_u32(&mut bytes, 20 + 16, 8);
        put_u32(&mut bytes, 20 + 20, 100);
        put_u32(&mut bytes, 20 + 36, 0x6050_0020);
        bytes[60..64].copy_from_slice(b".bss");
        put_u32(&mut bytes, 60 + 16, 65_664);
        put_u32(
            &mut bytes,
            60 + 36,
            IMAGE_SCN_CNT_UNINITIALIZED_DATA | 0xc000_0000,
        );
        bytes[100..108].copy_from_slice(&[0xe0, 0x03, 0x1f, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
        bytes
    }

    fn pe_image() -> Vec<u8> {
        const TIMESTAMP: u32 = 0x1234_5678;
        let mut bytes = vec![0u8; 0x800];
        bytes[..LLD_PE_OFFSET].copy_from_slice(&LLD_DOS_STUB);
        bytes[TEST_PE..TEST_PE + 4].copy_from_slice(b"PE\0\0");
        put_u16(&mut bytes, TEST_PE + 4, IMAGE_FILE_MACHINE_ARM64);
        put_u16(&mut bytes, TEST_PE + 6, 3);
        put_u32(&mut bytes, TEST_PE + 8, TIMESTAMP);
        put_u16(
            &mut bytes,
            TEST_PE + 20,
            u16::try_from(PE_OPTIONAL_HEADER_BYTES).expect("optional header bytes"),
        );
        put_u16(&mut bytes, TEST_PE + 22, IMAGE_FILE_CHARACTERISTICS_WRELA);
        put_u16(&mut bytes, TEST_OPTIONAL, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        bytes[TEST_OPTIONAL + 2] = PE_MAJOR_LINKER_VERSION;
        bytes[TEST_OPTIONAL + 3] = PE_MINOR_LINKER_VERSION;
        put_u32(&mut bytes, TEST_OPTIONAL + 4, 0x200);
        put_u32(&mut bytes, TEST_OPTIONAL + 8, 0x400);
        put_u32(&mut bytes, TEST_OPTIONAL + 16, 0x1000);
        put_u32(&mut bytes, TEST_OPTIONAL + 20, 0x1000);
        put_u64(&mut bytes, TEST_OPTIONAL + 24, EFI_IMAGE_BASE);
        put_u32(&mut bytes, TEST_OPTIONAL + 32, PE_SECTION_ALIGNMENT);
        put_u32(&mut bytes, TEST_OPTIONAL + 36, PE_FILE_ALIGNMENT);
        put_u16(&mut bytes, TEST_OPTIONAL + 40, PE_MAJOR_OS_VERSION);
        put_u16(&mut bytes, TEST_OPTIONAL + 42, PE_MINOR_OS_VERSION);
        put_u16(&mut bytes, TEST_OPTIONAL + 44, PE_MAJOR_IMAGE_VERSION);
        put_u16(&mut bytes, TEST_OPTIONAL + 46, PE_MINOR_IMAGE_VERSION);
        put_u16(&mut bytes, TEST_OPTIONAL + 48, PE_MAJOR_SUBSYSTEM_VERSION);
        put_u16(&mut bytes, TEST_OPTIONAL + 50, PE_MINOR_SUBSYSTEM_VERSION);
        put_u32(&mut bytes, TEST_OPTIONAL + 56, 0x4000);
        put_u32(&mut bytes, TEST_OPTIONAL + 60, PE_FILE_ALIGNMENT);
        put_u16(
            &mut bytes,
            TEST_OPTIONAL + 68,
            IMAGE_SUBSYSTEM_EFI_APPLICATION,
        );
        put_u16(&mut bytes, TEST_OPTIONAL + 70, PE_DLL_CHARACTERISTICS);
        put_u64(&mut bytes, TEST_OPTIONAL + 72, PE_STACK_RESERVE);
        put_u64(&mut bytes, TEST_OPTIONAL + 80, PE_STACK_COMMIT);
        put_u64(&mut bytes, TEST_OPTIONAL + 88, PE_HEAP_RESERVE);
        put_u64(&mut bytes, TEST_OPTIONAL + 96, PE_HEAP_COMMIT);
        put_u32(
            &mut bytes,
            TEST_OPTIONAL + 108,
            PE_DATA_DIRECTORY_COUNT as u32,
        );
        let reloc_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
        put_u32(&mut bytes, reloc_directory, 0x3000);
        put_u32(&mut bytes, reloc_directory + 4, 12);
        let debug_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
        put_u32(&mut bytes, debug_directory, 0x2000);
        put_u32(
            &mut bytes,
            debug_directory + 4,
            IMAGE_DEBUG_DIRECTORY_BYTES as u32,
        );

        bytes[TEST_SECTIONS..TEST_SECTIONS + 5].copy_from_slice(b".text");
        put_u32(&mut bytes, TEST_SECTIONS + 8, 8);
        put_u32(&mut bytes, TEST_SECTIONS + 12, 0x1000);
        put_u32(&mut bytes, TEST_SECTIONS + 16, 0x200);
        put_u32(&mut bytes, TEST_SECTIONS + 20, 0x200);
        put_u32(&mut bytes, TEST_SECTIONS + 36, IMAGE_SCN_WRELA_TEXT);

        let rdata = TEST_SECTIONS + 40;
        bytes[rdata..rdata + 6].copy_from_slice(b".rdata");
        put_u32(&mut bytes, rdata + 8, IMAGE_DEBUG_DIRECTORY_BYTES as u32);
        put_u32(&mut bytes, rdata + 12, 0x2000);
        put_u32(&mut bytes, rdata + 16, 0x200);
        put_u32(&mut bytes, rdata + 20, 0x400);
        put_u32(&mut bytes, rdata + 36, IMAGE_SCN_WRELA_READ_ONLY);

        let reloc = TEST_SECTIONS + 80;
        bytes[reloc..reloc + 6].copy_from_slice(b".reloc");
        put_u32(&mut bytes, reloc + 8, 12);
        put_u32(&mut bytes, reloc + 12, 0x3000);
        put_u32(&mut bytes, reloc + 16, 0x200);
        put_u32(&mut bytes, reloc + 20, 0x600);
        put_u32(&mut bytes, reloc + 36, IMAGE_SCN_WRELA_RELOC);

        bytes[0x200..0x208].copy_from_slice(&[0xe0, 0x03, 0x1f, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
        put_u32(&mut bytes, 0x404, TIMESTAMP);
        put_u32(&mut bytes, 0x40c, IMAGE_DEBUG_TYPE_REPRO);
        put_u32(&mut bytes, 0x600, 0x1000);
        put_u32(&mut bytes, 0x604, 12);
        put_u16(&mut bytes, 0x608, 0xa000);
        put_u16(&mut bytes, 0x60a, 0);
        bytes
    }

    fn pe_image_with_retained_header_page() -> Vec<u8> {
        let mut image = pe_image();
        image.splice(0x200..0x200, std::iter::repeat_n(0, 0x200));
        put_u32(&mut image, TEST_OPTIONAL + 60, 0x400);
        put_u32(&mut image, TEST_SECTIONS + 20, 0x400);
        put_u32(&mut image, TEST_SECTIONS + 40 + 20, 0x600);
        put_u32(&mut image, TEST_SECTIONS + 80 + 20, 0x800);
        image
    }

    fn pe_image_with_zero_fill_data() -> Vec<u8> {
        let mut image = pe_image();
        image.splice(0x200..0x200, std::iter::repeat_n(0, 0x200));

        let relocation_header = image[TEST_SECTIONS + 80..TEST_SECTIONS + 120].to_vec();
        image[TEST_SECTIONS + 120..TEST_SECTIONS + 160].copy_from_slice(&relocation_header);
        image[TEST_SECTIONS + 80..TEST_SECTIONS + 120].fill(0);

        put_u16(&mut image, TEST_PE + 6, 4);
        put_u32(&mut image, TEST_OPTIONAL + 56, 0x15_000);
        put_u32(&mut image, TEST_OPTIONAL + 60, 0x400);
        let relocation_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
        put_u32(&mut image, relocation_directory, 0x14_000);

        put_u32(&mut image, TEST_SECTIONS + 20, 0x400);
        put_u32(&mut image, TEST_SECTIONS + 40 + 20, 0x600);

        let data = TEST_SECTIONS + 80;
        image[data..data + 5].copy_from_slice(b".data");
        put_u32(&mut image, data + 8, 0x1_0080);
        put_u32(&mut image, data + 12, 0x3000);
        put_u32(&mut image, data + 16, 0);
        put_u32(&mut image, data + 20, 0);
        put_u32(&mut image, data + 36, IMAGE_SCN_WRELA_DATA);

        let reloc = TEST_SECTIONS + 120;
        put_u32(&mut image, reloc + 12, 0x14_000);
        put_u32(&mut image, reloc + 20, 0x800);
        image
    }

    fn pe_image_with_mixed_data_raw_bytes(raw_bytes: u32) -> Vec<u8> {
        assert!(raw_bytes > 0);
        let mut image = pe_image_with_zero_fill_data();
        image.splice(
            0x800..0x800,
            std::iter::repeat_n(
                0,
                usize::try_from(raw_bytes).expect("synthetic data raw bytes"),
            ),
        );
        image[0x800] = 0x5a;
        put_u32(&mut image, TEST_OPTIONAL + 8, 0x400 + raw_bytes);
        let data = TEST_SECTIONS + 80;
        put_u32(&mut image, data + 16, raw_bytes);
        put_u32(&mut image, data + 20, 0x800);
        let reloc = TEST_SECTIONS + 120;
        put_u32(&mut image, reloc + 20, 0x800 + raw_bytes);
        image
    }

    fn pe_image_with_mixed_data() -> Vec<u8> {
        pe_image_with_mixed_data_raw_bytes(0x200)
    }

    const fn packed_unwind(function_words: u32) -> u32 {
        (1 << 23) | (1 << 21) | (function_words << 2) | 1
    }

    fn pe_image_with_packed_unwind(records: u32) -> Vec<u8> {
        assert!((1..=2).contains(&records));
        let mut image = pe_image();
        image.splice(0x200..0x200, std::iter::repeat_n(0, 0x200));
        image.splice(0x800..0x800, std::iter::repeat_n(0, 0x200));

        let relocation_header = image[TEST_SECTIONS + 80..TEST_SECTIONS + 120].to_vec();
        image[TEST_SECTIONS + 120..TEST_SECTIONS + 160].copy_from_slice(&relocation_header);
        image[TEST_SECTIONS + 80..TEST_SECTIONS + 120].fill(0);

        put_u16(&mut image, TEST_PE + 6, 4);
        put_u32(&mut image, TEST_OPTIONAL + 8, 0x600);
        put_u32(&mut image, TEST_OPTIONAL + 56, 0x5000);
        put_u32(&mut image, TEST_OPTIONAL + 60, 0x400);
        let exception_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
        put_u32(&mut image, exception_directory, 0x3000);
        put_u32(&mut image, exception_directory + 4, records * 8);
        let relocation_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
        put_u32(&mut image, relocation_directory, 0x4000);

        put_u32(&mut image, TEST_SECTIONS + 8, records * 8);
        put_u32(&mut image, TEST_SECTIONS + 20, 0x400);
        put_u32(&mut image, TEST_SECTIONS + 40 + 20, 0x600);

        let pdata = TEST_SECTIONS + 80;
        image[pdata..pdata + 6].copy_from_slice(b".pdata");
        put_u32(&mut image, pdata + 8, records * 8);
        put_u32(&mut image, pdata + 12, 0x3000);
        put_u32(&mut image, pdata + 16, 0x200);
        put_u32(&mut image, pdata + 20, 0x800);
        put_u32(&mut image, pdata + 36, IMAGE_SCN_WRELA_READ_ONLY);

        let reloc = TEST_SECTIONS + 120;
        put_u32(&mut image, reloc + 12, 0x4000);
        put_u32(&mut image, reloc + 20, 0xa00);
        for index in 0..records {
            let raw = 0x800 + index as usize * 8;
            let function = 0x1000 + index * 8;
            put_u32(&mut image, raw, function);
            put_u32(&mut image, raw + 4, packed_unwind(2));
            let code = 0x400 + index as usize * 8;
            image[code..code + 8]
                .copy_from_slice(&[0xe0, 0x03, 0x1f, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
        }
        image
    }

    fn pe_image_with_full_unwind() -> Vec<u8> {
        let mut image = pe_image_with_packed_unwind(1);
        image.splice(0xa00..0xa00, std::iter::repeat_n(0, 0x200));

        let relocation_header = image[TEST_SECTIONS + 120..TEST_SECTIONS + 160].to_vec();
        image[TEST_SECTIONS + 160..TEST_SECTIONS + 200].copy_from_slice(&relocation_header);
        image[TEST_SECTIONS + 120..TEST_SECTIONS + 160].fill(0);

        put_u16(&mut image, TEST_PE + 6, 5);
        put_u32(&mut image, TEST_OPTIONAL + 8, 0x800);
        put_u32(&mut image, TEST_OPTIONAL + 56, 0x6000);
        let relocation_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
        put_u32(&mut image, relocation_directory, 0x5000);

        let xdata = TEST_SECTIONS + 120;
        image[xdata..xdata + 6].copy_from_slice(b".xdata");
        put_u32(&mut image, xdata + 8, 8);
        put_u32(&mut image, xdata + 12, 0x4000);
        put_u32(&mut image, xdata + 16, 0x200);
        put_u32(&mut image, xdata + 20, 0xa00);
        put_u32(&mut image, xdata + 36, IMAGE_SCN_WRELA_READ_ONLY);

        let reloc = TEST_SECTIONS + 160;
        put_u32(&mut image, reloc + 12, 0x5000);
        put_u32(&mut image, reloc + 20, 0xc00);
        put_u32(&mut image, 0x804, 0x4000);
        put_u32(&mut image, 0xa00, (1 << 27) | (1 << 21) | 2);
        image[0xa04] = 0xe4;
        image
    }

    fn pe_image_with_merged_full_unwind() -> (Vec<u8>, XdataContribution) {
        const XDATA_RVA: u64 = 0x202c;
        const XDATA_FILE_OFFSET: u64 = 0x62c;
        const XDATA_BYTES: u64 = 0x10;
        let mut image = pe_image_with_packed_unwind(1);
        put_u32(&mut image, TEST_SECTIONS + 8, 0x38);
        put_u32(&mut image, TEST_SECTIONS + 40 + 8, 0x3c);
        put_u32(&mut image, 0x804, u32::try_from(XDATA_RVA).unwrap());
        image[0x62c..0x63c].copy_from_slice(&[
            0x0e, 0x00, 0x80, 0x08, 0x07, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xd2, 0xc2,
            0x02, 0xe4,
        ]);
        (
            image,
            XdataContribution {
                output_section: 1,
                rva: XDATA_RVA,
                file_offset: XDATA_FILE_OFFSET,
                bytes: XDATA_BYTES,
            },
        )
    }

    fn parse_pe_structure(
        directory: &TestDirectory,
        name: &str,
        image: &[u8],
        inspect_limits: ImageInspectLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ParsedPe, InspectError> {
        parse_pe_structure_with_contributions(
            directory,
            name,
            image,
            None,
            inspect_limits,
            is_cancelled,
        )
    }

    fn parse_pe_structure_with_contributions(
        directory: &TestDirectory,
        name: &str,
        image: &[u8],
        explicit_contributions: Option<&[XdataContribution]>,
        inspect_limits: ImageInspectLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ParsedPe, InspectError> {
        let section_count = usize::from(le_u16(image, TEST_PE + 6).ok_or(InspectError::Truncated)?);
        let section_table_end = TEST_SECTIONS
            .checked_add(
                section_count
                    .checked_mul(PE_SECTION_BYTES as usize)
                    .ok_or(InspectError::Truncated)?,
            )
            .ok_or(InspectError::Truncated)?;
        let header = image
            .get(..section_table_end)
            .ok_or(InspectError::Truncated)?;
        let target = target();
        let pe = parse_pe_header(
            header,
            image.len() as u64,
            inspect_limits,
            target.backend(),
            is_cancelled,
        )?;
        let derived_contributions = pe
            .sections
            .iter()
            .enumerate()
            .filter(|(_, section)| section.name == ".xdata")
            .map(|(output_section, section)| XdataContribution {
                output_section,
                rva: section.virtual_address,
                file_offset: section.file_offset,
                bytes: section.virtual_bytes,
            })
            .collect::<Vec<_>>();
        let xdata_contributions = explicit_contributions.unwrap_or(&derived_contributions);
        let path = directory.write(name, image);
        let mut file = File::open(path).map_err(|error| InspectError::Io(io_kind(error)))?;
        validate_pe_contents(
            &mut file,
            section_table_end as u64,
            &pe,
            xdata_contributions,
            inspect_limits,
            is_cancelled,
        )?;
        Ok(pe)
    }

    fn assert_pe_rejected(directory: &TestDirectory, name: &str, image: &[u8]) {
        assert!(
            parse_pe_structure(directory, name, image, limits(), &|| false).is_err(),
            "malformed PE image was accepted: {name}",
        );
    }

    fn lld_map() -> Vec<u8> {
        b" image\n\n Timestamp is 00000000 (Repro mode)\n\n Preferred load address is 0000000000000000\n\n Start         Length     Name                   Class\n 0001:00000000 00000008H .text                   CODE\n 0002:00000000 0000001cH .rdata                  DATA\n 0003:00000000 0000000cH .reloc                  DATA\n\n  Address         Publics by Value              Rva+Base               Lib:Object\n\n 0001:00000000       wrela_image_entry          0000000000001000     image.obj\n 0001:00000004       wrela_image_helper         0000000000001004     image.obj\n\n entry point at         0001:00000000\n\n Static symbols\n\n"
            .to_vec()
    }

    fn provenance_coff() -> Vec<u8> {
        provenance_coff_with_relocations(8, &[0], IMAGE_REL_ARM64_ADDR64)
    }

    fn provenance_coff_with_relocations(section_bytes: usize, sites: &[u32], kind: u16) -> Vec<u8> {
        const RAW_DATA: usize = 60;
        let relocation = RAW_DATA + section_bytes;
        let symbol_table = relocation + sites.len() * COFF_RELOCATION_BYTES as usize;
        let string_table = symbol_table + COFF_SYMBOL_BYTES as usize;
        let mut bytes = vec![0u8; string_table + 4];
        put_u16(&mut bytes, 0, IMAGE_FILE_MACHINE_ARM64);
        put_u16(&mut bytes, 2, 1);
        put_u32(
            &mut bytes,
            8,
            u32::try_from(symbol_table).expect("symbol table offset"),
        );
        put_u32(&mut bytes, 12, 1);
        bytes[20..25].copy_from_slice(b".text");
        put_u32(
            &mut bytes,
            20 + 16,
            u32::try_from(section_bytes).expect("section bytes"),
        );
        put_u32(
            &mut bytes,
            20 + 20,
            u32::try_from(RAW_DATA).expect("raw data offset"),
        );
        put_u32(
            &mut bytes,
            20 + 24,
            u32::try_from(relocation).expect("relocation offset"),
        );
        put_u16(
            &mut bytes,
            20 + 32,
            u16::try_from(sites.len()).expect("relocation count"),
        );
        put_u32(&mut bytes, 20 + 36, 0x6050_0020);
        for (index, site) in sites.iter().copied().enumerate() {
            let record = relocation + index * COFF_RELOCATION_BYTES as usize;
            put_u32(&mut bytes, record, site);
            put_u32(&mut bytes, record + 4, 0);
            put_u16(&mut bytes, record + 8, kind);
        }
        bytes[symbol_table..symbol_table + 6].copy_from_slice(b"target");
        put_u32(&mut bytes, symbol_table + 8, 0);
        put_u16(&mut bytes, symbol_table + 12, 1);
        bytes[symbol_table + 16] = IMAGE_SYM_CLASS_EXTERNAL;
        put_u32(&mut bytes, string_table, 4);
        bytes
    }

    fn provenance_coff_with_repeated_unwind_sections() -> Vec<u8> {
        const SECTION_COUNT: usize = 4;
        const RAW_DATA: usize =
            COFF_HEADER_BYTES as usize + SECTION_COUNT * COFF_SECTION_BYTES as usize;
        let sections = [
            (".xdata", 8usize, 0x4030_0040u32),
            (".xdata", 4usize, 0x4030_0040u32),
            (".pdata", 8usize, 0x4030_0040u32),
            (".pdata", 8usize, 0x4030_0040u32),
        ];
        let raw_bytes = sections
            .iter()
            .try_fold(0usize, |total, (_, bytes, _)| total.checked_add(*bytes))
            .expect("bounded repeated-unwind bytes");
        let mut object = vec![0u8; RAW_DATA + raw_bytes];
        put_u16(&mut object, 0, IMAGE_FILE_MACHINE_ARM64);
        put_u16(
            &mut object,
            2,
            u16::try_from(SECTION_COUNT).expect("bounded section count"),
        );
        let mut raw_offset = RAW_DATA;
        for (index, (name, bytes, characteristics)) in sections.into_iter().enumerate() {
            let base = COFF_HEADER_BYTES as usize + index * COFF_SECTION_BYTES as usize;
            object[base..base + name.len()].copy_from_slice(name.as_bytes());
            put_u32(
                &mut object,
                base + 16,
                u32::try_from(bytes).expect("bounded section bytes"),
            );
            put_u32(
                &mut object,
                base + 20,
                u32::try_from(raw_offset).expect("bounded raw offset"),
            );
            put_u32(&mut object, base + 36, characteristics);
            object[raw_offset..raw_offset + bytes]
                .fill(u8::try_from(index + 1).expect("bounded repeated-unwind section ordinal"));
            raw_offset += bytes;
        }
        object
    }

    fn provenance_input<'a>(path: &'a Path, bytes: &[u8]) -> CoffProvenanceInput<'a> {
        provenance_input_with_ordinal(0, path, bytes)
    }

    fn provenance_input_with_ordinal<'a>(
        ordinal: u32,
        path: &'a Path,
        bytes: &[u8],
    ) -> CoffProvenanceInput<'a> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        CoffProvenanceInput {
            ordinal,
            path,
            expected_digest: sha256_digest(hasher),
            expected_bytes: bytes.len() as u64,
        }
    }

    fn lld_contribution_map(input: &Path) -> Vec<u8> {
        lld_contribution_map_with_layout(input, 8, 8)
    }

    fn lld_contribution_map_with_layout(
        input: &Path,
        output_text_bytes: u32,
        contribution_bytes: u32,
    ) -> Vec<u8> {
        format!(
            "Address  Size     Align Out     In      Symbol\n\
             00001000 {output_text_bytes:08x}  4096 .text\n\
             00001000 {contribution_bytes:08x}    16         {}:(.text)\n\
             00002000 0000001c  4096 .rdata\n\
             00003000 0000000c  4096 .reloc\n",
            input.display(),
        )
        .into_bytes()
    }

    fn repeated_unwind_contribution_map(
        input: &Path,
        pe: &ParsedPe,
        reverse_xdata: bool,
        omit_second_pdata: bool,
    ) -> Vec<u8> {
        let mut map = String::from("Address  Size     Align Out     In      Symbol\n");
        for section in &pe.sections {
            map.push_str(&format!(
                "{:08x} {:08x}  {} {}\n",
                section.virtual_address, section.virtual_bytes, pe.section_alignment, section.name,
            ));
            if section.name == ".rdata" {
                let first = format!(
                    "{:08x} 00000008     4         {}:(.xdata)\n",
                    section.virtual_address,
                    input.display(),
                );
                let second = format!(
                    "{:08x} 00000004     4         {}:(.xdata)\n",
                    section.virtual_address + 8,
                    input.display(),
                );
                if reverse_xdata {
                    map.push_str(&second);
                    map.push_str(&first);
                } else {
                    map.push_str(&first);
                    map.push_str(&second);
                }
            } else if section.name == ".pdata" {
                map.push_str(&format!(
                    "{:08x} 00000008     4         {}:(.pdata)\n",
                    section.virtual_address,
                    input.display(),
                ));
                if !omit_second_pdata {
                    map.push_str(&format!(
                        "{:08x} 00000008     4         {}:(.pdata)\n",
                        section.virtual_address + 8,
                        input.display(),
                    ));
                }
            }
        }
        map.into_bytes()
    }

    fn pe_image_with_relocations(text_bytes: u32, offsets: &[u16]) -> Vec<u8> {
        let mut image = pe_image();
        const SECTIONS: usize = LLD_PE_OFFSET + 24 + PE_OPTIONAL_HEADER_BYTES;
        put_u32(&mut image, SECTIONS + 8, text_bytes);
        let relocations = relocation_block(0x1000, offsets);
        assert_eq!(relocations.len(), 12);
        image[0x600..0x60c].copy_from_slice(&relocations);
        image
    }

    fn lld_map_with_text_bytes(text_bytes: u32) -> Vec<u8> {
        String::from_utf8(lld_map())
            .expect("ASCII map")
            .replace("00000008H .text", &format!("{text_bytes:08x}H .text"))
            .into_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_fixture(
        directory: &TestDirectory,
        name: &str,
        image: &[u8],
        map: &[u8],
        input: &[u8],
        contribution_map: impl FnOnce(&Path) -> Vec<u8>,
        inspect_limits: ImageInspectLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ImageMeasurements, InspectError> {
        let image_path = directory.write(&format!("{name}.efi"), image);
        let map_path = directory.write(&format!("{name}.map"), map);
        let input_path = directory.write(&format!("{name}.obj"), input);
        let provenance_path = directory.write(
            &format!("{name}.map.lldmap"),
            &contribution_map(&input_path),
        );
        let identity = provenance_input(&input_path, input);
        CanonicalLinkedImageInspector::new().inspect(
            &image_path,
            &map_path,
            &provenance_path,
            &[identity],
            target().backend(),
            inspect_limits,
            is_cancelled,
        )
    }

    fn inspect_repeated_unwind_contributions(
        directory: &TestDirectory,
        name: &str,
        object: &[u8],
        reverse_xdata: bool,
        omit_second_pdata: bool,
        inspect_limits: ImageInspectLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(Vec<ProvenanceObject>, ParsedPe), InspectError> {
        let pe = parse_pe_structure(
            directory,
            &format!("{name}.efi"),
            &pe_image_with_packed_unwind(2),
            inspect_limits,
            &|| false,
        )?;
        let input_path = directory.write(&format!("{name}.obj"), object);
        let identity = provenance_input(&input_path, object);
        let mut objects = inspect_provenance_inputs(&[identity], inspect_limits, is_cancelled)?;
        let map =
            repeated_unwind_contribution_map(&input_path, &pe, reverse_xdata, omit_second_pdata);
        let map_path = directory.write(&format!("{name}.map.lldmap"), &map);
        let mut map_file =
            File::open(map_path).map_err(|error| InspectError::Io(io_kind(error)))?;
        parse_lld_contribution_map(
            &mut map_file,
            u64::try_from(map.len()).map_err(|_| InspectError::LimitExceeded {
                resource: "relocation provenance map bytes",
                limit: inspect_limits.map_bytes,
                actual: u64::MAX,
            })?,
            &pe,
            &mut objects,
            inspect_limits,
            is_cancelled,
        )?;
        Ok((objects, pe))
    }

    fn relocation_block(page_rva: u32, offsets: &[u16]) -> Vec<u8> {
        let padded_entries = offsets.len() + usize::from(offsets.len() % 2 == 1);
        let block_bytes = BASE_RELOCATION_BLOCK_HEADER_BYTES as usize
            + padded_entries * BASE_RELOCATION_ENTRY_BYTES as usize;
        let mut bytes = vec![0u8; block_bytes];
        put_u32(&mut bytes, 0, page_rva);
        put_u32(
            &mut bytes,
            4,
            u32::try_from(block_bytes).expect("relocation block bytes"),
        );
        for (index, offset) in offsets.iter().copied().enumerate() {
            put_u16(
                &mut bytes,
                BASE_RELOCATION_BLOCK_HEADER_BYTES as usize
                    + index * BASE_RELOCATION_ENTRY_BYTES as usize,
                (IMAGE_REL_BASED_DIR64 << 12) | offset,
            );
        }
        bytes
    }

    fn relocation_sections() -> Vec<LinkedSection> {
        vec![LinkedSection {
            name: ".text".to_owned(),
            virtual_address: 0x1000,
            virtual_bytes: 0x2000,
            file_offset: 0x200,
            file_bytes: 0x2000,
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE,
        }]
    }

    fn inspect_relocations(
        bytes: &[u8],
        maximum_relocations: u32,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<BaseRelocationMeasurements, InspectError> {
        let mut limits = limits();
        limits.base_relocations = maximum_relocations;
        parse_base_relocations(
            &mut &*bytes,
            bytes.len() as u64,
            &relocation_sections(),
            None,
            limits,
            is_cancelled,
        )
    }

    #[test]
    fn ordinary_coff_is_streamed_hashed_and_machine_checked() {
        let directory = TestDirectory::new();
        let bytes = ordinary_coff();
        let path = directory.write("image.obj", &bytes);
        let measured = CanonicalCoffObjectInspector::new()
            .inspect(&path, bytes.len() as u64, &|| false)
            .expect("ordinary ARM64 COFF");
        assert_eq!(measured.bytes, bytes.len() as u64);
        assert_eq!(measured.coff_machine, "arm64");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hasher.finalize());
        assert_eq!(measured.digest, Sha256Digest::from_bytes(digest));

        let mut foreign = bytes.clone();
        put_u16(&mut foreign, 0, 0x8664);
        let foreign_path = directory.write("foreign.obj", &foreign);
        assert_eq!(
            CanonicalCoffObjectInspector::new().inspect(
                &foreign_path,
                foreign.len() as u64,
                &|| false
            ),
            Err(CoffInspectError::UnsupportedMachine(0x8664))
        );

        let mut overlapping = bytes;
        put_u32(&mut overlapping, 20 + 20, 20);
        let overlapping_path = directory.write("overlapping.obj", &overlapping);
        assert_eq!(
            CanonicalCoffObjectInspector::new().inspect(
                &overlapping_path,
                overlapping.len() as u64,
                &|| false,
            ),
            Err(CoffInspectError::InvalidCoffHeader)
        );
    }

    #[test]
    fn generated_entry_definition_is_exactly_function_typed_and_executable() {
        let directory = TestDirectory::new();
        let bytes = coff_with_entry_definition();
        let path = directory.write("entry.obj", &bytes);
        let evidence = inspect_coff_entry_contract(
            &path,
            "wrela_image_entry",
            bytes.len() as u64,
            1,
            1,
            &|| false,
        )
        .expect("exact generated entry definition");
        assert!(evidence.defines_entry);

        let mut wrong_type = bytes.clone();
        put_u16(&mut wrong_type, 68 + 14, 0);
        let wrong_type_path = directory.write("entry-type-drift.obj", &wrong_type);
        assert_eq!(
            inspect_coff_entry_contract(
                &wrong_type_path,
                "wrela_image_entry",
                wrong_type.len() as u64,
                1,
                1,
                &|| false,
            ),
            Err(CoffInspectError::InvalidEntryAbi)
        );

        let mut overlapping_symbols = bytes.clone();
        put_u32(&mut overlapping_symbols, 8, 60);
        let overlapping_symbols_path =
            directory.write("entry-symbol-overlap.obj", &overlapping_symbols);
        assert_eq!(
            inspect_coff_entry_contract(
                &overlapping_symbols_path,
                "wrela_image_entry",
                overlapping_symbols.len() as u64,
                1,
                1,
                &|| false,
            ),
            Err(CoffInspectError::InvalidCoffHeader)
        );

        let mut non_executable = bytes.clone();
        put_u32(&mut non_executable, 20 + 36, IMAGE_SCN_CNT_CODE);
        let non_executable_path = directory.write("entry-data.obj", &non_executable);
        assert_eq!(
            inspect_coff_entry_contract(
                &non_executable_path,
                "wrela_image_entry",
                non_executable.len() as u64,
                1,
                1,
                &|| false,
            ),
            Err(CoffInspectError::InvalidEntryAbi)
        );

        assert!(matches!(
            inspect_coff_entry_contract(
                &path,
                "wrela_image_entry",
                bytes.len() as u64,
                0,
                1,
                &|| false,
            ),
            Err(CoffInspectError::LimitExceeded {
                resource: "COFF sections",
                limit: 0,
                actual: 1,
            })
        ));
        assert_eq!(
            inspect_coff_entry_contract(
                &path,
                "wrela_image_entry",
                bytes.len() as u64,
                1,
                1,
                &|| true,
            ),
            Err(CoffInspectError::Cancelled)
        );
    }

    #[test]
    fn embedded_linker_directives_are_rejected_before_the_native_boundary() {
        let directory = TestDirectory::new();
        let mut inline = ordinary_coff();
        inline[20..20 + COFF_SECTION_NAME_BYTES].copy_from_slice(LINKER_DIRECTIVE_SECTION);
        let inline_path = directory.write("inline-directive.obj", &inline);
        assert_eq!(
            CanonicalCoffObjectInspector::new()
                .inspect(&inline_path, inline.len() as u64, &|| false,),
            Err(CoffInspectError::LinkerDirectiveSection)
        );
        assert_eq!(
            inspect_coff_entry_contract(
                &inline_path,
                "wrela_image_entry",
                inline.len() as u64,
                1,
                1,
                &|| false,
            ),
            Err(CoffInspectError::LinkerDirectiveSection)
        );

        let long = coff_with_long_directive_section_name();
        let long_path = directory.write("long-directive.obj", &long);
        assert_eq!(
            CanonicalCoffObjectInspector::new().inspect(&long_path, long.len() as u64, &|| false,),
            Err(CoffInspectError::LinkerDirectiveSection)
        );
        assert_eq!(
            inspect_coff_entry_contract(
                &long_path,
                "wrela_image_entry",
                long.len() as u64,
                1,
                1,
                &|| false,
            ),
            Err(CoffInspectError::LinkerDirectiveSection)
        );
    }

    #[test]
    fn uninitialized_coff_sections_have_bounded_virtual_extent_without_raw_bytes() {
        let directory = TestDirectory::new();
        let bytes = coff_with_bss();
        let path = directory.write("bss.obj", &bytes);
        CanonicalCoffObjectInspector::new()
            .inspect(&path, 128 * 1024, &|| false)
            .expect("canonical uninitialized COFF section");

        let mut initialized = bytes.clone();
        put_u32(
            &mut initialized,
            60 + 36,
            IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_CNT_INITIALIZED_DATA | 0xc000_0000,
        );
        let initialized_path = directory.write("mixed-bss.obj", &initialized);
        assert_eq!(
            CanonicalCoffObjectInspector::new().inspect(&initialized_path, 128 * 1024, &|| false),
            Err(CoffInspectError::InvalidCoffHeader)
        );

        let mut raw = bytes;
        put_u32(&mut raw, 60 + 20, 100);
        let raw_path = directory.write("raw-bss.obj", &raw);
        assert_eq!(
            CanonicalCoffObjectInspector::new().inspect(&raw_path, 128 * 1024, &|| false),
            Err(CoffInspectError::InvalidCoffHeader)
        );

        assert_eq!(
            CanonicalCoffObjectInspector::new().inspect(&path, 64 * 1024, &|| false),
            Err(CoffInspectError::LimitExceeded {
                resource: "COFF uninitialized bytes",
                limit: 65_536,
                actual: 65_664,
            })
        );
    }

    #[test]
    fn checked_in_runtime_object_passes_the_production_coff_inspector() {
        let runtime = fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../toolchain/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj",
        ))
        .expect("canonical runtime path");
        let bytes = fs::read(&runtime).expect("runtime bytes");
        let symbol_table = u64::from(le_u32(&bytes, 8).expect("symbol table offset"));
        let symbol_count = u64::from(le_u32(&bytes, 12).expect("symbol count"));
        assert_eq!(symbol_count, 62, "runtime symbol-table contract changed");
        validate_symbol_table(symbol_table, symbol_count, 180, bytes.len() as u64)
            .expect("runtime symbol table");
        validate_coff_sections(&bytes[..180], 4, bytes.len() as u64, 1024 * 1024, &|| false)
            .expect("runtime section table");
        let measurement = CanonicalCoffObjectInspector::new()
            .inspect(&runtime, 1024 * 1024, &|| false)
            .expect("checked-in runtime is canonical ARM64 COFF");
        assert_eq!(measurement.coff_machine, "arm64");
        assert_ne!(measurement.bytes, 0);
        assert!(measurement.digest.as_bytes().iter().any(|byte| *byte != 0));
        let entry = inspect_coff_entry_contract(
            &runtime,
            "wrela_image_entry",
            1024 * 1024,
            4,
            u32::try_from(symbol_count).expect("bounded runtime symbol count"),
            &|| false,
        )
        .expect("runtime symbol table has exact bounded entry evidence");
        assert!(!entry.defines_entry);
        assert_eq!(
            inspect_coff_entry_contract(
                &runtime,
                "wrela_image_entry",
                1024 * 1024,
                4,
                u32::try_from(symbol_count - 1).expect("one-under runtime symbol count"),
                &|| false,
            ),
            Err(CoffInspectError::LimitExceeded {
                resource: "COFF symbols",
                limit: symbol_count - 1,
                actual: symbol_count,
            })
        );

        let inputs = [CoffProvenanceInput {
            ordinal: 0,
            path: &runtime,
            expected_digest: measurement.digest,
            expected_bytes: measurement.bytes,
        }];
        let mut provenance_limits = limits();
        provenance_limits.symbols = 64;
        provenance_limits.base_relocations = 192;
        provenance_limits.image_bytes = 73_984;
        let provenance = inspect_provenance_inputs(&inputs, provenance_limits, &|| false)
            .expect("runtime BSS virtual extent fits the sealed image resource limit");
        assert_eq!(provenance.len(), 1);
        assert_eq!(provenance[0].sections.len(), 4);
        provenance_limits.image_bytes = 73_983;
        assert!(matches!(
            inspect_provenance_inputs(&inputs, provenance_limits, &|| false),
            Err(InspectError::LimitExceeded {
                resource: "COFF uninitialized bytes",
                limit: 73_983,
                actual: 73_984,
            })
        ));
    }

    #[test]
    fn object_limits_cancellation_and_file_identity_fail_closed() {
        let directory = TestDirectory::new();
        let bytes = ordinary_coff();
        let path = directory.write("image.obj", &bytes);
        assert!(matches!(
            CanonicalCoffObjectInspector::new().inspect(&path, bytes.len() as u64 - 1, &|| false),
            Err(CoffInspectError::TooLarge { .. })
        ));
        assert_eq!(
            CanonicalCoffObjectInspector::new().inspect(&path, bytes.len() as u64, &|| true),
            Err(CoffInspectError::Cancelled)
        );

        #[cfg(unix)]
        {
            let alias = directory.root.join("alias.obj");
            fs::hard_link(&path, &alias).expect("fixture hard link");
            assert_eq!(
                CanonicalCoffObjectInspector::new().inspect(&path, bytes.len() as u64, &|| false),
                Err(CoffInspectError::InvalidCoffHeader)
            );
        }
    }

    #[test]
    fn pe_and_lld_map_produce_cross_checked_canonical_measurements() {
        let directory = TestDirectory::new();
        let image_path = directory.write("image.efi", &pe_image());
        let map_path = directory.write("image.map", &lld_map());
        let input_bytes = provenance_coff();
        let input_path = directory.write("image.obj", &input_bytes);
        let input = provenance_input(&input_path, &input_bytes);
        let provenance_path =
            directory.write("image.map.lldmap", &lld_contribution_map(&input_path));
        let target = target();
        let measured = CanonicalLinkedImageInspector::new()
            .inspect(
                &image_path,
                &map_path,
                &provenance_path,
                &[input],
                target.backend(),
                limits(),
                &|| false,
            )
            .expect("canonical PE32+ and map");
        assert_eq!(measured.artifact_bytes, 0x800);
        assert_eq!(measured.coff_machine, "arm64");
        assert_eq!(measured.subsystem, "efi_application");
        assert_eq!(measured.image_base, EFI_IMAGE_BASE);
        assert_eq!(measured.entry_symbol, "wrela_image_entry");
        assert_eq!(measured.entry_virtual_address, 0x1000);
        assert_eq!(measured.relocation_directory_bytes, 12);
        assert_eq!(measured.base_relocation_blocks, 1);
        assert_eq!(measured.base_relocations, 1);
        assert!(
            measured
                .base_relocation_provenance_digest
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_eq!(
            measured
                .sections
                .iter()
                .map(|section| section.name.as_str())
                .collect::<Vec<_>>(),
            [".text", ".rdata", ".reloc"]
        );
        assert_eq!(
            measured
                .symbols
                .iter()
                .map(|symbol| (symbol.name.as_str(), symbol.virtual_address, symbol.bytes))
                .collect::<Vec<_>>(),
            [
                ("wrela_image_entry", 0x1000, 4),
                ("wrela_image_helper", 0x1004, 4),
            ]
        );
    }

    #[test]
    fn repeated_unwind_section_names_bind_original_ordinals_and_map_order() {
        let directory = TestDirectory::new();
        let object = provenance_coff_with_repeated_unwind_sections();
        let mut exact_sections = limits();
        exact_sections.sections = 4;
        let (objects, pe) = inspect_repeated_unwind_contributions(
            &directory,
            "repeated-unwind",
            &object,
            false,
            false,
            exact_sections,
            &|| false,
        )
        .expect("same-named unwind sections in original COFF order");
        let [reviewed] = objects.as_slice() else {
            panic!("fixture must retain one reviewed COFF object");
        };
        let [first_xdata, second_xdata, first_pdata, second_pdata] = reviewed.sections.as_slice()
        else {
            panic!("fixture must retain four reviewed unwind sections");
        };
        assert_eq!(
            (
                first_xdata.name.as_str(),
                first_xdata.ordinal,
                first_xdata.bytes,
                first_xdata.alignment,
                first_xdata.characteristics,
            ),
            (".xdata", 0, 8, 4, 0x4030_0040),
        );
        assert_eq!(
            (
                second_xdata.name.as_str(),
                second_xdata.ordinal,
                second_xdata.bytes,
                second_xdata.alignment,
                second_xdata.characteristics,
            ),
            (".xdata", 1, 4, 4, 0x4030_0040),
        );
        assert_eq!(
            (
                first_pdata.name.as_str(),
                first_pdata.ordinal,
                first_pdata.bytes,
                first_pdata.alignment,
                first_pdata.characteristics,
            ),
            (".pdata", 2, 8, 4, 0x4030_0040),
        );
        assert_eq!(
            (
                second_pdata.name.as_str(),
                second_pdata.ordinal,
                second_pdata.bytes,
                second_pdata.alignment,
                second_pdata.characteristics,
            ),
            (".pdata", 3, 8, 4, 0x4030_0040),
        );
        let rdata = pe
            .sections
            .iter()
            .position(|section| section.name == ".rdata")
            .expect("packed-unwind PE rdata output");
        let pdata = pe
            .sections
            .iter()
            .position(|section| section.name == ".pdata")
            .expect("packed-unwind PE pdata output");
        let rdata_section = pe
            .sections
            .get(rdata)
            .expect("located rdata output remains addressable");
        let pdata_section = pe
            .sections
            .get(pdata)
            .expect("located pdata output remains addressable");
        assert_eq!(
            (
                first_xdata.contribution_output,
                first_xdata.contribution_rva,
                second_xdata.contribution_output,
                second_xdata.contribution_rva,
            ),
            (
                Some(u32::try_from(rdata).expect("bounded output ordinal")),
                Some(rdata_section.virtual_address),
                Some(u32::try_from(rdata).expect("bounded output ordinal")),
                Some(rdata_section.virtual_address + 8),
            ),
        );
        assert_eq!(
            (
                first_pdata.contribution_output,
                first_pdata.contribution_rva,
                second_pdata.contribution_output,
                second_pdata.contribution_rva,
            ),
            (
                Some(u32::try_from(pdata).expect("bounded output ordinal")),
                Some(pdata_section.virtual_address),
                Some(u32::try_from(pdata).expect("bounded output ordinal")),
                Some(pdata_section.virtual_address + 8),
            ),
        );
        let xdata = reviewed_xdata_contributions(&objects, &pe, exact_sections, &|| false)
            .expect("both same-named xdata sections remain reviewed");
        assert_eq!(
            xdata
                .iter()
                .map(|contribution| (contribution.rva, contribution.bytes))
                .collect::<Vec<_>>(),
            [
                (rdata_section.virtual_address, 8),
                (rdata_section.virtual_address + 8, 4),
            ],
        );

        assert!(matches!(
            inspect_repeated_unwind_contributions(
                &directory,
                "reordered-unwind",
                &object,
                true,
                false,
                exact_sections,
                &|| false,
            ),
            Err(InspectError::InvalidRelocationProvenance(_))
        ));
        assert!(matches!(
            inspect_repeated_unwind_contributions(
                &directory,
                "missing-repeated-pdata",
                &object,
                false,
                true,
                exact_sections,
                &|| false,
            ),
            Err(InspectError::InvalidRelocationProvenance(
                "nonempty repeated unwind section is missing from LLD contributions"
            ))
        ));

        let mut duplicate_text = object.clone();
        for ordinal in 0..2usize {
            let base = COFF_HEADER_BYTES as usize + ordinal * COFF_SECTION_BYTES as usize;
            duplicate_text[base..base + COFF_SECTION_NAME_BYTES].fill(0);
            duplicate_text[base..base + 5].copy_from_slice(b".text");
        }
        let duplicate_text_path = directory.write("duplicate-text.obj", &duplicate_text);
        let duplicate_text_identity = provenance_input(&duplicate_text_path, &duplicate_text);
        assert!(matches!(
            inspect_provenance_inputs(&[duplicate_text_identity], exact_sections, &|| false),
            Err(InspectError::InvalidRelocationProvenance(
                "duplicate input section names make LLD contributions ambiguous"
            ))
        ));

        let input_path = directory.write("cancelled-repeated-unwind.obj", &object);
        let identity = provenance_input(&input_path, &object);
        let cancellation_objects =
            inspect_provenance_inputs(&[identity], exact_sections, &|| false)
                .expect("reviewed input");
        let keys = contribution_keys(&cancellation_objects, exact_sections, &|| false)
            .expect("bounded repeated contribution keys");
        let mut state = ContributionMapState {
            saw_header: true,
            output_index: 0,
            current_output: None,
            previous_contribution_end: None,
            keys,
        };
        let key = format!("{}:(.xdata)", input_path.display());
        assert!(matches!(
            resolve_contribution_key(&mut state, &cancellation_objects, &key, 8, 16, &|| true,),
            Err(InspectError::Cancelled)
        ));

        let same_path_inputs = [
            provenance_input_with_ordinal(0, &input_path, &object),
            provenance_input_with_ordinal(1, &input_path, &object),
        ];
        let same_path_objects = inspect_provenance_inputs(&same_path_inputs, limits(), &|| false)
            .expect("individually reviewed same-path inputs");
        assert!(matches!(
            contribution_keys(&same_path_objects, limits(), &|| false),
            Err(InspectError::InvalidRelocationProvenance(
                "duplicate input contribution identity spans reviewed objects"
            ))
        ));

        let mut three_sections = limits();
        three_sections.sections = 3;
        let over_limit_path = directory.write("over-section-limit.obj", &object);
        let over_limit_identity = provenance_input(&over_limit_path, &object);
        assert!(matches!(
            inspect_provenance_inputs(&[over_limit_identity], three_sections, &|| false),
            Err(InspectError::LimitExceeded {
                resource: "input COFF sections",
                limit: 3,
                actual: 4,
            })
        ));
    }

    #[test]
    fn pinned_lld_header_extents_and_arm64_unwind_forms_are_accepted() {
        let directory = TestDirectory::new();
        parse_pe_structure(
            &directory,
            "minimal-header.efi",
            &pe_image(),
            limits(),
            &|| false,
        )
        .expect("minimal LLD header extent");
        let mut exact_virtual_limit = limits();
        exact_virtual_limit.image_bytes = 0x4000;
        parse_pe_structure(
            &directory,
            "exact-virtual-limit.efi",
            &pe_image(),
            exact_virtual_limit,
            &|| false,
        )
        .expect("SizeOfImage exactly at the declared virtual-image limit");
        let mut lower_virtual_limit = limits();
        lower_virtual_limit.image_bytes = 0x3fff;
        assert!(matches!(
            parse_pe_structure(
                &directory,
                "over-virtual-limit.efi",
                &pe_image(),
                lower_virtual_limit,
                &|| false,
            ),
            Err(InspectError::LimitExceeded {
                resource: "image virtual bytes",
                limit: 0x3fff,
                actual: 0x4000,
            })
        ));
        parse_pe_structure(
            &directory,
            "retained-empty-section-header.efi",
            &pe_image_with_retained_header_page(),
            limits(),
            &|| false,
        )
        .expect("LLD retained empty-section header page");
        let zero_fill = parse_pe_structure(
            &directory,
            "zero-fill-data.efi",
            &pe_image_with_zero_fill_data(),
            limits(),
            &|| false,
        )
        .expect("LLD zero-fill data extent");
        let data = zero_fill
            .sections
            .iter()
            .find(|section| section.name == ".data")
            .expect("zero-fill data section");
        assert_eq!(data.virtual_address, 0x3000);
        assert_eq!(data.virtual_bytes, 0x1_0080);
        assert_eq!((data.file_offset, data.file_bytes), (0, 0));
        let mixed = parse_pe_structure(
            &directory,
            "mixed-data.efi",
            &pe_image_with_mixed_data(),
            limits(),
            &|| false,
        )
        .expect("LLD initialized data prefix with zero-fill tail");
        let data = mixed
            .sections
            .iter()
            .find(|section| section.name == ".data")
            .expect("mixed data section");
        assert_eq!(data.virtual_bytes, 0x1_0080);
        assert_eq!((data.file_offset, data.file_bytes), (0x800, 0x200));
        parse_pe_structure(
            &directory,
            "packed-unwind.efi",
            &pe_image_with_packed_unwind(1),
            limits(),
            &|| false,
        )
        .expect("packed ARM64 unwind record");
        parse_pe_structure(
            &directory,
            "full-unwind.efi",
            &pe_image_with_full_unwind(),
            limits(),
            &|| false,
        )
        .expect("full ARM64 xdata unwind record");
    }

    #[test]
    fn pe_header_directories_permissions_and_padding_fail_closed() {
        let directory = TestDirectory::new();
        let critical_offsets = [
            0x40,
            TEST_PE,
            TEST_PE + 4,
            TEST_PE + 8,
            TEST_PE + 12,
            TEST_PE + 16,
            TEST_PE + 20,
            TEST_PE + 22,
            TEST_OPTIONAL,
            TEST_OPTIONAL + 2,
            TEST_OPTIONAL + 3,
            TEST_OPTIONAL + 4,
            TEST_OPTIONAL + 8,
            TEST_OPTIONAL + 12,
            TEST_OPTIONAL + 16,
            TEST_OPTIONAL + 20,
            TEST_OPTIONAL + 24,
            TEST_OPTIONAL + 32,
            TEST_OPTIONAL + 36,
            TEST_OPTIONAL + 40,
            TEST_OPTIONAL + 42,
            TEST_OPTIONAL + 44,
            TEST_OPTIONAL + 46,
            TEST_OPTIONAL + 48,
            TEST_OPTIONAL + 50,
            TEST_OPTIONAL + 52,
            TEST_OPTIONAL + 56,
            TEST_OPTIONAL + 60,
            TEST_OPTIONAL + 64,
            TEST_OPTIONAL + 68,
            TEST_OPTIONAL + 70,
            TEST_OPTIONAL + 72,
            TEST_OPTIONAL + 80,
            TEST_OPTIONAL + 88,
            TEST_OPTIONAL + 96,
            TEST_OPTIONAL + 104,
            TEST_OPTIONAL + 108,
        ];
        for (index, offset) in critical_offsets.into_iter().enumerate() {
            let mut image = pe_image();
            image[offset] ^= 1;
            assert_pe_rejected(&directory, &format!("critical-header-{index}.efi"), &image);
        }

        for index in 0..PE_DATA_DIRECTORY_COUNT {
            if matches!(
                index,
                IMAGE_DIRECTORY_ENTRY_EXCEPTION
                    | IMAGE_DIRECTORY_ENTRY_BASERELOC
                    | IMAGE_DIRECTORY_ENTRY_DEBUG
            ) {
                continue;
            }
            let mut image = pe_image();
            let offset = TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + index * 8;
            put_u32(&mut image, offset, 0x2000);
            put_u32(&mut image, offset + 4, 4);
            assert_pe_rejected(
                &directory,
                &format!("forbidden-directory-{index}.efi"),
                &image,
            );
        }

        let relocation_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
        let debug_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
        let exception_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
        for (name, mutate) in [
            ("missing-relocations", (relocation_directory, 0, 0)),
            ("missing-debug", (debug_directory, 0, 0)),
            ("one-sided-debug", (debug_directory, 0x2000, 0)),
            ("escaping-debug", (debug_directory, 0x2000, 29)),
            ("misbound-exception", (exception_directory, 0x3000, 12)),
        ] {
            let mut image = pe_image();
            put_u32(&mut image, mutate.0, mutate.1);
            put_u32(&mut image, mutate.0 + 4, mutate.2);
            assert_pe_rejected(&directory, &format!("{name}.efi"), &image);
        }

        for (section, section_name) in [(0, "text"), (40, "rdata"), (80, "reloc")] {
            for (index, bit) in [
                IMAGE_SCN_CNT_CODE,
                IMAGE_SCN_CNT_INITIALIZED_DATA,
                IMAGE_SCN_CNT_UNINITIALIZED_DATA,
                IMAGE_SCN_MEM_DISCARDABLE,
                IMAGE_SCN_MEM_EXECUTE,
                IMAGE_SCN_MEM_READ,
                IMAGE_SCN_MEM_WRITE,
            ]
            .into_iter()
            .enumerate()
            {
                let mut image = pe_image();
                let characteristics = TEST_SECTIONS + section + 36;
                let observed = le_u32(&image, characteristics).expect("section characteristics");
                put_u32(&mut image, characteristics, observed ^ bit);
                assert_pe_rejected(
                    &directory,
                    &format!("{section_name}-permission-{index}.efi"),
                    &image,
                );
            }
        }

        for (index, offset) in [0, 4, 8, 10, 12, 16, 20, 24].into_iter().enumerate() {
            let mut image = pe_image();
            image[0x400 + offset] ^= 1;
            assert_pe_rejected(&directory, &format!("repro-field-{index}.efi"), &image);
        }

        let mut undeclared_section = pe_image();
        undeclared_section[TEST_SECTIONS + 40..TEST_SECTIONS + 48].copy_from_slice(b".idata\0\0");
        assert_pe_rejected(&directory, "undeclared-section.efi", &undeclared_section);

        let mut writable_code = pe_image();
        put_u32(
            &mut writable_code,
            TEST_SECTIONS + 36,
            IMAGE_SCN_WRELA_TEXT | IMAGE_SCN_MEM_WRITE,
        );
        assert_pe_rejected(&directory, "write-execute.efi", &writable_code);

        let mut header_padding = pe_image();
        header_padding[TEST_SECTIONS + 120] = 1;
        assert_pe_rejected(&directory, "header-padding.efi", &header_padding);

        let mut section_padding = pe_image();
        section_padding[0x208] = 1;
        assert_pe_rejected(&directory, "section-padding.efi", &section_padding);

        let mut virtual_size = pe_image();
        put_u32(&mut virtual_size, TEST_SECTIONS + 8, 9);
        assert_pe_rejected(&directory, "unaligned-code-size.efi", &virtual_size);

        let mut overlapping_raw = pe_image();
        put_u32(&mut overlapping_raw, TEST_SECTIONS + 40 + 20, 0x200);
        assert_pe_rejected(&directory, "overlapping-raw.efi", &overlapping_raw);

        let mut zero_fill_raw_pointer = pe_image_with_zero_fill_data();
        put_u32(&mut zero_fill_raw_pointer, TEST_SECTIONS + 80 + 20, 0x800);
        assert_pe_rejected(
            &directory,
            "zero-fill-data-raw-pointer.efi",
            &zero_fill_raw_pointer,
        );

        let mut mixed_data_null_pointer = pe_image_with_mixed_data();
        put_u32(&mut mixed_data_null_pointer, TEST_SECTIONS + 80 + 20, 0);
        assert_pe_rejected(
            &directory,
            "mixed-data-null-pointer.efi",
            &mixed_data_null_pointer,
        );

        let mut mixed_data_wrong_pointer = pe_image_with_mixed_data();
        put_u32(
            &mut mixed_data_wrong_pointer,
            TEST_SECTIONS + 80 + 20,
            0x600,
        );
        assert_pe_rejected(
            &directory,
            "mixed-data-wrong-pointer.efi",
            &mixed_data_wrong_pointer,
        );

        let mut mixed_data_unaligned_raw = pe_image_with_mixed_data();
        put_u32(
            &mut mixed_data_unaligned_raw,
            TEST_SECTIONS + 80 + 16,
            0x100,
        );
        assert_pe_rejected(
            &directory,
            "mixed-data-unaligned-raw.efi",
            &mixed_data_unaligned_raw,
        );

        let oversized_mixed_data = pe_image_with_mixed_data_raw_bytes(0x1_0400);
        assert_pe_rejected(
            &directory,
            "mixed-data-raw-exceeds-aligned-virtual.efi",
            &oversized_mixed_data,
        );

        let mut mixed_data_out_of_range = pe_image_with_mixed_data();
        put_u32(
            &mut mixed_data_out_of_range,
            TEST_SECTIONS + 80 + 16,
            0x1000,
        );
        assert_pe_rejected(
            &directory,
            "mixed-data-raw-out-of-range.efi",
            &mixed_data_out_of_range,
        );

        let mut rawless_read_only = pe_image_with_zero_fill_data();
        put_u32(&mut rawless_read_only, TEST_SECTIONS + 40 + 16, 0);
        put_u32(&mut rawless_read_only, TEST_SECTIONS + 40 + 20, 0);
        assert_pe_rejected(&directory, "rawless-read-only.efi", &rawless_read_only);

        let mut zero_fill_wrong_characteristics = pe_image_with_zero_fill_data();
        put_u32(
            &mut zero_fill_wrong_characteristics,
            TEST_SECTIONS + 80 + 36,
            IMAGE_SCN_WRELA_BSS,
        );
        assert_pe_rejected(
            &directory,
            "zero-fill-data-wrong-characteristics.efi",
            &zero_fill_wrong_characteristics,
        );

        let mut unexpected_uninitialized_size = pe_image_with_zero_fill_data();
        put_u32(
            &mut unexpected_uninitialized_size,
            TEST_OPTIONAL + 12,
            0x1_0200,
        );
        assert_pe_rejected(
            &directory,
            "zero-fill-data-uninitialized-size.efi",
            &unexpected_uninitialized_size,
        );

        let mut virtual_gap = pe_image();
        put_u32(&mut virtual_gap, TEST_SECTIONS + 40 + 12, 0x3000);
        assert_pe_rejected(&directory, "virtual-gap.efi", &virtual_gap);

        let mut overlay = pe_image();
        overlay.extend_from_slice(&[0; 0x200]);
        assert_pe_rejected(&directory, "file-overlay.efi", &overlay);

        let mut truncated = pe_image();
        truncated.pop();
        assert_pe_rejected(&directory, "truncated.efi", &truncated);

        let mut excessive_header_slack = pe_image_with_retained_header_page();
        put_u32(&mut excessive_header_slack, TEST_OPTIONAL + 60, 0x600);
        assert_pe_rejected(
            &directory,
            "excessive-header-slack.efi",
            &excessive_header_slack,
        );
    }

    #[test]
    fn merged_xdata_is_bound_to_reviewed_contributions_and_shared_records() {
        let directory = TestDirectory::new();
        let (image, contribution) = pe_image_with_merged_full_unwind();
        parse_pe_structure_with_contributions(
            &directory,
            "merged-xdata.efi",
            &image,
            Some(&[contribution]),
            limits(),
            &|| false,
        )
        .expect("reviewed xdata contribution merged into rdata");

        for (name, unwind_rva) in [("prefix", 0x2028), ("end", 0x203c)] {
            let mut malformed = image.clone();
            put_u32(&mut malformed, 0x804, unwind_rva);
            assert!(
                parse_pe_structure_with_contributions(
                    &directory,
                    &format!("merged-xdata-{name}.efi"),
                    &malformed,
                    Some(&[contribution]),
                    limits(),
                    &|| false,
                )
                .is_err()
            );
        }

        let undersized = XdataContribution {
            bytes: 0x0c,
            ..contribution
        };
        assert!(
            parse_pe_structure_with_contributions(
                &directory,
                "merged-xdata-undersized.efi",
                &image,
                Some(&[undersized]),
                limits(),
                &|| false,
            )
            .is_err()
        );

        let leading_gap = XdataContribution {
            rva: 0x2028,
            file_offset: 0x628,
            bytes: 0x14,
            ..contribution
        };
        parse_pe_structure_with_contributions(
            &directory,
            "merged-xdata-zero-leading-gap.efi",
            &image,
            Some(&[leading_gap]),
            limits(),
            &|| false,
        )
        .expect("zero padding before reviewed xdata record");
        let mut nonzero_gap = image.clone();
        nonzero_gap[0x628] = 1;
        assert!(
            parse_pe_structure_with_contributions(
                &directory,
                "merged-xdata-nonzero-leading-gap.efi",
                &nonzero_gap,
                Some(&[leading_gap]),
                limits(),
                &|| false,
            )
            .is_err()
        );

        let mut zero_tail = image.clone();
        put_u32(&mut zero_tail, TEST_SECTIONS + 40 + 8, 0x40);
        let trailing_gap = XdataContribution {
            bytes: 0x14,
            ..contribution
        };
        parse_pe_structure_with_contributions(
            &directory,
            "merged-xdata-zero-tail.efi",
            &zero_tail,
            Some(&[trailing_gap]),
            limits(),
            &|| false,
        )
        .expect("zero padding after reviewed xdata record");
        zero_tail[0x63c] = 1;
        assert!(
            parse_pe_structure_with_contributions(
                &directory,
                "merged-xdata-nonzero-tail.efi",
                &zero_tail,
                Some(&[trailing_gap]),
                limits(),
                &|| false,
            )
            .is_err()
        );

        let mut packed_with_xdata = image.clone();
        put_u32(&mut packed_with_xdata, 0x804, packed_unwind(14));
        assert!(
            parse_pe_structure_with_contributions(
                &directory,
                "packed-with-reviewed-xdata.efi",
                &packed_with_xdata,
                Some(&[contribution]),
                limits(),
                &|| false,
            )
            .is_err()
        );

        let mut shared = image;
        put_u32(&mut shared, TEST_SECTIONS + 8, 0x10);
        put_u32(&mut shared, TEST_SECTIONS + 40 + 8, 0x34);
        let exception_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
        put_u32(&mut shared, exception_directory + 4, 16);
        put_u32(&mut shared, TEST_SECTIONS + 80 + 8, 16);
        put_u32(&mut shared, 0x808, 0x1008);
        put_u32(&mut shared, 0x80c, 0x202c);
        shared[0x62c..0x63c].fill(0);
        put_u32(&mut shared, 0x62c, (1 << 27) | (1 << 21) | 2);
        shared[0x630] = 0xe4;
        let shared_contribution = XdataContribution {
            bytes: 8,
            ..contribution
        };
        parse_pe_structure_with_contributions(
            &directory,
            "shared-xdata-record.efi",
            &shared,
            Some(&[shared_contribution]),
            limits(),
            &|| false,
        )
        .expect("two ordered functions may share one reviewed xdata record");
    }

    #[test]
    fn arm64_exception_records_are_exact_limited_and_cancellable() {
        let directory = TestDirectory::new();
        let two_records = pe_image_with_packed_unwind(2);
        let mut exact_limit = limits();
        exact_limit.exception_records = 2;
        parse_pe_structure(
            &directory,
            "two-packed-records.efi",
            &two_records,
            exact_limit,
            &|| false,
        )
        .expect("exact exception-record limit");

        let mut one_record_limit = limits();
        one_record_limit.exception_records = 1;
        assert_eq!(
            parse_pe_structure(
                &directory,
                "exception-max-plus-one.efi",
                &two_records,
                one_record_limit,
                &|| false,
            )
            .expect_err("exception max+1 must fail"),
            InspectError::LimitExceeded {
                resource: "ARM64 exception records",
                limit: 1,
                actual: 2,
            }
        );

        let pe = parse_pe_structure(
            &directory,
            "exception-cancel-source.efi",
            &two_records,
            exact_limit,
            &|| false,
        )
        .expect("cancellation source image");
        let path = directory.write("exception-cancel.efi", &two_records);
        let mut file = File::open(path).expect("exception cancellation image");
        assert_eq!(
            validate_arm64_exceptions(&mut file, &pe, &[], exact_limit, &|| true),
            Err(InspectError::Cancelled)
        );

        let packed_mutations = [
            ("reserved-flag", (packed_unwind(2) & !3) | 3),
            ("zero-function", packed_unwind(0)),
            ("too-many-integer-registers", packed_unwind(2) | (11 << 16)),
            (
                "undersized-frame",
                (packed_unwind(2) & !(0x1ff << 23)) | (2 << 16),
            ),
            ("function-escapes-text", packed_unwind(3)),
        ];
        for (name, unwind) in packed_mutations {
            let mut image = pe_image_with_packed_unwind(1);
            put_u32(&mut image, 0x804, unwind);
            assert_pe_rejected(&directory, &format!("packed-{name}.efi"), &image);
        }

        let mut duplicate_start = two_records.clone();
        put_u32(&mut duplicate_start, 0x808, 0x1000);
        assert_pe_rejected(&directory, "duplicate-pdata-start.efi", &duplicate_start);

        let mut overlapping_functions = two_records.clone();
        put_u32(&mut overlapping_functions, 0x804, packed_unwind(3));
        assert_pe_rejected(
            &directory,
            "overlapping-pdata-functions.efi",
            &overlapping_functions,
        );

        let mut non_multiple_directory = two_records;
        let exception_directory =
            TEST_OPTIONAL + PE32_PLUS_DATA_DIRECTORY_OFFSET + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
        put_u32(&mut non_multiple_directory, exception_directory + 4, 12);
        assert_pe_rejected(
            &directory,
            "partial-pdata-record.efi",
            &non_multiple_directory,
        );

        let full_mutations = [
            ("xdata-version", 0xa00, 1 << 18),
            ("xdata-handler", 0xa00, 1 << 20),
            ("xdata-epilog-index", 0xa00, 1 << 22),
            ("xdata-reserved-opcode", 0xa04, 0x19),
            ("xdata-nonzero-padding", 0xa05, 1),
        ];
        for (name, offset, xor) in full_mutations {
            let mut image = pe_image_with_full_unwind();
            image[offset] ^= u8::try_from(xor & 0xff).expect("low mutation byte");
            if xor > 0xff {
                let word = le_u32(&image, offset).expect("xdata header") ^ xor;
                put_u32(&mut image, offset, word);
            }
            assert_pe_rejected(&directory, &format!("{name}.efi"), &image);
        }

        let mut escaped_xdata = pe_image_with_full_unwind();
        put_u32(&mut escaped_xdata, 0x804, 0x6000);
        assert_pe_rejected(&directory, "escaped-xdata-rva.efi", &escaped_xdata);

        let mut empty_xdata = pe_image_with_full_unwind();
        put_u32(&mut empty_xdata, 0xa00, (1 << 27) | (1 << 21));
        assert_pe_rejected(&directory, "zero-xdata-function.efi", &empty_xdata);

        let mut escaping_record = pe_image_with_full_unwind();
        put_u32(&mut escaping_record, TEST_SECTIONS + 120 + 8, 4);
        assert_pe_rejected(&directory, "escaping-xdata-record.efi", &escaping_record);

        let mut hidden_xdata = pe_image_with_full_unwind();
        put_u32(&mut hidden_xdata, TEST_SECTIONS + 120 + 8, 12);
        hidden_xdata[0xa08] = 1;
        assert_pe_rejected(&directory, "hidden-xdata-bytes.efi", &hidden_xdata);

        let mut extended = pe_image_with_full_unwind();
        put_u32(&mut extended, TEST_SECTIONS + 120 + 8, 12);
        put_u32(&mut extended, 0xa00, 2);
        put_u32(&mut extended, 0xa04, 1 << 16);
        extended[0xa08] = 0xe4;
        parse_pe_structure(
            &directory,
            "extended-xdata.efi",
            &extended,
            limits(),
            &|| false,
        )
        .expect("extended ARM64 xdata header");
    }

    #[test]
    fn relocation_provenance_rejects_missing_extra_duplicate_and_substituted_sites() {
        let directory = TestDirectory::new();
        let canonical_input = provenance_coff();
        assert_ne!(
            lld_contribution_map(&directory.root.join("path-a.obj")),
            lld_contribution_map(&directory.root.join("independent-much-longer-path-b.obj")),
            "the fixture must exercise distinct path-bearing native maps",
        );
        let short_root = inspect_fixture(
            &directory,
            "path-a",
            &pe_image(),
            &lld_map(),
            &canonical_input,
            lld_contribution_map,
            limits(),
            &|| false,
        )
        .expect("short-root relocation provenance");
        let long_root = inspect_fixture(
            &directory,
            "independent-much-longer-path-b",
            &pe_image(),
            &lld_map(),
            &canonical_input,
            lld_contribution_map,
            limits(),
            &|| false,
        )
        .expect("long-root relocation provenance");
        assert_eq!(
            short_root, long_root,
            "relocation provenance must encode reviewed input identity and layout, not private paths",
        );
        for (name, mutate) in [
            ("missing-contribution", 0u8),
            ("duplicate-contribution", 1u8),
            ("substituted-contribution", 2u8),
        ] {
            let result = inspect_fixture(
                &directory,
                name,
                &pe_image(),
                &lld_map(),
                &canonical_input,
                |input| {
                    let canonical = String::from_utf8(lld_contribution_map(input))
                        .expect("ASCII contribution map");
                    let contribution = format!(
                        "00001000 00000008    16         {}:(.text)\n",
                        input.display(),
                    );
                    match mutate {
                        0 => canonical.replace(&contribution, ""),
                        1 => canonical
                            .replace(&contribution, &(contribution.clone() + &contribution)),
                        2 => canonical.replace(
                            &input.display().to_string(),
                            &input
                                .with_file_name("substituted.obj")
                                .display()
                                .to_string(),
                        ),
                        _ => unreachable!(),
                    }
                    .into_bytes()
                },
                limits(),
                &|| false,
            );
            assert!(
                matches!(result, Err(InspectError::InvalidRelocationProvenance(_))),
                "{name} contribution evidence was accepted: {result:?}",
            );
        }

        let unsupported = provenance_coff_with_relocations(8, &[0], 0x000c);
        let unsupported_result = inspect_fixture(
            &directory,
            "unsupported-input-relocation",
            &pe_image(),
            &lld_map(),
            &unsupported,
            lld_contribution_map,
            limits(),
            &|| false,
        );
        assert!(matches!(
            unsupported_result,
            Err(InspectError::InvalidRelocationProvenance(_))
        ));

        let input_one = provenance_coff_with_relocations(16, &[0], IMAGE_REL_ARM64_ADDR64);
        let input_two = provenance_coff_with_relocations(16, &[0, 8], IMAGE_REL_ARM64_ADDR64);
        for (name, image, input) in [
            (
                "extra-output-site",
                pe_image_with_relocations(16, &[0, 8]),
                input_one.clone(),
            ),
            (
                "missing-output-site",
                pe_image_with_relocations(16, &[0]),
                input_two.clone(),
            ),
            (
                "substituted-output-site",
                pe_image_with_relocations(16, &[8]),
                input_one.clone(),
            ),
        ] {
            let result = inspect_fixture(
                &directory,
                name,
                &image,
                &lld_map_with_text_bytes(16),
                &input,
                |path| lld_contribution_map_with_layout(path, 16, 16),
                limits(),
                &|| false,
            );
            assert!(
                matches!(result, Err(InspectError::InvalidRelocationProvenance(_))),
                "{name} output relocation evidence was accepted: {result:?}",
            );
        }

        let mut one_relocation = limits();
        one_relocation.base_relocations = 1;
        let over_limit = inspect_fixture(
            &directory,
            "input-relocation-max-plus-one",
            &pe_image_with_relocations(16, &[0]),
            &lld_map_with_text_bytes(16),
            &input_two,
            |path| lld_contribution_map_with_layout(path, 16, 16),
            one_relocation,
            &|| false,
        );
        assert!(matches!(
            over_limit,
            Err(InspectError::LimitExceeded {
                resource: "input COFF relocations",
                limit: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn arm64_base_relocations_are_fully_decoded_limited_and_cancellable() {
        let mut directory = relocation_block(0x1000, &[0, 8]);
        directory.extend_from_slice(&relocation_block(0x2000, &[0]));
        assert_eq!(
            inspect_relocations(&directory, 3, &|| false),
            Ok(BaseRelocationMeasurements {
                blocks: 2,
                entries: 3,
            })
        );
        assert_eq!(
            inspect_relocations(&directory, 2, &|| false),
            Err(InspectError::LimitExceeded {
                resource: "base relocations",
                limit: 2,
                actual: 3,
            })
        );

        let checks = Cell::new(0u32);
        assert_eq!(
            inspect_relocations(&directory, 3, &|| {
                let current = checks.get();
                checks.set(current + 1);
                current == 2
            }),
            Err(InspectError::Cancelled)
        );
        assert_eq!(checks.get(), 3);

        let sections = relocation_sections();
        let mut truncated = &directory[..directory.len() - 1];
        assert_eq!(
            parse_base_relocations(
                &mut truncated,
                directory.len() as u64,
                &sections,
                None,
                limits(),
                &|| false,
            ),
            Err(InspectError::Truncated)
        );
    }

    #[test]
    fn malformed_arm64_base_relocation_blocks_fail_closed() {
        let canonical = relocation_block(0x1000, &[0]);
        let mut malformed = Vec::new();

        let mut block_size_is_not_aligned = canonical.clone();
        put_u32(&mut block_size_is_not_aligned, 4, 10);
        malformed.push(("unaligned block size", block_size_is_not_aligned));

        let mut block_escapes_directory = canonical.clone();
        put_u32(&mut block_escapes_directory, 4, 16);
        malformed.push(("block escapes directory", block_escapes_directory));

        let mut page_is_not_aligned = canonical.clone();
        put_u32(&mut page_is_not_aligned, 0, 0x1004);
        malformed.push(("unaligned page", page_is_not_aligned));

        let mut illegal_arm64_type = canonical.clone();
        put_u16(&mut illegal_arm64_type, 8, 0x3000);
        malformed.push(("illegal ARM64 type", illegal_arm64_type));

        let mut nonzero_padding = canonical.clone();
        put_u16(&mut nonzero_padding, 10, 1);
        malformed.push(("nonzero padding", nonzero_padding));

        let mut padding_is_not_final = canonical.clone();
        put_u16(&mut padding_is_not_final, 8, 0);
        put_u16(&mut padding_is_not_final, 10, 0xa000);
        malformed.push(("padding before relocation", padding_is_not_final));

        let mut target_is_not_aligned = canonical.clone();
        put_u16(&mut target_is_not_aligned, 8, 0xa004);
        malformed.push(("unaligned DIR64 target", target_is_not_aligned));

        malformed.push(("unmapped target", relocation_block(0x3000, &[0])));
        malformed.push(("reversed entries", relocation_block(0x1000, &[8, 0])));
        malformed.push(("overlapping entries", relocation_block(0x1000, &[0, 0])));

        let mut reversed_blocks = relocation_block(0x2000, &[0]);
        reversed_blocks.extend_from_slice(&relocation_block(0x1000, &[0]));
        malformed.push(("reversed blocks", reversed_blocks));

        let mut overlapping_pages = relocation_block(0x1000, &[0]);
        overlapping_pages.extend_from_slice(&relocation_block(0x1000, &[8]));
        malformed.push(("overlapping page blocks", overlapping_pages));

        let mut partial_trailing_header = canonical;
        partial_trailing_header.extend_from_slice(&[0; 4]);
        malformed.push(("partial trailing block", partial_trailing_header));

        for (name, bytes) in malformed {
            assert!(
                matches!(
                    inspect_relocations(&bytes, 16, &|| false),
                    Err(InspectError::InvalidBaseRelocations(_))
                ),
                "malformed relocation fixture was accepted: {name}",
            );
        }

        let mut discardable = relocation_sections();
        discardable[0].characteristics |= IMAGE_SCN_MEM_DISCARDABLE;
        let bytes = relocation_block(0x1000, &[0]);
        assert!(matches!(
            parse_base_relocations(
                &mut &*bytes,
                bytes.len() as u64,
                &discardable,
                None,
                limits(),
                &|| false,
            ),
            Err(InspectError::InvalidBaseRelocations(_))
        ));
    }

    #[test]
    fn pe_map_corruption_limits_and_cancellation_are_rejected() {
        let directory = TestDirectory::new();
        let target = target();
        let input_bytes = provenance_coff();
        let input_path = directory.write("image.obj", &input_bytes);
        let input = provenance_input(&input_path, &input_bytes);
        let provenance_path =
            directory.write("image.map.lldmap", &lld_contribution_map(&input_path));
        let mut bad_pe = pe_image();
        put_u16(&mut bad_pe, LLD_PE_OFFSET + 24 + 68, 3);
        let bad_pe_path = directory.write("bad.efi", &bad_pe);
        let map_path = directory.write("image.map", &lld_map());
        assert!(matches!(
            CanonicalLinkedImageInspector::new().inspect(
                &bad_pe_path,
                &map_path,
                &provenance_path,
                &[input],
                target.backend(),
                limits(),
                &|| false,
            ),
            Err(InspectError::NonCanonical(_))
        ));

        let mut bad_relocation = pe_image();
        put_u16(&mut bad_relocation, 0x608, 0x3000);
        let bad_relocation_path = directory.write("bad-relocation.efi", &bad_relocation);
        assert!(matches!(
            CanonicalLinkedImageInspector::new().inspect(
                &bad_relocation_path,
                &map_path,
                &provenance_path,
                &[input],
                target.backend(),
                limits(),
                &|| false,
            ),
            Err(InspectError::InvalidBaseRelocations(_))
        ));

        let mut bad_base = pe_image();
        put_u64(
            &mut bad_base,
            LLD_PE_OFFSET + 24 + 24,
            0x0000_0001_4000_0000,
        );
        let bad_base_path = directory.write("bad-base.efi", &bad_base);
        assert!(matches!(
            CanonicalLinkedImageInspector::new().inspect(
                &bad_base_path,
                &map_path,
                &provenance_path,
                &[input],
                target.backend(),
                limits(),
                &|| false,
            ),
            Err(InspectError::NonCanonical(_))
        ));

        let image_path = directory.write("image.efi", &pe_image());
        let bad_map = String::from_utf8(lld_map()).expect("ASCII map").replace(
            "Preferred load address is 0000000000000000",
            "Preferred load address is 0000000000001000",
        );
        let bad_map_path = directory.write("bad.map", bad_map.as_bytes());
        assert!(matches!(
            CanonicalLinkedImageInspector::new().inspect(
                &image_path,
                &bad_map_path,
                &provenance_path,
                &[input],
                target.backend(),
                limits(),
                &|| false,
            ),
            Err(InspectError::InvalidMap(_))
        ));

        let bad_timestamp = String::from_utf8(lld_map())
            .expect("ASCII map")
            .replace("Timestamp is 00000000", "Timestamp is 00000001");
        let bad_timestamp_path = directory.write("bad-timestamp.map", bad_timestamp.as_bytes());
        assert!(matches!(
            CanonicalLinkedImageInspector::new().inspect(
                &image_path,
                &bad_timestamp_path,
                &provenance_path,
                &[input],
                target.backend(),
                limits(),
                &|| false,
            ),
            Err(InspectError::InvalidMap(_))
        ));

        let mut one_symbol = limits();
        one_symbol.symbols = 1;
        assert!(matches!(
            CanonicalLinkedImageInspector::new().inspect(
                &image_path,
                &map_path,
                &provenance_path,
                &[input],
                target.backend(),
                one_symbol,
                &|| false,
            ),
            Err(InspectError::LimitExceeded {
                resource: "symbols",
                ..
            })
        ));
        assert_eq!(
            CanonicalLinkedImageInspector::new().inspect(
                &image_path,
                &map_path,
                &provenance_path,
                &[input],
                target.backend(),
                limits(),
                &|| true,
            ),
            Err(InspectError::Cancelled)
        );
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
