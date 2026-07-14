//! Target-laid-out, LLVM-independent machine IR.
//!
//! MachineWir fixes ABI, data layout, sections, stack/frame objects, runtime
//! intrinsics, and every undefined-behavior-bearing backend fact. Codegen is a
//! translation of this contract, not another semantic lowering pass.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use wrela_build_model::BuildIdentity;
use wrela_runtime_abi::{
    AbiType, INTERRUPT_ROUTE_LAYOUT, INTERRUPT_ROUTE_SECTION, INTERRUPT_ROUTE_TABLE_SYMBOL,
    RuntimeAbiError, RuntimeIntrinsic, RuntimeRequirements,
};
use wrela_source::Span;
use wrela_target::{InterruptDomain, TargetError, TargetPackage};

pub const MACHINE_WIR_VERSION: u32 = 1;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);
    };
}

id_type!(MachineTypeId);
id_type!(FunctionId);
id_type!(BlockId);
id_type!(ValueId);
id_type!(InstructionId);
id_type!(GlobalId);
id_type!(StackSlotId);
id_type!(SectionId);
id_type!(SymbolId);
id_type!(ProofId);
id_type!(InterruptEntryId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endianness {
    Little,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataLayout {
    pub pointer_bits: u16,
    pub pointer_alignment: u32,
    pub stack_alignment: u32,
    pub aggregate_alignment: u32,
    pub maximum_object_alignment: u32,
    pub endianness: Endianness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineTypeKind {
    Void,
    Integer {
        bits: u16,
    },
    Float32,
    Float64,
    Pointer {
        address_space: u32,
        pointee: Option<MachineTypeId>,
    },
    Vector {
        element: MachineTypeId,
        lanes: u32,
    },
    Array {
        element: MachineTypeId,
        length: u64,
    },
    Struct {
        fields: Vec<MachineField>,
        packed: bool,
    },
    Function {
        parameters: Vec<MachineTypeId>,
        result: MachineTypeId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineField {
    pub ty: MachineTypeId,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineType {
    pub id: MachineTypeId,
    pub kind: MachineTypeKind,
    pub size: u64,
    pub alignment: u32,
    pub source_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Code,
    ReadOnlyData,
    WritableData,
    ZeroFill,
    Relocations,
    RuntimeMetadata,
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub id: SectionId,
    pub name: String,
    pub kind: SectionKind,
    pub alignment: u32,
    pub reserved_bytes: u64,
    pub owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolVisibility {
    Private,
    ImageEntry,
    Runtime,
    RuntimeMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolDefinition {
    Function(FunctionId),
    Global(GlobalId),
    SectionOffset {
        section: SectionId,
        offset: u64,
        bytes: u64,
    },
    ExternalRuntime(RuntimeIntrinsic),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub id: SymbolId,
    pub name: String,
    pub visibility: SymbolVisibility,
    pub definition: SymbolDefinition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Compiler-private convention. It never crosses an object boundary.
    Internal,
    /// AAPCS64 boundary used by target/runtime glue.
    Aapcs64,
    /// The sole UEFI image entry. Codegen maps this marker to the AAPCS64 C
    /// convention only after validating the firmware signature.
    UefiAarch64,
    /// A no-argument, void interrupt body reached only through target-owned
    /// exception entry and dispatch glue. It is not an ordinary call target.
    InterruptHandler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linkage {
    Private,
    InternalRuntime,
    ExportedEntry,
}

/// One statically sealed interrupt route. The target binding is retained so
/// startup, codegen, and reporting do not have to reconstruct the association
/// from source-level device plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptEntry {
    pub id: InterruptEntryId,
    pub device: u32,
    pub target_binding: String,
    /// GIC SPI number, excluding the architectural offset of 32.
    pub line: u32,
    /// Architectural GIC interrupt ID (INTID).
    pub global_id: u32,
    pub handler: FunctionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOrdering {
    Relaxed,
    Acquire,
    Release,
    AcquireRelease,
    Sequential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySemantics {
    Ordinary,
    Volatile,
    Device,
    Atomic(AtomicOrdering),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerPredicate {
    Equal,
    NotEqual,
    UnsignedLess,
    UnsignedLessEqual,
    UnsignedGreater,
    UnsignedGreaterEqual,
    SignedLess,
    SignedLessEqual,
    SignedGreater,
    SignedGreaterEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatPredicate {
    OrderedEqual,
    OrderedNotEqual,
    OrderedLess,
    OrderedLessEqual,
    OrderedGreater,
    OrderedGreaterEqual,
    Unordered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticOp {
    IntegerAdd,
    IntegerSubtract,
    IntegerMultiply,
    UnsignedDivide,
    SignedDivide,
    UnsignedRemainder,
    SignedRemainder,
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeft,
    LogicalShiftRight,
    ArithmeticShiftRight,
    FloatAdd,
    FloatSubtract,
    FloatMultiply,
    FloatDivide,
}

/// Exact scalar conversion selected after signedness, widths, and checked/exact
/// source semantics have already been resolved. LLVM must not infer a choice
/// from otherwise signless machine integer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionOp {
    IntegerTruncate,
    ZeroExtend,
    SignExtend,
    FloatTruncate,
    FloatExtend,
    UnsignedIntegerToFloat,
    SignedIntegerToFloat,
    FloatToUnsignedInteger,
    FloatToSignedInteger,
    PointerToInteger,
    IntegerToPointer,
    Bitcast,
}

/// Hardware/compiler fence selected by lowering. Load/store semantics remain
/// attached to those operations; a standalone fence can never be "ordinary"
/// or merely "volatile".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineFence {
    Acquire,
    Release,
    AcquireRelease,
    Sequential,
    DeviceRead,
    DeviceWrite,
    DeviceFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineImmediate {
    Integer {
        ty: MachineTypeId,
        bytes_le: Vec<u8>,
    },
    Float32(u32),
    Float64(u64),
    Null(MachineTypeId),
    Zero(MachineTypeId),
    SymbolAddress(SymbolId),
    Bytes(Vec<u8>),
}

/// Facts codegen may translate into LLVM attributes or inbounds operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendFacts {
    pub proof: ProofId,
    pub alignment: Option<u32>,
    pub non_null: bool,
    pub no_alias: bool,
    pub in_bounds: bool,
    pub no_unsigned_wrap: bool,
    pub no_signed_wrap: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineOperation {
    Immediate(MachineImmediate),
    Arithmetic {
        op: ArithmeticOp,
        left: ValueId,
        right: ValueId,
    },
    IntegerCompare {
        predicate: IntegerPredicate,
        left: ValueId,
        right: ValueId,
    },
    FloatCompare {
        predicate: FloatPredicate,
        left: ValueId,
        right: ValueId,
    },
    Convert {
        op: ConversionOp,
        value: ValueId,
        destination: MachineTypeId,
    },
    Select {
        condition: ValueId,
        then_value: ValueId,
        else_value: ValueId,
    },
    AddressOffset {
        base: ValueId,
        byte_offset: ValueId,
        facts: BackendFacts,
    },
    Load {
        address: ValueId,
        ty: MachineTypeId,
        semantics: MemorySemantics,
        facts: BackendFacts,
    },
    Store {
        address: ValueId,
        value: ValueId,
        semantics: MemorySemantics,
        facts: BackendFacts,
    },
    MemoryCopy {
        destination: ValueId,
        source: ValueId,
        bytes: ValueId,
        destination_alignment: u32,
        source_alignment: u32,
        non_overlapping: bool,
        proof: ProofId,
    },
    MemorySet {
        destination: ValueId,
        byte: ValueId,
        bytes: ValueId,
        alignment: u32,
    },
    StackAddress(StackSlotId),
    GlobalAddress(GlobalId),
    Call {
        function: FunctionId,
        arguments: Vec<ValueId>,
        convention: CallingConvention,
    },
    RuntimeCall {
        intrinsic: RuntimeIntrinsic,
        arguments: Vec<ValueId>,
    },
    Fence(MachineFence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineInstruction {
    pub id: InstructionId,
    pub results: Vec<ValueId>,
    pub operation: MachineOperation,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineTerminator {
    Jump {
        block: BlockId,
        arguments: Vec<ValueId>,
    },
    Branch {
        condition: ValueId,
        then_block: BlockId,
        then_arguments: Vec<ValueId>,
        else_block: BlockId,
        else_arguments: Vec<ValueId>,
    },
    Switch {
        value: ValueId,
        cases: Vec<(u128, BlockId, Vec<ValueId>)>,
        default: BlockId,
        default_arguments: Vec<ValueId>,
    },
    Return(Vec<ValueId>),
    TailCall {
        function: FunctionId,
        arguments: Vec<ValueId>,
    },
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineBlock {
    pub id: BlockId,
    pub parameters: Vec<ValueId>,
    pub instructions: Vec<MachineInstruction>,
    pub terminator: MachineTerminator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineValue {
    pub id: ValueId,
    pub ty: MachineTypeId,
    pub source_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSlot {
    pub id: StackSlotId,
    pub size: u64,
    pub alignment: u32,
    pub source_name: Option<String>,
    pub live_states: Vec<u32>,
    pub overlay_group: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineFunctionRole {
    Ordinary,
    ActorTurn(u32),
    TaskEntry(u32),
    Isr(u32),
    Cleanup,
    ImageEntry,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFunction {
    pub id: FunctionId,
    /// Exact FlowWir function lowered into this machine function. Revision 0.1
    /// requires a canonical one-to-one function mapping.
    pub flow_function: u32,
    pub role: MachineFunctionRole,
    pub symbol: SymbolId,
    /// Exact code section selected by machine lowering. Codegen determines the
    /// final section-relative offset and extent, but never section ownership.
    pub section: SectionId,
    pub linkage: Linkage,
    pub convention: CallingConvention,
    pub parameters: Vec<ValueId>,
    pub result: MachineTypeId,
    pub values: Vec<MachineValue>,
    pub stack_slots: Vec<StackSlot>,
    pub blocks: Vec<MachineBlock>,
    pub entry: BlockId,
    pub stack_bytes: u64,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineGlobal {
    pub id: GlobalId,
    pub symbol: SymbolId,
    pub ty: MachineTypeId,
    pub section: SectionId,
    pub offset: u64,
    pub alignment: u32,
    pub initializer: MachineImmediate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProof {
    pub id: ProofId,
    pub source_proofs: Vec<u32>,
    pub statement: String,
    pub source: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTarget {
    pub identity: String,
    pub llvm_triple: String,
    pub data_layout: String,
    pub cpu: String,
    pub features: Vec<String>,
    pub coff_machine: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineWir {
    pub version: u32,
    pub name: String,
    pub build: BuildIdentity,
    pub target: MachineTarget,
    pub layout: DataLayout,
    pub runtime: RuntimeRequirements,
    pub types: Vec<MachineType>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub globals: Vec<MachineGlobal>,
    pub functions: Vec<MachineFunction>,
    pub interrupts: Vec<InterruptEntry>,
    pub proofs: Vec<BackendProof>,
    pub image_entry: FunctionId,
}

impl MachineWir {
    /// Seal this module only after matching every target-owned backend field and
    /// interrupt route against the exact content-addressed package selected by
    /// the build. There is intentionally no context-free sealing operation.
    pub fn validate_for_target(
        self,
        target: &TargetPackage,
    ) -> Result<ValidatedMachineWir, ValidationErrors> {
        let errors = validate_module(&self, target);
        if errors.is_empty() {
            Ok(ValidatedMachineWir(self))
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

fn validate_module(module: &MachineWir, target: &TargetPackage) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    if let Err(error) = target.validate() {
        errors.push(ValidationError::TargetPackage(error));
    }
    if module.version != MACHINE_WIR_VERSION {
        errors.push(ValidationError::UnsupportedVersion(module.version));
    }
    if module.name.trim().is_empty() {
        errors.push(ValidationError::MissingImageName);
    }
    if let Err(error) = module.runtime.validate() {
        errors.push(ValidationError::RuntimeAbi(error));
    }
    validate_target_and_layout(module, target, &mut errors);
    check_dense(
        "type",
        module.types.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "section",
        module.sections.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "symbol",
        module.symbols.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "global",
        module.globals.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "function",
        module.functions.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "flow function provenance",
        module.functions.iter().map(|item| item.flow_function),
        &mut errors,
    );
    check_dense(
        "interrupt entry",
        module.interrupts.iter().map(|item| item.id.0),
        &mut errors,
    );
    check_dense(
        "proof",
        module.proofs.iter().map(|item| item.id.0),
        &mut errors,
    );

    for ty in &module.types {
        validate_type(module, ty, &mut errors);
    }
    for section in &module.sections {
        if section.name.trim().is_empty() || !valid_alignment(section.alignment) {
            errors.push(ValidationError::InvalidRecord {
                kind: "section",
                id: section.id.0,
            });
        }
    }
    require_unique_names(
        "section",
        module.sections.iter().map(|item| item.name.as_str()),
        &mut errors,
    );
    let mut function_symbol_counts = vec![0usize; module.functions.len()];
    let mut global_symbol_counts = vec![0usize; module.globals.len()];
    let mut runtime_symbol_counts = std::collections::BTreeMap::new();
    for symbol in &module.symbols {
        if symbol.name.trim().is_empty() {
            errors.push(ValidationError::InvalidRecord {
                kind: "symbol",
                id: symbol.id.0,
            });
        }
        match symbol.definition {
            SymbolDefinition::Function(id) => {
                require_id("symbol function", id.0, module.functions.len(), &mut errors);
                if let Some(count) = function_symbol_counts.get_mut(id.0 as usize) {
                    *count += 1;
                }
            }
            SymbolDefinition::Global(id) => {
                require_id("symbol global", id.0, module.globals.len(), &mut errors);
                if let Some(count) = global_symbol_counts.get_mut(id.0 as usize) {
                    *count += 1;
                }
            }
            SymbolDefinition::SectionOffset {
                section,
                offset,
                bytes,
            } => {
                require_id(
                    "symbol section",
                    section.0,
                    module.sections.len(),
                    &mut errors,
                );
                if module.sections.get(section.0 as usize).is_some_and(|item| {
                    bytes == 0
                        || offset
                            .checked_add(bytes)
                            .is_none_or(|end| end > item.reserved_bytes)
                }) {
                    errors.push(ValidationError::InvalidRecord {
                        kind: "section symbol",
                        id: symbol.id.0,
                    });
                }
            }
            SymbolDefinition::ExternalRuntime(intrinsic) => {
                *runtime_symbol_counts.entry(intrinsic).or_insert(0usize) += 1;
                if symbol.name != intrinsic.symbol_name() {
                    errors.push(ValidationError::InvalidRuntimeSymbol { intrinsic });
                }
                if !module.runtime.intrinsics.contains(&intrinsic) {
                    errors.push(ValidationError::UnexpectedRuntimeSymbol(intrinsic));
                }
            }
        }
        let expected_visibility = match symbol.definition {
            SymbolDefinition::Function(id) if id == module.image_entry => {
                SymbolVisibility::ImageEntry
            }
            SymbolDefinition::ExternalRuntime(_) => SymbolVisibility::Runtime,
            SymbolDefinition::SectionOffset { .. }
                if symbol.name == INTERRUPT_ROUTE_TABLE_SYMBOL =>
            {
                SymbolVisibility::RuntimeMetadata
            }
            SymbolDefinition::Function(_)
            | SymbolDefinition::Global(_)
            | SymbolDefinition::SectionOffset { .. } => SymbolVisibility::Private,
        };
        if symbol.visibility != expected_visibility {
            errors.push(ValidationError::InvalidSymbolVisibility(symbol.id));
        }
    }
    require_unique_names(
        "symbol",
        module.symbols.iter().map(|item| item.name.as_str()),
        &mut errors,
    );
    let mut runtime_call_counts = std::collections::BTreeMap::new();
    for instruction in module
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
    {
        if let MachineOperation::RuntimeCall { intrinsic, .. } = &instruction.operation {
            *runtime_call_counts.entry(*intrinsic).or_insert(0usize) += 1;
        }
    }
    for intrinsic in &module.runtime.intrinsics {
        let count = runtime_symbol_counts.get(intrinsic).copied().unwrap_or(0);
        if count != 1 {
            errors.push(ValidationError::RuntimeSymbolCount {
                intrinsic: *intrinsic,
                count,
            });
        }
        let call_count = runtime_call_counts.get(intrinsic).copied().unwrap_or(0);
        if call_count == 0 {
            errors.push(ValidationError::UnusedRuntimeIntrinsic(*intrinsic));
        }
    }
    for global in &module.globals {
        let symbol_count = global_symbol_counts
            .get(global.id.0 as usize)
            .copied()
            .unwrap_or(0);
        if symbol_count != 1 {
            errors.push(ValidationError::DefinitionSymbolCount {
                kind: "global",
                id: global.id.0,
                count: symbol_count,
            });
        }
        require_id(
            "global symbol",
            global.symbol.0,
            module.symbols.len(),
            &mut errors,
        );
        require_id("global type", global.ty.0, module.types.len(), &mut errors);
        require_id(
            "global section",
            global.section.0,
            module.sections.len(),
            &mut errors,
        );
        if !valid_alignment(global.alignment) {
            errors.push(ValidationError::InvalidRecord {
                kind: "global",
                id: global.id.0,
            });
        }
        if module
            .symbols
            .get(global.symbol.0 as usize)
            .is_some_and(|symbol| symbol.definition != SymbolDefinition::Global(global.id))
        {
            errors.push(ValidationError::SymbolDefinitionMismatch(global.symbol));
        }
        if let (Some(ty), Some(section)) = (
            module.types.get(global.ty.0 as usize),
            module.sections.get(global.section.0 as usize),
        ) {
            let end = global.offset.checked_add(ty.size);
            if end.is_none_or(|end| end > section.reserved_bytes)
                || global.offset % u64::from(global.alignment) != 0
            {
                errors.push(ValidationError::InvalidRecord {
                    kind: "global placement",
                    id: global.id.0,
                });
            }
        }
        validate_immediate(module, &global.initializer, &mut errors);
        if !immediate_matches_type(module, &global.initializer, global.ty) {
            errors.push(ValidationError::InvalidGlobalInitializer(global.id));
        }
    }
    let mut global_placements: Vec<_> = module
        .globals
        .iter()
        .filter_map(|global| {
            module
                .types
                .get(global.ty.0 as usize)
                .and_then(|ty| global.offset.checked_add(ty.size))
                .map(|end| (global.section, global.offset, end, global.id))
        })
        .collect();
    global_placements.sort_unstable_by_key(|placement| (placement.0, placement.1, placement.2));
    for pair in global_placements.windows(2) {
        if pair[0].0 == pair[1].0 && pair[0].2 > pair[1].1 {
            errors.push(ValidationError::InvalidRecord {
                kind: "overlapping global placement",
                id: pair[1].3.0,
            });
        }
    }
    for function in &module.functions {
        let symbol_count = function_symbol_counts
            .get(function.id.0 as usize)
            .copied()
            .unwrap_or(0);
        if symbol_count != 1 {
            errors.push(ValidationError::DefinitionSymbolCount {
                kind: "function",
                id: function.id.0,
                count: symbol_count,
            });
        }
        validate_function(module, function, &mut errors);
    }
    validate_interrupt_entries(module, target, &mut errors);
    validate_interrupt_metadata(module, &mut errors);
    if module.image_entry.0 as usize >= module.functions.len() {
        errors.push(ValidationError::UnknownImageEntry(module.image_entry));
    } else {
        validate_image_entry(module, target, &mut errors);
        if module.functions[module.image_entry.0 as usize].role != MachineFunctionRole::ImageEntry
            || module
                .functions
                .iter()
                .filter(|function| function.role == MachineFunctionRole::ImageEntry)
                .count()
                != 1
        {
            errors.push(ValidationError::InvalidImageEntry(module.image_entry));
        }
    }
    errors
}

fn validate_target_and_layout(
    module: &MachineWir,
    target: &TargetPackage,
    errors: &mut Vec<ValidationError>,
) {
    let backend = target.backend();
    if target.identity() != &module.build.target
        || target.semantic().content_digest() != module.build.target_package
        || module.target.identity != module.build.target.as_str()
        || module.target.llvm_triple != backend.llvm_triple()
        || module.target.coff_machine != backend.coff_machine()
        || module.target.cpu != backend.llvm_cpu()
        || module.target.features != backend.llvm_features()
        || module.target.data_layout != backend.llvm_data_layout()
    {
        errors.push(ValidationError::InvalidAarch64Target);
    }
    let layout = &module.layout;
    if layout.pointer_bits != 64
        || !valid_alignment(layout.pointer_alignment)
        || !valid_alignment(layout.stack_alignment)
        || !valid_alignment(layout.aggregate_alignment)
        || !valid_alignment(layout.maximum_object_alignment)
        || layout.pointer_alignment > layout.maximum_object_alignment
        || layout.aggregate_alignment > layout.maximum_object_alignment
        || layout.stack_alignment < 16
    {
        errors.push(ValidationError::InvalidDataLayout);
    }
}

fn validate_type(module: &MachineWir, ty: &MachineType, errors: &mut Vec<ValidationError>) {
    if !valid_alignment(ty.alignment)
        || ty.alignment > module.layout.maximum_object_alignment
        || (ty.size != 0 && ty.size % u64::from(ty.alignment) != 0)
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "machine type layout",
            id: ty.id.0,
        });
    }
    match &ty.kind {
        MachineTypeKind::Void => {
            if ty.size != 0 {
                errors.push(ValidationError::InvalidRecord {
                    kind: "void type",
                    id: ty.id.0,
                });
            }
        }
        MachineTypeKind::Integer { bits } => {
            if *bits == 0 || *bits > 128 || u64::from(*bits).div_ceil(8) > ty.size {
                errors.push(ValidationError::InvalidRecord {
                    kind: "integer type",
                    id: ty.id.0,
                });
            }
        }
        MachineTypeKind::Float32 => require_minimum_size(ty, 4, errors),
        MachineTypeKind::Float64 => require_minimum_size(ty, 8, errors),
        MachineTypeKind::Pointer { pointee, .. } => {
            if ty.size != u64::from(module.layout.pointer_bits / 8) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "pointer type",
                    id: ty.id.0,
                });
            }
            if let Some(pointee) = pointee {
                require_id("pointer pointee", pointee.0, module.types.len(), errors);
            }
        }
        MachineTypeKind::Vector { element, lanes } => {
            require_id("vector element", element.0, module.types.len(), errors);
            if *lanes == 0 {
                errors.push(ValidationError::InvalidRecord {
                    kind: "vector type",
                    id: ty.id.0,
                });
            }
        }
        MachineTypeKind::Array { element, .. } => {
            require_id("array element", element.0, module.types.len(), errors)
        }
        MachineTypeKind::Struct { fields, .. } => {
            let mut previous_end = 0;
            for field in fields {
                require_id("struct field type", field.ty.0, module.types.len(), errors);
                if let Some(field_ty) = module.types.get(field.ty.0 as usize) {
                    let end = field.offset.checked_add(field_ty.size);
                    if field.offset < previous_end || end.is_none_or(|end| end > ty.size) {
                        errors.push(ValidationError::InvalidRecord {
                            kind: "struct field",
                            id: ty.id.0,
                        });
                    }
                    previous_end = end.unwrap_or(u64::MAX);
                }
            }
        }
        MachineTypeKind::Function { parameters, result } => {
            for parameter in parameters {
                require_id(
                    "function parameter type",
                    parameter.0,
                    module.types.len(),
                    errors,
                );
            }
            require_id("function result type", result.0, module.types.len(), errors);
        }
    }
}

fn require_minimum_size(ty: &MachineType, minimum: u64, errors: &mut Vec<ValidationError>) {
    if ty.size < minimum {
        errors.push(ValidationError::InvalidRecord {
            kind: "floating type",
            id: ty.id.0,
        });
    }
}

fn validate_immediate(
    module: &MachineWir,
    immediate: &MachineImmediate,
    errors: &mut Vec<ValidationError>,
) {
    match immediate {
        MachineImmediate::Integer { ty, .. }
        | MachineImmediate::Null(ty)
        | MachineImmediate::Zero(ty) => {
            require_id("immediate type", ty.0, module.types.len(), errors);
        }
        MachineImmediate::SymbolAddress(symbol) => {
            require_id("immediate symbol", symbol.0, module.symbols.len(), errors)
        }
        MachineImmediate::Float32(_)
        | MachineImmediate::Float64(_)
        | MachineImmediate::Bytes(_) => {}
    }
}

fn validate_function(
    module: &MachineWir,
    function: &MachineFunction,
    errors: &mut Vec<ValidationError>,
) {
    require_id(
        "function symbol",
        function.symbol.0,
        module.symbols.len(),
        errors,
    );
    require_id(
        "function section",
        function.section.0,
        module.sections.len(),
        errors,
    );
    require_id(
        "function result type",
        function.result.0,
        module.types.len(),
        errors,
    );
    if module
        .symbols
        .get(function.symbol.0 as usize)
        .is_some_and(|symbol| symbol.definition != SymbolDefinition::Function(function.id))
    {
        errors.push(ValidationError::SymbolDefinitionMismatch(function.symbol));
    }
    if module
        .sections
        .get(function.section.0 as usize)
        .is_some_and(|section| section.kind != SectionKind::Code)
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "function code section",
            id: function.id.0,
        });
    }
    if function.id != module.image_entry {
        let valid_abi = match (function.linkage, function.convention) {
            (Linkage::Private, CallingConvention::Internal | CallingConvention::Aapcs64)
            | (Linkage::Private, CallingConvention::InterruptHandler)
            | (Linkage::InternalRuntime, CallingConvention::Aapcs64) => true,
            (Linkage::Private | Linkage::InternalRuntime, CallingConvention::UefiAarch64)
            | (Linkage::InternalRuntime, CallingConvention::Internal)
            | (Linkage::InternalRuntime, CallingConvention::InterruptHandler)
            | (Linkage::ExportedEntry, _) => false,
        };
        if !valid_abi {
            errors.push(ValidationError::InvalidFunctionAbi(function.id));
        }
    }
    check_dense(
        "value",
        function.values.iter().map(|item| item.id.0),
        errors,
    );
    check_dense(
        "stack slot",
        function.stack_slots.iter().map(|item| item.id.0),
        errors,
    );
    check_dense(
        "block",
        function.blocks.iter().map(|item| item.id.0),
        errors,
    );
    for value in &function.values {
        require_id("value type", value.ty.0, module.types.len(), errors);
    }
    for slot in &function.stack_slots {
        if !valid_alignment(slot.alignment)
            || slot.alignment > module.layout.stack_alignment
            || slot.size > function.stack_bytes
        {
            errors.push(ValidationError::InvalidRecord {
                kind: "stack slot",
                id: slot.id.0,
            });
        }
    }
    if function.stack_bytes % u64::from(module.layout.stack_alignment) != 0 {
        errors.push(ValidationError::InvalidRecord {
            kind: "function stack",
            id: function.id.0,
        });
    }
    require_id(
        "function entry block",
        function.entry.0,
        function.blocks.len(),
        errors,
    );
    if function
        .blocks
        .get(function.entry.0 as usize)
        .is_some_and(|entry| !entry.parameters.is_empty())
    {
        errors.push(ValidationError::InvalidRecord {
            kind: "function entry block parameters",
            id: function.id.0,
        });
    }
    let mut definitions = vec![0u8; function.values.len()];
    for value in &function.parameters {
        define_value(function.id, *value, &mut definitions, errors);
    }
    let mut instruction_ids = Vec::new();
    for block in &function.blocks {
        for value in &block.parameters {
            define_value(function.id, *value, &mut definitions, errors);
        }
        for (index, instruction) in block.instructions.iter().enumerate() {
            instruction_ids.push(instruction.id.0);
            for value in &instruction.results {
                define_value(function.id, *value, &mut definitions, errors);
            }
            validate_operation(module, function, instruction, errors);
            if matches!(
                instruction.operation,
                MachineOperation::RuntimeCall { intrinsic, .. }
                    if !intrinsic.signature().may_return
            ) && (index + 1 != block.instructions.len()
                || !matches!(block.terminator, MachineTerminator::Unreachable))
            {
                errors.push(ValidationError::NonReturningRuntimeFallthrough {
                    function: function.id,
                    instruction: instruction.id,
                });
            }
        }
        validate_terminator(module, function, &block.terminator, errors);
    }
    check_dense("instruction", instruction_ids, errors);
    for (index, count) in definitions.into_iter().enumerate() {
        if count != 1 {
            errors.push(ValidationError::ValueDefinitionCount {
                function: function.id,
                value: ValueId(index as u32),
                definitions: count,
            });
        }
    }
}

fn validate_operation(
    module: &MachineWir,
    function: &MachineFunction,
    instruction: &MachineInstruction,
    errors: &mut Vec<ValidationError>,
) {
    macro_rules! value {
        ($id:expr) => {
            require_id("instruction value", ($id).0, function.values.len(), errors)
        };
    }
    macro_rules! proof {
        ($facts:expr) => {{
            require_id(
                "backend proof",
                ($facts).proof.0,
                module.proofs.len(),
                errors,
            );
            if ($facts)
                .alignment
                .is_some_and(|alignment| !valid_alignment(alignment))
            {
                errors.push(ValidationError::InvalidBackendFacts(($facts).proof));
            }
        }};
    }
    match &instruction.operation {
        MachineOperation::Immediate(immediate) => validate_immediate(module, immediate, errors),
        MachineOperation::Arithmetic { left, right, .. }
        | MachineOperation::IntegerCompare { left, right, .. }
        | MachineOperation::FloatCompare { left, right, .. } => {
            value!(*left);
            value!(*right);
        }
        MachineOperation::Convert {
            value: source,
            destination,
            ..
        } => {
            value!(*source);
            require_id("conversion type", destination.0, module.types.len(), errors);
        }
        MachineOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            value!(*condition);
            value!(*then_value);
            value!(*else_value);
        }
        MachineOperation::AddressOffset {
            base,
            byte_offset,
            facts,
        } => {
            value!(*base);
            value!(*byte_offset);
            proof!(facts);
        }
        MachineOperation::Load {
            address, ty, facts, ..
        } => {
            value!(*address);
            require_id("load type", ty.0, module.types.len(), errors);
            proof!(facts);
        }
        MachineOperation::Store {
            address,
            value: stored,
            facts,
            ..
        } => {
            value!(*address);
            value!(*stored);
            proof!(facts);
        }
        MachineOperation::MemoryCopy {
            destination,
            source,
            bytes,
            destination_alignment,
            source_alignment,
            proof,
            ..
        } => {
            value!(*destination);
            value!(*source);
            value!(*bytes);
            require_id("memory copy proof", proof.0, module.proofs.len(), errors);
            if !valid_alignment(*destination_alignment) || !valid_alignment(*source_alignment) {
                errors.push(ValidationError::InvalidBackendFacts(*proof));
            }
        }
        MachineOperation::MemorySet {
            destination,
            byte,
            bytes,
            alignment,
        } => {
            value!(*destination);
            value!(*byte);
            value!(*bytes);
            if !valid_alignment(*alignment) {
                errors.push(ValidationError::InvalidRecord {
                    kind: "memory set",
                    id: instruction.id.0,
                });
            }
        }
        MachineOperation::StackAddress(slot) => {
            require_id("stack slot", slot.0, function.stack_slots.len(), errors)
        }
        MachineOperation::GlobalAddress(global) => {
            require_id("global", global.0, module.globals.len(), errors)
        }
        MachineOperation::Call {
            function: callee,
            arguments,
            convention,
        } => {
            require_id("callee", callee.0, module.functions.len(), errors);
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| callee.convention != *convention)
            {
                errors.push(ValidationError::CallingConventionMismatch {
                    caller: function.id,
                    callee: *callee,
                });
            }
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| {
                    matches!(
                        callee.convention,
                        CallingConvention::UefiAarch64 | CallingConvention::InterruptHandler
                    )
                })
            {
                errors.push(ValidationError::ForbiddenDirectCall {
                    caller: function.id,
                    callee: *callee,
                });
            }
            for argument in arguments {
                value!(*argument);
            }
            validate_machine_call(module, function, instruction, *callee, arguments, errors);
        }
        MachineOperation::RuntimeCall {
            intrinsic,
            arguments,
        } => {
            if !module.runtime.intrinsics.contains(intrinsic) {
                errors.push(ValidationError::UnrequiredRuntimeCall(*intrinsic));
            }
            let signature = intrinsic.signature();
            if arguments.len() != signature.parameters.len() {
                errors.push(ValidationError::RuntimeArity {
                    intrinsic: *intrinsic,
                    expected: signature.parameters.len(),
                    actual: arguments.len(),
                });
            }
            for (argument, abi) in arguments.iter().zip(&signature.parameters) {
                value!(*argument);
                if let Some(value) = function.values.get(argument.0 as usize) {
                    validate_abi_type(module, value.ty, *abi, *intrinsic, errors);
                }
            }
            let expected_results = usize::from(signature.result != AbiType::Unit);
            if instruction.results.len() != expected_results {
                errors.push(ValidationError::RuntimeResultCount {
                    intrinsic: *intrinsic,
                    expected: expected_results,
                    actual: instruction.results.len(),
                });
            } else if let Some(result) = instruction
                .results
                .first()
                .and_then(|id| function.values.get(id.0 as usize))
            {
                validate_abi_type(module, result.ty, signature.result, *intrinsic, errors);
            }
        }
        MachineOperation::Fence(_) => {}
    }
    validate_operation_types(module, function, instruction, errors);
}

fn validate_operation_types(
    module: &MachineWir,
    function: &MachineFunction,
    instruction: &MachineInstruction,
    errors: &mut Vec<ValidationError>,
) {
    let value_ty = |id: ValueId| function.values.get(id.0 as usize).map(|value| value.ty);
    let result_ty = |index: usize| instruction.results.get(index).and_then(|id| value_ty(*id));
    let result_count = instruction.results.len();
    let same = |left: ValueId, right: ValueId| {
        value_ty(left)
            .zip(value_ty(right))
            .is_some_and(|(left, right)| left == right)
    };
    let valid = match &instruction.operation {
        MachineOperation::Immediate(immediate) => {
            result_count == 1
                && result_ty(0).is_some_and(|ty| immediate_matches_type(module, immediate, ty))
        }
        MachineOperation::Arithmetic { op, left, right } => {
            let ty = value_ty(*left);
            let operands_match = same(*left, *right) && ty == result_ty(0);
            let valid_kind = ty
                .and_then(|ty| module.types.get(ty.0 as usize))
                .is_some_and(|ty| match op {
                    ArithmeticOp::FloatAdd
                    | ArithmeticOp::FloatSubtract
                    | ArithmeticOp::FloatMultiply
                    | ArithmeticOp::FloatDivide => {
                        matches!(ty.kind, MachineTypeKind::Float32 | MachineTypeKind::Float64)
                    }
                    _ => matches!(ty.kind, MachineTypeKind::Integer { .. }),
                });
            result_count == 1 && operands_match && valid_kind
        }
        MachineOperation::IntegerCompare { left, right, .. } => {
            result_count == 1
                && same(*left, *right)
                && value_ty(*left).is_some_and(|ty| is_integer(module, ty))
                && result_ty(0).is_some_and(|ty| is_bool(module, ty))
        }
        MachineOperation::FloatCompare { left, right, .. } => {
            result_count == 1
                && same(*left, *right)
                && value_ty(*left).is_some_and(|ty| is_float(module, ty))
                && result_ty(0).is_some_and(|ty| is_bool(module, ty))
        }
        MachineOperation::Convert {
            op,
            value,
            destination,
        } => {
            result_count == 1
                && result_ty(0) == Some(*destination)
                && value_ty(*value)
                    .is_some_and(|source| valid_conversion(module, *op, source, *destination))
        }
        MachineOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            result_count == 1
                && value_ty(*condition).is_some_and(|ty| is_bool(module, ty))
                && same(*then_value, *else_value)
                && value_ty(*then_value) == result_ty(0)
        }
        MachineOperation::AddressOffset {
            base, byte_offset, ..
        } => {
            result_count == 1
                && value_ty(*base).is_some_and(|ty| is_pointer(module, ty))
                && value_ty(*byte_offset).is_some_and(|ty| is_integer(module, ty))
                && value_ty(*base) == result_ty(0)
        }
        MachineOperation::Load { address, ty, .. } => {
            result_count == 1
                && result_ty(0) == Some(*ty)
                && value_ty(*address).is_some_and(|address| pointer_accepts(module, address, *ty))
        }
        MachineOperation::Store { address, value, .. } => {
            result_count == 0
                && value_ty(*address)
                    .zip(value_ty(*value))
                    .is_some_and(|(address, value)| pointer_accepts(module, address, value))
        }
        MachineOperation::MemoryCopy {
            destination,
            source,
            bytes,
            ..
        } => {
            result_count == 0
                && value_ty(*destination).is_some_and(|ty| is_pointer(module, ty))
                && value_ty(*source).is_some_and(|ty| is_pointer(module, ty))
                && value_ty(*bytes).is_some_and(|ty| is_integer(module, ty))
        }
        MachineOperation::MemorySet {
            destination,
            byte,
            bytes,
            ..
        } => {
            result_count == 0
                && value_ty(*destination).is_some_and(|ty| is_pointer(module, ty))
                && value_ty(*byte).is_some_and(|ty| is_bool(module, ty))
                && value_ty(*bytes).is_some_and(|ty| is_integer(module, ty))
        }
        MachineOperation::Fence(_) => result_count == 0,
        MachineOperation::StackAddress(_) => {
            result_count == 1 && result_ty(0).is_some_and(|ty| is_pointer(module, ty))
        }
        MachineOperation::GlobalAddress(global) => {
            result_count == 1
                && result_ty(0).is_some_and(|pointer| {
                    module
                        .globals
                        .get(global.0 as usize)
                        .is_some_and(|global| pointer_accepts(module, pointer, global.ty))
                })
        }
        // Arity and result types for these operations are validated against
        // their declared callee/runtime signatures by the main validator.
        MachineOperation::Call { .. } | MachineOperation::RuntimeCall { .. } => true,
    };
    if !valid {
        errors.push(ValidationError::OperationTypeMismatch {
            function: function.id,
            instruction: instruction.id,
        });
    }
}

fn immediate_matches_type(
    module: &MachineWir,
    immediate: &MachineImmediate,
    expected: MachineTypeId,
) -> bool {
    let Some(ty) = module.types.get(expected.0 as usize) else {
        return false;
    };
    match immediate {
        MachineImmediate::Integer {
            ty: immediate_ty,
            bytes_le,
        } => {
            *immediate_ty == expected
                && matches!(ty.kind, MachineTypeKind::Integer { .. })
                && integer_bytes_are_canonical(ty, bytes_le)
        }
        MachineImmediate::Float32(_) => matches!(ty.kind, MachineTypeKind::Float32),
        MachineImmediate::Float64(_) => matches!(ty.kind, MachineTypeKind::Float64),
        MachineImmediate::Null(immediate_ty) => {
            *immediate_ty == expected && matches!(ty.kind, MachineTypeKind::Pointer { .. })
        }
        MachineImmediate::Zero(immediate_ty) => {
            *immediate_ty == expected && !matches!(ty.kind, MachineTypeKind::Void)
        }
        MachineImmediate::SymbolAddress(_) => matches!(ty.kind, MachineTypeKind::Pointer { .. }),
        MachineImmediate::Bytes(bytes) => {
            !matches!(ty.kind, MachineTypeKind::Void) && bytes.len() as u64 == ty.size
        }
    }
}

fn integer_bytes_are_canonical(ty: &MachineType, bytes: &[u8]) -> bool {
    let MachineTypeKind::Integer { bits } = ty.kind else {
        return false;
    };
    let expected = usize::from(bits.div_ceil(8));
    if bytes.len() != expected {
        return false;
    }
    let used = bits % 8;
    used == 0
        || bytes
            .last()
            .is_some_and(|last| *last & !((1u8 << used) - 1) == 0)
}

fn is_integer(module: &MachineWir, ty: MachineTypeId) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { .. }))
}

fn is_bool(module: &MachineWir, ty: MachineTypeId) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { bits: 8 }))
}

fn is_float(module: &MachineWir, ty: MachineTypeId) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Float32 | MachineTypeKind::Float64))
}

fn is_pointer(module: &MachineWir, ty: MachineTypeId) -> bool {
    module
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Pointer { .. }))
}

fn pointer_accepts(module: &MachineWir, pointer: MachineTypeId, value: MachineTypeId) -> bool {
    module
        .types
        .get(pointer.0 as usize)
        .is_some_and(|pointer| match pointer.kind {
            MachineTypeKind::Pointer { pointee, .. } => {
                pointee.is_none_or(|pointee| pointee == value)
            }
            _ => false,
        })
}

fn valid_conversion(
    module: &MachineWir,
    op: ConversionOp,
    source: MachineTypeId,
    destination: MachineTypeId,
) -> bool {
    let Some(source_ty) = module.types.get(source.0 as usize) else {
        return false;
    };
    let Some(destination_ty) = module.types.get(destination.0 as usize) else {
        return false;
    };
    let integer_bits = |ty: &MachineType| match ty.kind {
        MachineTypeKind::Integer { bits } => Some(bits),
        _ => None,
    };
    match op {
        ConversionOp::IntegerTruncate => integer_bits(source_ty)
            .zip(integer_bits(destination_ty))
            .is_some_and(|(source, destination)| destination < source),
        ConversionOp::ZeroExtend | ConversionOp::SignExtend => integer_bits(source_ty)
            .zip(integer_bits(destination_ty))
            .is_some_and(|(source, destination)| destination > source),
        ConversionOp::FloatTruncate => {
            matches!(source_ty.kind, MachineTypeKind::Float64)
                && matches!(destination_ty.kind, MachineTypeKind::Float32)
        }
        ConversionOp::FloatExtend => {
            matches!(source_ty.kind, MachineTypeKind::Float32)
                && matches!(destination_ty.kind, MachineTypeKind::Float64)
        }
        ConversionOp::UnsignedIntegerToFloat | ConversionOp::SignedIntegerToFloat => {
            integer_bits(source_ty).is_some()
                && matches!(
                    destination_ty.kind,
                    MachineTypeKind::Float32 | MachineTypeKind::Float64
                )
        }
        ConversionOp::FloatToUnsignedInteger | ConversionOp::FloatToSignedInteger => {
            matches!(
                source_ty.kind,
                MachineTypeKind::Float32 | MachineTypeKind::Float64
            ) && integer_bits(destination_ty).is_some()
        }
        ConversionOp::PointerToInteger => {
            matches!(source_ty.kind, MachineTypeKind::Pointer { .. })
                && integer_bits(destination_ty) == Some(module.layout.pointer_bits)
        }
        ConversionOp::IntegerToPointer => {
            integer_bits(source_ty) == Some(module.layout.pointer_bits)
                && matches!(destination_ty.kind, MachineTypeKind::Pointer { .. })
        }
        ConversionOp::Bitcast => {
            source_ty.size == destination_ty.size
                && scalar_or_vector(source_ty)
                && scalar_or_vector(destination_ty)
        }
    }
}

fn scalar_or_vector(ty: &MachineType) -> bool {
    matches!(
        ty.kind,
        MachineTypeKind::Integer { .. }
            | MachineTypeKind::Float32
            | MachineTypeKind::Float64
            | MachineTypeKind::Pointer { .. }
            | MachineTypeKind::Vector { .. }
    )
}

fn validate_abi_type(
    module: &MachineWir,
    ty: MachineTypeId,
    abi: AbiType,
    intrinsic: RuntimeIntrinsic,
    errors: &mut Vec<ValidationError>,
) {
    let Some(ty) = module.types.get(ty.0 as usize) else {
        return;
    };
    let valid = match abi {
        AbiType::Unit => matches!(ty.kind, MachineTypeKind::Void),
        AbiType::Bool | AbiType::U8 => matches!(ty.kind, MachineTypeKind::Integer { bits: 8 }),
        AbiType::U32 => matches!(ty.kind, MachineTypeKind::Integer { bits: 32 }),
        AbiType::U64 | AbiType::Usize | AbiType::Status => {
            matches!(ty.kind, MachineTypeKind::Integer { bits: 64 })
        }
        AbiType::Address => matches!(ty.kind, MachineTypeKind::Pointer { .. }),
    };
    if !valid {
        errors.push(ValidationError::RuntimeTypeMismatch {
            intrinsic,
            abi,
            ty: ty.id,
        });
    }
}

fn validate_terminator(
    module: &MachineWir,
    function: &MachineFunction,
    terminator: &MachineTerminator,
    errors: &mut Vec<ValidationError>,
) {
    macro_rules! value {
        ($id:expr) => {
            require_id("terminator value", ($id).0, function.values.len(), errors)
        };
    }
    macro_rules! block {
        ($id:expr) => {
            require_id("terminator block", ($id).0, function.blocks.len(), errors)
        };
    }
    match terminator {
        MachineTerminator::Jump {
            block: target,
            arguments,
        } => {
            block!(*target);
            for argument in arguments {
                value!(*argument);
            }
            if !block_arguments_match(function, *target, arguments) {
                errors.push(ValidationError::ControlFlowTypeMismatch(function.id));
            }
        }
        MachineTerminator::Branch {
            condition,
            then_block,
            then_arguments,
            else_block,
            else_arguments,
        } => {
            value!(*condition);
            block!(*then_block);
            block!(*else_block);
            for argument in then_arguments.iter().chain(else_arguments) {
                value!(*argument);
            }
            if function
                .values
                .get(condition.0 as usize)
                .is_none_or(|value| !is_bool(module, value.ty))
                || !block_arguments_match(function, *then_block, then_arguments)
                || !block_arguments_match(function, *else_block, else_arguments)
            {
                errors.push(ValidationError::ControlFlowTypeMismatch(function.id));
            }
        }
        MachineTerminator::Switch {
            value: switched,
            cases,
            default,
            default_arguments,
        } => {
            value!(*switched);
            block!(*default);
            for argument in default_arguments {
                value!(*argument);
            }
            for (_, target, arguments) in cases {
                block!(*target);
                for argument in arguments {
                    value!(*argument);
                }
            }
            let switched_is_integer = function
                .values
                .get(switched.0 as usize)
                .is_some_and(|value| is_integer(module, value.ty));
            let unique_cases = cases
                .iter()
                .map(|(value, _, _)| value)
                .collect::<BTreeSet<_>>()
                .len()
                == cases.len();
            let case_arguments_match = cases
                .iter()
                .all(|(_, target, arguments)| block_arguments_match(function, *target, arguments));
            if !switched_is_integer
                || !unique_cases
                || !block_arguments_match(function, *default, default_arguments)
                || !case_arguments_match
            {
                errors.push(ValidationError::ControlFlowTypeMismatch(function.id));
            }
        }
        MachineTerminator::Return(values) => {
            for value in values {
                value!(*value);
            }
            let expected = usize::from(
                module
                    .types
                    .get(function.result.0 as usize)
                    .is_some_and(|ty| !matches!(ty.kind, MachineTypeKind::Void)),
            );
            if values.len() != expected
                || (expected == 1
                    && function
                        .values
                        .get(values[0].0 as usize)
                        .is_some_and(|value| value.ty != function.result))
            {
                errors.push(ValidationError::ReturnMismatch(function.id));
            }
        }
        MachineTerminator::TailCall {
            function: callee,
            arguments,
        } => {
            require_id("tail callee", callee.0, module.functions.len(), errors);
            for argument in arguments {
                value!(*argument);
            }
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| {
                    callee.convention != function.convention
                        || matches!(
                            callee.convention,
                            CallingConvention::UefiAarch64 | CallingConvention::InterruptHandler
                        )
                })
            {
                errors.push(ValidationError::ForbiddenTailCall {
                    caller: function.id,
                    callee: *callee,
                });
            }
            validate_machine_call_shape(module, function, *callee, arguments, errors);
            if module
                .functions
                .get(callee.0 as usize)
                .is_some_and(|callee| callee.result != function.result)
            {
                errors.push(ValidationError::CallResultMismatch {
                    caller: function.id,
                    callee: *callee,
                });
            }
        }
        MachineTerminator::Unreachable => {}
    }
}

fn block_arguments_match(
    function: &MachineFunction,
    target: BlockId,
    arguments: &[ValueId],
) -> bool {
    let Some(block) = function.blocks.get(target.0 as usize) else {
        return false;
    };
    arguments.len() == block.parameters.len()
        && arguments
            .iter()
            .zip(&block.parameters)
            .all(|(argument, parameter)| {
                function
                    .values
                    .get(argument.0 as usize)
                    .zip(function.values.get(parameter.0 as usize))
                    .is_some_and(|(argument, parameter)| argument.ty == parameter.ty)
            })
}

fn validate_machine_call(
    module: &MachineWir,
    caller: &MachineFunction,
    instruction: &MachineInstruction,
    callee: FunctionId,
    arguments: &[ValueId],
    errors: &mut Vec<ValidationError>,
) {
    validate_machine_call_shape(module, caller, callee, arguments, errors);
    let Some(callee) = module.functions.get(callee.0 as usize) else {
        return;
    };
    let expected = usize::from(
        module
            .types
            .get(callee.result.0 as usize)
            .is_some_and(|ty| !matches!(ty.kind, MachineTypeKind::Void)),
    );
    if instruction.results.len() != expected
        || (expected == 1
            && caller
                .values
                .get(instruction.results[0].0 as usize)
                .is_some_and(|value| value.ty != callee.result))
    {
        errors.push(ValidationError::CallResultMismatch {
            caller: caller.id,
            callee: callee.id,
        });
    }
}

fn validate_machine_call_shape(
    module: &MachineWir,
    caller: &MachineFunction,
    callee: FunctionId,
    arguments: &[ValueId],
    errors: &mut Vec<ValidationError>,
) {
    let Some(callee) = module.functions.get(callee.0 as usize) else {
        return;
    };
    if arguments.len() != callee.parameters.len() {
        errors.push(ValidationError::CallArity {
            caller: caller.id,
            callee: callee.id,
            expected: callee.parameters.len(),
            actual: arguments.len(),
        });
        return;
    }
    for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
        let types = caller
            .values
            .get(argument.0 as usize)
            .zip(callee.values.get(parameter.0 as usize))
            .map(|(argument, parameter)| (argument.ty, parameter.ty));
        if types.is_some_and(|(argument, parameter)| argument != parameter) {
            errors.push(ValidationError::CallTypeMismatch {
                caller: caller.id,
                callee: callee.id,
            });
        }
    }
}

fn validate_image_entry(
    module: &MachineWir,
    target: &TargetPackage,
    errors: &mut Vec<ValidationError>,
) {
    let entry = &module.functions[module.image_entry.0 as usize];
    let valid_symbol = module
        .symbols
        .get(entry.symbol.0 as usize)
        .is_some_and(|symbol| {
            symbol.visibility == SymbolVisibility::ImageEntry
                && symbol.name == target.backend().entry_symbol()
                && symbol.definition == SymbolDefinition::Function(entry.id)
        });
    let parameter_types: Vec<_> = entry
        .parameters
        .iter()
        .filter_map(|parameter| entry.values.get(parameter.0 as usize))
        .filter_map(|value| module.types.get(value.ty.0 as usize))
        .collect();
    let valid_signature = parameter_types.len() == 2
        && parameter_types
            .iter()
            .all(|ty| matches!(ty.kind, MachineTypeKind::Pointer { .. }))
        && module
            .types
            .get(entry.result.0 as usize)
            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { bits: 64 }));
    if entry.linkage != Linkage::ExportedEntry
        || entry.convention != CallingConvention::UefiAarch64
        || !valid_symbol
        || !valid_signature
    {
        errors.push(ValidationError::InvalidImageEntry(module.image_entry));
    }
    let image_entries = module
        .symbols
        .iter()
        .filter(|symbol| symbol.visibility == SymbolVisibility::ImageEntry)
        .count();
    if image_entries != 1 {
        errors.push(ValidationError::ImageEntrySymbolCount(image_entries));
    }
}

fn validate_interrupt_entries(
    module: &MachineWir,
    target: &TargetPackage,
    errors: &mut Vec<ValidationError>,
) {
    if !module
        .interrupts
        .windows(2)
        .all(|pair| pair[0].target_binding < pair[1].target_binding)
    {
        errors.push(ValidationError::NonCanonicalInterruptEntries);
    }
    let mut global_counts = BTreeMap::new();
    let mut handler_counts = BTreeMap::new();
    for interrupt in &module.interrupts {
        *global_counts.entry(interrupt.global_id).or_insert(0usize) += 1;
        *handler_counts.entry(interrupt.handler).or_insert(0usize) += 1;
    }
    for interrupt in &module.interrupts {
        let matches_target = target
            .semantic()
            .mmio_bindings()
            .binary_search_by(|binding| binding.name.cmp(&interrupt.target_binding))
            .ok()
            .and_then(|index| target.semantic().mmio_bindings().get(index))
            .and_then(|binding| binding.interrupt)
            .is_some_and(|binding| {
                binding.domain == InterruptDomain::GicSpi
                    && binding.line == interrupt.line
                    && binding.global_id == interrupt.global_id
            });
        let unique_route = !interrupt.target_binding.trim().is_empty()
            && interrupt.line.checked_add(32) == Some(interrupt.global_id)
            && matches_target
            && global_counts.get(&interrupt.global_id) == Some(&1)
            && handler_counts.get(&interrupt.handler) == Some(&1);
        let valid_handler = module
            .functions
            .get(interrupt.handler.0 as usize)
            .is_some_and(|handler| {
                let private_symbol = module
                    .symbols
                    .get(handler.symbol.0 as usize)
                    .is_some_and(|symbol| symbol.visibility == SymbolVisibility::Private);
                let void_result = module
                    .types
                    .get(handler.result.0 as usize)
                    .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Void));
                handler.linkage == Linkage::Private
                    && handler.convention == CallingConvention::InterruptHandler
                    && handler.role == MachineFunctionRole::Isr(interrupt.device)
                    && handler.parameters.is_empty()
                    && void_result
                    && private_symbol
            });
        if !unique_route || !valid_handler {
            errors.push(ValidationError::InvalidInterruptEntry(interrupt.id));
        }
    }
    for handler in module
        .functions
        .iter()
        .filter(|function| function.convention == CallingConvention::InterruptHandler)
    {
        let count = handler_counts.get(&handler.id).copied().unwrap_or(0);
        if count != 1 {
            errors.push(ValidationError::InterruptHandlerRouteCount {
                handler: handler.id,
                count,
            });
        }
        validate_interrupt_call_graph(module, handler.id, errors);
    }
}

fn validate_interrupt_metadata(module: &MachineWir, errors: &mut Vec<ValidationError>) {
    let expected_bytes = u64::try_from(module.interrupts.len())
        .ok()
        .and_then(|count| count.checked_mul(u64::from(INTERRUPT_ROUTE_LAYOUT.record_bytes)))
        .and_then(|records| records.checked_add(u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes)));
    let sections: Vec<_> = module
        .sections
        .iter()
        .filter(|section| section.name == INTERRUPT_ROUTE_SECTION)
        .collect();
    let valid_section = match sections.as_slice() {
        [section] => {
            section.kind == SectionKind::RuntimeMetadata
                && section.alignment == INTERRUPT_ROUTE_LAYOUT.table_alignment
                && Some(section.reserved_bytes) == expected_bytes
        }
        _ => false,
    };
    let symbols: Vec<_> = module
        .symbols
        .iter()
        .filter(|symbol| symbol.name == INTERRUPT_ROUTE_TABLE_SYMBOL)
        .collect();
    let valid_symbol = sections
        .first()
        .is_some_and(|section| match symbols.as_slice() {
            [symbol] => {
                symbol.visibility == SymbolVisibility::RuntimeMetadata
                    && symbol.definition
                        == SymbolDefinition::SectionOffset {
                            section: section.id,
                            offset: 0,
                            bytes: section.reserved_bytes,
                        }
            }
            _ => false,
        });
    if !valid_section || !valid_symbol {
        errors.push(ValidationError::InvalidInterruptMetadata);
    }
}

fn validate_interrupt_call_graph(
    module: &MachineWir,
    handler: FunctionId,
    errors: &mut Vec<ValidationError>,
) {
    let mut pending = vec![handler];
    let mut visited = vec![false; module.functions.len()];
    while let Some(function_id) = pending.pop() {
        let Some(function) = module.functions.get(function_id.0 as usize) else {
            continue;
        };
        if std::mem::replace(&mut visited[function_id.0 as usize], true) {
            continue;
        }
        let has_forbidden_type = function
            .values
            .iter()
            .map(|value| value.ty)
            .chain(std::iter::once(function.result))
            .any(|ty| type_requires_simd(module, ty, &mut vec![false; module.types.len()]));
        let mut forbidden_operation = false;
        for block in &function.blocks {
            for instruction in &block.instructions {
                match &instruction.operation {
                    MachineOperation::Arithmetic {
                        op:
                            ArithmeticOp::FloatAdd
                            | ArithmeticOp::FloatSubtract
                            | ArithmeticOp::FloatMultiply
                            | ArithmeticOp::FloatDivide,
                        ..
                    }
                    | MachineOperation::FloatCompare { .. }
                    | MachineOperation::Immediate(
                        MachineImmediate::Float32(_) | MachineImmediate::Float64(_),
                    ) => forbidden_operation = true,
                    MachineOperation::Convert {
                        op:
                            ConversionOp::FloatTruncate
                            | ConversionOp::FloatExtend
                            | ConversionOp::UnsignedIntegerToFloat
                            | ConversionOp::SignedIntegerToFloat
                            | ConversionOp::FloatToUnsignedInteger
                            | ConversionOp::FloatToSignedInteger,
                        ..
                    } => forbidden_operation = true,
                    MachineOperation::RuntimeCall { intrinsic, .. }
                        if *intrinsic != RuntimeIntrinsic::Fatal =>
                    {
                        forbidden_operation = true;
                    }
                    MachineOperation::Call {
                        function: callee, ..
                    } => pending.push(*callee),
                    _ => {}
                }
            }
            if let MachineTerminator::TailCall {
                function: callee, ..
            } = block.terminator
            {
                pending.push(callee);
            }
        }
        if has_forbidden_type || forbidden_operation {
            errors.push(ValidationError::InvalidInterruptReachableCode {
                handler,
                function: function_id,
            });
        }
    }
}

fn type_requires_simd(module: &MachineWir, ty: MachineTypeId, visited: &mut [bool]) -> bool {
    let Some(record) = module.types.get(ty.0 as usize) else {
        return false;
    };
    if std::mem::replace(&mut visited[ty.0 as usize], true) {
        return false;
    }
    match &record.kind {
        MachineTypeKind::Float32 | MachineTypeKind::Float64 | MachineTypeKind::Vector { .. } => {
            true
        }
        MachineTypeKind::Array { element, .. } => type_requires_simd(module, *element, visited),
        MachineTypeKind::Struct { fields, .. } => fields
            .iter()
            .any(|field| type_requires_simd(module, field.ty, visited)),
        MachineTypeKind::Function { parameters, result } => parameters
            .iter()
            .copied()
            .chain(std::iter::once(*result))
            .any(|ty| type_requires_simd(module, ty, visited)),
        MachineTypeKind::Void
        | MachineTypeKind::Integer { .. }
        | MachineTypeKind::Pointer { .. } => false,
    }
}

fn valid_alignment(alignment: u32) -> bool {
    alignment.is_power_of_two()
}

fn require_id(kind: &'static str, id: u32, length: usize, errors: &mut Vec<ValidationError>) {
    if id as usize >= length {
        errors.push(ValidationError::UnknownReference { kind, id });
    }
}

fn define_value(
    function: FunctionId,
    value: ValueId,
    definitions: &mut [u8],
    errors: &mut Vec<ValidationError>,
) {
    let Some(count) = definitions.get_mut(value.0 as usize) else {
        errors.push(ValidationError::UnknownValue { function, value });
        return;
    };
    *count = count.saturating_add(1);
}

fn require_unique_names<'a>(
    kind: &'static str,
    names: impl IntoIterator<Item = &'a str>,
    errors: &mut Vec<ValidationError>,
) {
    let mut names: Vec<_> = names.into_iter().collect();
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        errors.push(ValidationError::DuplicateName(kind));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMachineWir(MachineWir);

impl ValidatedMachineWir {
    #[must_use]
    pub fn as_wir(&self) -> &MachineWir {
        &self.0
    }

    #[must_use]
    pub fn into_wir(self) -> MachineWir {
        self.0
    }
}

fn check_dense(
    kind: &'static str,
    ids: impl IntoIterator<Item = u32>,
    errors: &mut Vec<ValidationError>,
) {
    for (expected, actual) in ids.into_iter().enumerate() {
        if actual as usize != expected {
            errors.push(ValidationError::NonDenseId {
                kind,
                expected,
                actual,
            });
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    TargetPackage(TargetError),
    UnsupportedVersion(u32),
    MissingImageName,
    RuntimeAbi(RuntimeAbiError),
    NonDenseId {
        kind: &'static str,
        expected: usize,
        actual: u32,
    },
    UnknownReference {
        kind: &'static str,
        id: u32,
    },
    UnknownValue {
        function: FunctionId,
        value: ValueId,
    },
    ValueDefinitionCount {
        function: FunctionId,
        value: ValueId,
        definitions: u8,
    },
    InvalidRecord {
        kind: &'static str,
        id: u32,
    },
    DuplicateName(&'static str),
    InvalidAarch64Target,
    InvalidDataLayout,
    SymbolDefinitionMismatch(SymbolId),
    DefinitionSymbolCount {
        kind: &'static str,
        id: u32,
        count: usize,
    },
    CallingConventionMismatch {
        caller: FunctionId,
        callee: FunctionId,
    },
    InvalidFunctionAbi(FunctionId),
    ForbiddenDirectCall {
        caller: FunctionId,
        callee: FunctionId,
    },
    ForbiddenTailCall {
        caller: FunctionId,
        callee: FunctionId,
    },
    CallArity {
        caller: FunctionId,
        callee: FunctionId,
        expected: usize,
        actual: usize,
    },
    CallTypeMismatch {
        caller: FunctionId,
        callee: FunctionId,
    },
    CallResultMismatch {
        caller: FunctionId,
        callee: FunctionId,
    },
    OperationTypeMismatch {
        function: FunctionId,
        instruction: InstructionId,
    },
    ControlFlowTypeMismatch(FunctionId),
    ReturnMismatch(FunctionId),
    InvalidGlobalInitializer(GlobalId),
    NonReturningRuntimeFallthrough {
        function: FunctionId,
        instruction: InstructionId,
    },
    InvalidRuntimeSymbol {
        intrinsic: RuntimeIntrinsic,
    },
    RuntimeSymbolCount {
        intrinsic: RuntimeIntrinsic,
        count: usize,
    },
    UnexpectedRuntimeSymbol(RuntimeIntrinsic),
    UnrequiredRuntimeCall(RuntimeIntrinsic),
    UnusedRuntimeIntrinsic(RuntimeIntrinsic),
    RuntimeArity {
        intrinsic: RuntimeIntrinsic,
        expected: usize,
        actual: usize,
    },
    RuntimeResultCount {
        intrinsic: RuntimeIntrinsic,
        expected: usize,
        actual: usize,
    },
    RuntimeTypeMismatch {
        intrinsic: RuntimeIntrinsic,
        abi: AbiType,
        ty: MachineTypeId,
    },
    InvalidBackendFacts(ProofId),
    UnknownImageEntry(FunctionId),
    InvalidImageEntry(FunctionId),
    ImageEntrySymbolCount(usize),
    InvalidSymbolVisibility(SymbolId),
    NonCanonicalInterruptEntries,
    InvalidInterruptEntry(InterruptEntryId),
    InterruptHandlerRouteCount {
        handler: FunctionId,
        count: usize,
    },
    InvalidInterruptReachableCode {
        handler: FunctionId,
        function: FunctionId,
    },
    InvalidInterruptMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MachineWir validation failed with {} error(s)",
            self.0.len()
        )
    }
}

impl std::error::Error for ValidationErrors {}

#[cfg(test)]
mod tests {
    use super::*;
    use wrela_build_model::{LanguageRevision, Sha256Digest, TargetIdentity};

    fn fixture() -> (MachineWir, TargetPackage) {
        let digest = Sha256Digest::from_bytes([7; 32]);
        let target = TargetPackage::aarch64_qemu_virt_uefi(digest);
        let module = MachineWir {
            version: MACHINE_WIR_VERSION,
            name: "fixture".to_owned(),
            build: BuildIdentity {
                compiler: Sha256Digest::from_bytes([1; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: digest,
                standard_library: Sha256Digest::from_bytes([2; 32]),
                source_graph: Sha256Digest::from_bytes([3; 32]),
                request: Sha256Digest::from_bytes([4; 32]),
                profile: Sha256Digest::from_bytes([5; 32]),
            },
            target: MachineTarget {
                identity: "aarch64-qemu-virt-uefi".to_owned(),
                llvm_triple: "aarch64-unknown-uefi".to_owned(),
                data_layout: "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32".to_owned(),
                cpu: "cortex-a57".to_owned(),
                features: vec!["+reserve-x18".to_owned()],
                coff_machine: "arm64".to_owned(),
            },
            layout: DataLayout {
                pointer_bits: 64,
                pointer_alignment: 8,
                stack_alignment: 16,
                aggregate_alignment: 8,
                maximum_object_alignment: 16,
                endianness: Endianness::Little,
            },
            runtime: RuntimeRequirements::new(Vec::new()),
            types: vec![
                MachineType {
                    id: MachineTypeId(0),
                    kind: MachineTypeKind::Void,
                    size: 0,
                    alignment: 1,
                    source_name: None,
                },
                MachineType {
                    id: MachineTypeId(1),
                    kind: MachineTypeKind::Pointer {
                        address_space: 0,
                        pointee: None,
                    },
                    size: 8,
                    alignment: 8,
                    source_name: None,
                },
                MachineType {
                    id: MachineTypeId(2),
                    kind: MachineTypeKind::Integer { bits: 64 },
                    size: 8,
                    alignment: 8,
                    source_name: None,
                },
            ],
            sections: vec![
                Section {
                    id: SectionId(0),
                    name: ".text".to_owned(),
                    kind: SectionKind::Code,
                    alignment: 16,
                    reserved_bytes: 4096,
                    owner: "image".to_owned(),
                },
                Section {
                    id: SectionId(1),
                    name: INTERRUPT_ROUTE_SECTION.to_owned(),
                    kind: SectionKind::RuntimeMetadata,
                    alignment: INTERRUPT_ROUTE_LAYOUT.table_alignment,
                    reserved_bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                    owner: "runtime".to_owned(),
                },
            ],
            symbols: vec![
                Symbol {
                    id: SymbolId(0),
                    name: "wrela_image_entry".to_owned(),
                    visibility: SymbolVisibility::ImageEntry,
                    definition: SymbolDefinition::Function(FunctionId(0)),
                },
                Symbol {
                    id: SymbolId(1),
                    name: INTERRUPT_ROUTE_TABLE_SYMBOL.to_owned(),
                    visibility: SymbolVisibility::RuntimeMetadata,
                    definition: SymbolDefinition::SectionOffset {
                        section: SectionId(1),
                        offset: 0,
                        bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                    },
                },
            ],
            globals: Vec::new(),
            functions: vec![MachineFunction {
                id: FunctionId(0),
                flow_function: 0,
                role: MachineFunctionRole::ImageEntry,
                symbol: SymbolId(0),
                section: SectionId(0),
                linkage: Linkage::ExportedEntry,
                convention: CallingConvention::UefiAarch64,
                parameters: vec![ValueId(0), ValueId(1)],
                result: MachineTypeId(2),
                values: vec![
                    MachineValue {
                        id: ValueId(0),
                        ty: MachineTypeId(1),
                        source_name: None,
                    },
                    MachineValue {
                        id: ValueId(1),
                        ty: MachineTypeId(1),
                        source_name: None,
                    },
                    MachineValue {
                        id: ValueId(2),
                        ty: MachineTypeId(2),
                        source_name: None,
                    },
                ],
                stack_slots: Vec::new(),
                blocks: vec![MachineBlock {
                    id: BlockId(0),
                    parameters: Vec::new(),
                    instructions: vec![MachineInstruction {
                        id: InstructionId(0),
                        results: vec![ValueId(2)],
                        operation: MachineOperation::Immediate(MachineImmediate::Integer {
                            ty: MachineTypeId(2),
                            bytes_le: vec![0; 8],
                        }),
                        source: None,
                    }],
                    terminator: MachineTerminator::Return(vec![ValueId(2)]),
                }],
                entry: BlockId(0),
                stack_bytes: 0,
                source: None,
            }],
            interrupts: Vec::new(),
            proofs: Vec::new(),
            image_entry: FunctionId(0),
        };
        (module, target)
    }

    #[test]
    fn minimal_module_seals_against_exact_target() {
        let (module, target) = fixture();
        module
            .validate_for_target(&target)
            .expect("valid MachineWir fixture");
    }

    #[test]
    fn function_section_and_fixed_symbol_extent_are_not_codegen_choices() {
        let (mut module, target) = fixture();
        module.functions[0].section = SectionId(1);
        assert!(module.clone().validate_for_target(&target).is_err());

        module.functions[0].section = SectionId(0);
        if let SymbolDefinition::SectionOffset { bytes, .. } = &mut module.symbols[1].definition {
            *bytes = 0;
        }
        assert!(module.validate_for_target(&target).is_err());
    }

    #[test]
    fn interrupt_route_must_match_target_and_runtime_metadata() {
        let (mut module, target) = fixture();
        module.symbols.push(Symbol {
            id: SymbolId(2),
            name: "virtio_mmio_irq".to_owned(),
            visibility: SymbolVisibility::Private,
            definition: SymbolDefinition::Function(FunctionId(1)),
        });
        module.functions.push(MachineFunction {
            id: FunctionId(1),
            flow_function: 1,
            role: MachineFunctionRole::Isr(0),
            symbol: SymbolId(2),
            section: SectionId(0),
            linkage: Linkage::Private,
            convention: CallingConvention::InterruptHandler,
            parameters: Vec::new(),
            result: MachineTypeId(0),
            values: Vec::new(),
            stack_slots: Vec::new(),
            blocks: vec![MachineBlock {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(Vec::new()),
            }],
            entry: BlockId(0),
            stack_bytes: 0,
            source: None,
        });
        module.interrupts.push(InterruptEntry {
            id: InterruptEntryId(0),
            device: 0,
            target_binding: "virtio-mmio-0".to_owned(),
            line: 16,
            global_id: 48,
            handler: FunctionId(1),
        });
        module.sections[1].reserved_bytes = u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes)
            + u64::from(INTERRUPT_ROUTE_LAYOUT.record_bytes);
        if let SymbolDefinition::SectionOffset { bytes, .. } = &mut module.symbols[1].definition {
            *bytes = module.sections[1].reserved_bytes;
        }
        module
            .clone()
            .validate_for_target(&target)
            .expect("valid target-owned interrupt route");

        module.interrupts[0].global_id = 49;
        let errors = module
            .validate_for_target(&target)
            .expect_err("mismatched target route must fail");
        assert!(
            errors
                .0
                .contains(&ValidationError::InvalidInterruptEntry(InterruptEntryId(0)))
        );
    }
}
