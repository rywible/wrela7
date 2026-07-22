//! Exact, cooperatively cancellable equality for the sealer boundary.
//!
//! The public sealer accepts an implementation candidate and independently
//! recomputes the canonical output. Derived `PartialEq` is exact, but one large
//! retained vector or payload can make it unresponsive to cancellation. These
//! comparators preserve exact structural equality while polling every
//! aggregate element and every bounded byte chunk.

use wrela_build_model::BuildIdentity;
use wrela_machine_wir::{
    BackendProof, DataLayout, InterruptEntry, MachineActivationPlan, MachineBlock, MachineFunction,
    MachineGlobal, MachineImmediate, MachineInstruction, MachineOperation, MachineTarget,
    MachineTerminator, MachineTestEntry, MachineType, MachineTypeKind, MachineValue, MachineWir,
    Section, StackSlot, Symbol, SymbolDefinition,
};
use wrela_runtime_abi::RuntimeRequirements;

use crate::{
    CANCELLABLE_COPY_CHUNK_BYTES, LayoutSummary, MachineLowerError, MachineLoweringReport,
    RuntimeUse, check_cancelled,
};

fn slice_equal_by<T>(
    left: &[T],
    right: &[T],
    is_cancelled: &dyn Fn() -> bool,
    mut equal: impl FnMut(&T, &T) -> Result<bool, MachineLowerError>,
) -> Result<bool, MachineLowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        check_cancelled(is_cancelled)?;
        if !equal(left, right)? {
            return Ok(false);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(true)
}

fn fixed_slice_equal<T: PartialEq>(
    left: &[T],
    right: &[T],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    slice_equal_by(left, right, is_cancelled, |left, right| Ok(left == right))
}

fn bytes_equal(
    left: &[u8],
    right: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .chunks(CANCELLABLE_COPY_CHUNK_BYTES)
        .zip(right.chunks(CANCELLABLE_COPY_CHUNK_BYTES))
    {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(true)
}

fn text_equal(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    bytes_equal(left.as_bytes(), right.as_bytes(), is_cancelled)
}

fn option_text_equal(
    left: Option<&str>,
    right: Option<&str>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    match (left, right) {
        (Some(left), Some(right)) => text_equal(left, right, is_cancelled),
        (None, None) => Ok(true),
        (Some(_), None) | (None, Some(_)) => Ok(false),
    }
}

fn build_equal(
    left: &BuildIdentity,
    right: &BuildIdentity,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.compiler == right.compiler
        && left.language == right.language
        && text_equal(left.target.as_str(), right.target.as_str(), is_cancelled)?
        && left.target_package == right.target_package
        && left.standard_library == right.standard_library
        && left.source_graph == right.source_graph
        && left.request == right.request
        && left.profile == right.profile)
}

fn target_equal(
    left: &MachineTarget,
    right: &MachineTarget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(text_equal(&left.identity, &right.identity, is_cancelled)?
        && text_equal(&left.llvm_triple, &right.llvm_triple, is_cancelled)?
        && text_equal(&left.data_layout, &right.data_layout, is_cancelled)?
        && text_equal(&left.cpu, &right.cpu, is_cancelled)?
        && slice_equal_by(
            &left.features,
            &right.features,
            is_cancelled,
            |left, right| text_equal(left, right, is_cancelled),
        )?
        && text_equal(&left.coff_machine, &right.coff_machine, is_cancelled)?)
}

fn layout_equal(left: &DataLayout, right: &DataLayout) -> bool {
    left.pointer_bits == right.pointer_bits
        && left.pointer_alignment == right.pointer_alignment
        && left.stack_alignment == right.stack_alignment
        && left.aggregate_alignment == right.aggregate_alignment
        && left.maximum_object_alignment == right.maximum_object_alignment
        && left.endianness == right.endianness
}

fn runtime_equal(
    left: &RuntimeRequirements,
    right: &RuntimeRequirements,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.version == right.version
        && fixed_slice_equal(&left.intrinsics, &right.intrinsics, is_cancelled)?)
}

fn type_kind_equal(
    left: &MachineTypeKind,
    right: &MachineTypeKind,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(match (left, right) {
        (MachineTypeKind::Void, MachineTypeKind::Void)
        | (MachineTypeKind::Float32, MachineTypeKind::Float32)
        | (MachineTypeKind::Float64, MachineTypeKind::Float64) => true,
        (MachineTypeKind::Integer { bits: left }, MachineTypeKind::Integer { bits: right }) => {
            left == right
        }
        (
            MachineTypeKind::Pointer {
                address_space: left_space,
                pointee: left_pointee,
            },
            MachineTypeKind::Pointer {
                address_space: right_space,
                pointee: right_pointee,
            },
        ) => left_space == right_space && left_pointee == right_pointee,
        (
            MachineTypeKind::Vector {
                element: left_element,
                lanes: left_lanes,
            },
            MachineTypeKind::Vector {
                element: right_element,
                lanes: right_lanes,
            },
        ) => left_element == right_element && left_lanes == right_lanes,
        (
            MachineTypeKind::Array {
                element: left_element,
                length: left_length,
            },
            MachineTypeKind::Array {
                element: right_element,
                length: right_length,
            },
        ) => left_element == right_element && left_length == right_length,
        (
            MachineTypeKind::Struct {
                fields: left_fields,
                packed: left_packed,
            },
            MachineTypeKind::Struct {
                fields: right_fields,
                packed: right_packed,
            },
        ) => {
            left_packed == right_packed
                && fixed_slice_equal(left_fields, right_fields, is_cancelled)?
        }
        (
            MachineTypeKind::TaggedEnum {
                tag: left_tag,
                payload: left_payload,
                storage: left_storage,
                variants: left_variants,
                variant_payloads: left_variant_payloads,
            },
            MachineTypeKind::TaggedEnum {
                tag: right_tag,
                payload: right_payload,
                storage: right_storage,
                variants: right_variants,
                variant_payloads: right_variant_payloads,
            },
        ) => {
            left_tag == right_tag
                && left_payload == right_payload
                && left_storage == right_storage
                && left_variants == right_variants
                && fixed_slice_equal(left_variant_payloads, right_variant_payloads, is_cancelled)?
        }
        (
            MachineTypeKind::Function {
                parameters: left_parameters,
                result: left_result,
            },
            MachineTypeKind::Function {
                parameters: right_parameters,
                result: right_result,
            },
        ) => {
            left_result == right_result
                && fixed_slice_equal(left_parameters, right_parameters, is_cancelled)?
        }
        _ => false,
    })
}

fn type_equal(
    left: &MachineType,
    right: &MachineType,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && type_kind_equal(&left.kind, &right.kind, is_cancelled)?
        && left.size == right.size
        && left.alignment == right.alignment
        && option_text_equal(
            left.source_name.as_deref(),
            right.source_name.as_deref(),
            is_cancelled,
        )?)
}

fn section_equal(
    left: &Section,
    right: &Section,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, is_cancelled)?
        && left.kind == right.kind
        && left.alignment == right.alignment
        && left.reserved_bytes == right.reserved_bytes
        && text_equal(&left.owner, &right.owner, is_cancelled)?)
}

fn symbol_definition_equal(left: &SymbolDefinition, right: &SymbolDefinition) -> bool {
    match (left, right) {
        (SymbolDefinition::Function(left), SymbolDefinition::Function(right)) => left == right,
        (SymbolDefinition::Global(left), SymbolDefinition::Global(right)) => left == right,
        (
            SymbolDefinition::SectionOffset {
                section: left_section,
                offset: left_offset,
                bytes: left_bytes,
            },
            SymbolDefinition::SectionOffset {
                section: right_section,
                offset: right_offset,
                bytes: right_bytes,
            },
        ) => {
            left_section == right_section
                && left_offset == right_offset
                && left_bytes == right_bytes
        }
        (SymbolDefinition::ExternalRuntime(left), SymbolDefinition::ExternalRuntime(right)) => {
            left == right
        }
        _ => false,
    }
}

fn symbol_equal(
    left: &Symbol,
    right: &Symbol,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, is_cancelled)?
        && left.visibility == right.visibility
        && symbol_definition_equal(&left.definition, &right.definition))
}

fn immediate_equal(
    left: &MachineImmediate,
    right: &MachineImmediate,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    match (left, right) {
        (
            MachineImmediate::Integer {
                ty: left_ty,
                bytes_le: left_bytes,
            },
            MachineImmediate::Integer {
                ty: right_ty,
                bytes_le: right_bytes,
            },
        ) => Ok(left_ty == right_ty && bytes_equal(left_bytes, right_bytes, is_cancelled)?),
        (MachineImmediate::Float32(left), MachineImmediate::Float32(right)) => Ok(left == right),
        (MachineImmediate::Float64(left), MachineImmediate::Float64(right)) => Ok(left == right),
        (MachineImmediate::Null(left), MachineImmediate::Null(right))
        | (MachineImmediate::Zero(left), MachineImmediate::Zero(right)) => Ok(left == right),
        (MachineImmediate::SymbolAddress(left), MachineImmediate::SymbolAddress(right)) => {
            Ok(left == right)
        }
        (MachineImmediate::Bytes(left), MachineImmediate::Bytes(right)) => {
            bytes_equal(left, right, is_cancelled)
        }
        _ => Ok(false),
    }
}

fn global_equal(
    left: &MachineGlobal,
    right: &MachineGlobal,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && left.symbol == right.symbol
        && left.ty == right.ty
        && left.section == right.section
        && left.offset == right.offset
        && left.alignment == right.alignment
        && immediate_equal(&left.initializer, &right.initializer, is_cancelled)?)
}

fn operation_equal(
    left: &MachineOperation,
    right: &MachineOperation,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(match (left, right) {
        (MachineOperation::Immediate(left), MachineOperation::Immediate(right)) => {
            immediate_equal(left, right, is_cancelled)?
        }
        (
            MachineOperation::MakeEnum {
                ty: left_ty,
                variant: left_variant,
                payload: left_payload,
            },
            MachineOperation::MakeEnum {
                ty: right_ty,
                variant: right_variant,
                payload: right_payload,
            },
        ) => left_ty == right_ty && left_variant == right_variant && left_payload == right_payload,
        (MachineOperation::EnumTag { value: left }, MachineOperation::EnumTag { value: right })
        | (
            MachineOperation::EnumPayload { value: left },
            MachineOperation::EnumPayload { value: right },
        ) => left == right,
        (
            MachineOperation::MakeStruct {
                ty: left_ty,
                fields: left_fields,
            },
            MachineOperation::MakeStruct {
                ty: right_ty,
                fields: right_fields,
            },
        ) => left_ty == right_ty && fixed_slice_equal(left_fields, right_fields, is_cancelled)?,
        (
            MachineOperation::InsertField {
                aggregate: left_aggregate,
                field: left_field,
                value: left_value,
            },
            MachineOperation::InsertField {
                aggregate: right_aggregate,
                field: right_field,
                value: right_value,
            },
        ) => {
            left_aggregate == right_aggregate
                && left_field == right_field
                && left_value == right_value
        }
        (
            MachineOperation::ExtractField {
                aggregate: left_aggregate,
                field: left_field,
            },
            MachineOperation::ExtractField {
                aggregate: right_aggregate,
                field: right_field,
            },
        ) => left_aggregate == right_aggregate && left_field == right_field,
        (MachineOperation::Copy { value: left }, MachineOperation::Copy { value: right }) => {
            left == right
        }
        (
            MachineOperation::Unary {
                op: left_op,
                value: left_value,
            },
            MachineOperation::Unary {
                op: right_op,
                value: right_value,
            },
        ) => left_op == right_op && left_value == right_value,
        (
            MachineOperation::Arithmetic {
                op: left_op,
                left: left_left,
                right: left_right,
            },
            MachineOperation::Arithmetic {
                op: right_op,
                left: right_left,
                right: right_right,
            },
        ) => left_op == right_op && left_left == right_left && left_right == right_right,
        (
            MachineOperation::CheckedInteger {
                op: left_op,
                signedness: left_signedness,
                left: left_left,
                right: left_right,
                failure: left_failure,
            },
            MachineOperation::CheckedInteger {
                op: right_op,
                signedness: right_signedness,
                left: right_left,
                right: right_right,
                failure: right_failure,
            },
        ) => {
            left_op == right_op
                && left_signedness == right_signedness
                && left_left == right_left
                && left_right == right_right
                && left_failure == right_failure
        }
        (
            MachineOperation::IntegerCompare {
                predicate: left_predicate,
                left: left_left,
                right: left_right,
            },
            MachineOperation::IntegerCompare {
                predicate: right_predicate,
                left: right_left,
                right: right_right,
            },
        ) => {
            left_predicate == right_predicate
                && left_left == right_left
                && left_right == right_right
        }
        (
            MachineOperation::FloatCompare {
                predicate: left_predicate,
                left: left_left,
                right: left_right,
            },
            MachineOperation::FloatCompare {
                predicate: right_predicate,
                left: right_left,
                right: right_right,
            },
        ) => {
            left_predicate == right_predicate
                && left_left == right_left
                && left_right == right_right
        }
        (
            MachineOperation::Convert {
                op: left_op,
                value: left_value,
                destination: left_destination,
            },
            MachineOperation::Convert {
                op: right_op,
                value: right_value,
                destination: right_destination,
            },
        ) => {
            left_op == right_op
                && left_value == right_value
                && left_destination == right_destination
        }
        (
            MachineOperation::CheckedConvert {
                source: left_source,
                destination_kind: left_destination_kind,
                value: left_value,
                destination: left_destination,
                failure: left_failure,
            },
            MachineOperation::CheckedConvert {
                source: right_source,
                destination_kind: right_destination_kind,
                value: right_value,
                destination: right_destination,
                failure: right_failure,
            },
        ) => {
            left_source == right_source
                && left_destination_kind == right_destination_kind
                && left_value == right_value
                && left_destination == right_destination
                && left_failure == right_failure
        }
        (
            MachineOperation::Select {
                condition: left_condition,
                then_value: left_then,
                else_value: left_else,
            },
            MachineOperation::Select {
                condition: right_condition,
                then_value: right_then,
                else_value: right_else,
            },
        ) => {
            left_condition == right_condition && left_then == right_then && left_else == right_else
        }
        (
            MachineOperation::AddressOffset {
                base: left_base,
                byte_offset: left_offset,
                facts: left_facts,
            },
            MachineOperation::AddressOffset {
                base: right_base,
                byte_offset: right_offset,
                facts: right_facts,
            },
        ) => left_base == right_base && left_offset == right_offset && left_facts == right_facts,
        (
            MachineOperation::Load {
                address: left_address,
                ty: left_ty,
                semantics: left_semantics,
                facts: left_facts,
            },
            MachineOperation::Load {
                address: right_address,
                ty: right_ty,
                semantics: right_semantics,
                facts: right_facts,
            },
        ) => {
            left_address == right_address
                && left_ty == right_ty
                && left_semantics == right_semantics
                && left_facts == right_facts
        }
        (
            MachineOperation::Store {
                address: left_address,
                value: left_value,
                semantics: left_semantics,
                facts: left_facts,
            },
            MachineOperation::Store {
                address: right_address,
                value: right_value,
                semantics: right_semantics,
                facts: right_facts,
            },
        ) => {
            left_address == right_address
                && left_value == right_value
                && left_semantics == right_semantics
                && left_facts == right_facts
        }
        (
            MachineOperation::ActorReserve {
                mailbox: left_mailbox,
                actor: left_actor,
                method: left_method,
                proof: left_proof,
                failure: left_failure,
            },
            MachineOperation::ActorReserve {
                mailbox: right_mailbox,
                actor: right_actor,
                method: right_method,
                proof: right_proof,
                failure: right_failure,
            },
        ) => {
            left_mailbox == right_mailbox
                && left_actor == right_actor
                && left_method == right_method
                && left_proof == right_proof
                && left_failure == right_failure
        }
        (
            MachineOperation::ActorReplyRequest {
                slot: left_slot,
                mailbox: left_mailbox,
                actor: left_actor,
                method: left_method,
                permit: left_permit,
                reply: left_reply,
                failure: left_failure,
                duplicate_failure: left_duplicate,
            },
            MachineOperation::ActorReplyRequest {
                slot: right_slot,
                mailbox: right_mailbox,
                actor: right_actor,
                method: right_method,
                permit: right_permit,
                reply: right_reply,
                failure: right_failure,
                duplicate_failure: right_duplicate,
            },
        ) => {
            left_slot == right_slot
                && left_mailbox == right_mailbox
                && left_actor == right_actor
                && left_method == right_method
                && left_permit == right_permit
                && left_reply == right_reply
                && left_failure == right_failure
                && left_duplicate == right_duplicate
        }
        (
            MachineOperation::ActorReplyResolve {
                outcome: left_outcome,
                reply: left_reply,
            },
            MachineOperation::ActorReplyResolve {
                outcome: right_outcome,
                reply: right_reply,
            },
        ) => left_outcome == right_outcome && left_reply == right_reply,
        (
            MachineOperation::ActorCommit {
                reservation: left_reservation,
                mailbox: left_mailbox,
                actor: left_actor,
                method: left_method,
            },
            MachineOperation::ActorCommit {
                reservation: right_reservation,
                mailbox: right_mailbox,
                actor: right_actor,
                method: right_method,
            },
        ) => {
            left_reservation == right_reservation
                && left_mailbox == right_mailbox
                && left_actor == right_actor
                && left_method == right_method
        }
        (
            MachineOperation::MailboxReceive {
                mailbox: left_mailbox,
                actor: left_actor,
                method: left_method,
                failure: left_failure,
            },
            MachineOperation::MailboxReceive {
                mailbox: right_mailbox,
                actor: right_actor,
                method: right_method,
                failure: right_failure,
            },
        ) => {
            left_mailbox == right_mailbox
                && left_actor == right_actor
                && left_method == right_method
                && left_failure == right_failure
        }
        (
            MachineOperation::MailboxDispatch {
                mailbox: left_mailbox,
                actor: left_actor,
                method: left_method,
            },
            MachineOperation::MailboxDispatch {
                mailbox: right_mailbox,
                actor: right_actor,
                method: right_method,
            },
        ) => {
            left_mailbox == right_mailbox
                && left_actor == right_actor
                && left_method == right_method
        }
        (
            MachineOperation::MemoryCopy {
                destination: left_destination,
                source: left_source,
                bytes: left_bytes,
                destination_alignment: left_destination_alignment,
                source_alignment: left_source_alignment,
                non_overlapping: left_non_overlapping,
                proof: left_proof,
            },
            MachineOperation::MemoryCopy {
                destination: right_destination,
                source: right_source,
                bytes: right_bytes,
                destination_alignment: right_destination_alignment,
                source_alignment: right_source_alignment,
                non_overlapping: right_non_overlapping,
                proof: right_proof,
            },
        ) => {
            left_destination == right_destination
                && left_source == right_source
                && left_bytes == right_bytes
                && left_destination_alignment == right_destination_alignment
                && left_source_alignment == right_source_alignment
                && left_non_overlapping == right_non_overlapping
                && left_proof == right_proof
        }
        (
            MachineOperation::MemorySet {
                destination: left_destination,
                byte: left_byte,
                bytes: left_bytes,
                alignment: left_alignment,
            },
            MachineOperation::MemorySet {
                destination: right_destination,
                byte: right_byte,
                bytes: right_bytes,
                alignment: right_alignment,
            },
        ) => {
            left_destination == right_destination
                && left_byte == right_byte
                && left_bytes == right_bytes
                && left_alignment == right_alignment
        }
        (MachineOperation::StackAddress(left), MachineOperation::StackAddress(right)) => {
            left == right
        }
        (MachineOperation::GlobalAddress(left), MachineOperation::GlobalAddress(right)) => {
            left == right
        }
        (
            MachineOperation::Call {
                function: left_function,
                arguments: left_arguments,
                convention: left_convention,
            },
            MachineOperation::Call {
                function: right_function,
                arguments: right_arguments,
                convention: right_convention,
            },
        ) => {
            left_function == right_function
                && left_convention == right_convention
                && fixed_slice_equal(left_arguments, right_arguments, is_cancelled)?
        }
        (
            MachineOperation::RuntimeCall {
                intrinsic: left_intrinsic,
                arguments: left_arguments,
            },
            MachineOperation::RuntimeCall {
                intrinsic: right_intrinsic,
                arguments: right_arguments,
            },
        ) => {
            left_intrinsic == right_intrinsic
                && fixed_slice_equal(left_arguments, right_arguments, is_cancelled)?
        }
        (
            MachineOperation::TestAssert {
                condition: left_condition,
                failure: left_failure,
            },
            MachineOperation::TestAssert {
                condition: right_condition,
                failure: right_failure,
            },
        ) => left_condition == right_condition && left_failure == right_failure,
        (MachineOperation::Fence(left), MachineOperation::Fence(right)) => left == right,
        _ => false,
    })
}

fn instruction_equal(
    left: &MachineInstruction,
    right: &MachineInstruction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && fixed_slice_equal(&left.results, &right.results, is_cancelled)?
        && operation_equal(&left.operation, &right.operation, is_cancelled)?
        && left.source == right.source)
}

fn terminator_equal(
    left: &MachineTerminator,
    right: &MachineTerminator,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(match (left, right) {
        (
            MachineTerminator::Jump {
                block: left_block,
                arguments: left_arguments,
            },
            MachineTerminator::Jump {
                block: right_block,
                arguments: right_arguments,
            },
        ) => {
            left_block == right_block
                && fixed_slice_equal(left_arguments, right_arguments, is_cancelled)?
        }
        (
            MachineTerminator::Branch {
                condition: left_condition,
                then_block: left_then_block,
                then_arguments: left_then_arguments,
                else_block: left_else_block,
                else_arguments: left_else_arguments,
            },
            MachineTerminator::Branch {
                condition: right_condition,
                then_block: right_then_block,
                then_arguments: right_then_arguments,
                else_block: right_else_block,
                else_arguments: right_else_arguments,
            },
        ) => {
            left_condition == right_condition
                && left_then_block == right_then_block
                && fixed_slice_equal(left_then_arguments, right_then_arguments, is_cancelled)?
                && left_else_block == right_else_block
                && fixed_slice_equal(left_else_arguments, right_else_arguments, is_cancelled)?
        }
        (
            MachineTerminator::Switch {
                value: left_value,
                cases: left_cases,
                default: left_default,
                default_arguments: left_default_arguments,
            },
            MachineTerminator::Switch {
                value: right_value,
                cases: right_cases,
                default: right_default,
                default_arguments: right_default_arguments,
            },
        ) => {
            left_value == right_value
                && slice_equal_by(
                    left_cases,
                    right_cases,
                    is_cancelled,
                    |(left_value, left_block, left_arguments),
                     (right_value, right_block, right_arguments)| {
                        Ok(left_value == right_value
                            && left_block == right_block
                            && fixed_slice_equal(left_arguments, right_arguments, is_cancelled)?)
                    },
                )?
                && left_default == right_default
                && fixed_slice_equal(
                    left_default_arguments,
                    right_default_arguments,
                    is_cancelled,
                )?
        }
        (MachineTerminator::Return(left), MachineTerminator::Return(right)) => {
            fixed_slice_equal(left, right, is_cancelled)?
        }
        (
            MachineTerminator::TailCall {
                function: left_function,
                arguments: left_arguments,
            },
            MachineTerminator::TailCall {
                function: right_function,
                arguments: right_arguments,
            },
        ) => {
            left_function == right_function
                && fixed_slice_equal(left_arguments, right_arguments, is_cancelled)?
        }
        (MachineTerminator::Unreachable, MachineTerminator::Unreachable) => true,
        _ => false,
    })
}

fn block_equal(
    left: &MachineBlock,
    right: &MachineBlock,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && fixed_slice_equal(&left.parameters, &right.parameters, is_cancelled)?
        && slice_equal_by(
            &left.instructions,
            &right.instructions,
            is_cancelled,
            |left, right| instruction_equal(left, right, is_cancelled),
        )?
        && terminator_equal(&left.terminator, &right.terminator, is_cancelled)?)
}

fn value_equal(
    left: &MachineValue,
    right: &MachineValue,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && left.ty == right.ty
        && option_text_equal(
            left.source_name.as_deref(),
            right.source_name.as_deref(),
            is_cancelled,
        )?)
}

fn stack_slot_equal(
    left: &StackSlot,
    right: &StackSlot,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && left.size == right.size
        && left.alignment == right.alignment
        && option_text_equal(
            left.source_name.as_deref(),
            right.source_name.as_deref(),
            is_cancelled,
        )?
        && fixed_slice_equal(&left.live_states, &right.live_states, is_cancelled)?
        && left.overlay_group == right.overlay_group)
}

fn function_equal(
    left: &MachineFunction,
    right: &MachineFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && left.flow_function == right.flow_function
        && left.origin == right.origin
        && left.role == right.role
        && left.symbol == right.symbol
        && left.section == right.section
        && left.linkage == right.linkage
        && left.convention == right.convention
        && fixed_slice_equal(&left.parameters, &right.parameters, is_cancelled)?
        && left.result == right.result
        && fixed_slice_equal(&left.proofs, &right.proofs, is_cancelled)?
        && slice_equal_by(&left.values, &right.values, is_cancelled, |left, right| {
            value_equal(left, right, is_cancelled)
        })?
        && slice_equal_by(
            &left.stack_slots,
            &right.stack_slots,
            is_cancelled,
            |left, right| stack_slot_equal(left, right, is_cancelled),
        )?
        && slice_equal_by(&left.blocks, &right.blocks, is_cancelled, |left, right| {
            block_equal(left, right, is_cancelled)
        })?
        && left.entry == right.entry
        && left.stack_bytes == right.stack_bytes
        && left.source == right.source)
}

fn interrupt_equal(
    left: &InterruptEntry,
    right: &InterruptEntry,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && left.device == right.device
        && text_equal(&left.target_binding, &right.target_binding, is_cancelled)?
        && left.line == right.line
        && left.global_id == right.global_id
        && left.handler == right.handler)
}

fn test_equal(
    left: &MachineTestEntry,
    right: &MachineTestEntry,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, is_cancelled)?
        && left.function == right.function
        && left.kind == right.kind
        && left.source == right.source
        && left.timeout_ns == right.timeout_ns)
}

fn proof_equal(
    left: &BackendProof,
    right: &BackendProof,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && fixed_slice_equal(&left.source_proofs, &right.source_proofs, is_cancelled)?
        && left.kind == right.kind
        && fixed_slice_equal(&left.depends_on, &right.depends_on, is_cancelled)?
        && left.bound == right.bound
        && fixed_slice_equal(&left.sources, &right.sources, is_cancelled)?
        && text_equal(&left.statement, &right.statement, is_cancelled)?
        && left.source == right.source)
}

fn activation_equal(left: &MachineActivationPlan, right: &MachineActivationPlan) -> bool {
    left == right
}

fn region_storage_equal(
    left: &wrela_machine_wir::MachineRegionStorage,
    right: &wrela_machine_wir::MachineRegionStorage,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.id == right.id
        && left.flow_region == right.flow_region
        && text_equal(&left.name, &right.name, is_cancelled)?
        && left.kind == right.kind
        && left.global == right.global
        && left.symbol == right.symbol
        && left.section == right.section
        && left.ty == right.ty
        && left.capacity_proof == right.capacity_proof
        && left.capacity_units == right.capacity_units
        && left.bytes_per_unit == right.bytes_per_unit
        && left.capacity_bytes == right.capacity_bytes
        && left.alignment == right.alignment
        && left.source == right.source
        && left.capacity_source == right.capacity_source)
}

pub(super) fn machine_wir_equal(
    left: &MachineWir,
    right: &MachineWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    check_cancelled(is_cancelled)?;
    Ok(left.version == right.version
        && text_equal(&left.name, &right.name, is_cancelled)?
        && build_equal(&left.build, &right.build, is_cancelled)?
        && target_equal(&left.target, &right.target, is_cancelled)?
        && layout_equal(&left.layout, &right.layout)
        && runtime_equal(&left.runtime, &right.runtime, is_cancelled)?
        && slice_equal_by(&left.types, &right.types, is_cancelled, |left, right| {
            type_equal(left, right, is_cancelled)
        })?
        && slice_equal_by(
            &left.sections,
            &right.sections,
            is_cancelled,
            |left, right| section_equal(left, right, is_cancelled),
        )?
        && slice_equal_by(
            &left.symbols,
            &right.symbols,
            is_cancelled,
            |left, right| symbol_equal(left, right, is_cancelled),
        )?
        && slice_equal_by(
            &left.globals,
            &right.globals,
            is_cancelled,
            |left, right| global_equal(left, right, is_cancelled),
        )?
        && slice_equal_by(
            &left.functions,
            &right.functions,
            is_cancelled,
            |left, right| function_equal(left, right, is_cancelled),
        )?
        && slice_equal_by(
            &left.activations,
            &right.activations,
            is_cancelled,
            |left, right| Ok(activation_equal(left, right)),
        )?
        && slice_equal_by(
            &left.schedulers,
            &right.schedulers,
            is_cancelled,
            |left, right| Ok(left == right),
        )?
        && slice_equal_by(
            &left.region_storage,
            &right.region_storage,
            is_cancelled,
            |left, right| region_storage_equal(left, right, is_cancelled),
        )?
        && slice_equal_by(
            &left.interrupts,
            &right.interrupts,
            is_cancelled,
            |left, right| interrupt_equal(left, right, is_cancelled),
        )?
        && slice_equal_by(&left.tests, &right.tests, is_cancelled, |left, right| {
            test_equal(left, right, is_cancelled)
        })?
        && slice_equal_by(&left.proofs, &right.proofs, is_cancelled, |left, right| {
            proof_equal(left, right, is_cancelled)
        })?
        && left.image_entry == right.image_entry)
}

fn layout_summary_equal(left: &LayoutSummary, right: &LayoutSummary) -> bool {
    left.code_bytes_upper_bound == right.code_bytes_upper_bound
        && left.read_only_bytes == right.read_only_bytes
        && left.writable_bytes == right.writable_bytes
        && left.zero_fill_bytes == right.zero_fill_bytes
        && left.maximum_stack_bytes == right.maximum_stack_bytes
        && left.maximum_alignment == right.maximum_alignment
}

fn runtime_use_equal(
    left: &RuntimeUse,
    right: &RuntimeUse,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(left.intrinsic == right.intrinsic
        && left.call_sites == right.call_sites
        && text_equal(&left.reason, &right.reason, is_cancelled)?)
}

pub(super) fn report_equal(
    left: &MachineLoweringReport,
    right: &MachineLoweringReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(
        text_equal(&left.target_identity, &right.target_identity, is_cancelled)?
            && left.types_laid_out == right.types_laid_out
            && left.functions_lowered == right.functions_lowered
            && layout_summary_equal(&left.layout, &right.layout)
            && runtime_equal(&left.runtime, &right.runtime, is_cancelled)?
            && slice_equal_by(
                &left.runtime_uses,
                &right.runtime_uses,
                is_cancelled,
                |left, right| runtime_use_equal(left, right, is_cancelled),
            )?,
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn long_equal_payload_comparison_cancels_between_chunks() {
        let payload = vec![0x5a; CANCELLABLE_COPY_CHUNK_BYTES * 3];
        let polls = Cell::new(0u64);
        assert_eq!(
            bytes_equal(&payload, &payload, &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next == 2
            }),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(polls.get(), 2);
    }
}
