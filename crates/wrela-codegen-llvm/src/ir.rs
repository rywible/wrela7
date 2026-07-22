use wrela_machine_wir::{
    ArithmeticOp, AtomicOrdering, CallingConvention, CheckedIntegerOp, CheckedNumericKind,
    ConversionOp, FloatPredicate, FunctionId, GlobalId, IntegerPredicate, IntegerSignedness,
    MachineBlock, MachineFence, MachineFunction, MachineImmediate, MachineInstruction,
    MachineOperation, MachineTerminator, MachineTypeId, MachineTypeKind, MachineUnaryOp,
    MemorySemantics, ScalarFailureProvenance, SymbolDefinition, ValueId,
};
use wrela_runtime_abi::{AbiType, RuntimeFatalCode, RuntimeIntrinsic};

use crate::{CodegenError, CodegenRequest};

const INTERRUPT_ASSEMBLY: &str = "module asm \".section .rdata$wrela_irq,\\22dr\\22\\0A.p2align 3\\0A.globl wrela_rt_v2_interrupt_route_table\\0Awrela_rt_v2_interrupt_route_table:\\0A.long 0\\0A.long 0\\0A\"\n\n";

#[derive(Debug)]
struct IrText {
    bytes: Vec<u8>,
    limit: u64,
}

impl IrText {
    fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn push(&mut self, value: &str) -> Result<(), CodegenError> {
        self.push_bytes(value.as_bytes())
    }

    fn push_cancellable(
        &mut self,
        value: &str,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), CodegenError> {
        self.push_bytes_cancellable(value.as_bytes(), is_cancelled)
    }

    fn push_bytes(&mut self, value: &[u8]) -> Result<(), CodegenError> {
        self.reserve_append(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn push_bytes_cancellable(
        &mut self,
        value: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), CodegenError> {
        check_cancelled(is_cancelled)?;
        self.reserve_append(value.len())?;
        check_cancelled(is_cancelled)?;
        for chunk in value.chunks(64 * 1024) {
            check_cancelled(is_cancelled)?;
            self.bytes.extend_from_slice(chunk);
        }
        check_cancelled(is_cancelled)
    }

    fn reserve_append(&mut self, additional: usize) -> Result<(), CodegenError> {
        let actual = u64::try_from(self.bytes.len())
            .ok()
            .and_then(|bytes| bytes.checked_add(u64::try_from(additional).ok()?))
            .unwrap_or(u64::MAX);
        if actual > self.limit {
            return Err(CodegenError::ResourceLimit {
                resource: "LLVM IR bytes",
                limit: self.limit,
                actual,
            });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| CodegenError::ResourceLimit {
                resource: "LLVM IR bytes",
                limit: self.limit,
                actual,
            })
    }

    fn number(&mut self, value: u128) -> Result<(), CodegenError> {
        let mut digits = [0u8; 39];
        let mut cursor = digits.len();
        let mut remaining = value;
        loop {
            cursor = cursor
                .checked_sub(1)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "an integer exceeded its text buffer",
                ))?;
            let digit = u8::try_from(remaining % 10).map_err(|_| {
                CodegenError::UnsupportedMachineContract("an integer digit did not fit in u8")
            })?;
            *digits
                .get_mut(cursor)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "an integer digit escaped its text buffer",
                ))? = b'0' + digit;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        self.push_bytes(
            digits
                .get(cursor..)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "an integer escaped its text buffer",
                ))?,
        )
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, Copy)]
struct IncomingEdge<'a> {
    target: u32,
    predecessor: u32,
    checked_continuation: Option<u32>,
    arguments: &'a [ValueId],
}

pub(super) fn render_module(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, CodegenError> {
    let machine = request.module.as_wir();
    let mut ir = IrText::new(request.options.maximum_ir_bytes);
    render_target_header(
        &mut ir,
        request.target.llvm_data_layout(),
        request.target.llvm_triple(),
        is_cancelled,
    )?;
    ir.push(INTERRUPT_ASSEMBLY)?;
    render_runtime_declarations(&mut ir, request, is_cancelled)?;
    render_checked_intrinsic_declarations(&mut ir, request, is_cancelled)?;
    render_globals(&mut ir, request, is_cancelled)?;

    for function in &machine.functions {
        check_cancelled(is_cancelled)?;
        render_function(&mut ir, request, function, is_cancelled)?;
    }
    check_cancelled(is_cancelled)?;
    Ok(ir.finish())
}

fn render_target_header(
    ir: &mut IrText,
    data_layout: &str,
    triple: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    check_cancelled(is_cancelled)?;
    ir.push("target datalayout = \"")?;
    ir.push_cancellable(data_layout, is_cancelled)?;
    ir.push("\"\ntarget triple = \"")?;
    ir.push_cancellable(triple, is_cancelled)?;
    ir.push("\"\n\n")?;
    check_cancelled(is_cancelled)
}

fn render_checked_intrinsic_declarations(
    ir: &mut IrText,
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let mut needs_ctlz_i128 = false;
    for function in &machine.functions {
        check_cancelled(is_cancelled)?;
        for_each_instruction(&function.blocks, is_cancelled, |instruction| {
            let MachineOperation::CheckedConvert { source, value, .. } = instruction.operation
            else {
                return Ok(());
            };
            if matches!(
                source,
                CheckedNumericKind::UnsignedInteger | CheckedNumericKind::SignedInteger
            ) && integer_bits(machine, value_type(function, value)?)? == 128
            {
                needs_ctlz_i128 = true;
            }
            Ok(())
        })?;
    }
    if needs_ctlz_i128 {
        ir.push("declare i128 @llvm.ctlz.i128(i128, i1)\n\n")?;
    }
    Ok(())
}

fn for_each_instruction(
    blocks: &[MachineBlock],
    is_cancelled: &dyn Fn() -> bool,
    mut visit: impl FnMut(&MachineInstruction) -> Result<(), CodegenError>,
) -> Result<(), CodegenError> {
    for block in blocks {
        check_cancelled(is_cancelled)?;
        for instruction in &block.instructions {
            check_cancelled(is_cancelled)?;
            visit(instruction)?;
        }
    }
    check_cancelled(is_cancelled)
}

fn render_runtime_declarations(
    ir: &mut IrText,
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    for (intrinsic_index, intrinsic) in machine.runtime.intrinsics.iter().enumerate() {
        check_periodically(intrinsic_index, is_cancelled)?;
        let signature = intrinsic.signature();
        let symbol = runtime_symbol(machine, *intrinsic)?;
        ir.push("declare ")?;
        render_abi_type(ir, signature.result)?;
        ir.push(" @")?;
        ir.push_cancellable(symbol, is_cancelled)?;
        ir.push("(")?;
        for (index, parameter) in signature.parameters.iter().enumerate() {
            check_periodically(index, is_cancelled)?;
            if index != 0 {
                ir.push(", ")?;
            }
            render_abi_type(ir, *parameter)?;
        }
        ir.push(")")?;
        if !signature.may_return {
            ir.push(" noreturn")?;
        }
        ir.push("\n")?;
    }
    if !machine.runtime.intrinsics.is_empty() {
        ir.push("\n")?;
    }
    Ok(())
}

fn render_globals(
    ir: &mut IrText,
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let actual = u64::try_from(machine.globals.len()).unwrap_or(u64::MAX);
    let mut globals = Vec::new();
    check_cancelled(is_cancelled)?;
    globals
        .try_reserve_exact(machine.globals.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "LLVM global render order",
            limit: u64::from(request.options.maximum_symbols),
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for (index, global) in machine.globals.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        globals.push((global.section.0, index, global));
    }
    crate::cancellable_sort_by(
        &mut globals,
        |left, right| Ok((left.0, left.1).cmp(&(right.0, right.1))),
        is_cancelled,
    )?;

    let mut global_cursor = 0usize;
    for (section_index, section) in machine.sections.iter().enumerate() {
        check_periodically(section_index, is_cancelled)?;
        let section_start = global_cursor;
        while let Some((section_id, _, _)) = globals.get(global_cursor) {
            check_periodically(global_cursor, is_cancelled)?;
            if *section_id < section.id.0 {
                return Err(CodegenError::UnsupportedMachineContract(
                    "LLVM global render order escaped its validated section",
                ));
            }
            if *section_id > section.id.0 {
                break;
            }
            global_cursor =
                global_cursor
                    .checked_add(1)
                    .ok_or(CodegenError::UnsupportedMachineContract(
                        "LLVM global render order overflowed",
                    ))?;
        }
        if !matches!(
            section.kind,
            wrela_machine_wir::SectionKind::ReadOnlyData
                | wrela_machine_wir::SectionKind::WritableData
                | wrela_machine_wir::SectionKind::ZeroFill
        ) {
            if global_cursor != section_start {
                return Err(CodegenError::UnsupportedMachineContract(
                    "a global reached an unsupported LLVM section",
                ));
            }
            continue;
        }
        let section_globals = globals.get(section_start..global_cursor).ok_or(
            CodegenError::UnsupportedMachineContract(
                "LLVM global render range escaped its validated module",
            ),
        )?;
        for (global_index, (_, _, global)) in section_globals.iter().enumerate() {
            check_periodically(global_index, is_cancelled)?;
            let symbol = symbol_name(machine, global.symbol.0)?;
            ir.push("@")?;
            ir.push_cancellable(symbol, is_cancelled)?;
            ir.push(match section.kind {
                wrela_machine_wir::SectionKind::ReadOnlyData => " = internal constant ",
                wrela_machine_wir::SectionKind::WritableData
                | wrela_machine_wir::SectionKind::ZeroFill => " = internal global ",
                _ => {
                    return Err(CodegenError::UnsupportedMachineContract(
                        "an unsupported static section reached LLVM rendering",
                    ));
                }
            })?;
            render_type(ir, machine, global.ty)?;
            match (&global.initializer, section.kind) {
                (MachineImmediate::Bytes(bytes), wrela_machine_wir::SectionKind::ReadOnlyData) => {
                    ir.push(" c\"")?;
                    for (byte_index, byte) in bytes.iter().enumerate() {
                        check_periodically(byte_index, is_cancelled)?;
                        render_escaped_byte(ir, *byte)?;
                    }
                    ir.push("\"")?;
                }
                (
                    MachineImmediate::Zero(_),
                    wrela_machine_wir::SectionKind::WritableData
                    | wrela_machine_wir::SectionKind::ZeroFill,
                ) => ir.push(" zeroinitializer")?,
                _ => {
                    return Err(CodegenError::UnsupportedMachineContract(
                        "a static global initializer disagrees with its section",
                    ));
                }
            }
            ir.push(", section \"")?;
            ir.push_cancellable(&section.name, is_cancelled)?;
            ir.push("\", align ")?;
            ir.number(u128::from(if global_index == 0 {
                section.alignment
            } else {
                global.alignment
            }))?;
            ir.push("\n")?;
        }
    }
    if global_cursor != globals.len() {
        return Err(CodegenError::UnsupportedMachineContract(
            "LLVM global render order outlived its validated sections",
        ));
    }
    if !machine.globals.is_empty() {
        ir.push("\n")?;
    }
    Ok(())
}

fn render_escaped_byte(ir: &mut IrText, byte: u8) -> Result<(), CodegenError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let high = HEX.get(usize::from(byte >> 4)).copied().ok_or(
        CodegenError::UnsupportedMachineContract("an escaped byte had an invalid high nibble"),
    )?;
    let low = HEX.get(usize::from(byte & 0x0f)).copied().ok_or(
        CodegenError::UnsupportedMachineContract("an escaped byte had an invalid low nibble"),
    )?;
    ir.push_bytes(&[b'\\', high, low])
}

fn render_function(
    ir: &mut IrText,
    request: &CodegenRequest<'_>,
    function: &MachineFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let symbol = symbol_name(machine, function.symbol.0)?;
    let section = machine_section(machine, function.section.0)?;
    ir.push("define ")?;
    if function.id == machine.image_entry {
        ir.push("dso_local ")?;
    } else {
        ir.push("internal ")?;
    }
    render_calling_convention(ir, function.convention)?;
    render_type(ir, machine, function.result)?;
    ir.push(" @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push("(")?;
    for (index, parameter) in function.parameters.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if index != 0 {
            ir.push(", ")?;
        }
        render_type(ir, machine, value_type(function, *parameter)?)?;
        ir.push(" %v")?;
        ir.number(u128::from(parameter.0))?;
    }
    ir.push(") section \"")?;
    ir.push_cancellable(&section.name, is_cancelled)?;
    ir.push("\" align ")?;
    ir.number(u128::from(section.alignment))?;
    ir.push(" {\n")?;

    let edges = incoming_edges(function, request.options.maximum_model_edges, is_cancelled)?;
    render_block(
        ir,
        request,
        function,
        function.entry.0,
        &edges,
        is_cancelled,
    )?;
    for block in &function.blocks {
        check_cancelled(is_cancelled)?;
        if block.id != function.entry {
            render_block(ir, request, function, block.id.0, &edges, is_cancelled)?;
        }
    }
    ir.push("}\n\n")
}

fn render_block(
    ir: &mut IrText,
    request: &CodegenRequest<'_>,
    function: &MachineFunction,
    block_id: u32,
    edges: &[IncomingEdge<'_>],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let block = function_block(function, block_id)?;
    ir.push("b")?;
    ir.number(u128::from(block.id.0))?;
    ir.push(":\n")?;
    if block.id == function.entry {
        for slot in &function.stack_slots {
            check_cancelled(is_cancelled)?;
            ir.push("  %s")?;
            ir.number(u128::from(slot.id.0))?;
            ir.push(" = alloca [")?;
            ir.number(u128::from(slot.size))?;
            ir.push(" x i8], align ")?;
            ir.number(u128::from(slot.alignment))?;
            ir.push("\n")?;
        }
    }
    let incoming_start = edges.partition_point(|edge| edge.target < block.id.0);
    let incoming_end = edges.partition_point(|edge| edge.target <= block.id.0);
    let incoming =
        edges
            .get(incoming_start..incoming_end)
            .ok_or(CodegenError::UnsupportedMachineContract(
                "LLVM incoming-edge range escaped its validated function",
            ))?;
    for (parameter_index, parameter) in block.parameters.iter().enumerate() {
        check_periodically(parameter_index, is_cancelled)?;
        ir.push("  %v")?;
        ir.number(u128::from(parameter.0))?;
        ir.push(" = phi ")?;
        render_type(ir, machine, value_type(function, *parameter)?)?;
        ir.push(" ")?;
        let mut first = true;
        let mut previous = None;
        for (edge_index, edge) in incoming.iter().enumerate() {
            check_periodically(edge_index, is_cancelled)?;
            if previous == Some(edge.predecessor) {
                continue;
            }
            previous = Some(edge.predecessor);
            if !first {
                ir.push(", ")?;
            }
            first = false;
            ir.push("[ %v")?;
            let argument = edge.arguments.get(parameter_index).ok_or(
                CodegenError::UnsupportedMachineContract(
                    "a CFG edge omitted a validated block argument",
                ),
            )?;
            ir.number(u128::from(argument.0))?;
            ir.push(", %")?;
            if let Some(instruction) = edge.checked_continuation {
                ir.push("i")?;
                ir.number(u128::from(instruction))?;
                ir.push("_ok")?;
            } else {
                ir.push("b")?;
                ir.number(u128::from(edge.predecessor))?;
            }
            ir.push(" ]")?;
        }
        ir.push("\n")?;
    }
    for instruction in &block.instructions {
        check_cancelled(is_cancelled)?;
        render_instruction(ir, request, function, instruction, is_cancelled)?;
    }
    render_terminator(
        ir,
        request,
        function,
        block.id.0,
        &block.terminator,
        is_cancelled,
    )?;
    Ok(())
}

fn render_instruction(
    ir: &mut IrText,
    request: &CodegenRequest<'_>,
    function: &MachineFunction,
    instruction: &wrela_machine_wir::MachineInstruction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let result = instruction.results.first().copied();
    match &instruction.operation {
        MachineOperation::Immediate(immediate) => {
            let result = required_result(result)?;
            ir.push("  %v")?;
            ir.number(u128::from(result.0))?;
            ir.push(" = ")?;
            render_immediate(ir, machine, function, result, immediate, is_cancelled)?;
        }
        MachineOperation::Unary { op, value } => {
            render_unary(ir, machine, function, instruction.id.0, result, *op, *value)?
        }
        MachineOperation::Arithmetic { op, left, right } => {
            render_result(ir, result)?;
            ir.push(arithmetic_opcode(*op))?;
            ir.push(" ")?;
            render_value_type(ir, machine, function, *left)?;
            render_value_pair(ir, *left, *right)?;
        }
        MachineOperation::CheckedInteger {
            op,
            signedness,
            left,
            right,
            failure,
        } => render_checked_integer(
            ir,
            machine,
            function,
            instruction.id.0,
            result,
            *op,
            *signedness,
            *left,
            *right,
            *failure,
            is_cancelled,
        )?,
        MachineOperation::IntegerCompare {
            predicate,
            left,
            right,
        } => {
            render_comparison(
                ir,
                machine,
                function,
                instruction.id.0,
                result,
                "icmp",
                integer_predicate(*predicate),
                *left,
                *right,
            )?;
        }
        MachineOperation::FloatCompare {
            predicate,
            left,
            right,
        } => {
            render_comparison(
                ir,
                machine,
                function,
                instruction.id.0,
                result,
                "fcmp",
                float_predicate(*predicate),
                *left,
                *right,
            )?;
        }
        MachineOperation::Convert {
            op,
            value,
            destination,
        } => render_conversion(ir, machine, function, result, *op, *value, *destination)?,
        MachineOperation::CheckedConvert {
            source,
            destination_kind,
            value,
            destination,
            failure,
        } => render_checked_conversion(
            ir,
            machine,
            function,
            instruction.id.0,
            result,
            *source,
            *destination_kind,
            *value,
            *destination,
            *failure,
            is_cancelled,
        )?,
        MachineOperation::Copy { value } => {
            render_result(ir, result)?;
            ir.push("select i1 true, ")?;
            render_value_type(ir, machine, function, *value)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            ir.push(", ")?;
            render_value_type(ir, machine, function, *value)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            ir.push("\n")?;
        }
        MachineOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            render_bool_test(ir, instruction.id.0, "select", *condition)?;
            render_result(ir, result)?;
            ir.push("select i1 %t")?;
            ir.number(u128::from(instruction.id.0))?;
            ir.push("_select, ")?;
            render_value_type(ir, machine, function, *then_value)?;
            ir.push(" %v")?;
            ir.number(u128::from(then_value.0))?;
            ir.push(", ")?;
            render_value_type(ir, machine, function, *else_value)?;
            ir.push(" %v")?;
            ir.number(u128::from(else_value.0))?;
            ir.push("\n")?;
        }
        MachineOperation::MakeStruct { ty, fields } => {
            let result = required_result(result)?;
            let mut current = None;
            for (index, field) in fields.iter().enumerate() {
                if index + 1 == fields.len() {
                    ir.push("  %v")?;
                    ir.number(u128::from(result.0))?;
                } else {
                    ir.push("  %t")?;
                    ir.number(u128::from(instruction.id.0))?;
                    ir.push("_struct_")?;
                    ir.number(index as u128)?;
                }
                ir.push(" = insertvalue ")?;
                render_type(ir, machine, *ty)?;
                match current {
                    Some(previous) => {
                        ir.push(" %t")?;
                        ir.number(u128::from(instruction.id.0))?;
                        ir.push("_struct_")?;
                        ir.number(previous as u128)?;
                    }
                    None => ir.push(" poison")?,
                }
                ir.push(", ")?;
                render_value_type(ir, machine, function, *field)?;
                ir.push(" %v")?;
                ir.number(u128::from(field.0))?;
                ir.push(", ")?;
                ir.number(index as u128)?;
                ir.push("\n")?;
                current = Some(index);
            }
        }
        MachineOperation::MakeArray { ty, elements } => {
            let result = required_result(result)?;
            let mut current = None;
            for (index, element) in elements.iter().enumerate() {
                if index + 1 == elements.len() {
                    ir.push("  %v")?;
                    ir.number(u128::from(result.0))?;
                } else {
                    ir.push("  %t")?;
                    ir.number(u128::from(instruction.id.0))?;
                    ir.push("_array_")?;
                    ir.number(index as u128)?;
                }
                ir.push(" = insertvalue ")?;
                render_type(ir, machine, *ty)?;
                match current {
                    Some(previous) => {
                        ir.push(" %t")?;
                        ir.number(u128::from(instruction.id.0))?;
                        ir.push("_array_")?;
                        ir.number(previous as u128)?;
                    }
                    None => ir.push(" poison")?,
                }
                ir.push(", ")?;
                render_value_type(ir, machine, function, *element)?;
                ir.push(" %v")?;
                ir.number(u128::from(element.0))?;
                ir.push(", ")?;
                ir.number(index as u128)?;
                ir.push("\n")?;
                current = Some(index);
            }
        }
        MachineOperation::InsertField {
            aggregate,
            field,
            value,
        } => {
            render_result(ir, result)?;
            ir.push("insertvalue ")?;
            render_value_type(ir, machine, function, *aggregate)?;
            ir.push(" %v")?;
            ir.number(u128::from(aggregate.0))?;
            ir.push(", ")?;
            render_value_type(ir, machine, function, *value)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            ir.push(", ")?;
            ir.number(u128::from(*field))?;
            ir.push("\n")?;
        }
        MachineOperation::ExtractField { aggregate, field } => {
            render_result(ir, result)?;
            ir.push("extractvalue ")?;
            render_value_type(ir, machine, function, *aggregate)?;
            ir.push(" %v")?;
            ir.number(u128::from(aggregate.0))?;
            ir.push(", ")?;
            ir.number(u128::from(*field))?;
            ir.push("\n")?;
        }
        MachineOperation::ExtractIndex {
            aggregate,
            index,
            slot,
            ..
        } => {
            let result = required_result(result)?;
            let aggregate_ty = function
                .values
                .get(aggregate.0 as usize)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "fixed-array aggregate value",
                ))?
                .ty;
            let element_ty = match machine
                .types
                .get(aggregate_ty.0 as usize)
                .map(|record| &record.kind)
            {
                Some(MachineTypeKind::Array { element, .. }) => *element,
                _ => return Err(CodegenError::UnsupportedMachineContract("fixed-array type")),
            };
            let alignment = machine
                .types
                .get(element_ty.0 as usize)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "fixed-array element type",
                ))?
                .alignment;
            ir.push("  store ")?;
            render_type(ir, machine, aggregate_ty)?;
            ir.push(" %v")?;
            ir.number(u128::from(aggregate.0))?;
            ir.push(", ptr %s")?;
            ir.number(u128::from(slot.0))?;
            ir.push(", align ")?;
            ir.number(u128::from(alignment))?;
            ir.push("\n  %t")?;
            ir.number(u128::from(instruction.id.0))?;
            ir.push("_array_element = getelementptr inbounds ")?;
            render_type(ir, machine, aggregate_ty)?;
            ir.push(", ptr %s")?;
            ir.number(u128::from(slot.0))?;
            ir.push(", i64 0, i64 %v")?;
            ir.number(u128::from(index.0))?;
            ir.push("\n  %v")?;
            ir.number(u128::from(result.0))?;
            ir.push(" = load ")?;
            render_type(ir, machine, element_ty)?;
            ir.push(", ptr %t")?;
            ir.number(u128::from(instruction.id.0))?;
            ir.push("_array_element, align ")?;
            ir.number(u128::from(alignment))?;
            ir.push("\n")?;
        }
        MachineOperation::MakeEnum {
            ty,
            variant,
            payload,
        } => {
            let result = required_result(result)?;
            match payload {
                Some(payload) => {
                    let storage = match type_kind(machine, *ty)? {
                        MachineTypeKind::TaggedEnum { storage, .. } => *storage,
                        _ => None,
                    };
                    if let Some(storage) = storage {
                        let payload_ty = value_type(function, *payload)?;
                        let payload_alignment = machine
                            .types
                            .get(payload_ty.0 as usize)
                            .ok_or(CodegenError::UnsupportedMachineContract(
                                "an enum payload has no machine type",
                            ))?
                            .alignment;
                        ir.push("  %t")?;
                        ir.number(u128::from(instruction.id.0))?;
                        ir.push("_enum_slot = alloca ")?;
                        render_enum_storage(ir, storage)?;
                        ir.push(", align ")?;
                        ir.number(u128::from(storage.alignment))?;
                        ir.push("\n  store ")?;
                        render_enum_storage(ir, storage)?;
                        ir.push(" zeroinitializer, ptr %t")?;
                        ir.number(u128::from(instruction.id.0))?;
                        ir.push("_enum_slot, align ")?;
                        ir.number(u128::from(storage.alignment))?;
                        ir.push("\n  store ")?;
                        render_value_type(ir, machine, function, *payload)?;
                        ir.push(" %v")?;
                        ir.number(u128::from(payload.0))?;
                        ir.push(", ptr %t")?;
                        ir.number(u128::from(instruction.id.0))?;
                        ir.push("_enum_slot, align ")?;
                        ir.number(u128::from(payload_alignment))?;
                        ir.push("\n  %t")?;
                        ir.number(u128::from(instruction.id.0))?;
                        ir.push("_enum_bits = load ")?;
                        render_enum_storage(ir, storage)?;
                        ir.push(", ptr %t")?;
                        ir.number(u128::from(instruction.id.0))?;
                        ir.push("_enum_slot, align ")?;
                        ir.number(u128::from(storage.alignment))?;
                        ir.push("\n")?;
                    }
                    ir.push("  %t")?;
                    ir.number(u128::from(instruction.id.0))?;
                    ir.push("_enum_tag = insertvalue ")?;
                    render_type(ir, machine, *ty)?;
                    ir.push(" zeroinitializer, i8 ")?;
                    ir.number(u128::from(*variant))?;
                    ir.push(", 0\n  %v")?;
                    ir.number(u128::from(result.0))?;
                    ir.push(" = insertvalue ")?;
                    render_type(ir, machine, *ty)?;
                    ir.push(" %t")?;
                    ir.number(u128::from(instruction.id.0))?;
                    ir.push("_enum_tag, ")?;
                    if let Some(storage) = storage {
                        render_enum_storage(ir, storage)?;
                        ir.push(" %t")?;
                        ir.number(u128::from(instruction.id.0))?;
                        ir.push("_enum_bits")?;
                    } else {
                        render_value_type(ir, machine, function, *payload)?;
                        ir.push(" %v")?;
                        ir.number(u128::from(payload.0))?;
                    }
                    ir.push(", 1\n")?;
                }
                None => {
                    ir.push("  %v")?;
                    ir.number(u128::from(result.0))?;
                    ir.push(" = insertvalue ")?;
                    render_type(ir, machine, *ty)?;
                    ir.push(" zeroinitializer, i8 ")?;
                    ir.number(u128::from(*variant))?;
                    ir.push(", 0\n")?;
                }
            }
        }
        MachineOperation::EnumTag { value } => {
            render_result(ir, result)?;
            ir.push("extractvalue ")?;
            render_value_type(ir, machine, function, *value)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            ir.push(", 0\n")?;
        }
        MachineOperation::EnumPayload { value, .. } => {
            let result = required_result(result)?;
            let enum_ty = value_type(function, *value)?;
            let storage = match type_kind(machine, enum_ty)? {
                MachineTypeKind::TaggedEnum { storage, .. } => *storage,
                _ => None,
            };
            if let Some(storage) = storage {
                let payload_ty = value_type(function, result)?;
                let payload_alignment = machine
                    .types
                    .get(payload_ty.0 as usize)
                    .ok_or(CodegenError::UnsupportedMachineContract(
                        "an enum projection result has no machine type",
                    ))?
                    .alignment;
                ir.push("  %t")?;
                ir.number(u128::from(instruction.id.0))?;
                ir.push("_enum_bits = extractvalue ")?;
                render_value_type(ir, machine, function, *value)?;
                ir.push(" %v")?;
                ir.number(u128::from(value.0))?;
                ir.push(", 1\n  %t")?;
                ir.number(u128::from(instruction.id.0))?;
                ir.push("_enum_slot = alloca ")?;
                render_enum_storage(ir, storage)?;
                ir.push(", align ")?;
                ir.number(u128::from(storage.alignment))?;
                ir.push("\n  store ")?;
                render_enum_storage(ir, storage)?;
                ir.push(" %t")?;
                ir.number(u128::from(instruction.id.0))?;
                ir.push("_enum_bits, ptr %t")?;
                ir.number(u128::from(instruction.id.0))?;
                ir.push("_enum_slot, align ")?;
                ir.number(u128::from(storage.alignment))?;
                ir.push("\n  %v")?;
                ir.number(u128::from(result.0))?;
                ir.push(" = load ")?;
                render_type(ir, machine, payload_ty)?;
                ir.push(", ptr %t")?;
                ir.number(u128::from(instruction.id.0))?;
                ir.push("_enum_slot, align ")?;
                ir.number(u128::from(payload_alignment))?;
                ir.push("\n")?;
            } else {
                ir.push("  %v")?;
                ir.number(u128::from(result.0))?;
                ir.push(" = extractvalue ")?;
                render_value_type(ir, machine, function, *value)?;
                ir.push(" %v")?;
                ir.number(u128::from(value.0))?;
                ir.push(", 1\n")?;
            }
        }
        MachineOperation::AddressOffset {
            base,
            byte_offset,
            facts,
        } => {
            render_result(ir, result)?;
            ir.push("getelementptr ")?;
            if facts.in_bounds {
                ir.push("inbounds ")?;
            }
            ir.push("i8, ptr %v")?;
            ir.number(u128::from(base.0))?;
            ir.push(", ")?;
            render_value_type(ir, machine, function, *byte_offset)?;
            ir.push(" %v")?;
            ir.number(u128::from(byte_offset.0))?;
            ir.push("\n")?;
        }
        MachineOperation::Load {
            address,
            ty,
            semantics,
            facts,
        } => render_load(
            ir,
            machine,
            result,
            *address,
            *ty,
            *semantics,
            facts.alignment,
        )?,
        MachineOperation::Store {
            address,
            value,
            semantics,
            facts,
        } => render_store(
            ir,
            machine,
            function,
            *address,
            *value,
            *semantics,
            facts.alignment,
        )?,
        MachineOperation::ActorReserve {
            mailbox, failure, ..
        } => render_actor_reserve(
            ir,
            machine,
            instruction.id.0,
            result,
            *mailbox,
            *failure,
            is_cancelled,
        )?,
        MachineOperation::ActorCommit {
            reservation,
            method,
            ..
        } => render_actor_commit(ir, *reservation, *method)?,
        MachineOperation::ActorReplyRequest {
            slot,
            mailbox,
            method,
            failure,
            duplicate_failure,
            ..
        } => render_actor_reply_request(
            ir,
            machine,
            instruction.id.0,
            result,
            *slot,
            *mailbox,
            *method,
            *failure,
            *duplicate_failure,
            is_cancelled,
        )?,
        MachineOperation::ActorReplyResolve { .. } => {}
        MachineOperation::MailboxReceive {
            mailbox,
            method,
            failure,
            ..
        } => render_mailbox_receive(
            ir,
            machine,
            instruction.id.0,
            *mailbox,
            *method,
            *failure,
            is_cancelled,
        )?,
        MachineOperation::MailboxDispatch {
            mailbox, method, ..
        } => render_mailbox_dispatch(
            ir,
            machine,
            function,
            instruction.id.0,
            *mailbox,
            *method,
            is_cancelled,
        )?,
        MachineOperation::Call {
            function: callee,
            arguments,
            convention,
        } => render_call(
            ir,
            machine,
            function,
            result,
            *callee,
            arguments,
            *convention,
            false,
            0,
            is_cancelled,
        )?,
        MachineOperation::GlobalAddress(global) => {
            let global = machine.globals.get(global.0 as usize).ok_or(
                CodegenError::UnsupportedMachineOperation {
                    function: function.id.0,
                    instruction: instruction.id.0,
                },
            )?;
            let symbol = machine.symbols.get(global.symbol.0 as usize).ok_or(
                CodegenError::UnsupportedMachineOperation {
                    function: function.id.0,
                    instruction: instruction.id.0,
                },
            )?;
            render_result(ir, result)?;
            ir.push("getelementptr i8, ptr @")?;
            ir.push_cancellable(&symbol.name, is_cancelled)?;
            ir.push(", i64 0\n")?;
        }
        MachineOperation::RuntimeCall {
            intrinsic,
            arguments,
        } => render_runtime_call(
            ir,
            machine,
            function,
            result,
            *intrinsic,
            arguments,
            is_cancelled,
        )?,
        MachineOperation::TestAssert { condition, failure } => {
            let symbol = runtime_symbol(machine, RuntimeIntrinsic::TestAssertionFail)?;
            let expression_symbol = machine
                .globals
                .get(failure.expression_global.0 as usize)
                .and_then(|global| machine.symbols.get(global.symbol.0 as usize))
                .map(|symbol| symbol.name.as_str())
                .ok_or(CodegenError::UnsupportedMachineOperation {
                    function: function.id.0,
                    instruction: instruction.id.0,
                })?;
            let message_symbol = failure
                .message_global
                .map(|global| {
                    machine
                        .globals
                        .get(global.0 as usize)
                        .and_then(|global| machine.symbols.get(global.symbol.0 as usize))
                        .map(|symbol| symbol.name.as_str())
                        .ok_or(CodegenError::UnsupportedMachineOperation {
                            function: function.id.0,
                            instruction: instruction.id.0,
                        })
                })
                .transpose()?;
            render_bool_test(ir, instruction.id.0, "assertion", *condition)?;
            ir.push("  br i1 %t")?;
            ir.number(u128::from(instruction.id.0))?;
            ir.push("_assertion")?;
            ir.push(", label %i")?;
            ir.number(u128::from(instruction.id.0))?;
            ir.push("_ok, label %i")?;
            ir.number(u128::from(instruction.id.0))?;
            ir.push("_assert_fail\n")?;
            ir.push("i")?;
            ir.number(u128::from(instruction.id.0))?;
            ir.push("_assert_fail:\n  call void @")?;
            ir.push_cancellable(symbol, is_cancelled)?;
            ir.push("(ptr @")?;
            ir.push_cancellable(expression_symbol, is_cancelled)?;
            ir.push(", i64 ")?;
            ir.number(failure.expression.len() as u128)?;
            ir.push(", ptr ")?;
            if let Some(message_symbol) = message_symbol {
                ir.push("@")?;
                ir.push_cancellable(message_symbol, is_cancelled)?;
            } else {
                ir.push("null")?;
            }
            ir.push(", i64 ")?;
            ir.number(failure.message.as_ref().map_or(0, String::len) as u128)?;
            ir.push(", i32 ")?;
            ir.number(u128::from(failure.source.file.0))?;
            ir.push(", i32 ")?;
            ir.number(u128::from(failure.source.range.start))?;
            ir.push(", i32 ")?;
            ir.number(u128::from(failure.source.range.end))?;
            ir.push(")\n  unreachable\ni")?;
            ir.number(u128::from(instruction.id.0))?;
            ir.push("_ok:\n")?;
        }
        MachineOperation::Fence(fence) => render_fence(ir, *fence)?,
        MachineOperation::MemoryCopy { .. }
        | MachineOperation::MemorySet { .. }
        | MachineOperation::StackAddress(_) => {
            return Err(CodegenError::UnsupportedMachineOperation {
                function: function.id.0,
                instruction: instruction.id.0,
            });
        }
    }
    Ok(())
}

fn render_immediate(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    result: ValueId,
    immediate: &MachineImmediate,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let result_ty = value_type(function, result)?;
    match immediate {
        MachineImmediate::Integer { bytes_le, .. } => {
            ir.push("add ")?;
            render_type(ir, machine, result_ty)?;
            ir.push(" 0, ")?;
            ir.number(integer_value(bytes_le)?)?;
            ir.push("\n")
        }
        MachineImmediate::Float32(bits) => {
            ir.push("bitcast i32 ")?;
            ir.number(u128::from(*bits))?;
            ir.push(" to float\n")
        }
        MachineImmediate::Float64(bits) => {
            ir.push("bitcast i64 ")?;
            ir.number(u128::from(*bits))?;
            ir.push(" to double\n")
        }
        MachineImmediate::Null(_) => ir.push("getelementptr i8, ptr null, i64 0\n"),
        MachineImmediate::Zero(_) => match type_kind(machine, result_ty)? {
            MachineTypeKind::Integer { .. } => {
                ir.push("add ")?;
                render_type(ir, machine, result_ty)?;
                ir.push(" 0, 0\n")
            }
            MachineTypeKind::Float32 => ir.push("bitcast i32 0 to float\n"),
            MachineTypeKind::Float64 => ir.push("bitcast i64 0 to double\n"),
            MachineTypeKind::Pointer { .. } => ir.push("getelementptr i8, ptr null, i64 0\n"),
            _ => Err(CodegenError::UnsupportedMachineContract(
                "non-scalar zero immediate",
            )),
        },
        MachineImmediate::SymbolAddress(symbol) => {
            let symbol = symbol_name(machine, symbol.0)?;
            ir.push("getelementptr i8, ptr @")?;
            ir.push_cancellable(symbol, is_cancelled)?;
            ir.push(", i64 0\n")
        }
        MachineImmediate::Bytes(_) => Err(CodegenError::UnsupportedMachineContract(
            "byte-string immediate in scalar IR",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn render_comparison(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    instruction: u32,
    result: Option<ValueId>,
    opcode: &str,
    predicate: &str,
    left: ValueId,
    right: ValueId,
) -> Result<(), CodegenError> {
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_compare = ")?;
    ir.push(opcode)?;
    ir.push(" ")?;
    ir.push(predicate)?;
    ir.push(" ")?;
    render_value_type(ir, machine, function, left)?;
    render_value_pair(ir, left, right)?;
    render_result(ir, result)?;
    ir.push("zext i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_compare to i8\n")
}

fn render_unary(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    instruction: u32,
    result: Option<ValueId>,
    operation: MachineUnaryOp,
    value: ValueId,
) -> Result<(), CodegenError> {
    match operation {
        MachineUnaryOp::BoolNot => {
            ir.push("  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_bool_not = icmp eq ")?;
            render_value_type(ir, machine, function, value)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            ir.push(", 0\n")?;
            render_result(ir, result)?;
            ir.push("zext i1 %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_bool_not to i8\n")
        }
        MachineUnaryOp::BitNot => {
            render_result(ir, result)?;
            ir.push("xor ")?;
            render_value_type(ir, machine, function, value)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            ir.push(", -1\n")
        }
        MachineUnaryOp::FloatNegate => {
            let value_ty = value_type(function, value)?;
            let (storage, canonical_nan) = match type_kind(machine, value_ty)? {
                MachineTypeKind::Float32 => ("i32", u128::from(0x7fc0_0000_u32)),
                MachineTypeKind::Float64 => ("i64", u128::from(0x7ff8_0000_0000_0000_u64)),
                _ => {
                    return Err(CodegenError::UnsupportedMachineContract(
                        "floating negation used a non-floating machine type",
                    ));
                }
            };
            ir.push("  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_negated = fneg ")?;
            render_value_type(ir, machine, function, value)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            ir.push("\n  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_nan = fcmp uno ")?;
            render_value_type(ir, machine, function, value)?;
            render_value_pair(ir, value, value)?;
            ir.push("  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_canonical_nan = bitcast ")?;
            ir.push(storage)?;
            ir.push(" ")?;
            ir.number(canonical_nan)?;
            ir.push(" to ")?;
            render_value_type(ir, machine, function, value)?;
            ir.push("\n")?;
            render_result(ir, result)?;
            ir.push("select i1 %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_nan, ")?;
            render_value_type(ir, machine, function, value)?;
            ir.push(" %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_canonical_nan, ")?;
            render_value_type(ir, machine, function, value)?;
            ir.push(" %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_negated\n")
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_checked_integer(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    instruction: u32,
    result: Option<ValueId>,
    operation: CheckedIntegerOp,
    signedness: IntegerSignedness,
    left: ValueId,
    right: ValueId,
    failure: ScalarFailureProvenance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let result = required_result(result)?;
    let bits = integer_bits(machine, value_type(function, left)?)?;
    match operation {
        CheckedIntegerOp::Add | CheckedIntegerOp::Subtract | CheckedIntegerOp::Multiply => {
            let wide = bits
                .checked_mul(2)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "checked integer width overflowed",
                ))?;
            let extension = match signedness {
                IntegerSignedness::Unsigned => "zext",
                IntegerSignedness::Signed => "sext",
            };
            ir.push("  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_wide_left = ")?;
            ir.push(extension)?;
            ir.push(" i")?;
            ir.number(u128::from(bits))?;
            ir.push(" %v")?;
            ir.number(u128::from(left.0))?;
            ir.push(" to i")?;
            ir.number(u128::from(wide))?;
            ir.push("\n  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_wide_right = ")?;
            ir.push(extension)?;
            ir.push(" i")?;
            ir.number(u128::from(bits))?;
            ir.push(" %v")?;
            ir.number(u128::from(right.0))?;
            ir.push(" to i")?;
            ir.number(u128::from(wide))?;
            ir.push("\n  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_wide_result = ")?;
            ir.push(match operation {
                CheckedIntegerOp::Add => "add",
                CheckedIntegerOp::Subtract => "sub",
                CheckedIntegerOp::Multiply => "mul",
                _ => unreachable!(),
            })?;
            ir.push(" i")?;
            ir.number(u128::from(wide))?;
            ir.push(" %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_wide_left, %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_wide_right\n  %v")?;
            ir.number(u128::from(result.0))?;
            ir.push(" = trunc i")?;
            ir.number(u128::from(wide))?;
            ir.push(" %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_wide_result to i")?;
            ir.number(u128::from(bits))?;
            ir.push("\n  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_roundtrip = ")?;
            ir.push(extension)?;
            ir.push(" i")?;
            ir.number(u128::from(bits))?;
            ir.push(" %v")?;
            ir.number(u128::from(result.0))?;
            ir.push(" to i")?;
            ir.number(u128::from(wide))?;
            ir.push("\n  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_failed = icmp ne i")?;
            ir.number(u128::from(wide))?;
            ir.push(" %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_wide_result, %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_roundtrip\n")?;
            render_checked_failure(ir, machine, instruction, failure, is_cancelled)
        }
        CheckedIntegerOp::Divide | CheckedIntegerOp::Remainder => {
            ir.push("  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_zero = icmp eq i")?;
            ir.number(u128::from(bits))?;
            ir.push(" %v")?;
            ir.number(u128::from(right.0))?;
            ir.push(", 0\n")?;
            if operation == CheckedIntegerOp::Divide && signedness == IntegerSignedness::Signed {
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_minimum = icmp eq i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(left.0))?;
                ir.push(", ")?;
                ir.number(1_u128 << u32::from(bits - 1))?;
                ir.push("\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_minus_one = icmp eq i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(right.0))?;
                ir.push(", ")?;
                ir.number(integer_mask(bits))?;
                ir.push("\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_overflow = and i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_minimum, %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_minus_one\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_failed = or i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_zero, %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_overflow\n")?;
            } else {
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_failed = or i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_zero, false\n")?;
            }
            render_checked_failure(ir, machine, instruction, failure, is_cancelled)?;
            if bits == 128 {
                return render_i128_division_or_remainder(
                    ir,
                    instruction,
                    result,
                    operation,
                    signedness,
                    left,
                    right,
                    is_cancelled,
                );
            }
            render_result(ir, Some(result))?;
            ir.push(match (operation, signedness) {
                (CheckedIntegerOp::Divide, IntegerSignedness::Unsigned) => "udiv",
                (CheckedIntegerOp::Divide, IntegerSignedness::Signed) => "sdiv",
                (CheckedIntegerOp::Remainder, IntegerSignedness::Unsigned) => "urem",
                (CheckedIntegerOp::Remainder, IntegerSignedness::Signed) => "srem",
                _ => unreachable!(),
            })?;
            ir.push(" i")?;
            ir.number(u128::from(bits))?;
            render_value_pair(ir, left, right)
        }
        CheckedIntegerOp::ShiftLeft | CheckedIntegerOp::ShiftLeftWrapping => {
            if signedness == IntegerSignedness::Signed {
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_negative = icmp slt i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(right.0))?;
                ir.push(", 0\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_wide_shift = icmp sge i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(right.0))?;
                ir.push(", ")?;
                ir.number(u128::from(bits))?;
                ir.push("\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_count_invalid = or i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_negative, %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_wide_shift\n")?;
            } else {
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_count_invalid = icmp uge i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(right.0))?;
                ir.push(", ")?;
                ir.number(u128::from(bits))?;
                ir.push("\n")?;
            }
            ir.push("  %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_safe_count = select i1 %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_count_invalid, i")?;
            ir.number(u128::from(bits))?;
            ir.push(" 0, i")?;
            ir.number(u128::from(bits))?;
            ir.push(" %v")?;
            ir.number(u128::from(right.0))?;
            ir.push("\n")?;
            render_result(ir, Some(result))?;
            ir.push("shl i")?;
            ir.number(u128::from(bits))?;
            ir.push(" %v")?;
            ir.number(u128::from(left.0))?;
            ir.push(", %t")?;
            ir.number(u128::from(instruction))?;
            ir.push("_safe_count\n")?;
            let invalid_count_code = operation.invalid_shift_count_fatal_code().ok_or(
                CodegenError::UnsupportedMachineContract(
                    "left shift is missing its invalid-count fatal code",
                ),
            )?;
            if operation == CheckedIntegerOp::ShiftLeft {
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_roundtrip = ")?;
                ir.push(match signedness {
                    IntegerSignedness::Unsigned => "lshr",
                    IntegerSignedness::Signed => "ashr",
                })?;
                ir.push(" i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(result.0))?;
                ir.push(", %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_safe_count\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_lost = icmp ne i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_roundtrip, %v")?;
                ir.number(u128::from(left.0))?;
                ir.push("\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_failed = or i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_count_invalid, %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_lost\n")?;
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_fatal_code = select i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_count_invalid, i32 ")?;
                ir.number(u128::from(invalid_count_code.as_u32()))?;
                ir.push(", i32 ")?;
                ir.number(u128::from(
                    operation
                        .result_loss_fatal_code()
                        .ok_or(CodegenError::UnsupportedMachineContract(
                            "checked left shift is missing its result-loss fatal code",
                        ))?
                        .as_u32(),
                ))?;
                ir.push("\n")?;
            } else {
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_failed = or i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_count_invalid, false\n")?;
            }
            render_checked_failure_with_code(
                ir,
                machine,
                instruction,
                failure,
                if operation == CheckedIntegerOp::ShiftLeft {
                    FatalCodeOperand::Temporary(instruction)
                } else {
                    FatalCodeOperand::Constant(invalid_count_code)
                },
                is_cancelled,
            )
        }
        CheckedIntegerOp::ShiftRight => {
            if signedness == IntegerSignedness::Signed {
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_negative = icmp slt i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(right.0))?;
                ir.push(", 0\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_wide_shift = icmp sge i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(right.0))?;
                ir.push(", ")?;
                ir.number(u128::from(bits))?;
                ir.push("\n  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_failed = or i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_negative, %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_wide_shift\n")?;
            } else {
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_failed = icmp uge i")?;
                ir.number(u128::from(bits))?;
                ir.push(" %v")?;
                ir.number(u128::from(right.0))?;
                ir.push(", ")?;
                ir.number(u128::from(bits))?;
                ir.push("\n")?;
            }
            render_checked_failure_with_code(
                ir,
                machine,
                instruction,
                failure,
                FatalCodeOperand::Constant(operation.invalid_shift_count_fatal_code().ok_or(
                    CodegenError::UnsupportedMachineContract(
                        "right shift is missing its invalid-count fatal code",
                    ),
                )?),
                is_cancelled,
            )?;
            render_result(ir, Some(result))?;
            ir.push(match signedness {
                IntegerSignedness::Unsigned => "lshr",
                IntegerSignedness::Signed => "ashr",
            })?;
            ir.push(" i")?;
            ir.number(u128::from(bits))?;
            render_value_pair(ir, left, right)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_i128_division_or_remainder(
    ir: &mut IrText,
    instruction: u32,
    result: ValueId,
    operation: CheckedIntegerOp,
    signedness: IntegerSignedness,
    left: ValueId,
    right: ValueId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_left_negative = icmp slt i128 %v")?;
    ir.number(u128::from(left.0))?;
    ir.push(", 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_right_negative = icmp slt i128 %v")?;
    ir.number(u128::from(right.0))?;
    ir.push(", 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_left_negated = sub i128 0, %v")?;
    ir.number(u128::from(left.0))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_right_negated = sub i128 0, %v")?;
    ir.number(u128::from(right.0))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_left = select i1 ")?;
    if signedness == IntegerSignedness::Signed {
        ir.push("%t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_left_negative")?;
    } else {
        ir.push("false")?;
    }
    ir.push(", i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_left_negated, i128 %v")?;
    ir.number(u128::from(left.0))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_right = select i1 ")?;
    if signedness == IntegerSignedness::Signed {
        ir.push("%t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_right_negative")?;
    } else {
        ir.push("false")?;
    }
    ir.push(", i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_right_negated, i128 %v")?;
    ir.number(u128::from(right.0))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_remainder_0 = or i128 0, 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_quotient_0 = or i128 0, 0\n")?;
    for step in 0_u16..128 {
        check_periodically(usize::from(step), is_cancelled)?;
        let bit = 127_u16 - step;
        let next = step + 1;
        ir.push("  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_input_shift_")?;
        ir.number(u128::from(step))?;
        ir.push(" = lshr i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_left, ")?;
        ir.number(u128::from(bit))?;
        ir.push("\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_input_bit_")?;
        ir.number(u128::from(step))?;
        ir.push(" = and i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_input_shift_")?;
        ir.number(u128::from(step))?;
        ir.push(", 1\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_remainder_shift_")?;
        ir.number(u128::from(step))?;
        ir.push(" = shl i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_remainder_")?;
        ir.number(u128::from(step))?;
        ir.push(", 1\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_candidate_")?;
        ir.number(u128::from(step))?;
        ir.push(" = or i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_remainder_shift_")?;
        ir.number(u128::from(step))?;
        ir.push(", %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_input_bit_")?;
        ir.number(u128::from(step))?;
        ir.push("\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_enough_")?;
        ir.number(u128::from(step))?;
        ir.push(" = icmp uge i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_candidate_")?;
        ir.number(u128::from(step))?;
        ir.push(", %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_right\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_reduced_")?;
        ir.number(u128::from(step))?;
        ir.push(" = sub i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_candidate_")?;
        ir.number(u128::from(step))?;
        ir.push(", %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_right\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_remainder_")?;
        ir.number(u128::from(next))?;
        ir.push(" = select i1 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_enough_")?;
        ir.number(u128::from(step))?;
        ir.push(", i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_reduced_")?;
        ir.number(u128::from(step))?;
        ir.push(", i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_candidate_")?;
        ir.number(u128::from(step))?;
        ir.push("\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_quotient_set_")?;
        ir.number(u128::from(step))?;
        ir.push(" = or i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_quotient_")?;
        ir.number(u128::from(step))?;
        ir.push(", ")?;
        ir.number(1_u128 << u32::from(bit))?;
        ir.push("\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_quotient_")?;
        ir.number(u128::from(next))?;
        ir.push(" = select i1 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_enough_")?;
        ir.number(u128::from(step))?;
        ir.push(", i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_quotient_set_")?;
        ir.number(u128::from(step))?;
        ir.push(", i128 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_quotient_")?;
        ir.number(u128::from(step))?;
        ir.push("\n")?;
    }
    let final_suffix = match operation {
        CheckedIntegerOp::Divide => "quotient_128",
        CheckedIntegerOp::Remainder => "remainder_128",
        _ => {
            return Err(CodegenError::UnsupportedMachineContract(
                "software i128 division received another operation",
            ));
        }
    };
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_unsigned_result = or i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_")?;
    ir.push(final_suffix)?;
    ir.push(", 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_result_negative = ")?;
    if operation == CheckedIntegerOp::Divide {
        ir.push("xor i1 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_left_negative, %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_right_negative")?;
    } else {
        ir.push("or i1 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_left_negative, false")?;
    }
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_signed_negated = sub i128 0, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_unsigned_result\n  %v")?;
    ir.number(u128::from(result.0))?;
    ir.push(" = select i1 ")?;
    if signedness == IntegerSignedness::Signed {
        ir.push("%t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_division_result_negative")?;
    } else {
        ir.push("false")?;
    }
    ir.push(", i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_signed_negated, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_division_unsigned_result\n")
}

#[allow(clippy::too_many_arguments)]
fn render_checked_conversion(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    instruction: u32,
    result: Option<ValueId>,
    source_kind: CheckedNumericKind,
    destination_kind: CheckedNumericKind,
    value: ValueId,
    destination: MachineTypeId,
    failure: ScalarFailureProvenance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let result = required_result(result)?;
    let source_ty = value_type(function, value)?;
    match (source_kind, destination_kind) {
        (
            CheckedNumericKind::UnsignedInteger | CheckedNumericKind::SignedInteger,
            CheckedNumericKind::UnsignedInteger | CheckedNumericKind::SignedInteger,
        ) => render_checked_integer_conversion(
            ir,
            machine,
            instruction,
            result,
            source_kind,
            destination_kind,
            value,
            source_ty,
            destination,
            failure,
            is_cancelled,
        ),
        (
            CheckedNumericKind::UnsignedInteger | CheckedNumericKind::SignedInteger,
            CheckedNumericKind::Float32 | CheckedNumericKind::Float64,
        ) => {
            if integer_bits(machine, source_ty)? == 128 {
                render_i128_to_float(
                    ir,
                    instruction,
                    result,
                    source_kind,
                    destination_kind,
                    value,
                )?;
            } else {
                render_result(ir, Some(result))?;
                ir.push(if source_kind == CheckedNumericKind::SignedInteger {
                    "sitofp"
                } else {
                    "uitofp"
                })?;
                ir.push(" ")?;
                render_type(ir, machine, source_ty)?;
                ir.push(" %v")?;
                ir.number(u128::from(value.0))?;
                ir.push(" to ")?;
                render_type(ir, machine, destination)?;
                ir.push("\n")?;
            }
            render_float_infinity_test(
                ir,
                machine,
                instruction,
                result,
                destination_kind,
                "failed",
            )?;
            render_checked_failure(ir, machine, instruction, failure, is_cancelled)
        }
        (
            CheckedNumericKind::Float32 | CheckedNumericKind::Float64,
            CheckedNumericKind::Float32 | CheckedNumericKind::Float64,
        ) => {
            render_result(ir, Some(result))?;
            match (source_kind, destination_kind) {
                (CheckedNumericKind::Float32, CheckedNumericKind::Float64) => ir.push("fpext ")?,
                (CheckedNumericKind::Float64, CheckedNumericKind::Float32) => {
                    ir.push("fptrunc ")?
                }
                _ => ir.push("select i1 true, ")?,
            }
            render_type(ir, machine, source_ty)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            if source_kind == destination_kind {
                ir.push(", ")?;
                render_type(ir, machine, source_ty)?;
                ir.push(" %v")?;
                ir.number(u128::from(value.0))?;
            } else {
                ir.push(" to ")?;
                render_type(ir, machine, destination)?;
            }
            ir.push("\n")?;
            if source_kind == CheckedNumericKind::Float64
                && destination_kind == CheckedNumericKind::Float32
            {
                render_float_finite_test(ir, instruction, value, source_kind)?;
                render_float_infinity_test(
                    ir,
                    machine,
                    instruction,
                    result,
                    destination_kind,
                    "narrowed_infinity",
                )?;
                ir.push("  %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_failed = and i1 %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_finite, %t")?;
                ir.number(u128::from(instruction))?;
                ir.push("_narrowed_infinity\n")?;
            } else {
                render_never_failed(ir, instruction)?;
            }
            render_checked_failure(ir, machine, instruction, failure, is_cancelled)
        }
        (
            CheckedNumericKind::Float32 | CheckedNumericKind::Float64,
            CheckedNumericKind::UnsignedInteger | CheckedNumericKind::SignedInteger,
        ) => {
            let destination_bits = integer_bits(machine, destination)?;
            render_float_integer_range_test(
                ir,
                instruction,
                value,
                source_kind,
                destination_kind,
                destination_bits,
            )?;
            render_checked_failure(ir, machine, instruction, failure, is_cancelled)?;
            if destination_bits == 128 {
                render_float_to_i128(
                    ir,
                    instruction,
                    result,
                    source_kind,
                    destination_kind,
                    value,
                )?;
            } else {
                render_result(ir, Some(result))?;
                ir.push(if destination_kind == CheckedNumericKind::SignedInteger {
                    "fptosi"
                } else {
                    "fptoui"
                })?;
                ir.push(" ")?;
                render_type(ir, machine, source_ty)?;
                ir.push(" %v")?;
                ir.number(u128::from(value.0))?;
                ir.push(" to ")?;
                render_type(ir, machine, destination)?;
                ir.push("\n")?;
            }
            Ok(())
        }
    }
}

fn render_i128_to_float(
    ir: &mut IrText,
    instruction: u32,
    result: ValueId,
    source: CheckedNumericKind,
    destination: CheckedNumericKind,
    value: ValueId,
) -> Result<(), CodegenError> {
    let (precision, mantissa_bits, bias, storage_bits, sign_mask, float_ty) = match destination {
        CheckedNumericKind::Float32 => (24_u16, 23_u16, 127_u16, 32_u16, 1_u128 << 31, "float"),
        CheckedNumericKind::Float64 => (53_u16, 52_u16, 1023_u16, 64_u16, 1_u128 << 63, "double"),
        _ => {
            return Err(CodegenError::UnsupportedMachineContract(
                "i128 conversion requested a non-floating destination",
            ));
        }
    };
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_negative = icmp slt i128 %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(", 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_negated_magnitude = sub i128 0, %v")?;
    ir.number(u128::from(value.0))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude = select i1 ")?;
    if source == CheckedNumericKind::SignedInteger {
        ir.push("%t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_negative")?;
    } else {
        ir.push("false")?;
    }
    ir.push(", i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_negated_magnitude, i128 %v")?;
    ir.number(u128::from(value.0))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_zero = icmp eq i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude, 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_leading = call i128 @llvm.ctlz.i128(i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude, i1 false)\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_exponent = sub i128 127, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_leading\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_zero, i128 0, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_exponent\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_large = icmp uge i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent, ")?;
    ir.number(u128::from(precision - 1))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_right_shift = sub i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent, ")?;
    ir.number(u128::from(precision - 1))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_shift = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_large, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_right_shift, i128 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_left_shift = sub i128 ")?;
    ir.number(u128::from(precision - 1))?;
    ir.push(", %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left_shift = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_large, i128 0, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_left_shift\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_significand = lshr i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_shift\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left_significand = shl i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left_shift\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_significand = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_large, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_significand, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left_significand\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_shift_nonzero = icmp ne i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_shift, 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_half_shift = sub i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_shift, 1\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_half_shift = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_shift_nonzero, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_half_shift, i128 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_half = shl i128 1, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_half_shift\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mask_bit = shl i128 1, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_shift\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mask = sub i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mask_bit, 1\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_remainder = and i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mask\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_greater_half = icmp ugt i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_remainder, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_half\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_equal_half = icmp eq i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_remainder, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_half\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_odd_value = and i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_significand, 1\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_odd = icmp ne i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_odd_value, 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_tie_up = and i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_equal_half, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_odd\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_round_compare = or i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_greater_half, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_tie_up\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_roundable = and i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_large, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_shift_nonzero\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_round_up = and i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_roundable, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_round_compare\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_round_increment = zext i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_round_up to i128\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_rounded = add i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_significand, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_round_increment\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_carry = icmp eq i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_rounded, ")?;
    ir.number(1_u128 << u32::from(precision))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_normalized = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_carry, i128 ")?;
    ir.number(1_u128 << u32::from(precision - 1))?;
    ir.push(", i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_rounded\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_carry_increment = zext i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_carry to i128\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_final_exponent = add i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_carry_increment\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_biased_exponent = add i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_final_exponent, ")?;
    ir.number(u128::from(bias))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent_bits = shl i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_biased_exponent, ")?;
    ir.number(u128::from(mantissa_bits))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mantissa_bits = and i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_normalized, ")?;
    ir.number((1_u128 << u32::from(mantissa_bits)) - 1)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_unsigned_bits = or i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent_bits, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mantissa_bits\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_source_sign = select i1 ")?;
    if source == CheckedNumericKind::SignedInteger {
        ir.push("%t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_negative")?;
    } else {
        ir.push("false")?;
    }
    ir.push(", i128 ")?;
    ir.number(sign_mask)?;
    ir.push(", i128 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_signed_bits = or i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_unsigned_bits, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_source_sign\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_nonzero_bits = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_zero, i128 0, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_signed_bits\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_storage_bits = trunc i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_nonzero_bits to i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push("\n  %v")?;
    ir.number(u128::from(result.0))?;
    ir.push(" = bitcast i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_storage_bits to ")?;
    ir.push(float_ty)?;
    ir.push("\n")
}

fn render_float_to_i128(
    ir: &mut IrText,
    instruction: u32,
    result: ValueId,
    source: CheckedNumericKind,
    destination: CheckedNumericKind,
    value: ValueId,
) -> Result<(), CodegenError> {
    let (storage, storage_bits, exponent_mask, mantissa_mask, mantissa_bits, bias, sign_mask) =
        match source {
            CheckedNumericKind::Float32 => (
                "float",
                32_u16,
                0xff_u128,
                (1_u128 << 23) - 1,
                23_u16,
                127_u16,
                1_u128 << 31,
            ),
            CheckedNumericKind::Float64 => (
                "double",
                64_u16,
                0x7ff_u128,
                (1_u128 << 52) - 1,
                52_u16,
                1023_u16,
                1_u128 << 63,
            ),
            _ => {
                return Err(CodegenError::UnsupportedMachineContract(
                    "float-to-i128 conversion requested a non-floating source",
                ));
            }
        };
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_storage = bitcast ")?;
    ir.push(storage)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(" to i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_sign_storage = and i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_storage, ")?;
    ir.number(sign_mask)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_negative = icmp ne i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_sign_storage, 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_shifted_exponent = lshr i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_storage, ")?;
    ir.number(u128::from(mantissa_bits))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent_storage = and i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_shifted_exponent, ")?;
    ir.number(exponent_mask)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_fraction_storage = and i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_storage, ")?;
    ir.number(mantissa_mask)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_significand_storage = or i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_fraction_storage, ")?;
    ir.number(1_u128 << u32::from(mantissa_bits))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent_wide = zext i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent_storage to i128\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_significand_wide = zext i")?;
    ir.number(u128::from(storage_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_significand_storage to i128\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_has_integer = icmp uge i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent_wide, ")?;
    ir.number(u128::from(bias))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_exponent = sub i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent_wide, ")?;
    ir.number(u128::from(bias))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_has_integer, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_exponent, i128 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left = icmp uge i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent, ")?;
    ir.number(u128::from(mantissa_bits))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_left_shift = sub i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent, ")?;
    ir.number(u128::from(mantissa_bits))?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left_shift = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_left_shift, i128 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_right_shift = sub i128 ")?;
    ir.number(u128::from(mantissa_bits))?;
    ir.push(", %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_exponent\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_shift = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left, i128 0, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_right_shift\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left_magnitude = shl i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_significand_wide, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left_shift\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_magnitude = lshr i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_significand_wide, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_shift\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_magnitude = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_left_magnitude, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_right_magnitude\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude = select i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_has_integer, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_raw_magnitude, i128 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_negated = sub i128 0, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_converted = select i1 ")?;
    if destination == CheckedNumericKind::SignedInteger {
        ir.push("%t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_negative")?;
    } else {
        ir.push("false")?;
    }
    ir.push(", i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_negated, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_magnitude\n  %v")?;
    ir.number(u128::from(result.0))?;
    ir.push(" = select i1 true, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_converted, i128 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_converted\n")
}

#[allow(clippy::too_many_arguments)]
fn render_checked_integer_conversion(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    instruction: u32,
    result: ValueId,
    source_kind: CheckedNumericKind,
    destination_kind: CheckedNumericKind,
    value: ValueId,
    source: MachineTypeId,
    destination: MachineTypeId,
    failure: ScalarFailureProvenance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let source_bits = integer_bits(machine, source)?;
    let destination_bits = integer_bits(machine, destination)?;
    render_result(ir, Some(result))?;
    match destination_bits.cmp(&source_bits) {
        std::cmp::Ordering::Less => ir.push("trunc i")?,
        std::cmp::Ordering::Greater => {
            ir.push(if source_kind == CheckedNumericKind::SignedInteger {
                "sext i"
            } else {
                "zext i"
            })?;
        }
        std::cmp::Ordering::Equal => ir.push("select i1 true, i")?,
    }
    ir.number(u128::from(source_bits))?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    if source_bits == destination_bits {
        ir.push(", i")?;
        ir.number(u128::from(source_bits))?;
        ir.push(" %v")?;
        ir.number(u128::from(value.0))?;
    } else {
        ir.push(" to i")?;
        ir.number(u128::from(destination_bits))?;
    }
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_roundtrip = ")?;
    match source_bits.cmp(&destination_bits) {
        std::cmp::Ordering::Less => ir.push("trunc i")?,
        std::cmp::Ordering::Greater => {
            ir.push(if destination_kind == CheckedNumericKind::SignedInteger {
                "sext i"
            } else {
                "zext i"
            })?;
        }
        std::cmp::Ordering::Equal => ir.push("select i1 true, i")?,
    }
    ir.number(u128::from(destination_bits))?;
    ir.push(" %v")?;
    ir.number(u128::from(result.0))?;
    if source_bits == destination_bits {
        ir.push(", i")?;
        ir.number(u128::from(destination_bits))?;
        ir.push(" %v")?;
        ir.number(u128::from(result.0))?;
    } else {
        ir.push(" to i")?;
        ir.number(u128::from(source_bits))?;
    }
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_roundtrip_ok = icmp eq i")?;
    ir.number(u128::from(source_bits))?;
    ir.push(" %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_roundtrip, %v")?;
    ir.number(u128::from(value.0))?;
    if source_kind == CheckedNumericKind::SignedInteger
        && destination_kind == CheckedNumericKind::UnsignedInteger
    {
        ir.push("\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_sign_ok = icmp sge i")?;
        ir.number(u128::from(source_bits))?;
        ir.push(" %v")?;
        ir.number(u128::from(value.0))?;
        ir.push(", 0\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_valid = and i1 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_roundtrip_ok, %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_sign_ok\n")?;
    } else if source_kind == CheckedNumericKind::UnsignedInteger
        && destination_kind == CheckedNumericKind::SignedInteger
        && destination_bits <= source_bits
    {
        ir.push("\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_sign_ok = icmp ult i")?;
        ir.number(u128::from(source_bits))?;
        ir.push(" %v")?;
        ir.number(u128::from(value.0))?;
        ir.push(", ")?;
        ir.number(1_u128 << u32::from(destination_bits - 1))?;
        ir.push("\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_valid = and i1 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_roundtrip_ok, %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_sign_ok\n")?;
    } else {
        ir.push("\n  %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_valid = or i1 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_roundtrip_ok, false\n")?;
    }
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_failed = xor i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_valid, true\n")?;
    render_checked_failure(ir, machine, instruction, failure, is_cancelled)
}

fn render_checked_failure(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    instruction: u32,
    failure: ScalarFailureProvenance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    render_checked_failure_with_code(
        ir,
        machine,
        instruction,
        failure,
        FatalCodeOperand::Constant(failure.kind.runtime_code()),
        is_cancelled,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FatalCodeOperand {
    Constant(RuntimeFatalCode),
    Temporary(u32),
}

fn render_checked_failure_with_code(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    instruction: u32,
    failure: ScalarFailureProvenance,
    code: FatalCodeOperand,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let symbol = runtime_symbol(machine, RuntimeIntrinsic::Fatal)?;
    ir.push("  br i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_failed, label %i")?;
    ir.number(u128::from(instruction))?;
    ir.push("_fail, label %i")?;
    ir.number(u128::from(instruction))?;
    ir.push("_ok\ni")?;
    ir.number(u128::from(instruction))?;
    ir.push("_fail:\n  call void @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push("(i32 ")?;
    match code {
        FatalCodeOperand::Constant(code) => ir.number(u128::from(code.as_u32()))?,
        FatalCodeOperand::Temporary(code_instruction) => {
            ir.push("%t")?;
            ir.number(u128::from(code_instruction))?;
            ir.push("_fatal_code")?;
        }
    }
    ir.push(", i64 ")?;
    ir.number(u128::from(failure.runtime_detail()))?;
    ir.push(")\n  unreachable\ni")?;
    ir.number(u128::from(instruction))?;
    ir.push("_ok:\n")
}

#[allow(clippy::too_many_arguments)]
fn render_actor_reserve(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    instruction: u32,
    result: Option<ValueId>,
    mailbox: GlobalId,
    failure: ScalarFailureProvenance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let result = required_result(result)?;
    let symbol = actor_mailbox_symbol(machine, mailbox)?;
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_tag = load atomic i64, ptr @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push(" acquire, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_failed = icmp ne i64 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_tag, 0\n")?;
    render_checked_failure(ir, machine, instruction, failure, is_cancelled)?;
    ir.push("  %v")?;
    ir.number(u128::from(result.0))?;
    ir.push(" = getelementptr i8, ptr @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push(", i64 0\n")?;
    Ok(())
}

fn render_actor_commit(
    ir: &mut IrText,
    reservation: ValueId,
    method: FunctionId,
) -> Result<(), CodegenError> {
    ir.push("  store atomic i64 ")?;
    ir.number(u128::from(actor_message_tag(method)))?;
    ir.push(", ptr %v")?;
    ir.number(u128::from(reservation.0))?;
    ir.push(" release, align 8\n")
}

fn render_actor_reply_failure(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    instruction: u32,
    suffix: &str,
    failure: ScalarFailureProvenance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let symbol = runtime_symbol(machine, RuntimeIntrinsic::Fatal)?;
    ir.push("  br i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_")?;
    ir.push(suffix)?;
    ir.push("_failed, label %i")?;
    ir.number(u128::from(instruction))?;
    ir.push("_")?;
    ir.push(suffix)?;
    ir.push("_fail, label %i")?;
    ir.number(u128::from(instruction))?;
    ir.push("_")?;
    ir.push(suffix)?;
    ir.push("_ok\ni")?;
    ir.number(u128::from(instruction))?;
    ir.push("_")?;
    ir.push(suffix)?;
    ir.push("_fail:\n  call void @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push("(i32 ")?;
    ir.number(u128::from(failure.kind.runtime_code().as_u32()))?;
    ir.push(", i64 ")?;
    ir.number(u128::from(failure.runtime_detail()))?;
    ir.push(")\n  unreachable\ni")?;
    ir.number(u128::from(instruction))?;
    ir.push("_")?;
    ir.push(suffix)?;
    ir.push("_ok:\n")
}

#[allow(clippy::too_many_arguments)]
fn render_actor_reply_request(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    instruction: u32,
    result: Option<ValueId>,
    slot: wrela_machine_wir::StackSlotId,
    mailbox: GlobalId,
    method: FunctionId,
    state_failure: ScalarFailureProvenance,
    duplicate_failure: ScalarFailureProvenance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let result = required_result(result)?;
    let mailbox_symbol = actor_mailbox_symbol(machine, mailbox)?;
    let method_symbol = machine
        .functions
        .get(method.0 as usize)
        .and_then(|function| machine.symbols.get(function.symbol.0 as usize))
        .map(|symbol| symbol.name.as_str())
        .ok_or(CodegenError::UnsupportedMachineContract(
            "an actor reply target lacks its internal symbol",
        ))?;
    ir.push("  store atomic i64 0, ptr %s")?;
    ir.number(u128::from(slot.0))?;
    ir.push(" release, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_claim = cmpxchg ptr %s")?;
    ir.number(u128::from(slot.0))?;
    ir.push(", i64 0, i64 1 acq_rel acquire, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_claimed = extractvalue { i64, i1 } %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_claim, 1\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_tag = load atomic i64, ptr @")?;
    ir.push_cancellable(mailbox_symbol, is_cancelled)?;
    ir.push(" acquire, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_empty = icmp eq i64 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_tag, 0\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_admitted = and i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_claimed, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_empty\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_claim_failed = xor i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_admitted, true\n")?;
    render_actor_reply_failure(
        ir,
        machine,
        instruction,
        "claim",
        state_failure,
        is_cancelled,
    )?;
    ir.push("  store atomic i64 ")?;
    ir.number(u128::from(actor_message_tag(method)))?;
    ir.push(", ptr @")?;
    ir.push_cancellable(mailbox_symbol, is_cancelled)?;
    ir.push(" release, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_outcome = call fastcc i64 @")?;
    ir.push_cancellable(method_symbol, is_cancelled)?;
    ir.push("()\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_write = cmpxchg ptr %s")?;
    ir.number(u128::from(slot.0))?;
    ir.push(", i64 1, i64 2 acq_rel acquire, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_writing = extractvalue { i64, i1 } %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_write, 1\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_write_failed = xor i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_writing, true\n")?;
    render_actor_reply_failure(
        ir,
        machine,
        instruction,
        "write",
        duplicate_failure,
        is_cancelled,
    )?;
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_outcome_slot = getelementptr i8, ptr %s")?;
    ir.number(u128::from(slot.0))?;
    ir.push(", i64 8\n  store i64 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_outcome, ptr %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_outcome_slot, align 8\n  store atomic i64 3, ptr %s")?;
    ir.number(u128::from(slot.0))?;
    ir.push(" release, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_state = load atomic i64, ptr %s")?;
    ir.number(u128::from(slot.0))?;
    ir.push(" acquire, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_consume_failed = icmp ne i64 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_state, 3\n")?;
    render_actor_reply_failure(
        ir,
        machine,
        instruction,
        "consume",
        state_failure,
        is_cancelled,
    )?;
    ir.push("  %v")?;
    ir.number(u128::from(result.0))?;
    ir.push(" = load i64, ptr %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_outcome_slot, align 8\n  store atomic i64 4, ptr %s")?;
    ir.number(u128::from(slot.0))?;
    ir.push(" release, align 8\n  br label %i")?;
    ir.number(u128::from(instruction))?;
    ir.push("_ok\ni")?;
    ir.number(u128::from(instruction))?;
    ir.push("_ok:\n")
}

fn render_mailbox_receive(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    instruction: u32,
    mailbox: GlobalId,
    method: FunctionId,
    failure: ScalarFailureProvenance,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let symbol = actor_mailbox_symbol(machine, mailbox)?;
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_tag = load atomic i64, ptr @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push(" acquire, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_failed = icmp ne i64 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_tag, ")?;
    ir.number(u128::from(actor_message_tag(method)))?;
    ir.push("\n")?;
    render_checked_failure(ir, machine, instruction, failure, is_cancelled)?;
    ir.push("  store atomic i64 0, ptr @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push(" release, align 8\n")
}

fn render_mailbox_dispatch(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    instruction: u32,
    mailbox: GlobalId,
    method: FunctionId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let symbol = actor_mailbox_symbol(machine, mailbox)?;
    let mailbox_actor = machine.region_storage.iter().find_map(|storage| {
        if storage.global != mailbox {
            return None;
        }
        match storage.kind {
            wrela_machine_wir::MachineRegionStorageKind::ActorMailbox { actor, .. } => Some(actor),
            _ => None,
        }
    });
    let mut methods = Vec::new();
    methods
        .try_reserve_exact(machine.activations.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "actor scheduler method table",
            limit: u64::try_from(machine.activations.len()).unwrap_or(u64::MAX),
            actual: u64::MAX,
        })?;
    for activation in &machine.activations {
        check_cancelled(is_cancelled)?;
        if activation.schedule == wrela_machine_wir::MachineActivationSchedule::SchedulerFifo
            && matches!(
                activation.owner,
                wrela_machine_wir::MachineActivationOwner::Actor { actor, .. }
                    if Some(actor) == mailbox_actor
            )
        {
            methods.push(activation.caller);
        }
    }
    if methods.is_empty() {
        methods.push(method);
    }
    methods.sort_unstable_by_key(|turn| turn.0);
    methods.dedup();
    ir.push("  br label %i")?;
    ir.number(u128::from(instruction))?;
    ir.push("_scan\ni")?;
    ir.number(u128::from(instruction))?;
    ir.push("_scan:\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_tag = load atomic i64, ptr @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push(" acquire, align 8\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_pending = icmp ne i64 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_tag, 0\n  br i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_mailbox_pending, label %i")?;
    ir.number(u128::from(instruction))?;
    ir.push(if methods.len() == 1 {
        "_dispatch, label %i"
    } else {
        "_select, label %i"
    })?;
    ir.number(u128::from(instruction))?;
    ir.push("_ok\ni")?;
    ir.number(u128::from(instruction))?;
    if methods.len() == 1 {
        ir.push("_dispatch:\n")?;
        render_call(
            ir,
            machine,
            function,
            None,
            methods[0],
            &[],
            CallingConvention::Internal,
            false,
            0,
            is_cancelled,
        )?;
        ir.push("  br label %i")?;
        ir.number(u128::from(instruction))?;
        ir.push("_scan\ni")?;
    } else {
        ir.push("_select:\n  switch i64 %t")?;
        ir.number(u128::from(instruction))?;
        ir.push("_mailbox_tag, label %i")?;
        ir.number(u128::from(instruction))?;
        ir.push("_call_")?;
        ir.number(u128::from(methods[0].0))?;
        ir.push(" [")?;
        for turn in &methods {
            ir.push(" i64 ")?;
            ir.number(u128::from(actor_message_tag(*turn)))?;
            ir.push(", label %i")?;
            ir.number(u128::from(instruction))?;
            ir.push("_call_")?;
            ir.number(u128::from(turn.0))?;
        }
        ir.push(" ]\n")?;
        for turn in &methods {
            ir.push("i")?;
            ir.number(u128::from(instruction))?;
            ir.push("_call_")?;
            ir.number(u128::from(turn.0))?;
            ir.push(":\n")?;
            render_call(
                ir,
                machine,
                function,
                None,
                *turn,
                &[],
                CallingConvention::Internal,
                false,
                0,
                is_cancelled,
            )?;
            ir.push("  br label %i")?;
            ir.number(u128::from(instruction))?;
            ir.push("_scan\n")?;
        }
        ir.push("i")?;
    }
    ir.number(u128::from(instruction))?;
    ir.push("_ok:\n")
}

fn actor_mailbox_symbol(
    machine: &wrela_machine_wir::MachineWir,
    mailbox: GlobalId,
) -> Result<&str, CodegenError> {
    let global =
        machine
            .globals
            .get(mailbox.0 as usize)
            .ok_or(CodegenError::UnsupportedMachineContract(
                "actor mailbox global disappeared",
            ))?;
    symbol_name(machine, global.symbol.0)
}

fn actor_message_tag(method: FunctionId) -> u64 {
    u64::from(method.0) + 1
}

fn render_never_failed(ir: &mut IrText, instruction: u32) -> Result<(), CodegenError> {
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_failed = or i1 false, false\n")
}

fn render_float_infinity_test(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    instruction: u32,
    value: ValueId,
    kind: CheckedNumericKind,
    suffix: &str,
) -> Result<(), CodegenError> {
    let ty = match kind {
        CheckedNumericKind::Float32 => "float",
        CheckedNumericKind::Float64 => "double",
        _ => {
            return Err(CodegenError::UnsupportedMachineContract(
                "an integer reached a floating infinity check",
            ));
        }
    };
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_positive_infinity = fcmp oeq ")?;
    ir.push(ty)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(", ")?;
    render_float_constant(ir, kind, float_infinity_bits(kind, false)?)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_negative_infinity = fcmp oeq ")?;
    ir.push(ty)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(", ")?;
    render_float_constant(ir, kind, float_infinity_bits(kind, true)?)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_")?;
    ir.push(suffix)?;
    ir.push(" = or i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_positive_infinity, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_negative_infinity\n")?;
    let _ = machine;
    Ok(())
}

fn render_float_finite_test(
    ir: &mut IrText,
    instruction: u32,
    value: ValueId,
    kind: CheckedNumericKind,
) -> Result<(), CodegenError> {
    let ty = if kind == CheckedNumericKind::Float32 {
        "float"
    } else {
        "double"
    };
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_not_positive_infinity = fcmp one ")?;
    ir.push(ty)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(", ")?;
    render_float_constant(ir, kind, float_infinity_bits(kind, false)?)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_not_negative_infinity = fcmp one ")?;
    ir.push(ty)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(", ")?;
    render_float_constant(ir, kind, float_infinity_bits(kind, true)?)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_finite = and i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_not_positive_infinity, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_not_negative_infinity\n")
}

fn render_float_integer_range_test(
    ir: &mut IrText,
    instruction: u32,
    value: ValueId,
    source: CheckedNumericKind,
    destination: CheckedNumericKind,
    destination_bits: u16,
) -> Result<(), CodegenError> {
    let (lower_bits, inclusive) = float_integer_lower_bound(source, destination, destination_bits)?;
    let upper_bits = float_integer_upper_bound(source, destination, destination_bits)?;
    let ty = if source == CheckedNumericKind::Float32 {
        "float"
    } else {
        "double"
    };
    ir.push("  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_lower_ok = fcmp ")?;
    ir.push(if inclusive { "oge " } else { "ogt " })?;
    ir.push(ty)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(", ")?;
    render_float_constant(ir, source, lower_bits)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_upper_ok = fcmp olt ")?;
    ir.push(ty)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(", ")?;
    render_float_constant(ir, source, upper_bits)?;
    ir.push("\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_range_ok = and i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_lower_ok, %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_upper_ok\n  %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_failed = xor i1 %t")?;
    ir.number(u128::from(instruction))?;
    ir.push("_range_ok, true\n")
}

fn render_float_constant(
    ir: &mut IrText,
    kind: CheckedNumericKind,
    bits: u64,
) -> Result<(), CodegenError> {
    match kind {
        CheckedNumericKind::Float32 => {
            ir.push("bitcast (i32 ")?;
            ir.number(u128::from(bits as u32))?;
            ir.push(" to float)")
        }
        CheckedNumericKind::Float64 => {
            ir.push("bitcast (i64 ")?;
            ir.number(u128::from(bits))?;
            ir.push(" to double)")
        }
        _ => Err(CodegenError::UnsupportedMachineContract(
            "an integer reached floating constant rendering",
        )),
    }
}

fn float_infinity_bits(kind: CheckedNumericKind, negative: bool) -> Result<u64, CodegenError> {
    let (positive, sign) = match kind {
        CheckedNumericKind::Float32 => (u64::from(f32::INFINITY.to_bits()), 1_u64 << 31),
        CheckedNumericKind::Float64 => (f64::INFINITY.to_bits(), 1_u64 << 63),
        _ => {
            return Err(CodegenError::UnsupportedMachineContract(
                "an integer requested floating infinity",
            ));
        }
    };
    Ok(if negative { positive | sign } else { positive })
}

fn float_power_of_two_bits(
    kind: CheckedNumericKind,
    exponent: u16,
    negative: bool,
) -> Result<u64, CodegenError> {
    let bits = match kind {
        CheckedNumericKind::Float32 if exponent <= 127 => {
            u64::from((u32::from(exponent) + 127) << 23 | if negative { 1_u32 << 31 } else { 0 })
        }
        CheckedNumericKind::Float32 => float_infinity_bits(kind, negative)?,
        CheckedNumericKind::Float64 if exponent <= 1023 => {
            (u64::from(exponent) + 1023) << 52 | if negative { 1_u64 << 63 } else { 0 }
        }
        CheckedNumericKind::Float64 => float_infinity_bits(kind, negative)?,
        _ => {
            return Err(CodegenError::UnsupportedMachineContract(
                "an integer requested a floating power",
            ));
        }
    };
    Ok(bits)
}

fn float_integer_lower_bound(
    source: CheckedNumericKind,
    destination: CheckedNumericKind,
    bits: u16,
) -> Result<(u64, bool), CodegenError> {
    if destination == CheckedNumericKind::UnsignedInteger {
        return Ok((
            match source {
                CheckedNumericKind::Float32 => u64::from((-1.0_f32).to_bits()),
                CheckedNumericKind::Float64 => (-1.0_f64).to_bits(),
                _ => {
                    return Err(CodegenError::UnsupportedMachineContract(
                        "an integer requested a floating range",
                    ));
                }
            },
            false,
        ));
    }
    let precision = match source {
        CheckedNumericKind::Float32 => 24,
        CheckedNumericKind::Float64 => 53,
        _ => {
            return Err(CodegenError::UnsupportedMachineContract(
                "an integer requested a floating range",
            ));
        }
    };
    if bits <= precision {
        let magnitude = (1_u128 << u32::from(bits - 1)) + 1;
        Ok((
            match source {
                CheckedNumericKind::Float32 => u64::from((-(magnitude as f32)).to_bits()),
                CheckedNumericKind::Float64 => (-(magnitude as f64)).to_bits(),
                _ => unreachable!(),
            },
            false,
        ))
    } else {
        Ok((float_power_of_two_bits(source, bits - 1, true)?, true))
    }
}

fn float_integer_upper_bound(
    source: CheckedNumericKind,
    destination: CheckedNumericKind,
    bits: u16,
) -> Result<u64, CodegenError> {
    float_power_of_two_bits(
        source,
        if destination == CheckedNumericKind::SignedInteger {
            bits - 1
        } else {
            bits
        },
        false,
    )
}

fn integer_bits(
    machine: &wrela_machine_wir::MachineWir,
    ty: MachineTypeId,
) -> Result<u16, CodegenError> {
    match type_kind(machine, ty)? {
        MachineTypeKind::Integer { bits } => Ok(*bits),
        _ => Err(CodegenError::UnsupportedMachineContract(
            "checked integer semantics reached a non-integer type",
        )),
    }
}

fn integer_mask(bits: u16) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << u32::from(bits)) - 1
    }
}

fn render_conversion(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    result: Option<ValueId>,
    operation: ConversionOp,
    value: ValueId,
    destination: MachineTypeId,
) -> Result<(), CodegenError> {
    let opcode = match operation {
        ConversionOp::Bitcast => {
            return render_bitcast(ir, machine, function, result, value, destination);
        }
        ConversionOp::ZeroExtend => "zext",
        ConversionOp::SignExtend => "sext",
        ConversionOp::FloatExtend => "fpext",
        ConversionOp::UnsignedIntegerToFloat => "uitofp",
        ConversionOp::SignedIntegerToFloat => "sitofp",
        ConversionOp::IntegerTruncate
        | ConversionOp::FloatTruncate
        | ConversionOp::FloatToUnsignedInteger
        | ConversionOp::FloatToSignedInteger
        | ConversionOp::PointerToInteger
        | ConversionOp::IntegerToPointer => {
            return Err(CodegenError::UnsupportedMachineContract(
                "an unsealed scalar conversion reached LLVM rendering",
            ));
        }
    };
    render_result(ir, result)?;
    ir.push(opcode)?;
    ir.push(" ")?;
    render_value_type(ir, machine, function, value)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(" to ")?;
    render_type(ir, machine, destination)?;
    ir.push("\n")
}

fn render_bitcast(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    result: Option<ValueId>,
    value: ValueId,
    destination: MachineTypeId,
) -> Result<(), CodegenError> {
    let source = value_type(function, value)?;
    render_result(ir, result)?;
    if same_llvm_type(machine, source, destination)? {
        ir.push("select i1 true, ")?;
        render_type(ir, machine, source)?;
        ir.push(" %v")?;
        ir.number(u128::from(value.0))?;
        ir.push(", ")?;
        render_type(ir, machine, source)?;
        ir.push(" %v")?;
        ir.number(u128::from(value.0))?;
        ir.push("\n")
    } else {
        ir.push("bitcast ")?;
        render_type(ir, machine, source)?;
        ir.push(" %v")?;
        ir.number(u128::from(value.0))?;
        ir.push(" to ")?;
        render_type(ir, machine, destination)?;
        ir.push("\n")
    }
}

fn render_load(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    result: Option<ValueId>,
    address: ValueId,
    ty: MachineTypeId,
    semantics: MemorySemantics,
    alignment: Option<u32>,
) -> Result<(), CodegenError> {
    render_result(ir, result)?;
    ir.push("load ")?;
    if matches!(semantics, MemorySemantics::Atomic(_)) {
        ir.push("atomic ")?;
    }
    if matches!(
        semantics,
        MemorySemantics::Volatile | MemorySemantics::Device
    ) {
        ir.push("volatile ")?;
    }
    render_type(ir, machine, ty)?;
    ir.push(", ptr %v")?;
    ir.number(u128::from(address.0))?;
    if let MemorySemantics::Atomic(ordering) = semantics {
        ir.push(" ")?;
        ir.push(atomic_ordering(ordering))?;
    }
    ir.push(", align ")?;
    ir.number(u128::from(alignment.unwrap_or(1)))?;
    ir.push("\n")
}

fn render_store(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    address: ValueId,
    value: ValueId,
    semantics: MemorySemantics,
    alignment: Option<u32>,
) -> Result<(), CodegenError> {
    ir.push("  store ")?;
    if matches!(semantics, MemorySemantics::Atomic(_)) {
        ir.push("atomic ")?;
    }
    if matches!(
        semantics,
        MemorySemantics::Volatile | MemorySemantics::Device
    ) {
        ir.push("volatile ")?;
    }
    render_value_type(ir, machine, function, value)?;
    ir.push(" %v")?;
    ir.number(u128::from(value.0))?;
    ir.push(", ptr %v")?;
    ir.number(u128::from(address.0))?;
    if let MemorySemantics::Atomic(ordering) = semantics {
        ir.push(" ")?;
        ir.push(atomic_ordering(ordering))?;
    }
    ir.push(", align ")?;
    ir.number(u128::from(alignment.unwrap_or(1)))?;
    ir.push("\n")
}

#[allow(clippy::too_many_arguments)]
fn render_call(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    caller: &MachineFunction,
    result: Option<ValueId>,
    callee: wrela_machine_wir::FunctionId,
    arguments: &[ValueId],
    convention: CallingConvention,
    tail: bool,
    block: u32,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let callee = machine_function(machine, callee.0)?;
    ir.push("  ")?;
    if tail {
        let result_is_void = matches!(type_kind(machine, callee.result)?, MachineTypeKind::Void);
        if !result_is_void {
            ir.push("%tail_b")?;
            ir.number(u128::from(block))?;
            ir.push(" = ")?;
        }
        ir.push("musttail ")?;
    } else if let Some(result) = result {
        ir.push("%v")?;
        ir.number(u128::from(result.0))?;
        ir.push(" = ")?;
    }
    ir.push("call ")?;
    render_calling_convention(ir, convention)?;
    render_type(ir, machine, callee.result)?;
    ir.push(" @")?;
    ir.push_cancellable(symbol_name(machine, callee.symbol.0)?, is_cancelled)?;
    ir.push("(")?;
    for (index, argument) in arguments.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if index != 0 {
            ir.push(", ")?;
        }
        render_value_type(ir, machine, caller, *argument)?;
        ir.push(" %v")?;
        ir.number(u128::from(argument.0))?;
    }
    ir.push(")\n")
}

fn render_runtime_call(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    caller: &MachineFunction,
    result: Option<ValueId>,
    intrinsic: RuntimeIntrinsic,
    arguments: &[ValueId],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let signature = intrinsic.signature();
    let symbol = runtime_symbol(machine, intrinsic)?;
    ir.push("  ")?;
    if let Some(result) = result {
        ir.push("%v")?;
        ir.number(u128::from(result.0))?;
        ir.push(" = ")?;
    }
    ir.push("call ")?;
    render_abi_type(ir, signature.result)?;
    ir.push(" @")?;
    ir.push_cancellable(symbol, is_cancelled)?;
    ir.push("(")?;
    for (index, argument) in arguments.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if index != 0 {
            ir.push(", ")?;
        }
        render_value_type(ir, machine, caller, *argument)?;
        ir.push(" %v")?;
        ir.number(u128::from(argument.0))?;
    }
    ir.push(")\n")
}

fn runtime_symbol(
    machine: &wrela_machine_wir::MachineWir,
    intrinsic: RuntimeIntrinsic,
) -> Result<&str, CodegenError> {
    machine
        .symbols
        .iter()
        .find_map(|symbol| {
            (symbol.definition == SymbolDefinition::ExternalRuntime(intrinsic))
                .then_some(symbol.name.as_str())
        })
        .ok_or(CodegenError::UnsupportedMachineContract(
            "a runtime call without its exact external symbol",
        ))
}

fn render_abi_type(ir: &mut IrText, ty: AbiType) -> Result<(), CodegenError> {
    match ty {
        AbiType::Unit => ir.push("void"),
        AbiType::Bool | AbiType::U8 => ir.push("i8"),
        AbiType::U32 => ir.push("i32"),
        AbiType::U64 | AbiType::Usize | AbiType::Status => ir.push("i64"),
        AbiType::Address => ir.push("ptr"),
    }
}

fn render_fence(ir: &mut IrText, fence: MachineFence) -> Result<(), CodegenError> {
    match fence {
        MachineFence::Acquire => ir.push("  fence acquire\n"),
        MachineFence::Release => ir.push("  fence release\n"),
        MachineFence::AcquireRelease => ir.push("  fence acq_rel\n"),
        MachineFence::Sequential => ir.push("  fence seq_cst\n"),
        MachineFence::DeviceRead => {
            ir.push("  call void asm sideeffect \"dmb oshld\", \"~{memory}\"()\n")
        }
        MachineFence::DeviceWrite => {
            ir.push("  call void asm sideeffect \"dmb oshst\", \"~{memory}\"()\n")
        }
        MachineFence::DeviceFull => {
            ir.push("  call void asm sideeffect \"dmb osh\", \"~{memory}\"()\n")
        }
    }
}

fn render_terminator(
    ir: &mut IrText,
    request: &CodegenRequest<'_>,
    function: &MachineFunction,
    block: u32,
    terminator: &MachineTerminator,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    match terminator {
        MachineTerminator::Jump { block, .. } => {
            ir.push("  br label %b")?;
            ir.number(u128::from(block.0))?;
            ir.push("\n")?;
        }
        MachineTerminator::Branch {
            condition,
            then_block,
            else_block,
            ..
        } => {
            render_bool_test(ir, block, "branch", *condition)?;
            ir.push("  br i1 %t")?;
            ir.number(u128::from(block))?;
            ir.push("_branch, label %b")?;
            ir.number(u128::from(then_block.0))?;
            ir.push(", label %b")?;
            ir.number(u128::from(else_block.0))?;
            ir.push("\n")?;
        }
        MachineTerminator::Switch {
            value,
            cases,
            default,
            ..
        } => {
            ir.push("  switch ")?;
            render_value_type(ir, machine, function, *value)?;
            ir.push(" %v")?;
            ir.number(u128::from(value.0))?;
            ir.push(", label %b")?;
            ir.number(u128::from(default.0))?;
            ir.push(" [\n")?;
            for (case_index, (case, target, _)) in cases.iter().enumerate() {
                check_periodically(case_index, is_cancelled)?;
                ir.push("    ")?;
                render_value_type(ir, machine, function, *value)?;
                ir.push(" ")?;
                ir.number(*case)?;
                ir.push(", label %b")?;
                ir.number(u128::from(target.0))?;
                ir.push("\n")?;
            }
            ir.push("  ]\n")?;
        }
        MachineTerminator::Return(values) => {
            if let Some(value) = values.first() {
                ir.push("  ret ")?;
                render_value_type(ir, machine, function, *value)?;
                ir.push(" %v")?;
                ir.number(u128::from(value.0))?;
                ir.push("\n")?;
            } else {
                ir.push("  ret void\n")?;
            }
        }
        MachineTerminator::TailCall {
            function: callee,
            arguments,
        } => {
            let callee_function = machine_function(machine, callee.0)?;
            render_call(
                ir,
                machine,
                function,
                None,
                *callee,
                arguments,
                callee_function.convention,
                true,
                block,
                is_cancelled,
            )?;
            if matches!(
                type_kind(machine, callee_function.result)?,
                MachineTypeKind::Void
            ) {
                ir.push("  ret void\n")?;
            } else {
                ir.push("  ret ")?;
                render_type(ir, machine, callee_function.result)?;
                ir.push(" %tail_b")?;
                ir.number(u128::from(block))?;
                ir.push("\n")?;
            }
        }
        MachineTerminator::Unreachable => ir.push("  unreachable\n")?,
    }
    Ok(())
}

fn render_bool_test(
    ir: &mut IrText,
    discriminator: u32,
    suffix: &str,
    condition: ValueId,
) -> Result<(), CodegenError> {
    ir.push("  %t")?;
    ir.number(u128::from(discriminator))?;
    ir.push("_")?;
    ir.push(suffix)?;
    ir.push(" = icmp ne i8 %v")?;
    ir.number(u128::from(condition.0))?;
    ir.push(", 0\n")
}

fn render_result(ir: &mut IrText, result: Option<ValueId>) -> Result<(), CodegenError> {
    ir.push("  %v")?;
    ir.number(u128::from(required_result(result)?.0))?;
    ir.push(" = ")
}

fn render_value_pair(ir: &mut IrText, left: ValueId, right: ValueId) -> Result<(), CodegenError> {
    ir.push(" %v")?;
    ir.number(u128::from(left.0))?;
    ir.push(", %v")?;
    ir.number(u128::from(right.0))?;
    ir.push("\n")
}

fn render_value_type(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    value: ValueId,
) -> Result<(), CodegenError> {
    render_type(ir, machine, value_type(function, value)?)
}

fn render_type(
    ir: &mut IrText,
    machine: &wrela_machine_wir::MachineWir,
    ty: MachineTypeId,
) -> Result<(), CodegenError> {
    match type_kind(machine, ty)? {
        MachineTypeKind::Void => ir.push("void"),
        MachineTypeKind::Integer { bits } => {
            ir.push("i")?;
            ir.number(u128::from(*bits))
        }
        MachineTypeKind::Float32 => ir.push("float"),
        MachineTypeKind::Float64 => ir.push("double"),
        MachineTypeKind::Pointer {
            address_space: 0, ..
        } => ir.push("ptr"),
        MachineTypeKind::Array { element, length } => {
            ir.push("[")?;
            ir.number(u128::from(*length))?;
            ir.push(" x ")?;
            render_type(ir, machine, *element)?;
            ir.push("]")
        }
        MachineTypeKind::TaggedEnum {
            tag,
            payload,
            storage,
            ..
        } => {
            ir.push("{ ")?;
            render_type(ir, machine, *tag)?;
            if let Some(payload) = payload {
                ir.push(", ")?;
                render_type(ir, machine, *payload)?;
            } else if let Some(storage) = storage {
                ir.push(", ")?;
                render_enum_storage(ir, *storage)?;
            }
            ir.push(" }")
        }
        MachineTypeKind::Struct {
            fields,
            packed: false,
        } => {
            ir.push("{ ")?;
            for (index, field) in fields.iter().enumerate() {
                if index != 0 {
                    ir.push(", ")?;
                }
                render_type(ir, machine, field.ty)?;
            }
            ir.push(" }")
        }
        _ => Err(CodegenError::UnsupportedMachineContract(
            "non-scalar LLVM type",
        )),
    }
}

fn render_enum_storage(
    ir: &mut IrText,
    storage: wrela_machine_wir::MachineEnumStorage,
) -> Result<(), CodegenError> {
    if storage.size == 0
        || !storage.alignment.is_power_of_two()
        || storage.size % u64::from(storage.alignment) != 0
        || storage.alignment > 16
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "an invalid heterogeneous enum storage layout",
        ));
    }
    ir.push("{ i")?;
    ir.number(u128::from(storage.alignment) * 8)?;
    let tail = storage.size - u64::from(storage.alignment);
    if tail != 0 {
        ir.push(", [")?;
        ir.number(u128::from(tail))?;
        ir.push(" x i8]")?;
    }
    ir.push(" }")
}

fn required_result(result: Option<ValueId>) -> Result<ValueId, CodegenError> {
    result.ok_or(CodegenError::UnsupportedMachineContract(
        "a result-producing machine operation omitted its result",
    ))
}

fn value_type(function: &MachineFunction, value: ValueId) -> Result<MachineTypeId, CodegenError> {
    function
        .values
        .get(value.0 as usize)
        .map(|value| value.ty)
        .ok_or(CodegenError::UnsupportedMachineContract(
            "a machine operation referenced an unknown value",
        ))
}

fn type_kind(
    machine: &wrela_machine_wir::MachineWir,
    ty: MachineTypeId,
) -> Result<&MachineTypeKind, CodegenError> {
    machine.types.get(ty.0 as usize).map(|ty| &ty.kind).ok_or(
        CodegenError::UnsupportedMachineContract(
            "LLVM rendering encountered an unknown machine type",
        ),
    )
}

fn symbol_name(machine: &wrela_machine_wir::MachineWir, symbol: u32) -> Result<&str, CodegenError> {
    machine
        .symbols
        .get(symbol as usize)
        .map(|symbol| symbol.name.as_str())
        .ok_or(CodegenError::UnsupportedMachineContract(
            "LLVM rendering encountered an unknown machine symbol",
        ))
}

fn machine_section(
    machine: &wrela_machine_wir::MachineWir,
    section: u32,
) -> Result<&wrela_machine_wir::Section, CodegenError> {
    machine
        .sections
        .get(section as usize)
        .ok_or(CodegenError::UnsupportedMachineContract(
            "LLVM rendering encountered an unknown machine section",
        ))
}

fn machine_function(
    machine: &wrela_machine_wir::MachineWir,
    function: u32,
) -> Result<&MachineFunction, CodegenError> {
    machine
        .functions
        .get(function as usize)
        .ok_or(CodegenError::UnsupportedMachineContract(
            "LLVM rendering encountered an unknown machine function",
        ))
}

fn function_block(
    function: &MachineFunction,
    block: u32,
) -> Result<&wrela_machine_wir::MachineBlock, CodegenError> {
    function
        .blocks
        .get(block as usize)
        .ok_or(CodegenError::UnsupportedMachineContract(
            "LLVM rendering encountered an unknown machine block",
        ))
}

fn render_calling_convention(
    ir: &mut IrText,
    convention: CallingConvention,
) -> Result<(), CodegenError> {
    match convention {
        CallingConvention::Internal => ir.push("fastcc "),
        CallingConvention::Aapcs64 | CallingConvention::UefiAarch64 => Ok(()),
        CallingConvention::InterruptHandler => Err(CodegenError::UnsupportedMachineContract(
            "interrupt calling convention",
        )),
    }
}

fn same_llvm_type(
    machine: &wrela_machine_wir::MachineWir,
    left: MachineTypeId,
    right: MachineTypeId,
) -> Result<bool, CodegenError> {
    match (type_kind(machine, left)?, type_kind(machine, right)?) {
        (
            MachineTypeKind::Pointer {
                address_space: 0, ..
            },
            MachineTypeKind::Pointer {
                address_space: 0, ..
            },
        ) => Ok(true),
        (left, right) => Ok(left == right),
    }
}

fn integer_value(bytes: &[u8]) -> Result<u128, CodegenError> {
    if bytes.len() > 16 {
        return Err(CodegenError::UnsupportedMachineContract(
            "an integer immediate exceeded the supported 128-bit width",
        ));
    }
    let mut padded = [0u8; 16];
    padded
        .get_mut(..bytes.len())
        .ok_or(CodegenError::UnsupportedMachineContract(
            "an integer immediate escaped its supported width",
        ))?
        .copy_from_slice(bytes);
    Ok(u128::from_le_bytes(padded))
}

fn arithmetic_opcode(operation: ArithmeticOp) -> &'static str {
    match operation {
        ArithmeticOp::IntegerAdd => "add",
        ArithmeticOp::IntegerSubtract => "sub",
        ArithmeticOp::IntegerMultiply => "mul",
        ArithmeticOp::UnsignedDivide => "udiv",
        ArithmeticOp::SignedDivide => "sdiv",
        ArithmeticOp::UnsignedRemainder => "urem",
        ArithmeticOp::SignedRemainder => "srem",
        ArithmeticOp::BitAnd => "and",
        ArithmeticOp::BitOr => "or",
        ArithmeticOp::BitXor => "xor",
        ArithmeticOp::ShiftLeft => "shl",
        ArithmeticOp::LogicalShiftRight => "lshr",
        ArithmeticOp::ArithmeticShiftRight => "ashr",
        ArithmeticOp::FloatAdd => "fadd",
        ArithmeticOp::FloatSubtract => "fsub",
        ArithmeticOp::FloatMultiply => "fmul",
        ArithmeticOp::FloatDivide => "fdiv",
    }
}

fn integer_predicate(predicate: IntegerPredicate) -> &'static str {
    match predicate {
        IntegerPredicate::Equal => "eq",
        IntegerPredicate::NotEqual => "ne",
        IntegerPredicate::UnsignedLess => "ult",
        IntegerPredicate::UnsignedLessEqual => "ule",
        IntegerPredicate::UnsignedGreater => "ugt",
        IntegerPredicate::UnsignedGreaterEqual => "uge",
        IntegerPredicate::SignedLess => "slt",
        IntegerPredicate::SignedLessEqual => "sle",
        IntegerPredicate::SignedGreater => "sgt",
        IntegerPredicate::SignedGreaterEqual => "sge",
    }
}

fn float_predicate(predicate: FloatPredicate) -> &'static str {
    match predicate {
        FloatPredicate::OrderedEqual => "oeq",
        FloatPredicate::UnorderedNotEqual => "une",
        FloatPredicate::OrderedLess => "olt",
        FloatPredicate::OrderedLessEqual => "ole",
        FloatPredicate::OrderedGreater => "ogt",
        FloatPredicate::OrderedGreaterEqual => "oge",
        FloatPredicate::Unordered => "uno",
    }
}

fn atomic_ordering(ordering: AtomicOrdering) -> &'static str {
    match ordering {
        AtomicOrdering::Relaxed => "monotonic",
        AtomicOrdering::Acquire => "acquire",
        AtomicOrdering::Release => "release",
        AtomicOrdering::AcquireRelease => "acq_rel",
        AtomicOrdering::Sequential => "seq_cst",
    }
}

fn incoming_edges<'a>(
    function: &'a MachineFunction,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<IncomingEdge<'a>>, CodegenError> {
    let mut actual = 0u64;
    for (block_index, block) in function.blocks.iter().enumerate() {
        check_periodically(block_index, is_cancelled)?;
        let successors = match &block.terminator {
            MachineTerminator::Jump { .. } => 1u64,
            MachineTerminator::Branch { .. } => 2u64,
            MachineTerminator::Switch { cases, .. } => u64::try_from(cases.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
            MachineTerminator::Return(_)
            | MachineTerminator::TailCall { .. }
            | MachineTerminator::Unreachable => 0u64,
        };
        actual = actual.saturating_add(successors);
        if actual > limit {
            return Err(CodegenError::ResourceLimit {
                resource: "LLVM CFG edges",
                limit,
                actual,
            });
        }
    }
    let count = usize::try_from(actual).map_err(|_| CodegenError::ResourceLimit {
        resource: "LLVM CFG edges",
        limit,
        actual,
    })?;
    let mut edges = Vec::new();
    check_cancelled(is_cancelled)?;
    edges
        .try_reserve_exact(count)
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "LLVM CFG edges",
            limit,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for block in &function.blocks {
        check_cancelled(is_cancelled)?;
        let checked_continuation = checked_continuation(&block.instructions, is_cancelled)?;
        match &block.terminator {
            MachineTerminator::Jump {
                block: target,
                arguments,
            } => edges.push(IncomingEdge {
                target: target.0,
                predecessor: block.id.0,
                checked_continuation,
                arguments,
            }),
            MachineTerminator::Branch {
                then_block,
                then_arguments,
                else_block,
                else_arguments,
                ..
            } => {
                edges.push(IncomingEdge {
                    target: then_block.0,
                    predecessor: block.id.0,
                    checked_continuation,
                    arguments: then_arguments,
                });
                edges.push(IncomingEdge {
                    target: else_block.0,
                    predecessor: block.id.0,
                    checked_continuation,
                    arguments: else_arguments,
                });
            }
            MachineTerminator::Switch {
                cases,
                default,
                default_arguments,
                ..
            } => {
                for (case_index, (_, target, arguments)) in cases.iter().enumerate() {
                    check_periodically(case_index, is_cancelled)?;
                    edges.push(IncomingEdge {
                        target: target.0,
                        predecessor: block.id.0,
                        checked_continuation,
                        arguments,
                    });
                }
                edges.push(IncomingEdge {
                    target: default.0,
                    predecessor: block.id.0,
                    checked_continuation,
                    arguments: default_arguments,
                });
            }
            MachineTerminator::Return(_)
            | MachineTerminator::TailCall { .. }
            | MachineTerminator::Unreachable => {}
        }
    }
    if edges.len() != count {
        return Err(CodegenError::UnsupportedMachineContract(
            "LLVM CFG edge inventory changed while rendering",
        ));
    }
    crate::cancellable_sort_by(
        &mut edges,
        |left, right| Ok((left.target, left.predecessor).cmp(&(right.target, right.predecessor))),
        is_cancelled,
    )?;
    Ok(edges)
}

fn checked_continuation(
    instructions: &[MachineInstruction],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<u32>, CodegenError> {
    for instruction in instructions.iter().rev() {
        check_cancelled(is_cancelled)?;
        if matches!(
            instruction.operation,
            MachineOperation::CheckedInteger { .. }
                | MachineOperation::CheckedConvert { .. }
                | MachineOperation::ActorReserve { .. }
                | MachineOperation::ActorReplyRequest { .. }
                | MachineOperation::MailboxReceive { .. }
                | MachineOperation::MailboxDispatch { .. }
                | MachineOperation::TestAssert { .. }
        ) {
            return Ok(Some(instruction.id.0));
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(None)
}

fn check_periodically(index: usize, is_cancelled: &dyn Fn() -> bool) -> Result<(), CodegenError> {
    if index % 1_024 == 0 {
        check_cancelled(is_cancelled)?;
    }
    Ok(())
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), CodegenError> {
    if is_cancelled() {
        Err(CodegenError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod cancellation_tests {
    use std::cell::Cell;

    use wrela_machine_wir::{BlockId, InstructionId};

    use super::{
        CodegenError, IrText, MachineBlock, MachineImmediate, MachineInstruction, MachineOperation,
        MachineTerminator, checked_continuation, for_each_instruction, render_target_header,
    };

    #[test]
    fn target_header_copy_and_empty_block_scan_cancel_inside_input() {
        let mut ir = IrText::new(u64::MAX);
        assert_eq!(
            render_target_header(&mut ir, "layout", "triple", &|| true),
            Err(CodegenError::Cancelled)
        );
        assert!(ir.bytes.is_empty(), "pre-cancelled header wrote output");

        let layout = "x".repeat(3 * 64 * 1024);
        let polls = Cell::new(0usize);
        assert_eq!(
            render_target_header(&mut ir, &layout, "triple", &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next >= 5
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(polls.get(), 5);
        assert_eq!(ir.bytes.len(), "target datalayout = \"".len() + 64 * 1024);

        let blocks = (0..2_048)
            .map(|id| MachineBlock {
                id: BlockId(id),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Unreachable,
            })
            .collect::<Vec<_>>();
        let polls = Cell::new(0usize);
        assert_eq!(
            for_each_instruction(
                &blocks,
                &|| {
                    let prior = polls.get();
                    polls.set(prior.saturating_add(1));
                    prior >= 100
                },
                |_| Ok(()),
            ),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(polls.get(), 101);
    }

    #[test]
    fn reverse_checked_continuation_scan_cancels_mid_prefix() {
        let instructions = (0..2_048)
            .map(|id| MachineInstruction {
                id: InstructionId(id),
                results: Vec::new(),
                operation: MachineOperation::Immediate(MachineImmediate::Bytes(Vec::new())),
                source: None,
            })
            .collect::<Vec<_>>();
        let polls = Cell::new(0usize);
        assert_eq!(
            checked_continuation(&instructions, &|| {
                let prior = polls.get();
                polls.set(prior.saturating_add(1));
                prior >= 100
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(polls.get(), 101);
    }
}
