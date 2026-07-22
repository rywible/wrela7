//! Production canonical encoding for the complete FlowWir model.

use std::str;

use wrela_build_model::{
    BuildIdentity, LanguageRevision, MAX_PROFILE_ATOM_BYTES, Sha256Digest, TargetIdentity,
};
use wrela_flow_wir::{
    AccessKind, ActivationCancellation, ActivationId, ActivationPlan, ActorId, ActorPlan,
    AssertionFailureDescriptor, BinaryOp, Block, BlockId, CastMode, Checkpoint, CheckpointId,
    DeviceId, DevicePlan, DmaOwnership, FailureKind, FenceKind, FlowFunction, FlowGlobal,
    FlowOperation, FlowType, FlowTypeKind, FlowWir, FunctionColor, FunctionId, FunctionOrigin,
    FunctionRole, GlobalId, Immediate, Instruction, InstructionId, PlanOwner, PoolId, PoolPlan,
    Proof, ProofId, ProofKind, RegionClass, RegionId, RegionPlan, ScalarType, SourceSummary,
    SwitchCase, TaskId, TaskPlan, Terminator, TestEntry, TestId, TestKind, TypeId, UnaryOp,
    ValidatedFlowWir, Value, ValueId,
};
use wrela_source::{FileId, Span, TextRange};
use wrela_test_model::{
    FullImageTestGroup, FunctionKey, ImageGroupId, ImageRoot, ImageTest, ImageTestInvocation,
    PlannedAssertionDescriptor, ScenarioId, TestDescriptor, TestId as PlanTestId,
    TestKind as PlannedTestKind,
};

use crate::{
    CANCELLABLE_CODEC_CHUNK_BYTES, CodecError, CodecLimits, DecodeRequest, EncodeRequest,
    EncodedFlowWirCandidate, FLOW_WIR_MAGIC, FLOW_WIR_WIRE_VERSION, FlowWirCodec, WireHeader,
    build_identity_equal, check_cancelled, flow_validation_limits, map_validation_failure,
};

/// Stateless production codec for the complete current FlowWir model.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalFlowWirCodec;

impl FlowWirCodec for CanonicalFlowWirCodec {
    fn encode(
        &self,
        request: EncodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<EncodedFlowWirCandidate, CodecError> {
        request.limits.validate()?;
        cancelled(is_cancelled)?;
        let model = request.wir.as_wir();
        let mut writer = Writer::new(request.limits, is_cancelled);
        writer.raw(FLOW_WIR_MAGIC)?;
        writer.u32(FLOW_WIR_WIRE_VERSION)?;
        writer.u32(wrela_flow_wir::FLOW_WIR_VERSION)?;
        let payload_length_offset = writer.position();
        writer.u64(0)?;
        writer.build_identity(&model.build)?;
        let payload_start = writer.position();
        writer.flow_wir(model)?;
        cancelled(is_cancelled)?;
        let payload_bytes = writer
            .position()
            .checked_sub(payload_start)
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(CodecError::LengthOverflow)?;
        if payload_bytes == 0 {
            return Err(CodecError::NonCanonical("empty FlowWir payload"));
        }
        writer.patch_u64(payload_length_offset, payload_bytes)?;
        let bytes = writer.finish();
        Ok(EncodedFlowWirCandidate {
            header: WireHeader {
                wire_version: FLOW_WIR_WIRE_VERSION,
                flow_wir_version: wrela_flow_wir::FLOW_WIR_VERSION,
                payload_bytes,
                build: clone_build_identity(&model.build, is_cancelled)?,
            },
            bytes,
        })
    }

    fn inspect_header(
        &self,
        bytes: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<WireHeader, CodecError> {
        Ok(parse_header(bytes, is_cancelled)?.header)
    }

    fn decode(
        &self,
        request: DecodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedFlowWir, CodecError> {
        request.limits.validate()?;
        cancelled(is_cancelled)?;
        let frame_bytes =
            u64::try_from(request.bytes.len()).map_err(|_| CodecError::LengthOverflow)?;
        enforce(
            "FlowWir frame bytes",
            request.limits.frame_bytes,
            frame_bytes,
        )?;
        let parsed = parse_header(request.bytes, is_cancelled)?;
        if let Some(expected) = request.expected_build {
            if !build_identity_equal(expected, &parsed.header.build, is_cancelled)? {
                return Err(CodecError::BuildIdentityMismatch);
            }
        }
        let mut reader = Reader::new(
            request.bytes,
            parsed.payload_start,
            request.limits,
            is_cancelled,
        );
        reader.meter.charge_string(
            parsed.target_bytes,
            "aggregate string bytes",
            u64::from(request.limits.string_bytes),
        )?;
        let model = reader.flow_wir(parsed.header.build)?;
        reader.finish()?;
        cancelled(is_cancelled)?;
        model
            .validate_with_limits(flow_validation_limits(request.limits), is_cancelled)
            .map_err(map_validation_failure)
    }
}

struct ParsedHeader {
    header: WireHeader,
    payload_start: usize,
    target_bytes: u64,
}

fn parse_header(bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Result<ParsedHeader, CodecError> {
    let mut reader = HeaderReader::new(bytes, is_cancelled);
    if reader.raw(FLOW_WIR_MAGIC.len())? != FLOW_WIR_MAGIC {
        return Err(CodecError::InvalidMagic);
    }
    let wire_version = reader.u32()?;
    if wire_version != FLOW_WIR_WIRE_VERSION {
        return Err(CodecError::UnsupportedWireVersion(wire_version));
    }
    let flow_wir_version = reader.u32()?;
    if flow_wir_version != wrela_flow_wir::FLOW_WIR_VERSION {
        return Err(CodecError::UnsupportedFlowWirVersion(flow_wir_version));
    }
    let payload_bytes = reader.u64()?;
    if payload_bytes == 0 {
        return Err(CodecError::NonCanonical("empty FlowWir payload"));
    }
    let compiler = reader.digest()?;
    let language = match reader.u8()? {
        0 => LanguageRevision::Design0_1,
        tag => {
            return Err(CodecError::InvalidEnumTag {
                kind: "language revision",
                tag: u64::from(tag),
            });
        }
    };
    let (target, target_bytes) = reader.target_identity()?;
    let build = BuildIdentity {
        compiler,
        language,
        target,
        target_package: reader.digest()?,
        standard_library: reader.digest()?,
        source_graph: reader.digest()?,
        request: reader.digest()?,
        profile: reader.digest()?,
    };
    let payload_start = reader.position();
    let remaining = bytes
        .len()
        .checked_sub(payload_start)
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(CodecError::LengthOverflow)?;
    if remaining < payload_bytes {
        return Err(CodecError::UnexpectedEnd);
    }
    if remaining > payload_bytes {
        return Err(CodecError::TrailingBytes);
    }
    Ok(ParsedHeader {
        header: WireHeader {
            wire_version,
            flow_wir_version,
            payload_bytes,
            build,
        },
        payload_start,
        target_bytes,
    })
}

fn cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), CodecError> {
    check_cancelled(is_cancelled)
}

fn clone_build_identity(
    build: &BuildIdentity,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BuildIdentity, CodecError> {
    let target = build.target.as_str();
    let target_copy = copy_utf8(target.as_bytes(), is_cancelled)?;
    Ok(BuildIdentity {
        compiler: build.compiler,
        language: build.language,
        target: TargetIdentity::new(target_copy)
            .map_err(|_| CodecError::NonCanonical("invalid target identity"))?,
        target_package: build.target_package,
        standard_library: build.standard_library,
        source_graph: build.source_graph,
        request: build.request,
        profile: build.profile,
    })
}

fn copy_utf8(source: &[u8], is_cancelled: &dyn Fn() -> bool) -> Result<String, CodecError> {
    cancelled(is_cancelled)?;
    let mut output = String::new();
    output
        .try_reserve_exact(source.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut start = 0_usize;
    while start < source.len() {
        cancelled(is_cancelled)?;
        let mut end = start
            .checked_add(CANCELLABLE_CODEC_CHUNK_BYTES)
            .map_or(source.len(), |end| end.min(source.len()));
        if end < source.len() {
            while end > start && source[end] & 0b1100_0000 == 0b1000_0000 {
                end -= 1;
            }
            if end == start {
                return Err(CodecError::InvalidUtf8);
            }
        }
        let chunk = str::from_utf8(&source[start..end]).map_err(|_| CodecError::InvalidUtf8)?;
        output.push_str(chunk);
        start = end;
    }
    cancelled(is_cancelled)?;
    Ok(output)
}

fn copy_bytes(source: &[u8], is_cancelled: &dyn Fn() -> bool) -> Result<Vec<u8>, CodecError> {
    cancelled(is_cancelled)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(source.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for chunk in source.chunks(CANCELLABLE_CODEC_CHUNK_BYTES) {
        cancelled(is_cancelled)?;
        output.extend_from_slice(chunk);
    }
    cancelled(is_cancelled)?;
    Ok(output)
}

fn enforce(resource: &'static str, limit: u64, actual: u64) -> Result<(), CodecError> {
    if actual > limit {
        Err(CodecError::ResourceLimit {
            resource,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct Meter {
    string_bytes: u64,
    vector_items: u64,
    functions: u64,
    blocks: u64,
    instructions: u64,
    tests: u64,
}

#[derive(Clone, Copy)]
enum VectorKind {
    General,
    Functions,
    Blocks,
    Instructions,
    Tests,
}

impl Meter {
    fn charge_string(
        &mut self,
        amount: u64,
        resource: &'static str,
        limit: u64,
    ) -> Result<(), CodecError> {
        self.string_bytes = self
            .string_bytes
            .checked_add(amount)
            .ok_or(CodecError::LengthOverflow)?;
        enforce(resource, limit, self.string_bytes)
    }

    fn charge_vector(
        &mut self,
        amount: u64,
        kind: VectorKind,
        limits: CodecLimits,
    ) -> Result<(), CodecError> {
        self.vector_items = self
            .vector_items
            .checked_add(amount)
            .ok_or(CodecError::LengthOverflow)?;
        enforce(
            "aggregate vector items",
            u64::from(limits.vector_items),
            self.vector_items,
        )?;
        let (counter, limit, resource) = match kind {
            VectorKind::General => return Ok(()),
            VectorKind::Functions => (
                &mut self.functions,
                u64::from(limits.functions),
                "functions",
            ),
            VectorKind::Blocks => (&mut self.blocks, limits.blocks, "blocks"),
            VectorKind::Instructions => {
                (&mut self.instructions, limits.instructions, "instructions")
            }
            VectorKind::Tests => (&mut self.tests, u64::from(limits.tests), "tests"),
        };
        *counter = counter
            .checked_add(amount)
            .ok_or(CodecError::LengthOverflow)?;
        enforce(resource, limit, *counter)
    }
}

struct HeaderReader<'a> {
    bytes: &'a [u8],
    position: usize,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> HeaderReader<'a> {
    const fn new(bytes: &'a [u8], is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes,
            position: 0,
            is_cancelled,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        cancelled(self.is_cancelled)?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(CodecError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEnd)?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.raw(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes: [u8; 4] = self
            .raw(4)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        let bytes: [u8; 8] = self
            .raw(8)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn digest(&mut self) -> Result<Sha256Digest, CodecError> {
        let bytes: [u8; 32] = self
            .raw(32)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd)?;
        Ok(Sha256Digest::from_bytes(bytes))
    }

    fn target_identity(&mut self) -> Result<(TargetIdentity, u64), CodecError> {
        let length = usize::try_from(self.u32()?).map_err(|_| CodecError::LengthOverflow)?;
        if length == 0 || length > MAX_PROFILE_ATOM_BYTES {
            return Err(CodecError::NonCanonical("invalid target identity length"));
        }
        let source = self.raw(length)?;
        let owned = copy_utf8(source, self.is_cancelled)?;
        let identity = TargetIdentity::new(owned)
            .map_err(|_| CodecError::NonCanonical("invalid target identity"))?;
        Ok((
            identity,
            u64::try_from(length).map_err(|_| CodecError::LengthOverflow)?,
        ))
    }
}

struct Writer<'a> {
    bytes: Vec<u8>,
    limits: CodecLimits,
    meter: Meter,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> Writer<'a> {
    fn new(limits: CodecLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes: Vec::new(),
            limits,
            meter: Meter::default(),
            is_cancelled,
        }
    }

    fn position(&self) -> usize {
        self.bytes.len()
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn poll(&self) -> Result<(), CodecError> {
        cancelled(self.is_cancelled)
    }

    fn reserve(&mut self, length: usize) -> Result<(), CodecError> {
        let actual = self
            .bytes
            .len()
            .checked_add(length)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(CodecError::LengthOverflow)?;
        enforce("FlowWir frame bytes", self.limits.frame_bytes, actual)?;
        self.bytes
            .try_reserve_exact(length)
            .map_err(|_| CodecError::AllocationFailed)
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), CodecError> {
        self.poll()?;
        self.reserve(value.len())?;
        for chunk in value.chunks(CANCELLABLE_CODEC_CHUNK_BYTES) {
            self.poll()?;
            self.bytes.extend_from_slice(chunk);
        }
        self.poll()
    }

    fn u8(&mut self, value: u8) -> Result<(), CodecError> {
        self.raw(&[value])
    }

    fn bool(&mut self, value: bool) -> Result<(), CodecError> {
        self.u8(u8::from(value))
    }

    fn u16(&mut self, value: u16) -> Result<(), CodecError> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), CodecError> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), CodecError> {
        self.raw(&value.to_le_bytes())
    }

    fn u128(&mut self, value: u128) -> Result<(), CodecError> {
        self.raw(&value.to_le_bytes())
    }

    fn patch_u64(&mut self, offset: usize, value: u64) -> Result<(), CodecError> {
        let end = offset.checked_add(8).ok_or(CodecError::LengthOverflow)?;
        let destination = self
            .bytes
            .get_mut(offset..end)
            .ok_or(CodecError::NonCanonical("invalid payload length offset"))?;
        destination.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn digest(&mut self, value: Sha256Digest) -> Result<(), CodecError> {
        self.raw(value.as_bytes())
    }

    fn build_identity(&mut self, build: &BuildIdentity) -> Result<(), CodecError> {
        self.digest(build.compiler)?;
        self.u8(match build.language {
            LanguageRevision::Design0_1 => 0,
        })?;
        self.string(build.target.as_str())?;
        self.digest(build.target_package)?;
        self.digest(build.standard_library)?;
        self.digest(build.source_graph)?;
        self.digest(build.request)?;
        self.digest(build.profile)
    }

    fn string(&mut self, value: &str) -> Result<(), CodecError> {
        self.poll()?;
        let length = u64::try_from(value.len()).map_err(|_| CodecError::LengthOverflow)?;
        self.meter.charge_string(
            length,
            "aggregate string bytes",
            u64::from(self.limits.string_bytes),
        )?;
        let length = u32::try_from(value.len()).map_err(|_| CodecError::LengthOverflow)?;
        self.u32(length)?;
        self.raw(value.as_bytes())?;
        self.poll()
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), CodecError> {
        self.poll()?;
        self.charge_vector(value.len(), VectorKind::General)?;
        let length = u32::try_from(value.len()).map_err(|_| CodecError::LengthOverflow)?;
        self.u32(length)?;
        self.raw(value)?;
        self.poll()
    }

    fn charge_vector(&mut self, length: usize, kind: VectorKind) -> Result<(), CodecError> {
        let length = u64::try_from(length).map_err(|_| CodecError::LengthOverflow)?;
        self.meter.charge_vector(length, kind, self.limits)
    }

    fn vector<T>(
        &mut self,
        values: &[T],
        kind: VectorKind,
        mut encode: impl FnMut(&mut Self, &T) -> Result<(), CodecError>,
    ) -> Result<(), CodecError> {
        self.poll()?;
        self.charge_vector(values.len(), kind)?;
        self.u32(u32::try_from(values.len()).map_err(|_| CodecError::LengthOverflow)?)?;
        for value in values {
            self.poll()?;
            encode(self, value)?;
        }
        Ok(())
    }

    fn option<T>(
        &mut self,
        value: &Option<T>,
        encode: impl FnOnce(&mut Self, &T) -> Result<(), CodecError>,
    ) -> Result<(), CodecError> {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1)?;
                encode(self, value)
            }
        }
    }

    fn span(&mut self, span: &Span) -> Result<(), CodecError> {
        self.u32(span.file.0)?;
        self.u32(span.range.start)?;
        self.u32(span.range.end)
    }

    fn optional_span(&mut self, span: &Option<Span>) -> Result<(), CodecError> {
        self.option(span, Self::span)
    }

    fn id_vector<T>(&mut self, values: &[T], get: impl Fn(&T) -> u32) -> Result<(), CodecError> {
        self.vector(values, VectorKind::General, |writer, value| {
            writer.u32(get(value))
        })
    }

    fn flow_wir(&mut self, model: &FlowWir) -> Result<(), CodecError> {
        self.u32(model.version)?;
        self.string(&model.name)?;
        self.source_summary(model.source_summary)?;
        self.vector(&model.types, VectorKind::General, Self::flow_type)?;
        self.vector(&model.globals, VectorKind::General, Self::global)?;
        self.vector(&model.functions, VectorKind::Functions, Self::function)?;
        self.vector(&model.actors, VectorKind::General, Self::actor)?;
        self.vector(&model.tasks, VectorKind::General, Self::task)?;
        self.vector(&model.devices, VectorKind::General, Self::device)?;
        self.vector(&model.pools, VectorKind::General, Self::pool)?;
        self.vector(&model.regions, VectorKind::General, Self::region)?;
        self.vector(&model.activations, VectorKind::General, Self::activation)?;
        self.vector(&model.proofs, VectorKind::General, Self::proof)?;
        self.vector(&model.checkpoints, VectorKind::General, Self::checkpoint)?;
        self.vector(&model.tests, VectorKind::Tests, Self::test_entry)?;
        self.option(&model.compiled_test_group, Self::compiled_test_group)?;
        self.vector(&model.startup_order, VectorKind::General, Self::owner)?;
        self.vector(&model.shutdown_order, VectorKind::General, Self::owner)?;
        self.u32(model.image_entry.0)?;
        self.u64(model.static_bytes)?;
        self.u64(model.peak_bytes)
    }

    fn source_summary(&mut self, value: SourceSummary) -> Result<(), CodecError> {
        self.u32(value.semantic_wir_version)?;
        self.u32(value.semantic_functions)?;
        self.u32(value.hir_files)?;
        self.u32(value.hir_declarations)?;
        self.u64(value.reachable_declarations)?;
        self.u64(value.monomorphized_instantiations)?;
        self.u64(value.resolved_interface_calls)
    }

    fn flow_type(&mut self, value: &FlowType) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.type_kind(&value.kind)?;
        self.option(&value.name, |writer, name| writer.string(name))?;
        self.bool(value.copyable)?;
        self.bool(value.strict_linear)
    }

    fn type_kind(&mut self, value: &FlowTypeKind) -> Result<(), CodecError> {
        match value {
            FlowTypeKind::Unit => self.u8(0),
            FlowTypeKind::Scalar(value) => {
                self.u8(1)?;
                self.scalar_type(*value)
            }
            FlowTypeKind::Tuple(values) => {
                self.u8(2)?;
                self.id_vector(values, |id| id.0)
            }
            FlowTypeKind::Array { element, length } => {
                self.u8(3)?;
                self.u32(element.0)?;
                self.u64(*length)
            }
            FlowTypeKind::Struct { fields } => {
                self.u8(4)?;
                self.id_vector(fields, |id| id.0)
            }
            FlowTypeKind::Enum { variants } => {
                self.u8(5)?;
                if self.limits.nesting_depth < 2 {
                    return Err(CodecError::ResourceLimit {
                        resource: "nesting depth",
                        limit: u64::from(self.limits.nesting_depth),
                        actual: 2,
                    });
                }
                self.vector(variants, VectorKind::General, |writer, fields| {
                    writer.id_vector(fields, |id| id.0)
                })
            }
            FlowTypeKind::Function { parameters, result } => {
                self.u8(6)?;
                self.id_vector(parameters, |id| id.0)?;
                self.u32(result.0)
            }
            FlowTypeKind::RegionHandle(id) => {
                self.u8(7)?;
                self.u32(id.0)
            }
            FlowTypeKind::PoolHandle(id) => {
                self.u8(8)?;
                self.u32(id.0)
            }
            FlowTypeKind::ActorHandle(id) => {
                self.u8(9)?;
                self.u32(id.0)
            }
            FlowTypeKind::TaskHandle(id) => {
                self.u8(10)?;
                self.u32(id.0)
            }
            FlowTypeKind::Reservation => self.u8(11),
            FlowTypeKind::Receipt { payload, error } => {
                self.u8(12)?;
                self.u32(payload.0)?;
                self.u32(error.0)
            }
            FlowTypeKind::DmaToken { pool, payload } => {
                self.u8(13)?;
                self.u32(pool.0)?;
                self.u32(payload.0)
            }
            FlowTypeKind::OpaqueTarget { name } => {
                self.u8(14)?;
                self.string(name)
            }
            FlowTypeKind::Activation { result } => {
                self.u8(15)?;
                self.u32(result.0)
            }
        }
    }

    fn scalar_type(&mut self, value: ScalarType) -> Result<(), CodecError> {
        match value {
            ScalarType::Bool => self.u8(0),
            ScalarType::Integer { signed, bits } => {
                self.u8(1)?;
                self.bool(signed)?;
                self.u16(bits)
            }
            ScalarType::Float32 => self.u8(2),
            ScalarType::Float64 => self.u8(3),
            ScalarType::Address => self.u8(4),
        }
    }

    fn immediate(&mut self, value: &Immediate) -> Result<(), CodecError> {
        match value {
            Immediate::Unit => self.u8(0),
            Immediate::Bool(value) => {
                self.u8(1)?;
                self.bool(*value)
            }
            Immediate::Integer { bits, bytes_le } => {
                self.u8(2)?;
                self.u16(*bits)?;
                self.bytes(bytes_le)
            }
            Immediate::Float32(value) => {
                self.u8(3)?;
                self.u32(*value)
            }
            Immediate::Float64(value) => {
                self.u8(4)?;
                self.u64(*value)
            }
            Immediate::Bytes(value) => {
                self.u8(5)?;
                self.bytes(value)
            }
            Immediate::Zero(id) => {
                self.u8(6)?;
                self.u32(id.0)
            }
            Immediate::GlobalAddress(id) => {
                self.u8(7)?;
                self.u32(id.0)
            }
            Immediate::FunctionAddress(id) => {
                self.u8(8)?;
                self.u32(id.0)
            }
        }
    }

    fn global(&mut self, value: &FlowGlobal) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.string(&value.name)?;
        self.u32(value.ty.0)?;
        self.immediate(&value.initializer)?;
        self.bool(value.mutable)?;
        self.owner(&value.owner)
    }

    fn function(&mut self, value: &FlowFunction) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.string(&value.name)?;
        self.function_origin(value.origin)?;
        self.function_role(value.role)?;
        self.function_color(value.color)?;
        self.id_vector(&value.parameters, |id| id.0)?;
        self.id_vector(&value.result_types, |id| id.0)?;
        self.vector(&value.values, VectorKind::General, Self::value)?;
        self.vector(&value.blocks, VectorKind::Blocks, Self::block)?;
        self.u32(value.entry.0)?;
        self.u64(value.stack_bound)?;
        self.u64(value.frame_bound)?;
        self.id_vector(&value.proofs, |id| id.0)?;
        self.optional_span(&value.source)
    }

    fn function_origin(&mut self, value: FunctionOrigin) -> Result<(), CodecError> {
        match value {
            FunctionOrigin::SourceSemantic { semantic_function } => {
                self.u8(0)?;
                self.u32(semantic_function)
            }
            FunctionOrigin::GeneratedImageEntry {
                semantic_function,
                constructor,
            } => {
                self.u8(1)?;
                self.u32(semantic_function)?;
                self.u32(constructor)
            }
            FunctionOrigin::GeneratedTestHarness {
                semantic_function,
                group,
            } => {
                self.u8(2)?;
                self.u32(semantic_function)?;
                self.u32(group)
            }
            FunctionOrigin::GeneratedAsyncState {
                semantic_function,
                state,
            } => {
                self.u8(3)?;
                self.u32(semantic_function)?;
                self.u32(state)
            }
            FunctionOrigin::GeneratedCleanup {
                semantic_function,
                scope,
            } => {
                self.u8(4)?;
                self.u32(semantic_function)?;
                self.u32(scope)
            }
        }
    }

    fn function_role(&mut self, value: FunctionRole) -> Result<(), CodecError> {
        match value {
            FunctionRole::Ordinary => self.u8(0),
            FunctionRole::ActorTurn(id) => {
                self.u8(1)?;
                self.u32(id.0)
            }
            FunctionRole::TaskEntry(id) => {
                self.u8(2)?;
                self.u32(id.0)
            }
            FunctionRole::Isr(id) => {
                self.u8(3)?;
                self.u32(id.0)
            }
            FunctionRole::Cleanup => self.u8(4),
            FunctionRole::ImageEntry => self.u8(5),
            FunctionRole::Test => self.u8(6),
        }
    }

    fn function_color(&mut self, value: FunctionColor) -> Result<(), CodecError> {
        self.u8(match value {
            FunctionColor::Sync => 0,
            FunctionColor::Async => 1,
            FunctionColor::Isr => 2,
        })
    }

    fn value(&mut self, value: &Value) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.u32(value.ty.0)?;
        self.option(&value.source_name, |writer, name| writer.string(name))?;
        self.optional_span(&value.source)
    }

    fn block(&mut self, value: &Block) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.id_vector(&value.parameters, |id| id.0)?;
        self.vector(
            &value.instructions,
            VectorKind::Instructions,
            Self::instruction,
        )?;
        self.terminator(&value.terminator)?;
        self.optional_span(&value.source)
    }

    fn instruction(&mut self, value: &Instruction) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.id_vector(&value.results, |id| id.0)?;
        self.operation(&value.operation)?;
        self.optional_span(&value.source)
    }

    fn operation(&mut self, value: &FlowOperation) -> Result<(), CodecError> {
        encode_operation(self, value)
    }

    fn terminator(&mut self, value: &Terminator) -> Result<(), CodecError> {
        encode_terminator(self, value)
    }

    fn actor(&mut self, value: &ActorPlan) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.string(&value.name)?;
        self.u32(value.state_type.0)?;
        self.u32(value.mailbox_capacity)?;
        self.id_vector(&value.message_types, |id| id.0)?;
        self.id_vector(&value.turn_functions, |id| id.0)?;
        self.u8(value.priority)?;
        self.option(&value.supervisor, |writer, id| writer.u32(id.0))
    }

    fn task(&mut self, value: &TaskPlan) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.string(&value.name)?;
        self.u32(value.entry.0)?;
        self.u32(value.slots)?;
        self.u8(value.priority)?;
        self.u64(value.frame_bytes_bound)?;
        self.option(&value.supervisor, |writer, id| writer.u32(id.0))
    }

    fn device(&mut self, value: &DevicePlan) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.string(&value.name)?;
        self.string(&value.target_binding)?;
        self.u32(value.owner.0)?;
        self.option(&value.queue_capacity, |writer, value| writer.u32(*value))?;
        self.option(&value.maximum_in_flight, |writer, value| writer.u32(*value))?;
        self.vector(
            &value.required_features,
            VectorKind::General,
            |writer, value| writer.string(value),
        )?;
        self.vector(
            &value.optional_features,
            VectorKind::General,
            |writer, value| writer.string(value),
        )?;
        self.id_vector(&value.interrupt_functions, |id| id.0)?;
        self.u64(value.reset_timeout_ns)
    }

    fn pool(&mut self, value: &PoolPlan) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.string(&value.name)?;
        self.u32(value.element_type.0)?;
        self.u64(value.capacity)?;
        self.u64(value.alignment)?;
        self.id_vector(&value.devices, |id| id.0)
    }

    fn region(&mut self, value: &RegionPlan) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.string(&value.name)?;
        self.region_class(value.class)?;
        self.u64(value.capacity_bytes)?;
        self.u64(value.alignment)?;
        self.option(&value.reset_function, |writer, id| writer.u32(id.0))?;
        self.owner(&value.owner)?;
        self.u32(value.capacity_proof.0)?;
        self.span(&value.source)
    }

    fn activation(&mut self, value: &ActivationPlan) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.u32(value.caller.0)?;
        self.u32(value.callee.0)?;
        self.u32(value.region.0)?;
        self.u64(value.frame_bytes)?;
        self.u32(value.maximum_live)?;
        self.u8(match value.cancellation {
            ActivationCancellation::DropCalleeThenPropagate => 0,
        })?;
        self.u32(value.capacity_proof.0)?;
        self.span(&value.source)
    }

    fn region_class(&mut self, value: RegionClass) -> Result<(), CodecError> {
        match value {
            RegionClass::Image => self.u8(0),
            RegionClass::TaskFrame => self.u8(1),
            RegionClass::Call => self.u8(2),
            RegionClass::Request => self.u8(3),
            RegionClass::Pool(pool) => {
                self.u8(4)?;
                self.u32(pool.0)
            }
            RegionClass::Static => self.u8(5),
        }
    }

    fn owner(&mut self, value: &PlanOwner) -> Result<(), CodecError> {
        match *value {
            PlanOwner::Runtime => self.u8(0),
            PlanOwner::Actor(id) => {
                self.u8(1)?;
                self.u32(id.0)
            }
            PlanOwner::Task(id) => {
                self.u8(2)?;
                self.u32(id.0)
            }
            PlanOwner::Device(id) => {
                self.u8(3)?;
                self.u32(id.0)
            }
            PlanOwner::Pool(id) => {
                self.u8(4)?;
                self.u32(id.0)
            }
            PlanOwner::BakedArtifact(id) => {
                self.u8(5)?;
                self.u32(id)
            }
        }
    }

    fn proof(&mut self, value: &Proof) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.proof_kind(&value.kind)?;
        self.string(&value.subject)?;
        self.vector(&value.sources, VectorKind::General, Self::span)?;
        self.id_vector(&value.depends_on, |id| id.0)?;
        self.option(&value.bound, |writer, value| writer.u64(*value))?;
        self.vector(&value.explanation, VectorKind::General, |writer, line| {
            writer.string(line)
        })
    }

    fn proof_kind(&mut self, value: &ProofKind) -> Result<(), CodecError> {
        let tag = match value {
            ProofKind::TypeChecked => 0,
            ProofKind::EffectsAllowed => 1,
            ProofKind::DefiniteInitialization => 2,
            ProofKind::Ownership => 3,
            ProofKind::AccessExclusive => 4,
            ProofKind::ViewDoesNotEscape => 5,
            ProofKind::RegionBound => 6,
            ProofKind::CapacityBound => 7,
            ProofKind::WaitGraphAcyclic => 8,
            ProofKind::CleanupAcyclic => 9,
            ProofKind::WorkBound => 10,
            ProofKind::StackBound => 11,
            ProofKind::IsrSafe => 12,
            ProofKind::DmaTransition => 13,
            ProofKind::MmioPartition => 14,
            ProofKind::DeviceValueValidated => 15,
            ProofKind::WireLayout => 16,
            ProofKind::ReceiptLineage => 17,
            ProofKind::ActorAsIf => 18,
            ProofKind::SupervisionComplete => 19,
            ProofKind::ImageClosed => 20,
            ProofKind::FlowControl => 21,
            ProofKind::ValueRange => 22,
            ProofKind::Alignment => 23,
            ProofKind::NoAlias => 24,
        };
        self.u8(tag)
    }

    fn checkpoint(&mut self, value: &Checkpoint) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.u32(value.function.0)?;
        self.span(&value.source)?;
        self.u64(value.uninterrupted_bound)?;
        self.bool(value.may_observe_cancellation)?;
        self.bool(value.may_yield)
    }

    fn test_entry(&mut self, value: &TestEntry) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.u32(value.plan_id)?;
        self.digest(value.function_key)?;
        self.string(&value.name)?;
        self.u32(value.function.0)?;
        self.test_kind(value.kind)?;
        self.span(&value.source)?;
        self.u64(value.timeout_ns)
    }

    fn compiled_test_group(&mut self, value: &FullImageTestGroup) -> Result<(), CodecError> {
        self.u32(value.id.0)?;
        self.string(&value.name)?;
        match &value.root {
            ImageRoot::GeneratedHarness { harness_name } => {
                self.u8(0)?;
                self.string(harness_name)?;
            }
            ImageRoot::Declared {
                image_name,
                scenario,
            } => {
                self.u8(1)?;
                self.string(image_name)?;
                self.u32(scenario.0)?;
            }
        }
        self.vector(&value.tests, VectorKind::General, Self::planned_test)?;
        self.option(&value.deterministic_seed, |writer, seed| writer.u64(*seed))?;
        self.u64(value.boot_timeout_ns)?;
        self.u64(value.shutdown_timeout_ns)?;
        self.u32(value.maximum_events)?;
        self.u64(value.maximum_output_bytes)
    }

    fn planned_test(&mut self, value: &ImageTest) -> Result<(), CodecError> {
        self.u32(value.descriptor.id.0)?;
        self.string(&value.descriptor.name)?;
        self.u8(match value.descriptor.kind {
            PlannedTestKind::ComptimeUnit => 0,
            PlannedTestKind::IntegrationImage => 1,
            PlannedTestKind::DeclaredImage => 2,
        })?;
        self.optional_span(&value.descriptor.source)?;
        self.u64(value.descriptor.timeout_ns)?;
        match value.invocation {
            ImageTestInvocation::GeneratedFunction { function_key } => {
                self.u8(0)?;
                self.digest(function_key.0)?;
            }
            ImageTestInvocation::DeclaredScenario => self.u8(1)?,
        }
        self.vector(
            &value.assertions,
            VectorKind::General,
            |writer, assertion| {
                writer.span(&assertion.source)?;
                writer.string(&assertion.expression)?;
                writer.option(&assertion.message, |writer, message| writer.string(message))
            },
        )
    }

    fn test_kind(&mut self, value: TestKind) -> Result<(), CodecError> {
        self.u8(match value {
            TestKind::Comptime => 0,
            TestKind::Integration => 1,
            TestKind::Image => 2,
        })
    }
}

// Decoder and operation/terminator tables follow below. Keeping these tables
// explicit makes every stable tag reviewable and prevents an enum reorder from
// silently changing the private wire ABI.

fn encode_operation(writer: &mut Writer<'_>, value: &FlowOperation) -> Result<(), CodecError> {
    match value {
        FlowOperation::Immediate(value) => {
            writer.u8(0)?;
            writer.immediate(value)
        }
        FlowOperation::Unary { op, value } => {
            writer.u8(1)?;
            writer.unary_op(*op)?;
            writer.u32(value.0)
        }
        FlowOperation::Binary { op, left, right } => {
            writer.u8(2)?;
            writer.binary_op(*op)?;
            writer.u32(left.0)?;
            writer.u32(right.0)
        }
        FlowOperation::Cast { value, to, mode } => {
            writer.u8(3)?;
            writer.u32(value.0)?;
            writer.u32(to.0)?;
            writer.cast_mode(*mode)
        }
        FlowOperation::MakeAggregate { ty, fields } => {
            writer.u8(4)?;
            writer.u32(ty.0)?;
            writer.id_vector(fields, |id| id.0)
        }
        FlowOperation::ExtractField { aggregate, field } => {
            writer.u8(5)?;
            writer.u32(aggregate.0)?;
            writer.u32(*field)
        }
        FlowOperation::InsertField {
            aggregate,
            field,
            value,
        } => {
            writer.u8(6)?;
            writer.u32(aggregate.0)?;
            writer.u32(*field)?;
            writer.u32(value.0)
        }
        FlowOperation::Select {
            condition,
            then_value,
            else_value,
        } => {
            writer.u8(7)?;
            writer.u32(condition.0)?;
            writer.u32(then_value.0)?;
            writer.u32(else_value.0)
        }
        FlowOperation::BeginAccess { place, kind, proof } => {
            writer.u8(8)?;
            writer.u32(place.0)?;
            writer.access_kind(*kind)?;
            writer.u32(proof.0)
        }
        FlowOperation::EndAccess { access } => {
            writer.u8(9)?;
            writer.u32(access.0)
        }
        FlowOperation::Load { address, proof } => {
            writer.u8(10)?;
            writer.u32(address.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::Store {
            address,
            value,
            proof,
        } => {
            writer.u8(11)?;
            writer.u32(address.0)?;
            writer.u32(value.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::Move { value } => {
            writer.u8(12)?;
            writer.u32(value.0)
        }
        FlowOperation::Copy { value } => {
            writer.u8(13)?;
            writer.u32(value.0)
        }
        FlowOperation::Drop { value } => {
            writer.u8(14)?;
            writer.u32(value.0)
        }
        FlowOperation::Call {
            function,
            arguments,
        } => {
            writer.u8(15)?;
            writer.u32(function.0)?;
            writer.id_vector(arguments, |id| id.0)
        }
        FlowOperation::Allocate {
            region,
            ty,
            count,
            proof,
        } => {
            writer.u8(16)?;
            writer.u32(region.0)?;
            writer.u32(ty.0)?;
            writer.u32(count.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::RegionReset { region } => {
            writer.u8(17)?;
            writer.u32(region.0)
        }
        FlowOperation::ActorReserve {
            actor,
            method,
            proof,
        } => {
            writer.u8(18)?;
            writer.u32(actor.0)?;
            writer.u32(method.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::ActorCommit {
            reservation,
            arguments,
        } => {
            writer.u8(19)?;
            writer.u32(reservation.0)?;
            writer.id_vector(arguments, |id| id.0)
        }
        FlowOperation::ActorReject { reservation } => {
            writer.u8(20)?;
            writer.u32(reservation.0)
        }
        FlowOperation::MailboxReceive { actor, method } => {
            writer.u8(21)?;
            writer.u32(actor.0)?;
            writer.u32(method.0)
        }
        FlowOperation::ReplyResolve { endpoint, outcome } => {
            writer.u8(22)?;
            writer.u32(endpoint.0)?;
            writer.u32(outcome.0)
        }
        FlowOperation::ReceiptCommit { receipt, payload } => {
            writer.u8(23)?;
            writer.u32(receipt.0)?;
            writer.u32(payload.0)
        }
        FlowOperation::ReceiptResolve { receipt, outcome } => {
            writer.u8(24)?;
            writer.u32(receipt.0)?;
            writer.u32(outcome.0)
        }
        FlowOperation::TaskAcquireSlot { task, proof } => {
            writer.u8(25)?;
            writer.u32(task.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::TaskStart {
            slot,
            entry,
            arguments,
        } => {
            writer.u8(26)?;
            writer.u32(slot.0)?;
            writer.u32(entry.0)?;
            writer.id_vector(arguments, |id| id.0)
        }
        FlowOperation::TaskCancel { task } => {
            writer.u8(27)?;
            writer.u32(task.0)
        }
        FlowOperation::Park { wait_set } => {
            writer.u8(28)?;
            writer.u32(wait_set.0)
        }
        FlowOperation::Wake { target } => {
            writer.u8(29)?;
            writer.u32(target.0)
        }
        FlowOperation::Checkpoint { id, proof } => {
            writer.u8(30)?;
            writer.u32(id.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::DeadlineRead => writer.u8(31),
        FlowOperation::InterruptMask => writer.u8(32),
        FlowOperation::InterruptRestore { token } => {
            writer.u8(33)?;
            writer.u32(token.0)
        }
        FlowOperation::InterruptPublish { cell, value } => {
            writer.u8(34)?;
            writer.u32(cell.0)?;
            writer.u32(value.0)
        }
        FlowOperation::MmioRead { device, register } => {
            writer.u8(35)?;
            writer.u32(device.0)?;
            writer.u32(*register)
        }
        FlowOperation::MmioWrite {
            device,
            register,
            value,
        } => {
            writer.u8(36)?;
            writer.u32(device.0)?;
            writer.u32(*register)?;
            writer.u32(value.0)
        }
        FlowOperation::Fence { kind } => {
            writer.u8(37)?;
            writer.fence_kind(*kind)
        }
        FlowOperation::DmaTransition {
            token,
            device,
            from,
            to,
            proof,
        } => {
            writer.u8(38)?;
            writer.u32(token.0)?;
            writer.u32(device.0)?;
            writer.dma_ownership(*from)?;
            writer.dma_ownership(*to)?;
            writer.u32(proof.0)
        }
        FlowOperation::QueueReserve {
            device,
            descriptors,
            proof,
        } => {
            writer.u8(39)?;
            writer.u32(device.0)?;
            writer.u32(descriptors.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::QueuePublish {
            reservation,
            payload,
        } => {
            writer.u8(40)?;
            writer.u32(reservation.0)?;
            writer.u32(payload.0)
        }
        FlowOperation::ValidateDeviceValue { value, proof } => {
            writer.u8(41)?;
            writer.u32(value.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::Check {
            condition,
            failure,
            proof,
        } => {
            writer.u8(42)?;
            writer.u32(condition.0)?;
            writer.failure_kind(*failure)?;
            writer.option(proof, |writer, id| writer.u32(id.0))
        }
        FlowOperation::RecordEvent { kind, payload } => {
            writer.u8(43)?;
            writer.u32(*kind)?;
            writer.u32(payload.0)
        }
        FlowOperation::ReplayEvent { kind, destination } => {
            writer.u8(44)?;
            writer.u32(*kind)?;
            writer.u32(destination.0)
        }
        FlowOperation::TestEmit { payload } => {
            writer.u8(45)?;
            writer.u32(payload.0)
        }
        FlowOperation::TestFinish { outcome } => {
            writer.u8(46)?;
            writer.u32(outcome.0)
        }
        FlowOperation::AsyncCall {
            function,
            arguments,
            plan,
        } => {
            writer.u8(47)?;
            writer.u32(function.0)?;
            writer.id_vector(arguments, |id| id.0)?;
            writer.u32(plan.0)
        }
        FlowOperation::Assert { condition, failure } => {
            writer.u8(48)?;
            writer.u32(condition.0)?;
            writer.string(&failure.expression)?;
            writer.option(&failure.message, |writer, message| writer.string(message))?;
            writer.span(&failure.source)
        }
        FlowOperation::MakeEnum {
            ty,
            variant,
            payload,
        } => {
            writer.u8(49)?;
            writer.u32(ty.0)?;
            writer.u8(*variant)?;
            writer.option(payload, |writer, payload| writer.u32(payload.0))
        }
        FlowOperation::EnumTag { value } => {
            writer.u8(50)?;
            writer.u32(value.0)
        }
        FlowOperation::EnumPayload { value } => {
            writer.u8(51)?;
            writer.u32(value.0)
        }
        FlowOperation::ActorCapability { actor, proof } => {
            writer.u8(52)?;
            writer.u32(actor.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::ActorStateAddress {
            actor,
            region,
            proof,
        } => {
            writer.u8(53)?;
            writer.u32(actor.0)?;
            writer.u32(region.0)?;
            writer.u32(proof.0)
        }
        FlowOperation::Promote {
            value,
            destination,
            proof,
        } => {
            writer.u8(54)?;
            writer.u32(value.0)?;
            writer.u32(destination.0)?;
            writer.u32(proof.0)
        }
    }
}

fn encode_terminator(writer: &mut Writer<'_>, value: &Terminator) -> Result<(), CodecError> {
    match value {
        Terminator::Jump { target, arguments } => {
            writer.u8(0)?;
            writer.u32(target.0)?;
            writer.id_vector(arguments, |id| id.0)
        }
        Terminator::Branch {
            condition,
            then_block,
            then_arguments,
            else_block,
            else_arguments,
        } => {
            writer.u8(1)?;
            writer.u32(condition.0)?;
            writer.u32(then_block.0)?;
            writer.id_vector(then_arguments, |id| id.0)?;
            writer.u32(else_block.0)?;
            writer.id_vector(else_arguments, |id| id.0)
        }
        Terminator::Switch {
            value,
            cases,
            default,
            default_arguments,
        } => {
            writer.u8(2)?;
            writer.u32(value.0)?;
            writer.vector(cases, VectorKind::General, |writer, case| {
                writer.u128(case.value)?;
                writer.u32(case.target.0)?;
                writer.id_vector(&case.arguments, |id| id.0)
            })?;
            writer.u32(default.0)?;
            writer.id_vector(default_arguments, |id| id.0)
        }
        Terminator::Return(values) => {
            writer.u8(3)?;
            writer.id_vector(values, |id| id.0)
        }
        Terminator::Suspend {
            state,
            activation,
            resume,
        } => {
            writer.u8(4)?;
            writer.u32(*state)?;
            writer.u32(activation.0)?;
            writer.u32(resume.0)
        }
        Terminator::TailCall {
            function,
            arguments,
        } => {
            writer.u8(5)?;
            writer.u32(function.0)?;
            writer.id_vector(arguments, |id| id.0)
        }
        Terminator::Trap { failure, detail } => {
            writer.u8(6)?;
            writer.failure_kind(*failure)?;
            writer.option(detail, |writer, id| writer.u32(id.0))
        }
        Terminator::Unreachable => writer.u8(7),
    }
}

impl Writer<'_> {
    fn unary_op(&mut self, value: UnaryOp) -> Result<(), CodecError> {
        self.u8(match value {
            UnaryOp::Negate => 0,
            UnaryOp::BoolNot => 1,
            UnaryOp::BitNot => 2,
        })
    }

    fn binary_op(&mut self, value: BinaryOp) -> Result<(), CodecError> {
        self.u8(match value {
            BinaryOp::AddChecked => 0,
            BinaryOp::AddWrapping => 1,
            BinaryOp::SubChecked => 2,
            BinaryOp::SubWrapping => 3,
            BinaryOp::MulChecked => 4,
            BinaryOp::MulWrapping => 5,
            BinaryOp::DivChecked => 6,
            BinaryOp::RemChecked => 7,
            BinaryOp::BitAnd => 8,
            BinaryOp::BitOr => 9,
            BinaryOp::BitXor => 10,
            BinaryOp::ShiftLeftChecked => 11,
            BinaryOp::ShiftRightChecked => 12,
            BinaryOp::Equal => 13,
            BinaryOp::NotEqual => 14,
            BinaryOp::Less => 15,
            BinaryOp::LessEqual => 16,
            BinaryOp::Greater => 17,
            BinaryOp::GreaterEqual => 18,
            BinaryOp::ShiftLeftWrapping => 19,
        })
    }

    fn cast_mode(&mut self, value: CastMode) -> Result<(), CodecError> {
        self.u8(match value {
            CastMode::Checked => 0,
            CastMode::Exact => 1,
            CastMode::Bitcast => 2,
        })
    }

    fn access_kind(&mut self, value: AccessKind) -> Result<(), CodecError> {
        self.u8(match value {
            AccessKind::Read => 0,
            AccessKind::Mutate => 1,
            AccessKind::Take => 2,
        })
    }

    fn dma_ownership(&mut self, value: DmaOwnership) -> Result<(), CodecError> {
        self.u8(match value {
            DmaOwnership::Cpu => 0,
            DmaOwnership::Prepared => 1,
            DmaOwnership::Device => 2,
            DmaOwnership::Completed => 3,
            DmaOwnership::Quarantined => 4,
        })
    }

    fn fence_kind(&mut self, value: FenceKind) -> Result<(), CodecError> {
        self.u8(match value {
            FenceKind::Acquire => 0,
            FenceKind::Release => 1,
            FenceKind::AcquireRelease => 2,
            FenceKind::DeviceRead => 3,
            FenceKind::DeviceWrite => 4,
            FenceKind::DeviceFull => 5,
        })
    }

    fn failure_kind(&mut self, value: FailureKind) -> Result<(), CodecError> {
        self.u8(match value {
            FailureKind::Bounds => 0,
            FailureKind::Arithmetic => 1,
            FailureKind::Conversion => 2,
            FailureKind::Capacity => 3,
            FailureKind::Generation => 4,
            FailureKind::DmaState => 5,
            FailureKind::DeviceValue => 6,
            FailureKind::Cancellation => 7,
            FailureKind::Deadline => 8,
            FailureKind::PeerFailure => 9,
            FailureKind::TaskFailure => 10,
            FailureKind::FatalTarget => 11,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    limits: CodecLimits,
    meter: Meter,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> Reader<'a> {
    fn new(
        bytes: &'a [u8],
        position: usize,
        limits: CodecLimits,
        is_cancelled: &'a dyn Fn() -> bool,
    ) -> Self {
        Self {
            bytes,
            position,
            limits,
            meter: Meter::default(),
            is_cancelled,
        }
    }

    fn poll(&self) -> Result<(), CodecError> {
        cancelled(self.is_cancelled)
    }

    fn finish(&self) -> Result<(), CodecError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }

    fn raw(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CodecError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEnd)?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.raw(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, CodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(CodecError::InvalidEnumTag {
                kind: "boolean",
                tag: u64::from(tag),
            }),
        }
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        let bytes: [u8; 2] = self
            .raw(2)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes: [u8; 4] = self
            .raw(4)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        let bytes: [u8; 8] = self
            .raw(8)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn u128(&mut self) -> Result<u128, CodecError> {
        let bytes: [u8; 16] = self
            .raw(16)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd)?;
        Ok(u128::from_le_bytes(bytes))
    }

    fn digest(&mut self) -> Result<Sha256Digest, CodecError> {
        let bytes: [u8; 32] = self
            .raw(32)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEnd)?;
        Ok(Sha256Digest::from_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, CodecError> {
        self.poll()?;
        let length = usize::try_from(self.u32()?).map_err(|_| CodecError::LengthOverflow)?;
        self.meter.charge_string(
            u64::try_from(length).map_err(|_| CodecError::LengthOverflow)?,
            "aggregate string bytes",
            u64::from(self.limits.string_bytes),
        )?;
        let bytes = self.raw(length)?;
        copy_utf8(bytes, self.is_cancelled)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        self.poll()?;
        let length = usize::try_from(self.u32()?).map_err(|_| CodecError::LengthOverflow)?;
        self.charge_vector(length, VectorKind::General)?;
        let source = self.raw(length)?;
        copy_bytes(source, self.is_cancelled)
    }

    fn charge_vector(&mut self, length: usize, kind: VectorKind) -> Result<(), CodecError> {
        self.meter.charge_vector(
            u64::try_from(length).map_err(|_| CodecError::LengthOverflow)?,
            kind,
            self.limits,
        )
    }

    fn vector<T>(
        &mut self,
        kind: VectorKind,
        mut decode: impl FnMut(&mut Self) -> Result<T, CodecError>,
    ) -> Result<Vec<T>, CodecError> {
        self.poll()?;
        let length = usize::try_from(self.u32()?).map_err(|_| CodecError::LengthOverflow)?;
        self.charge_vector(length, kind)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| CodecError::AllocationFailed)?;
        for _ in 0..length {
            self.poll()?;
            values.push(decode(self)?);
        }
        Ok(values)
    }

    fn option<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, CodecError>,
    ) -> Result<Option<T>, CodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(decode(self)?)),
            tag => Err(CodecError::InvalidEnumTag {
                kind: "option",
                tag: u64::from(tag),
            }),
        }
    }

    fn id_vector<T>(&mut self, make: impl Fn(u32) -> T) -> Result<Vec<T>, CodecError> {
        self.vector(VectorKind::General, |reader| Ok(make(reader.u32()?)))
    }

    fn span(&mut self) -> Result<Span, CodecError> {
        Ok(Span {
            file: FileId(self.u32()?),
            range: TextRange {
                start: self.u32()?,
                end: self.u32()?,
            },
        })
    }

    fn flow_wir(&mut self, build: BuildIdentity) -> Result<FlowWir, CodecError> {
        let version = self.u32()?;
        if version != wrela_flow_wir::FLOW_WIR_VERSION {
            return Err(CodecError::UnsupportedFlowWirVersion(version));
        }
        Ok(FlowWir {
            version,
            name: self.string()?,
            build,
            source_summary: self.source_summary()?,
            types: self.vector(VectorKind::General, Self::flow_type)?,
            globals: self.vector(VectorKind::General, Self::global)?,
            functions: self.vector(VectorKind::Functions, Self::function)?,
            actors: self.vector(VectorKind::General, Self::actor)?,
            tasks: self.vector(VectorKind::General, Self::task)?,
            devices: self.vector(VectorKind::General, Self::device)?,
            pools: self.vector(VectorKind::General, Self::pool)?,
            regions: self.vector(VectorKind::General, Self::region)?,
            activations: self.vector(VectorKind::General, Self::activation)?,
            proofs: self.vector(VectorKind::General, Self::proof)?,
            checkpoints: self.vector(VectorKind::General, Self::checkpoint)?,
            tests: self.vector(VectorKind::Tests, Self::test_entry)?,
            compiled_test_group: self.option(Self::compiled_test_group)?,
            startup_order: self.vector(VectorKind::General, Self::owner)?,
            shutdown_order: self.vector(VectorKind::General, Self::owner)?,
            image_entry: FunctionId(self.u32()?),
            static_bytes: self.u64()?,
            peak_bytes: self.u64()?,
        })
    }

    fn source_summary(&mut self) -> Result<SourceSummary, CodecError> {
        Ok(SourceSummary {
            semantic_wir_version: self.u32()?,
            semantic_functions: self.u32()?,
            hir_files: self.u32()?,
            hir_declarations: self.u32()?,
            reachable_declarations: self.u64()?,
            monomorphized_instantiations: self.u64()?,
            resolved_interface_calls: self.u64()?,
        })
    }

    fn flow_type(&mut self) -> Result<FlowType, CodecError> {
        Ok(FlowType {
            id: TypeId(self.u32()?),
            kind: self.type_kind()?,
            name: self.option(Self::string)?,
            copyable: self.bool()?,
            strict_linear: self.bool()?,
        })
    }

    fn type_kind(&mut self) -> Result<FlowTypeKind, CodecError> {
        match self.u8()? {
            0 => Ok(FlowTypeKind::Unit),
            1 => Ok(FlowTypeKind::Scalar(self.scalar_type()?)),
            2 => Ok(FlowTypeKind::Tuple(self.id_vector(TypeId)?)),
            3 => Ok(FlowTypeKind::Array {
                element: TypeId(self.u32()?),
                length: self.u64()?,
            }),
            4 => Ok(FlowTypeKind::Struct {
                fields: self.id_vector(TypeId)?,
            }),
            5 => {
                enforce("nesting depth", u64::from(self.limits.nesting_depth), 2)?;
                Ok(FlowTypeKind::Enum {
                    variants: self
                        .vector(VectorKind::General, |reader| reader.id_vector(TypeId))?,
                })
            }
            6 => Ok(FlowTypeKind::Function {
                parameters: self.id_vector(TypeId)?,
                result: TypeId(self.u32()?),
            }),
            7 => Ok(FlowTypeKind::RegionHandle(RegionId(self.u32()?))),
            8 => Ok(FlowTypeKind::PoolHandle(PoolId(self.u32()?))),
            9 => Ok(FlowTypeKind::ActorHandle(ActorId(self.u32()?))),
            10 => Ok(FlowTypeKind::TaskHandle(TaskId(self.u32()?))),
            11 => Ok(FlowTypeKind::Reservation),
            12 => Ok(FlowTypeKind::Receipt {
                payload: TypeId(self.u32()?),
                error: TypeId(self.u32()?),
            }),
            13 => Ok(FlowTypeKind::DmaToken {
                pool: PoolId(self.u32()?),
                payload: TypeId(self.u32()?),
            }),
            14 => Ok(FlowTypeKind::OpaqueTarget {
                name: self.string()?,
            }),
            15 => Ok(FlowTypeKind::Activation {
                result: TypeId(self.u32()?),
            }),
            tag => Err(invalid_tag("FlowTypeKind", tag)),
        }
    }

    fn scalar_type(&mut self) -> Result<ScalarType, CodecError> {
        match self.u8()? {
            0 => Ok(ScalarType::Bool),
            1 => Ok(ScalarType::Integer {
                signed: self.bool()?,
                bits: self.u16()?,
            }),
            2 => Ok(ScalarType::Float32),
            3 => Ok(ScalarType::Float64),
            4 => Ok(ScalarType::Address),
            tag => Err(invalid_tag("ScalarType", tag)),
        }
    }

    fn immediate(&mut self) -> Result<Immediate, CodecError> {
        match self.u8()? {
            0 => Ok(Immediate::Unit),
            1 => Ok(Immediate::Bool(self.bool()?)),
            2 => Ok(Immediate::Integer {
                bits: self.u16()?,
                bytes_le: self.bytes()?,
            }),
            3 => Ok(Immediate::Float32(self.u32()?)),
            4 => Ok(Immediate::Float64(self.u64()?)),
            5 => Ok(Immediate::Bytes(self.bytes()?)),
            6 => Ok(Immediate::Zero(TypeId(self.u32()?))),
            7 => Ok(Immediate::GlobalAddress(GlobalId(self.u32()?))),
            8 => Ok(Immediate::FunctionAddress(FunctionId(self.u32()?))),
            tag => Err(invalid_tag("Immediate", tag)),
        }
    }

    fn global(&mut self) -> Result<FlowGlobal, CodecError> {
        Ok(FlowGlobal {
            id: GlobalId(self.u32()?),
            name: self.string()?,
            ty: TypeId(self.u32()?),
            initializer: self.immediate()?,
            mutable: self.bool()?,
            owner: self.owner()?,
        })
    }

    fn function(&mut self) -> Result<FlowFunction, CodecError> {
        Ok(FlowFunction {
            id: FunctionId(self.u32()?),
            name: self.string()?,
            origin: self.function_origin()?,
            role: self.function_role()?,
            color: self.function_color()?,
            parameters: self.id_vector(ValueId)?,
            result_types: self.id_vector(TypeId)?,
            values: self.vector(VectorKind::General, Self::value)?,
            blocks: self.vector(VectorKind::Blocks, Self::block)?,
            entry: BlockId(self.u32()?),
            stack_bound: self.u64()?,
            frame_bound: self.u64()?,
            proofs: self.id_vector(ProofId)?,
            source: self.option(Self::span)?,
        })
    }

    fn function_origin(&mut self) -> Result<FunctionOrigin, CodecError> {
        match self.u8()? {
            0 => Ok(FunctionOrigin::SourceSemantic {
                semantic_function: self.u32()?,
            }),
            1 => Ok(FunctionOrigin::GeneratedImageEntry {
                semantic_function: self.u32()?,
                constructor: self.u32()?,
            }),
            2 => Ok(FunctionOrigin::GeneratedTestHarness {
                semantic_function: self.u32()?,
                group: self.u32()?,
            }),
            3 => Ok(FunctionOrigin::GeneratedAsyncState {
                semantic_function: self.u32()?,
                state: self.u32()?,
            }),
            4 => Ok(FunctionOrigin::GeneratedCleanup {
                semantic_function: self.u32()?,
                scope: self.u32()?,
            }),
            tag => Err(invalid_tag("FunctionOrigin", tag)),
        }
    }

    fn function_role(&mut self) -> Result<FunctionRole, CodecError> {
        match self.u8()? {
            0 => Ok(FunctionRole::Ordinary),
            1 => Ok(FunctionRole::ActorTurn(ActorId(self.u32()?))),
            2 => Ok(FunctionRole::TaskEntry(TaskId(self.u32()?))),
            3 => Ok(FunctionRole::Isr(DeviceId(self.u32()?))),
            4 => Ok(FunctionRole::Cleanup),
            5 => Ok(FunctionRole::ImageEntry),
            6 => Ok(FunctionRole::Test),
            tag => Err(invalid_tag("FunctionRole", tag)),
        }
    }

    fn function_color(&mut self) -> Result<FunctionColor, CodecError> {
        match self.u8()? {
            0 => Ok(FunctionColor::Sync),
            1 => Ok(FunctionColor::Async),
            2 => Ok(FunctionColor::Isr),
            tag => Err(invalid_tag("FunctionColor", tag)),
        }
    }

    fn value(&mut self) -> Result<Value, CodecError> {
        Ok(Value {
            id: ValueId(self.u32()?),
            ty: TypeId(self.u32()?),
            source_name: self.option(Self::string)?,
            source: self.option(Self::span)?,
        })
    }

    fn block(&mut self) -> Result<Block, CodecError> {
        Ok(Block {
            id: BlockId(self.u32()?),
            parameters: self.id_vector(ValueId)?,
            instructions: self.vector(VectorKind::Instructions, Self::instruction)?,
            terminator: self.terminator()?,
            source: self.option(Self::span)?,
        })
    }

    fn instruction(&mut self) -> Result<Instruction, CodecError> {
        Ok(Instruction {
            id: InstructionId(self.u32()?),
            results: self.id_vector(ValueId)?,
            operation: self.operation()?,
            source: self.option(Self::span)?,
        })
    }

    fn actor(&mut self) -> Result<ActorPlan, CodecError> {
        Ok(ActorPlan {
            id: ActorId(self.u32()?),
            name: self.string()?,
            state_type: TypeId(self.u32()?),
            mailbox_capacity: self.u32()?,
            message_types: self.id_vector(TypeId)?,
            turn_functions: self.id_vector(FunctionId)?,
            priority: self.u8()?,
            supervisor: self.option(|reader| Ok(ActorId(reader.u32()?)))?,
        })
    }

    fn task(&mut self) -> Result<TaskPlan, CodecError> {
        Ok(TaskPlan {
            id: TaskId(self.u32()?),
            name: self.string()?,
            entry: FunctionId(self.u32()?),
            slots: self.u32()?,
            priority: self.u8()?,
            frame_bytes_bound: self.u64()?,
            supervisor: self.option(|reader| Ok(ActorId(reader.u32()?)))?,
        })
    }

    fn device(&mut self) -> Result<DevicePlan, CodecError> {
        Ok(DevicePlan {
            id: DeviceId(self.u32()?),
            name: self.string()?,
            target_binding: self.string()?,
            owner: ActorId(self.u32()?),
            queue_capacity: self.option(Self::u32)?,
            maximum_in_flight: self.option(Self::u32)?,
            required_features: self.vector(VectorKind::General, Self::string)?,
            optional_features: self.vector(VectorKind::General, Self::string)?,
            interrupt_functions: self.id_vector(FunctionId)?,
            reset_timeout_ns: self.u64()?,
        })
    }

    fn pool(&mut self) -> Result<PoolPlan, CodecError> {
        Ok(PoolPlan {
            id: PoolId(self.u32()?),
            name: self.string()?,
            element_type: TypeId(self.u32()?),
            capacity: self.u64()?,
            alignment: self.u64()?,
            devices: self.id_vector(DeviceId)?,
        })
    }

    fn region(&mut self) -> Result<RegionPlan, CodecError> {
        Ok(RegionPlan {
            id: RegionId(self.u32()?),
            name: self.string()?,
            class: self.region_class()?,
            capacity_bytes: self.u64()?,
            alignment: self.u64()?,
            reset_function: self.option(|reader| Ok(FunctionId(reader.u32()?)))?,
            owner: self.owner()?,
            capacity_proof: ProofId(self.u32()?),
            source: self.span()?,
        })
    }

    fn activation(&mut self) -> Result<ActivationPlan, CodecError> {
        Ok(ActivationPlan {
            id: ActivationId(self.u32()?),
            caller: FunctionId(self.u32()?),
            callee: FunctionId(self.u32()?),
            region: RegionId(self.u32()?),
            frame_bytes: self.u64()?,
            maximum_live: self.u32()?,
            cancellation: match self.u8()? {
                0 => ActivationCancellation::DropCalleeThenPropagate,
                tag => return Err(invalid_tag("ActivationCancellation", tag)),
            },
            capacity_proof: ProofId(self.u32()?),
            source: self.span()?,
        })
    }

    fn region_class(&mut self) -> Result<RegionClass, CodecError> {
        match self.u8()? {
            0 => Ok(RegionClass::Image),
            1 => Ok(RegionClass::TaskFrame),
            2 => Ok(RegionClass::Call),
            3 => Ok(RegionClass::Request),
            4 => Ok(RegionClass::Pool(PoolId(self.u32()?))),
            5 => Ok(RegionClass::Static),
            tag => Err(invalid_tag("RegionClass", tag)),
        }
    }

    fn owner(&mut self) -> Result<PlanOwner, CodecError> {
        match self.u8()? {
            0 => Ok(PlanOwner::Runtime),
            1 => Ok(PlanOwner::Actor(ActorId(self.u32()?))),
            2 => Ok(PlanOwner::Task(TaskId(self.u32()?))),
            3 => Ok(PlanOwner::Device(DeviceId(self.u32()?))),
            4 => Ok(PlanOwner::Pool(PoolId(self.u32()?))),
            5 => Ok(PlanOwner::BakedArtifact(self.u32()?)),
            tag => Err(invalid_tag("PlanOwner", tag)),
        }
    }

    fn proof(&mut self) -> Result<Proof, CodecError> {
        Ok(Proof {
            id: ProofId(self.u32()?),
            kind: self.proof_kind()?,
            subject: self.string()?,
            sources: self.vector(VectorKind::General, Self::span)?,
            depends_on: self.id_vector(ProofId)?,
            bound: self.option(Self::u64)?,
            explanation: self.vector(VectorKind::General, Self::string)?,
        })
    }

    fn proof_kind(&mut self) -> Result<ProofKind, CodecError> {
        Ok(match self.u8()? {
            0 => ProofKind::TypeChecked,
            1 => ProofKind::EffectsAllowed,
            2 => ProofKind::DefiniteInitialization,
            3 => ProofKind::Ownership,
            4 => ProofKind::AccessExclusive,
            5 => ProofKind::ViewDoesNotEscape,
            6 => ProofKind::RegionBound,
            7 => ProofKind::CapacityBound,
            8 => ProofKind::WaitGraphAcyclic,
            9 => ProofKind::CleanupAcyclic,
            10 => ProofKind::WorkBound,
            11 => ProofKind::StackBound,
            12 => ProofKind::IsrSafe,
            13 => ProofKind::DmaTransition,
            14 => ProofKind::MmioPartition,
            15 => ProofKind::DeviceValueValidated,
            16 => ProofKind::WireLayout,
            17 => ProofKind::ReceiptLineage,
            18 => ProofKind::ActorAsIf,
            19 => ProofKind::SupervisionComplete,
            20 => ProofKind::ImageClosed,
            21 => ProofKind::FlowControl,
            22 => ProofKind::ValueRange,
            23 => ProofKind::Alignment,
            24 => ProofKind::NoAlias,
            tag => return Err(invalid_tag("ProofKind", tag)),
        })
    }

    fn checkpoint(&mut self) -> Result<Checkpoint, CodecError> {
        Ok(Checkpoint {
            id: CheckpointId(self.u32()?),
            function: FunctionId(self.u32()?),
            source: self.span()?,
            uninterrupted_bound: self.u64()?,
            may_observe_cancellation: self.bool()?,
            may_yield: self.bool()?,
        })
    }

    fn test_entry(&mut self) -> Result<TestEntry, CodecError> {
        Ok(TestEntry {
            id: TestId(self.u32()?),
            plan_id: self.u32()?,
            function_key: self.digest()?,
            name: self.string()?,
            function: FunctionId(self.u32()?),
            kind: self.test_kind()?,
            source: self.span()?,
            timeout_ns: self.u64()?,
        })
    }

    fn compiled_test_group(&mut self) -> Result<FullImageTestGroup, CodecError> {
        let id = ImageGroupId(self.u32()?);
        let name = self.string()?;
        let root = match self.u8()? {
            0 => ImageRoot::GeneratedHarness {
                harness_name: self.string()?,
            },
            1 => ImageRoot::Declared {
                image_name: self.string()?,
                scenario: ScenarioId(self.u32()?),
            },
            tag => return Err(invalid_tag("ImageRoot", tag)),
        };
        Ok(FullImageTestGroup {
            id,
            name,
            root,
            tests: self.vector(VectorKind::General, Self::planned_test)?,
            deterministic_seed: self.option(Self::u64)?,
            boot_timeout_ns: self.u64()?,
            shutdown_timeout_ns: self.u64()?,
            maximum_events: self.u32()?,
            maximum_output_bytes: self.u64()?,
        })
    }

    fn planned_test(&mut self) -> Result<ImageTest, CodecError> {
        let descriptor = TestDescriptor {
            id: PlanTestId(self.u32()?),
            name: self.string()?,
            kind: match self.u8()? {
                0 => PlannedTestKind::ComptimeUnit,
                1 => PlannedTestKind::IntegrationImage,
                2 => PlannedTestKind::DeclaredImage,
                tag => return Err(invalid_tag("planned TestKind", tag)),
            },
            source: self.option(Self::span)?,
            timeout_ns: self.u64()?,
        };
        let invocation = match self.u8()? {
            0 => ImageTestInvocation::GeneratedFunction {
                function_key: FunctionKey(self.digest()?),
            },
            1 => ImageTestInvocation::DeclaredScenario,
            tag => return Err(invalid_tag("ImageTestInvocation", tag)),
        };
        let assertions = self.vector(VectorKind::General, |reader| {
            Ok(PlannedAssertionDescriptor {
                source: reader.span()?,
                expression: reader.string()?,
                message: reader.option(Self::string)?,
            })
        })?;
        Ok(ImageTest {
            descriptor,
            invocation,
            assertions,
        })
    }

    fn test_kind(&mut self) -> Result<TestKind, CodecError> {
        match self.u8()? {
            0 => Ok(TestKind::Comptime),
            1 => Ok(TestKind::Integration),
            2 => Ok(TestKind::Image),
            tag => Err(invalid_tag("TestKind", tag)),
        }
    }
}

fn invalid_tag(kind: &'static str, tag: u8) -> CodecError {
    CodecError::InvalidEnumTag {
        kind,
        tag: u64::from(tag),
    }
}

impl Reader<'_> {
    fn unary_op(&mut self) -> Result<UnaryOp, CodecError> {
        match self.u8()? {
            0 => Ok(UnaryOp::Negate),
            1 => Ok(UnaryOp::BoolNot),
            2 => Ok(UnaryOp::BitNot),
            tag => Err(invalid_tag("UnaryOp", tag)),
        }
    }

    fn binary_op(&mut self) -> Result<BinaryOp, CodecError> {
        Ok(match self.u8()? {
            0 => BinaryOp::AddChecked,
            1 => BinaryOp::AddWrapping,
            2 => BinaryOp::SubChecked,
            3 => BinaryOp::SubWrapping,
            4 => BinaryOp::MulChecked,
            5 => BinaryOp::MulWrapping,
            6 => BinaryOp::DivChecked,
            7 => BinaryOp::RemChecked,
            8 => BinaryOp::BitAnd,
            9 => BinaryOp::BitOr,
            10 => BinaryOp::BitXor,
            11 => BinaryOp::ShiftLeftChecked,
            12 => BinaryOp::ShiftRightChecked,
            13 => BinaryOp::Equal,
            14 => BinaryOp::NotEqual,
            15 => BinaryOp::Less,
            16 => BinaryOp::LessEqual,
            17 => BinaryOp::Greater,
            18 => BinaryOp::GreaterEqual,
            19 => BinaryOp::ShiftLeftWrapping,
            tag => return Err(invalid_tag("BinaryOp", tag)),
        })
    }

    fn cast_mode(&mut self) -> Result<CastMode, CodecError> {
        match self.u8()? {
            0 => Ok(CastMode::Checked),
            1 => Ok(CastMode::Exact),
            2 => Ok(CastMode::Bitcast),
            tag => Err(invalid_tag("CastMode", tag)),
        }
    }

    fn access_kind(&mut self) -> Result<AccessKind, CodecError> {
        match self.u8()? {
            0 => Ok(AccessKind::Read),
            1 => Ok(AccessKind::Mutate),
            2 => Ok(AccessKind::Take),
            tag => Err(invalid_tag("AccessKind", tag)),
        }
    }

    fn dma_ownership(&mut self) -> Result<DmaOwnership, CodecError> {
        match self.u8()? {
            0 => Ok(DmaOwnership::Cpu),
            1 => Ok(DmaOwnership::Prepared),
            2 => Ok(DmaOwnership::Device),
            3 => Ok(DmaOwnership::Completed),
            4 => Ok(DmaOwnership::Quarantined),
            tag => Err(invalid_tag("DmaOwnership", tag)),
        }
    }

    fn fence_kind(&mut self) -> Result<FenceKind, CodecError> {
        match self.u8()? {
            0 => Ok(FenceKind::Acquire),
            1 => Ok(FenceKind::Release),
            2 => Ok(FenceKind::AcquireRelease),
            3 => Ok(FenceKind::DeviceRead),
            4 => Ok(FenceKind::DeviceWrite),
            5 => Ok(FenceKind::DeviceFull),
            tag => Err(invalid_tag("FenceKind", tag)),
        }
    }

    fn failure_kind(&mut self) -> Result<FailureKind, CodecError> {
        Ok(match self.u8()? {
            0 => FailureKind::Bounds,
            1 => FailureKind::Arithmetic,
            2 => FailureKind::Conversion,
            3 => FailureKind::Capacity,
            4 => FailureKind::Generation,
            5 => FailureKind::DmaState,
            6 => FailureKind::DeviceValue,
            7 => FailureKind::Cancellation,
            8 => FailureKind::Deadline,
            9 => FailureKind::PeerFailure,
            10 => FailureKind::TaskFailure,
            11 => FailureKind::FatalTarget,
            tag => return Err(invalid_tag("FailureKind", tag)),
        })
    }

    fn operation(&mut self) -> Result<FlowOperation, CodecError> {
        Ok(match self.u8()? {
            0 => FlowOperation::Immediate(self.immediate()?),
            1 => FlowOperation::Unary {
                op: self.unary_op()?,
                value: ValueId(self.u32()?),
            },
            2 => FlowOperation::Binary {
                op: self.binary_op()?,
                left: ValueId(self.u32()?),
                right: ValueId(self.u32()?),
            },
            3 => FlowOperation::Cast {
                value: ValueId(self.u32()?),
                to: TypeId(self.u32()?),
                mode: self.cast_mode()?,
            },
            4 => FlowOperation::MakeAggregate {
                ty: TypeId(self.u32()?),
                fields: self.id_vector(ValueId)?,
            },
            5 => FlowOperation::ExtractField {
                aggregate: ValueId(self.u32()?),
                field: self.u32()?,
            },
            6 => FlowOperation::InsertField {
                aggregate: ValueId(self.u32()?),
                field: self.u32()?,
                value: ValueId(self.u32()?),
            },
            7 => FlowOperation::Select {
                condition: ValueId(self.u32()?),
                then_value: ValueId(self.u32()?),
                else_value: ValueId(self.u32()?),
            },
            8 => FlowOperation::BeginAccess {
                place: ValueId(self.u32()?),
                kind: self.access_kind()?,
                proof: ProofId(self.u32()?),
            },
            9 => FlowOperation::EndAccess {
                access: ValueId(self.u32()?),
            },
            10 => FlowOperation::Load {
                address: ValueId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            11 => FlowOperation::Store {
                address: ValueId(self.u32()?),
                value: ValueId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            12 => FlowOperation::Move {
                value: ValueId(self.u32()?),
            },
            13 => FlowOperation::Copy {
                value: ValueId(self.u32()?),
            },
            14 => FlowOperation::Drop {
                value: ValueId(self.u32()?),
            },
            15 => FlowOperation::Call {
                function: FunctionId(self.u32()?),
                arguments: self.id_vector(ValueId)?,
            },
            16 => FlowOperation::Allocate {
                region: RegionId(self.u32()?),
                ty: TypeId(self.u32()?),
                count: ValueId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            17 => FlowOperation::RegionReset {
                region: RegionId(self.u32()?),
            },
            18 => FlowOperation::ActorReserve {
                actor: ActorId(self.u32()?),
                method: FunctionId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            19 => FlowOperation::ActorCommit {
                reservation: ValueId(self.u32()?),
                arguments: self.id_vector(ValueId)?,
            },
            20 => FlowOperation::ActorReject {
                reservation: ValueId(self.u32()?),
            },
            21 => FlowOperation::MailboxReceive {
                actor: ActorId(self.u32()?),
                method: FunctionId(self.u32()?),
            },
            22 => FlowOperation::ReplyResolve {
                endpoint: ValueId(self.u32()?),
                outcome: ValueId(self.u32()?),
            },
            23 => FlowOperation::ReceiptCommit {
                receipt: ValueId(self.u32()?),
                payload: ValueId(self.u32()?),
            },
            24 => FlowOperation::ReceiptResolve {
                receipt: ValueId(self.u32()?),
                outcome: ValueId(self.u32()?),
            },
            25 => FlowOperation::TaskAcquireSlot {
                task: TaskId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            26 => FlowOperation::TaskStart {
                slot: ValueId(self.u32()?),
                entry: FunctionId(self.u32()?),
                arguments: self.id_vector(ValueId)?,
            },
            27 => FlowOperation::TaskCancel {
                task: ValueId(self.u32()?),
            },
            28 => FlowOperation::Park {
                wait_set: ValueId(self.u32()?),
            },
            29 => FlowOperation::Wake {
                target: ValueId(self.u32()?),
            },
            30 => FlowOperation::Checkpoint {
                id: CheckpointId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            31 => FlowOperation::DeadlineRead,
            32 => FlowOperation::InterruptMask,
            33 => FlowOperation::InterruptRestore {
                token: ValueId(self.u32()?),
            },
            34 => FlowOperation::InterruptPublish {
                cell: ValueId(self.u32()?),
                value: ValueId(self.u32()?),
            },
            35 => FlowOperation::MmioRead {
                device: DeviceId(self.u32()?),
                register: self.u32()?,
            },
            36 => FlowOperation::MmioWrite {
                device: DeviceId(self.u32()?),
                register: self.u32()?,
                value: ValueId(self.u32()?),
            },
            37 => FlowOperation::Fence {
                kind: self.fence_kind()?,
            },
            38 => FlowOperation::DmaTransition {
                token: ValueId(self.u32()?),
                device: DeviceId(self.u32()?),
                from: self.dma_ownership()?,
                to: self.dma_ownership()?,
                proof: ProofId(self.u32()?),
            },
            39 => FlowOperation::QueueReserve {
                device: DeviceId(self.u32()?),
                descriptors: ValueId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            40 => FlowOperation::QueuePublish {
                reservation: ValueId(self.u32()?),
                payload: ValueId(self.u32()?),
            },
            41 => FlowOperation::ValidateDeviceValue {
                value: ValueId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            42 => FlowOperation::Check {
                condition: ValueId(self.u32()?),
                failure: self.failure_kind()?,
                proof: self.option(|reader| Ok(ProofId(reader.u32()?)))?,
            },
            43 => FlowOperation::RecordEvent {
                kind: self.u32()?,
                payload: ValueId(self.u32()?),
            },
            44 => FlowOperation::ReplayEvent {
                kind: self.u32()?,
                destination: ValueId(self.u32()?),
            },
            45 => FlowOperation::TestEmit {
                payload: ValueId(self.u32()?),
            },
            46 => FlowOperation::TestFinish {
                outcome: ValueId(self.u32()?),
            },
            47 => FlowOperation::AsyncCall {
                function: FunctionId(self.u32()?),
                arguments: self.id_vector(ValueId)?,
                plan: ActivationId(self.u32()?),
            },
            48 => FlowOperation::Assert {
                condition: ValueId(self.u32()?),
                failure: AssertionFailureDescriptor {
                    expression: self.string()?,
                    message: self.option(Self::string)?,
                    source: self.span()?,
                },
            },
            49 => FlowOperation::MakeEnum {
                ty: TypeId(self.u32()?),
                variant: self.u8()?,
                payload: self.option(|reader| Ok(ValueId(reader.u32()?)))?,
            },
            50 => FlowOperation::EnumTag {
                value: ValueId(self.u32()?),
            },
            51 => FlowOperation::EnumPayload {
                value: ValueId(self.u32()?),
            },
            52 => FlowOperation::ActorCapability {
                actor: ActorId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            53 => FlowOperation::ActorStateAddress {
                actor: ActorId(self.u32()?),
                region: RegionId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            54 => FlowOperation::Promote {
                value: ValueId(self.u32()?),
                destination: RegionId(self.u32()?),
                proof: ProofId(self.u32()?),
            },
            tag => return Err(invalid_tag("FlowOperation", tag)),
        })
    }

    fn terminator(&mut self) -> Result<Terminator, CodecError> {
        Ok(match self.u8()? {
            0 => Terminator::Jump {
                target: BlockId(self.u32()?),
                arguments: self.id_vector(ValueId)?,
            },
            1 => Terminator::Branch {
                condition: ValueId(self.u32()?),
                then_block: BlockId(self.u32()?),
                then_arguments: self.id_vector(ValueId)?,
                else_block: BlockId(self.u32()?),
                else_arguments: self.id_vector(ValueId)?,
            },
            2 => Terminator::Switch {
                value: ValueId(self.u32()?),
                cases: self.vector(VectorKind::General, |reader| {
                    Ok(SwitchCase {
                        value: reader.u128()?,
                        target: BlockId(reader.u32()?),
                        arguments: reader.id_vector(ValueId)?,
                    })
                })?,
                default: BlockId(self.u32()?),
                default_arguments: self.id_vector(ValueId)?,
            },
            3 => Terminator::Return(self.id_vector(ValueId)?),
            4 => Terminator::Suspend {
                state: self.u32()?,
                activation: ValueId(self.u32()?),
                resume: BlockId(self.u32()?),
            },
            5 => Terminator::TailCall {
                function: FunctionId(self.u32()?),
                arguments: self.id_vector(ValueId)?,
            },
            6 => Terminator::Trap {
                failure: self.failure_kind()?,
                detail: self.option(|reader| Ok(ValueId(reader.u32()?)))?,
            },
            7 => Terminator::Unreachable,
            tag => return Err(invalid_tag("Terminator", tag)),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_flow_wir::{FLOW_WIR_VERSION, FlowWir, SourceSummary};

    use super::*;
    use crate::{decode_and_verify, encode_and_verify};

    fn build_identity(byte: u8) -> BuildIdentity {
        let digest = Sha256Digest::from_bytes([byte; 32]);
        BuildIdentity {
            compiler: digest,
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: digest,
            standard_library: digest,
            source_graph: digest,
            request: digest,
            profile: digest,
        }
    }

    fn fixture() -> ValidatedFlowWir {
        FlowWir {
            version: FLOW_WIR_VERSION,
            name: "canonical-image".to_owned(),
            build: build_identity(7),
            source_summary: SourceSummary {
                semantic_wir_version: 11,
                semantic_functions: 2,
                hir_files: 1,
                hir_declarations: 2,
                reachable_declarations: 2,
                monomorphized_instantiations: 2,
                resolved_interface_calls: 0,
            },
            types: vec![FlowType {
                id: TypeId(0),
                kind: FlowTypeKind::Unit,
                name: Some("unit".to_owned()),
                copyable: true,
                strict_linear: false,
            }],
            globals: Vec::new(),
            functions: vec![
                FlowFunction {
                    id: FunctionId(0),
                    name: "entry".to_owned(),
                    origin: FunctionOrigin::GeneratedTestHarness {
                        semantic_function: 0,
                        group: 0,
                    },
                    role: FunctionRole::ImageEntry,
                    color: FunctionColor::Sync,
                    parameters: Vec::new(),
                    result_types: Vec::new(),
                    values: Vec::new(),
                    blocks: vec![Block {
                        id: BlockId(0),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: Terminator::Return(Vec::new()),
                        source: None,
                    }],
                    entry: BlockId(0),
                    stack_bound: 32,
                    frame_bound: 16,
                    proofs: Vec::new(),
                    source: None,
                },
                FlowFunction {
                    id: FunctionId(1),
                    name: "integration-test".to_owned(),
                    origin: FunctionOrigin::SourceSemantic {
                        semantic_function: 1,
                    },
                    role: FunctionRole::Test,
                    color: FunctionColor::Sync,
                    parameters: Vec::new(),
                    result_types: Vec::new(),
                    values: Vec::new(),
                    blocks: vec![Block {
                        id: BlockId(0),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: Terminator::Return(Vec::new()),
                        source: Some(Span {
                            file: FileId(0),
                            range: TextRange { start: 10, end: 20 },
                        }),
                    }],
                    entry: BlockId(0),
                    stack_bound: 64,
                    frame_bound: 0,
                    proofs: Vec::new(),
                    source: Some(Span {
                        file: FileId(0),
                        range: TextRange { start: 10, end: 20 },
                    }),
                },
            ],
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            activations: Vec::new(),
            proofs: Vec::new(),
            checkpoints: Vec::new(),
            tests: vec![TestEntry {
                id: TestId(0),
                plan_id: 0,
                function_key: Sha256Digest::from_bytes([7; 32]),
                name: "integration-test".to_owned(),
                function: FunctionId(1),
                kind: TestKind::Integration,
                source: Span {
                    file: FileId(0),
                    range: TextRange { start: 10, end: 20 },
                },
                timeout_ns: 5_000_000_000,
            }],
            compiled_test_group: Some(FullImageTestGroup {
                id: ImageGroupId(0),
                name: "integration".to_owned(),
                root: ImageRoot::GeneratedHarness {
                    harness_name: "canonical-image".to_owned(),
                },
                tests: vec![ImageTest {
                    descriptor: TestDescriptor {
                        id: PlanTestId(0),
                        name: "integration-test".to_owned(),
                        kind: PlannedTestKind::IntegrationImage,
                        source: Some(Span {
                            file: FileId(0),
                            range: TextRange { start: 10, end: 20 },
                        }),
                        timeout_ns: 5_000_000_000,
                    },
                    invocation: ImageTestInvocation::GeneratedFunction {
                        function_key: FunctionKey(Sha256Digest::from_bytes([7; 32])),
                    },
                    assertions: Vec::new(),
                }],
                deterministic_seed: None,
                boot_timeout_ns: 1,
                shutdown_timeout_ns: 1,
                maximum_events: 5,
                maximum_output_bytes: 1,
            }),
            startup_order: vec![PlanOwner::Runtime],
            shutdown_order: vec![PlanOwner::Runtime],
            image_entry: FunctionId(0),
            static_bytes: 64,
            peak_bytes: 128,
        }
        .validate()
        .expect("valid canonical codec fixture")
    }

    fn async_fixture() -> ValidatedFlowWir {
        let mut model = fixture().into_wir();
        model.tests.clear();
        model.compiled_test_group = None;
        model.source_summary.semantic_functions = 3;
        model.source_summary.hir_declarations = 3;
        model.source_summary.reachable_declarations = 3;
        model.source_summary.monomorphized_instantiations = 3;
        model.functions[0].origin = FunctionOrigin::GeneratedImageEntry {
            semantic_function: 0,
            constructor: 0,
        };
        model.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Activation { result: TypeId(0) },
            name: Some("__wrela_activation_0".to_owned()),
            copyable: false,
            strict_linear: true,
        });
        let function = &mut model.functions[1];
        let source = function.source.expect("fixture source");
        function.name = "actor-turn".to_owned();
        function.role = FunctionRole::ActorTurn(ActorId(0));
        function.color = FunctionColor::Async;
        function.stack_bound = 8;
        function.frame_bound = 8;
        function.proofs = vec![ProofId(7)];
        function.values = vec![
            Value {
                id: ValueId(0),
                ty: TypeId(1),
                source_name: None,
                source: function.source,
            },
            Value {
                id: ValueId(1),
                ty: TypeId(0),
                source_name: None,
                source: function.source,
            },
        ];
        function.blocks = vec![
            Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: vec![Instruction {
                    id: InstructionId(0),
                    results: vec![ValueId(0)],
                    operation: FlowOperation::AsyncCall {
                        function: FunctionId(1),
                        arguments: Vec::new(),
                        plan: ActivationId(0),
                    },
                    source: function.source,
                }],
                terminator: Terminator::Suspend {
                    state: 0,
                    activation: ValueId(0),
                    resume: BlockId(1),
                },
                source: function.source,
            },
            Block {
                id: BlockId(1),
                parameters: vec![ValueId(1)],
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: function.source,
            },
        ];
        model.functions.push(FlowFunction {
            id: FunctionId(2),
            name: "async-helper".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 2,
            },
            role: FunctionRole::Ordinary,
            color: FunctionColor::Async,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: Some(source),
            }],
            entry: BlockId(0),
            stack_bound: 8,
            frame_bound: 8,
            proofs: vec![ProofId(2)],
            source: Some(source),
        });
        model.functions[0].proofs =
            vec![ProofId(3), ProofId(4), ProofId(5), ProofId(6), ProofId(8)];
        let FlowOperation::AsyncCall { function, .. } =
            &mut model.functions[1].blocks[0].instructions[0].operation
        else {
            panic!("async call fixture")
        };
        *function = FunctionId(2);
        model.actors = vec![ActorPlan {
            id: ActorId(0),
            name: "actor".to_owned(),
            state_type: TypeId(0),
            mailbox_capacity: 1,
            message_types: Vec::new(),
            turn_functions: vec![FunctionId(1)],
            priority: 1,
            supervisor: None,
        }];
        model.proofs = vec![
            Proof {
                id: ProofId(0),
                kind: ProofKind::TypeChecked,
                subject: "actor image types".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: None,
                explanation: vec!["actor image is typed".to_owned()],
            },
            Proof {
                id: ProofId(1),
                kind: ProofKind::EffectsAllowed,
                subject: "actor image effects".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(0)],
                bound: None,
                explanation: vec!["actor image effects are closed".to_owned()],
            },
            Proof {
                id: ProofId(2),
                kind: ProofKind::CleanupAcyclic,
                subject: "helper cleanup".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(0),
                explanation: vec!["drop helper frame".to_owned()],
            },
            Proof {
                id: ProofId(3),
                kind: ProofKind::CapacityBound,
                subject: "mailbox capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one mailbox slot".to_owned()],
            },
            Proof {
                id: ProofId(4),
                kind: ProofKind::CapacityBound,
                subject: "turn capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one turn frame".to_owned()],
            },
            Proof {
                id: ProofId(5),
                kind: ProofKind::WaitGraphAcyclic,
                subject: "closed actor wait graph".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(1)],
                bound: Some(1),
                explanation: vec!["one acyclic await edge".to_owned()],
            },
            Proof {
                id: ProofId(6),
                kind: ProofKind::CapacityBound,
                subject: "base actor allocation".to_owned(),
                sources: vec![source, source],
                depends_on: vec![ProofId(0), ProofId(1), ProofId(3), ProofId(4), ProofId(5)],
                bound: Some(24),
                explanation: vec!["mailbox plus root turn frame".to_owned()],
            },
            Proof {
                id: ProofId(7),
                kind: ProofKind::CapacityBound,
                subject: "call activation".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(2)],
                bound: Some(1),
                explanation: vec!["one helper frame".to_owned()],
            },
            Proof {
                id: ProofId(8),
                kind: ProofKind::ImageClosed,
                subject: "closed actor image".to_owned(),
                sources: vec![source],
                depends_on: vec![ProofId(6), ProofId(7)],
                bound: Some(32),
                explanation: vec!["base plus helper activation".to_owned()],
            },
        ];
        model.regions = vec![
            RegionPlan {
                id: RegionId(0),
                name: "actor.mailbox".to_owned(),
                class: RegionClass::Image,
                capacity_bytes: 16,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: ProofId(3),
                source,
            },
            RegionPlan {
                id: RegionId(1),
                name: "actor.turn-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: ProofId(4),
                source,
            },
            RegionPlan {
                id: RegionId(2),
                name: "actor-turn.async-activation-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: ProofId(7),
                source,
            },
        ];
        model.activations = vec![ActivationPlan {
            id: ActivationId(0),
            caller: FunctionId(1),
            callee: FunctionId(2),
            region: RegionId(2),
            frame_bytes: 8,
            maximum_live: 1,
            cancellation: ActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: ProofId(7),
            source,
        }];
        model.startup_order = vec![PlanOwner::Runtime, PlanOwner::Actor(ActorId(0))];
        model.shutdown_order = vec![PlanOwner::Actor(ActorId(0)), PlanOwner::Runtime];
        model.static_bytes = 32;
        model.peak_bytes = 32;
        model.validate().expect("valid async codec fixture")
    }

    fn long_prefix_fixture() -> ValidatedFlowWir {
        let mut model = fixture().into_wir();
        let name = "long-prefix-".to_owned() + &"x".repeat(CANCELLABLE_CODEC_CHUNK_BYTES * 3 + 1);
        model.name.clone_from(&name);
        let Some(FullImageTestGroup {
            root: ImageRoot::GeneratedHarness { harness_name },
            ..
        }) = &mut model.compiled_test_group
        else {
            panic!("fixture must retain its generated test harness");
        };
        harness_name.clone_from(&name);
        model
            .validate()
            .expect("valid long-prefix FlowWir v13 fixture")
    }

    struct SubstitutingCodec<'a> {
        model: &'a ValidatedFlowWir,
    }

    impl FlowWirCodec for SubstitutingCodec<'_> {
        fn encode(
            &self,
            request: EncodeRequest<'_>,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<EncodedFlowWirCandidate, CodecError> {
            CanonicalFlowWirCodec.encode(
                EncodeRequest {
                    wir: self.model,
                    limits: request.limits,
                },
                is_cancelled,
            )
        }

        fn inspect_header(
            &self,
            bytes: &[u8],
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<WireHeader, CodecError> {
            CanonicalFlowWirCodec.inspect_header(bytes, is_cancelled)
        }

        fn decode(
            &self,
            request: DecodeRequest<'_>,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ValidatedFlowWir, CodecError> {
            CanonicalFlowWirCodec.decode(request, is_cancelled)
        }
    }

    struct NondeterministicCodec {
        encode_calls: Cell<u32>,
    }

    impl FlowWirCodec for NondeterministicCodec {
        fn encode(
            &self,
            request: EncodeRequest<'_>,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<EncodedFlowWirCandidate, CodecError> {
            let call = self.encode_calls.get();
            self.encode_calls.set(call + 1);
            let mut candidate = CanonicalFlowWirCodec.encode(request, is_cancelled)?;
            if call > 0 {
                *candidate
                    .bytes
                    .last_mut()
                    .expect("canonical frame is nonempty") ^= 1;
            }
            Ok(candidate)
        }

        fn inspect_header(
            &self,
            bytes: &[u8],
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<WireHeader, CodecError> {
            CanonicalFlowWirCodec.inspect_header(bytes, is_cancelled)
        }

        fn decode(
            &self,
            request: DecodeRequest<'_>,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ValidatedFlowWir, CodecError> {
            CanonicalFlowWirCodec.decode(request, is_cancelled)
        }
    }

    fn roundtrip_type(value: &FlowTypeKind) {
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer.type_kind(value).expect("type encodes");
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        let decoded = reader.type_kind().expect("type decodes");
        reader.finish().expect("type consumes exactly");
        assert_eq!(&decoded, value);
    }

    fn roundtrip_immediate(value: &Immediate) {
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer.immediate(value).expect("immediate encodes");
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        let decoded = reader.immediate().expect("immediate decodes");
        reader.finish().expect("immediate consumes exactly");
        assert_eq!(&decoded, value);
    }

    fn roundtrip_operation(value: &FlowOperation) {
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        encode_operation(&mut writer, value).expect("operation encodes");
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        let decoded = reader.operation().expect("operation decodes");
        reader.finish().expect("operation consumes exactly");
        assert_eq!(&decoded, value);
    }

    fn roundtrip_terminator(value: &Terminator) {
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        encode_terminator(&mut writer, value).expect("terminator encodes");
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        let decoded = reader.terminator().expect("terminator decodes");
        reader.finish().expect("terminator consumes exactly");
        assert_eq!(&decoded, value);
    }

    #[test]
    fn production_frame_roundtrips_and_reencodes_exactly() {
        let model = fixture();
        let codec = CanonicalFlowWirCodec;
        let encoded = encode_and_verify(
            &codec,
            EncodeRequest {
                wir: &model,
                limits: CodecLimits::standard(),
            },
            &|| false,
        )
        .expect("canonical production frame");
        let decoded = decode_and_verify(
            &codec,
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: CodecLimits::standard(),
                expected_build: Some(&model.as_wir().build),
            },
            &|| false,
        )
        .expect("verified backend decode");
        assert_eq!(decoded, model);
        assert_eq!(
            codec
                .inspect_header(encoded.bytes(), &|| false)
                .expect("header"),
            *encoded.header()
        );
    }

    #[test]
    fn async_activation_delivery_roundtrips_canonically() {
        let model = async_fixture();
        let codec = CanonicalFlowWirCodec;
        let encoded = encode_and_verify(
            &codec,
            EncodeRequest {
                wir: &model,
                limits: CodecLimits::standard(),
            },
            &|| false,
        )
        .expect("canonical async frame");
        let decoded = decode_and_verify(
            &codec,
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: CodecLimits::standard(),
                expected_build: Some(&model.as_wir().build),
            },
            &|| false,
        )
        .expect("async frame decodes");
        assert_eq!(decoded, model);

        // The two owner vectors and trailing scalar fields occupy a fixed
        // 40-byte tail for this Runtime+Actor fixture. Remove the actor from
        // startup while keeping the frame structurally decodable: validation
        // must reject the semantically incomplete phase order.
        let startup = encoded.bytes().len() - 40;
        let mut omitted_startup_actor = encoded.bytes().to_vec();
        omitted_startup_actor[startup..startup + 4].copy_from_slice(&1_u32.to_le_bytes());
        omitted_startup_actor.drain(startup + 5..startup + 10);
        omitted_startup_actor[16..24]
            .copy_from_slice(&(encoded.header().payload_bytes - 5).to_le_bytes());
        assert!(matches!(
            codec.decode(
                DecodeRequest {
                    bytes: &omitted_startup_actor,
                    limits: CodecLimits::standard(),
                    expected_build: Some(&model.as_wir().build),
                },
                &|| false,
            ),
            Err(CodecError::InvalidFlowWir(_))
        ));

        let shutdown = encoded.bytes().len() - 30;
        let mut substituted_shutdown_actor = encoded.bytes().to_vec();
        substituted_shutdown_actor[shutdown + 5..shutdown + 9]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            codec.decode(
                DecodeRequest {
                    bytes: &substituted_shutdown_actor,
                    limits: CodecLimits::standard(),
                    expected_build: Some(&model.as_wir().build),
                },
                &|| false,
            ),
            Err(CodecError::InvalidFlowWir(_))
        ));
    }

    #[test]
    fn all_type_and_immediate_variants_roundtrip() {
        let types = vec![
            FlowTypeKind::Unit,
            FlowTypeKind::Scalar(ScalarType::Bool),
            FlowTypeKind::Scalar(ScalarType::Integer {
                signed: true,
                bits: 128,
            }),
            FlowTypeKind::Scalar(ScalarType::Float32),
            FlowTypeKind::Scalar(ScalarType::Float64),
            FlowTypeKind::Scalar(ScalarType::Address),
            FlowTypeKind::Tuple(vec![TypeId(1), TypeId(2)]),
            FlowTypeKind::Array {
                element: TypeId(3),
                length: u64::MAX,
            },
            FlowTypeKind::Struct {
                fields: vec![TypeId(4)],
            },
            FlowTypeKind::Enum {
                variants: vec![vec![], vec![TypeId(5), TypeId(6)]],
            },
            FlowTypeKind::Function {
                parameters: vec![TypeId(7)],
                result: TypeId(8),
            },
            FlowTypeKind::RegionHandle(RegionId(9)),
            FlowTypeKind::PoolHandle(PoolId(10)),
            FlowTypeKind::ActorHandle(ActorId(11)),
            FlowTypeKind::TaskHandle(TaskId(12)),
            FlowTypeKind::Reservation,
            FlowTypeKind::Receipt {
                payload: TypeId(13),
                error: TypeId(14),
            },
            FlowTypeKind::DmaToken {
                pool: PoolId(15),
                payload: TypeId(16),
            },
            FlowTypeKind::OpaqueTarget {
                name: "target::opaque".to_owned(),
            },
            FlowTypeKind::Activation { result: TypeId(17) },
        ];
        for value in types {
            roundtrip_type(&value);
        }

        let immediates = vec![
            Immediate::Unit,
            Immediate::Bool(true),
            Immediate::Integer {
                bits: 24,
                bytes_le: vec![1, 2, 3],
            },
            Immediate::Float32(f32::NAN.to_bits()),
            Immediate::Float64(f64::NEG_INFINITY.to_bits()),
            Immediate::Bytes(vec![0, 255]),
            Immediate::Zero(TypeId(1)),
            Immediate::GlobalAddress(GlobalId(2)),
            Immediate::FunctionAddress(FunctionId(3)),
        ];
        for value in immediates {
            roundtrip_immediate(&value);
        }
    }

    #[test]
    fn every_operation_and_terminator_variant_roundtrips() {
        let v = ValueId(1);
        let p = ProofId(2);
        let operations = vec![
            FlowOperation::Immediate(Immediate::Unit),
            FlowOperation::Unary {
                op: UnaryOp::Negate,
                value: v,
            },
            FlowOperation::Binary {
                op: BinaryOp::AddChecked,
                left: v,
                right: v,
            },
            FlowOperation::Cast {
                value: v,
                to: TypeId(3),
                mode: CastMode::Checked,
            },
            FlowOperation::MakeAggregate {
                ty: TypeId(3),
                fields: vec![v],
            },
            FlowOperation::MakeEnum {
                ty: TypeId(3),
                variant: 4,
                payload: Some(v),
            },
            FlowOperation::MakeEnum {
                ty: TypeId(3),
                variant: 2,
                payload: None,
            },
            FlowOperation::EnumTag { value: v },
            FlowOperation::EnumPayload { value: v },
            FlowOperation::ExtractField {
                aggregate: v,
                field: 4,
            },
            FlowOperation::InsertField {
                aggregate: v,
                field: 4,
                value: v,
            },
            FlowOperation::Select {
                condition: v,
                then_value: v,
                else_value: v,
            },
            FlowOperation::BeginAccess {
                place: v,
                kind: AccessKind::Read,
                proof: p,
            },
            FlowOperation::EndAccess { access: v },
            FlowOperation::Load {
                address: v,
                proof: p,
            },
            FlowOperation::Store {
                address: v,
                value: v,
                proof: p,
            },
            FlowOperation::Move { value: v },
            FlowOperation::Copy { value: v },
            FlowOperation::Drop { value: v },
            FlowOperation::Call {
                function: FunctionId(5),
                arguments: vec![v],
            },
            FlowOperation::AsyncCall {
                function: FunctionId(5),
                arguments: vec![v],
                plan: ActivationId(11),
            },
            FlowOperation::Allocate {
                region: RegionId(6),
                ty: TypeId(3),
                count: v,
                proof: p,
            },
            FlowOperation::RegionReset {
                region: RegionId(6),
            },
            FlowOperation::Promote {
                value: v,
                destination: RegionId(6),
                proof: p,
            },
            FlowOperation::ActorReserve {
                actor: ActorId(7),
                method: FunctionId(8),
                proof: p,
            },
            FlowOperation::ActorCommit {
                reservation: v,
                arguments: vec![v],
            },
            FlowOperation::ActorReject { reservation: v },
            FlowOperation::MailboxReceive {
                actor: ActorId(7),
                method: FunctionId(8),
            },
            FlowOperation::ReplyResolve {
                endpoint: v,
                outcome: v,
            },
            FlowOperation::ReceiptCommit {
                receipt: v,
                payload: v,
            },
            FlowOperation::ReceiptResolve {
                receipt: v,
                outcome: v,
            },
            FlowOperation::TaskAcquireSlot {
                task: TaskId(9),
                proof: p,
            },
            FlowOperation::TaskStart {
                slot: v,
                entry: FunctionId(5),
                arguments: vec![v],
            },
            FlowOperation::TaskCancel { task: v },
            FlowOperation::Park { wait_set: v },
            FlowOperation::Wake { target: v },
            FlowOperation::Checkpoint {
                id: CheckpointId(10),
                proof: p,
            },
            FlowOperation::DeadlineRead,
            FlowOperation::InterruptMask,
            FlowOperation::InterruptRestore { token: v },
            FlowOperation::InterruptPublish { cell: v, value: v },
            FlowOperation::MmioRead {
                device: DeviceId(11),
                register: 12,
            },
            FlowOperation::MmioWrite {
                device: DeviceId(11),
                register: 12,
                value: v,
            },
            FlowOperation::Fence {
                kind: FenceKind::Acquire,
            },
            FlowOperation::DmaTransition {
                token: v,
                device: DeviceId(11),
                from: DmaOwnership::Cpu,
                to: DmaOwnership::Device,
                proof: p,
            },
            FlowOperation::QueueReserve {
                device: DeviceId(11),
                descriptors: v,
                proof: p,
            },
            FlowOperation::QueuePublish {
                reservation: v,
                payload: v,
            },
            FlowOperation::ValidateDeviceValue { value: v, proof: p },
            FlowOperation::Check {
                condition: v,
                failure: FailureKind::Bounds,
                proof: Some(p),
            },
            FlowOperation::RecordEvent {
                kind: 13,
                payload: v,
            },
            FlowOperation::ReplayEvent {
                kind: 14,
                destination: v,
            },
            FlowOperation::TestEmit { payload: v },
            FlowOperation::TestFinish { outcome: v },
            FlowOperation::Assert {
                condition: v,
                failure: AssertionFailureDescriptor {
                    expression: "value == expected".to_owned(),
                    message: Some("closed assertion".to_owned()),
                    source: Span {
                        file: FileId(0),
                        range: TextRange { start: 1, end: 2 },
                    },
                },
            },
        ];
        assert_eq!(operations.len(), 54);
        for value in operations {
            roundtrip_operation(&value);
        }

        let terminators = vec![
            Terminator::Jump {
                target: BlockId(1),
                arguments: vec![v],
            },
            Terminator::Branch {
                condition: v,
                then_block: BlockId(1),
                then_arguments: vec![v],
                else_block: BlockId(2),
                else_arguments: vec![],
            },
            Terminator::Switch {
                value: v,
                cases: vec![SwitchCase {
                    value: u128::MAX,
                    target: BlockId(1),
                    arguments: vec![v],
                }],
                default: BlockId(2),
                default_arguments: vec![],
            },
            Terminator::Return(vec![v]),
            Terminator::Suspend {
                state: 3,
                activation: v,
                resume: BlockId(1),
            },
            Terminator::TailCall {
                function: FunctionId(5),
                arguments: vec![v],
            },
            Terminator::Trap {
                failure: FailureKind::FatalTarget,
                detail: Some(v),
            },
            Terminator::Unreachable,
        ];
        for value in terminators {
            roundtrip_terminator(&value);
        }
    }

    #[test]
    fn every_nested_enum_variant_roundtrips() {
        let unary = [UnaryOp::Negate, UnaryOp::BoolNot, UnaryOp::BitNot];
        let binary = [
            BinaryOp::AddChecked,
            BinaryOp::AddWrapping,
            BinaryOp::SubChecked,
            BinaryOp::SubWrapping,
            BinaryOp::MulChecked,
            BinaryOp::MulWrapping,
            BinaryOp::DivChecked,
            BinaryOp::RemChecked,
            BinaryOp::BitAnd,
            BinaryOp::BitOr,
            BinaryOp::BitXor,
            BinaryOp::ShiftLeftChecked,
            BinaryOp::ShiftRightChecked,
            BinaryOp::Equal,
            BinaryOp::NotEqual,
            BinaryOp::Less,
            BinaryOp::LessEqual,
            BinaryOp::Greater,
            BinaryOp::GreaterEqual,
            BinaryOp::ShiftLeftWrapping,
        ];
        let casts = [CastMode::Checked, CastMode::Exact, CastMode::Bitcast];
        let accesses = [AccessKind::Read, AccessKind::Mutate, AccessKind::Take];
        let ownership = [
            DmaOwnership::Cpu,
            DmaOwnership::Prepared,
            DmaOwnership::Device,
            DmaOwnership::Completed,
            DmaOwnership::Quarantined,
        ];
        let fences = [
            FenceKind::Acquire,
            FenceKind::Release,
            FenceKind::AcquireRelease,
            FenceKind::DeviceRead,
            FenceKind::DeviceWrite,
            FenceKind::DeviceFull,
        ];
        let failures = [
            FailureKind::Bounds,
            FailureKind::Arithmetic,
            FailureKind::Conversion,
            FailureKind::Capacity,
            FailureKind::Generation,
            FailureKind::DmaState,
            FailureKind::DeviceValue,
            FailureKind::Cancellation,
            FailureKind::Deadline,
            FailureKind::PeerFailure,
            FailureKind::TaskFailure,
            FailureKind::FatalTarget,
        ];
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        for value in unary {
            writer.unary_op(value).expect("unary encodes");
        }
        for value in binary {
            writer.binary_op(value).expect("binary encodes");
        }
        for value in casts {
            writer.cast_mode(value).expect("cast encodes");
        }
        for value in accesses {
            writer.access_kind(value).expect("access encodes");
        }
        for value in ownership {
            writer.dma_ownership(value).expect("ownership encodes");
        }
        for value in fences {
            writer.fence_kind(value).expect("fence encodes");
        }
        for value in failures {
            writer.failure_kind(value).expect("failure encodes");
        }
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        for expected in unary {
            assert_eq!(reader.unary_op().expect("unary decodes"), expected);
        }
        for expected in binary {
            assert_eq!(reader.binary_op().expect("binary decodes"), expected);
        }
        for expected in casts {
            assert_eq!(reader.cast_mode().expect("cast decodes"), expected);
        }
        for expected in accesses {
            assert_eq!(reader.access_kind().expect("access decodes"), expected);
        }
        for expected in ownership {
            assert_eq!(reader.dma_ownership().expect("ownership decodes"), expected);
        }
        for expected in fences {
            assert_eq!(reader.fence_kind().expect("fence decodes"), expected);
        }
        for expected in failures {
            assert_eq!(reader.failure_kind().expect("failure decodes"), expected);
        }
        reader.finish().expect("nested enums consume exactly");
    }

    #[test]
    fn every_role_origin_owner_and_proof_kind_variant_roundtrips() {
        let roles = [
            FunctionRole::Ordinary,
            FunctionRole::ActorTurn(ActorId(1)),
            FunctionRole::TaskEntry(TaskId(2)),
            FunctionRole::Isr(DeviceId(3)),
            FunctionRole::Cleanup,
            FunctionRole::ImageEntry,
            FunctionRole::Test,
        ];
        let origins = [
            FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            FunctionOrigin::GeneratedImageEntry {
                semantic_function: 2,
                constructor: 3,
            },
            FunctionOrigin::GeneratedTestHarness {
                semantic_function: 4,
                group: 5,
            },
            FunctionOrigin::GeneratedAsyncState {
                semantic_function: 6,
                state: 7,
            },
            FunctionOrigin::GeneratedCleanup {
                semantic_function: 8,
                scope: 9,
            },
        ];
        let colors = [
            FunctionColor::Sync,
            FunctionColor::Async,
            FunctionColor::Isr,
        ];
        let owners = [
            PlanOwner::Runtime,
            PlanOwner::Actor(ActorId(1)),
            PlanOwner::Task(TaskId(2)),
            PlanOwner::Device(DeviceId(3)),
            PlanOwner::Pool(PoolId(4)),
            PlanOwner::BakedArtifact(5),
        ];
        let region_classes = [
            RegionClass::Image,
            RegionClass::TaskFrame,
            RegionClass::Call,
            RegionClass::Request,
            RegionClass::Pool(PoolId(6)),
            RegionClass::Static,
        ];
        let proof_kinds = [
            ProofKind::TypeChecked,
            ProofKind::EffectsAllowed,
            ProofKind::DefiniteInitialization,
            ProofKind::Ownership,
            ProofKind::AccessExclusive,
            ProofKind::ViewDoesNotEscape,
            ProofKind::RegionBound,
            ProofKind::CapacityBound,
            ProofKind::WaitGraphAcyclic,
            ProofKind::CleanupAcyclic,
            ProofKind::WorkBound,
            ProofKind::StackBound,
            ProofKind::IsrSafe,
            ProofKind::DmaTransition,
            ProofKind::MmioPartition,
            ProofKind::DeviceValueValidated,
            ProofKind::WireLayout,
            ProofKind::ReceiptLineage,
            ProofKind::ActorAsIf,
            ProofKind::SupervisionComplete,
            ProofKind::ImageClosed,
            ProofKind::FlowControl,
            ProofKind::ValueRange,
            ProofKind::Alignment,
            ProofKind::NoAlias,
        ];
        let test_kinds = [TestKind::Comptime, TestKind::Integration, TestKind::Image];
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        for value in roles {
            writer.function_role(value).expect("role encodes");
        }
        for value in colors {
            writer.function_color(value).expect("color encodes");
        }
        for value in origins {
            writer.function_origin(value).expect("origin encodes");
        }
        for value in owners {
            writer.owner(&value).expect("owner encodes");
        }
        for value in region_classes {
            writer.region_class(value).expect("region class encodes");
        }
        for value in &proof_kinds {
            writer.proof_kind(value).expect("proof kind encodes");
        }
        for value in test_kinds {
            writer.test_kind(value).expect("test kind encodes");
        }
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        for expected in roles {
            assert_eq!(reader.function_role().expect("role decodes"), expected);
        }
        for expected in colors {
            assert_eq!(reader.function_color().expect("color decodes"), expected);
        }
        for expected in origins {
            assert_eq!(reader.function_origin().expect("origin decodes"), expected);
        }
        for expected in owners {
            assert_eq!(reader.owner().expect("owner decodes"), expected);
        }
        for expected in region_classes {
            assert_eq!(
                reader.region_class().expect("region class decodes"),
                expected
            );
        }
        for expected in proof_kinds {
            assert_eq!(reader.proof_kind().expect("proof kind decodes"), expected);
        }
        for expected in test_kinds {
            assert_eq!(reader.test_kind().expect("test kind decodes"), expected);
        }
        reader.finish().expect("enum tables consume exactly");
    }

    #[test]
    fn every_model_record_roundtrips_all_fields() {
        let span = Span {
            file: FileId(4),
            range: TextRange { start: 10, end: 20 },
        };
        let ty = FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: false,
                bits: 64,
            }),
            name: Some("word".to_owned()),
            copyable: true,
            strict_linear: false,
        };
        let global = FlowGlobal {
            id: GlobalId(2),
            name: "global".to_owned(),
            ty: TypeId(1),
            initializer: Immediate::Bytes(vec![1, 2, 3]),
            mutable: true,
            owner: PlanOwner::Actor(ActorId(3)),
        };
        let function = FlowFunction {
            id: FunctionId(4),
            name: "function".to_owned(),
            origin: FunctionOrigin::GeneratedAsyncState {
                semantic_function: 5,
                state: 6,
            },
            role: FunctionRole::TaskEntry(TaskId(7)),
            color: FunctionColor::Async,
            parameters: vec![ValueId(0)],
            result_types: vec![TypeId(1)],
            values: vec![
                Value {
                    id: ValueId(0),
                    ty: TypeId(1),
                    source_name: Some("input".to_owned()),
                    source: Some(span),
                },
                Value {
                    id: ValueId(1),
                    ty: TypeId(1),
                    source_name: None,
                    source: None,
                },
            ],
            blocks: vec![Block {
                id: BlockId(0),
                parameters: vec![ValueId(0)],
                instructions: vec![Instruction {
                    id: InstructionId(0),
                    results: vec![ValueId(1)],
                    operation: FlowOperation::Copy { value: ValueId(0) },
                    source: Some(span),
                }],
                terminator: Terminator::Return(vec![ValueId(1)]),
                source: Some(span),
            }],
            entry: BlockId(0),
            stack_bound: 8,
            frame_bound: 16,
            proofs: vec![ProofId(11)],
            source: Some(span),
        };
        let actor = ActorPlan {
            id: ActorId(3),
            name: "actor".to_owned(),
            state_type: TypeId(1),
            mailbox_capacity: 8,
            message_types: vec![TypeId(1)],
            turn_functions: vec![FunctionId(4)],
            priority: 9,
            supervisor: Some(ActorId(0)),
        };
        let task = TaskPlan {
            id: TaskId(7),
            name: "task".to_owned(),
            entry: FunctionId(4),
            slots: 2,
            priority: 10,
            frame_bytes_bound: 64,
            supervisor: Some(ActorId(3)),
        };
        let device = DevicePlan {
            id: DeviceId(8),
            name: "device".to_owned(),
            target_binding: "uart0".to_owned(),
            owner: ActorId(3),
            queue_capacity: Some(16),
            maximum_in_flight: None,
            required_features: vec!["a".to_owned()],
            optional_features: vec!["b".to_owned()],
            interrupt_functions: vec![FunctionId(4)],
            reset_timeout_ns: 100,
        };
        let pool = PoolPlan {
            id: PoolId(9),
            name: "pool".to_owned(),
            element_type: TypeId(1),
            capacity: 32,
            alignment: 64,
            devices: vec![DeviceId(8)],
        };
        let region = RegionPlan {
            id: RegionId(10),
            name: "region".to_owned(),
            class: RegionClass::TaskFrame,
            capacity_bytes: 1024,
            alignment: 16,
            reset_function: Some(FunctionId(4)),
            owner: PlanOwner::Task(TaskId(7)),
            capacity_proof: ProofId(11),
            source: span,
        };
        let proof = Proof {
            id: ProofId(11),
            kind: ProofKind::CapacityBound,
            subject: "subject".to_owned(),
            sources: vec![span],
            depends_on: vec![ProofId(1), ProofId(2)],
            bound: Some(99),
            explanation: vec!["because".to_owned(), "therefore".to_owned()],
        };
        let checkpoint = Checkpoint {
            id: CheckpointId(12),
            function: FunctionId(4),
            source: span,
            uninterrupted_bound: 77,
            may_observe_cancellation: true,
            may_yield: false,
        };
        let test = TestEntry {
            id: TestId(13),
            plan_id: 29,
            function_key: Sha256Digest::from_bytes([0x29; 32]),
            name: "integration test".to_owned(),
            function: FunctionId(4),
            kind: TestKind::Integration,
            source: span,
            timeout_ns: 123_456_789,
        };

        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer.flow_type(&ty).expect("type record encodes");
        writer.global(&global).expect("global encodes");
        writer.function(&function).expect("function encodes");
        writer.actor(&actor).expect("actor encodes");
        writer.task(&task).expect("task encodes");
        writer.device(&device).expect("device encodes");
        writer.pool(&pool).expect("pool encodes");
        writer.region(&region).expect("region encodes");
        writer.proof(&proof).expect("proof encodes");
        writer.checkpoint(&checkpoint).expect("checkpoint encodes");
        writer.test_entry(&test).expect("test entry encodes");
        let bytes = writer.finish();

        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.flow_type().expect("type record decodes"), ty);
        assert_eq!(reader.global().expect("global decodes"), global);
        assert_eq!(reader.function().expect("function decodes"), function);
        assert_eq!(reader.actor().expect("actor decodes"), actor);
        assert_eq!(reader.task().expect("task decodes"), task);
        assert_eq!(reader.device().expect("device decodes"), device);
        assert_eq!(reader.pool().expect("pool decodes"), pool);
        assert_eq!(reader.region().expect("region decodes"), region);
        assert_eq!(reader.proof().expect("proof decodes"), proof);
        assert_eq!(reader.checkpoint().expect("checkpoint decodes"), checkpoint);
        assert_eq!(reader.test_entry().expect("test entry decodes"), test);
        reader.finish().expect("model records consume exactly");
    }

    #[test]
    fn test_table_codec_rejects_tags_truncation_limits_and_cancellation() {
        let test = fixture().as_wir().tests[0].clone();
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer.test_entry(&test).expect("test entry encodes");
        let bytes = writer.finish();

        let kind_offset = 4 + 4 + 32 + 4 + test.name.len() + 4;
        let mut invalid_kind = bytes.clone();
        invalid_kind[kind_offset] = u8::MAX;
        let mut reader = Reader::new(&invalid_kind, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(
            reader.test_entry(),
            Err(CodecError::InvalidEnumTag {
                kind: "TestKind",
                tag: 255,
            })
        );

        let mut invalid_name_utf8 = bytes.clone();
        invalid_name_utf8[4 + 4 + 32 + 4] = u8::MAX;
        let mut reader = Reader::new(
            &invalid_name_utf8,
            0,
            CodecLimits::standard(),
            &not_cancelled,
        );
        assert_eq!(reader.test_entry(), Err(CodecError::InvalidUtf8));

        let truncated = &bytes[..bytes.len() - 1];
        let mut reader = Reader::new(truncated, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.test_entry(), Err(CodecError::UnexpectedEnd));

        let mut trailing = bytes.clone();
        trailing.push(0);
        let mut reader = Reader::new(&trailing, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.test_entry(), Ok(test.clone()));
        assert_eq!(reader.finish(), Err(CodecError::TrailingBytes));

        let one_test = CodecLimits {
            tests: 1,
            vector_items: u32::MAX,
            ..CodecLimits::standard()
        };
        let mut writer = Writer::new(one_test, &not_cancelled);
        assert!(matches!(
            writer.vector(
                &[test.clone(), test.clone()],
                VectorKind::Tests,
                Writer::test_entry,
            ),
            Err(CodecError::ResourceLimit {
                resource: "tests",
                limit: 1,
                actual: 2,
            })
        ));

        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer
            .vector(
                &[test.clone(), test.clone()],
                VectorKind::Tests,
                Writer::test_entry,
            )
            .expect("two-entry table encodes under the standard policy");
        let table_bytes = writer.finish();
        let mut reader = Reader::new(&table_bytes, 0, one_test, &not_cancelled);
        assert!(matches!(
            reader.vector(VectorKind::Tests, Reader::test_entry),
            Err(CodecError::ResourceLimit {
                resource: "tests",
                limit: 1,
                actual: 2,
            })
        ));

        let polls = Cell::new(0_u32);
        let cancel_during_test = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 2
        };
        let mut writer = Writer::new(CodecLimits::standard(), &cancel_during_test);
        assert_eq!(
            writer.test_entry(&fixture().as_wir().tests[0]),
            Err(CodecError::Cancelled)
        );

        let polls = Cell::new(0_u32);
        let cancel_during_test = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 2
        };
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &cancel_during_test);
        assert_eq!(reader.test_entry(), Err(CodecError::Cancelled));
    }

    #[test]
    fn corrupt_headers_payloads_and_identity_fail_closed() {
        let model = fixture();
        let codec = CanonicalFlowWirCodec;
        let encoded = codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            )
            .expect("frame");

        let mut bad_magic = encoded.bytes.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            codec.inspect_header(&bad_magic, &|| false),
            Err(CodecError::InvalidMagic)
        );

        let mut bad_wire = encoded.bytes.clone();
        bad_wire[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            codec.inspect_header(&bad_wire, &|| false),
            Err(CodecError::UnsupportedWireVersion(u32::MAX))
        );

        for stale in [11_u32, 12] {
            let mut stale_wire = encoded.bytes.clone();
            stale_wire[8..12].copy_from_slice(&stale.to_le_bytes());
            assert_eq!(
                codec.inspect_header(&stale_wire, &|| false),
                Err(CodecError::UnsupportedWireVersion(stale))
            );

            let mut stale_header_flow = encoded.bytes.clone();
            stale_header_flow[12..16].copy_from_slice(&stale.to_le_bytes());
            assert_eq!(
                codec.inspect_header(&stale_header_flow, &|| false),
                Err(CodecError::UnsupportedFlowWirVersion(stale))
            );
        }

        let mut trailing = encoded.bytes.clone();
        trailing.push(0);
        assert_eq!(
            codec.inspect_header(&trailing, &|| false),
            Err(CodecError::TrailingBytes)
        );

        let payload_bytes = encoded.header.payload_bytes;
        let mut short_length = encoded.bytes.clone();
        short_length[16..24].copy_from_slice(&(payload_bytes - 1).to_le_bytes());
        assert_eq!(
            codec.inspect_header(&short_length, &|| false),
            Err(CodecError::TrailingBytes)
        );
        let mut long_length = encoded.bytes.clone();
        long_length[16..24].copy_from_slice(&(payload_bytes + 1).to_le_bytes());
        assert_eq!(
            codec.inspect_header(&long_length, &|| false),
            Err(CodecError::UnexpectedEnd)
        );
        let mut truncated = encoded.bytes.clone();
        truncated.pop();
        assert_eq!(
            codec.inspect_header(&truncated, &|| false),
            Err(CodecError::UnexpectedEnd)
        );

        let mut invalid_header_utf8 = encoded.bytes.clone();
        invalid_header_utf8[61] = u8::MAX;
        assert_eq!(
            codec.inspect_header(&invalid_header_utf8, &|| false),
            Err(CodecError::InvalidUtf8)
        );

        let mut stale_build = encoded.bytes.clone();
        stale_build[24] ^= 1;
        assert_eq!(
            codec.decode(
                DecodeRequest {
                    bytes: &stale_build,
                    limits: CodecLimits::standard(),
                    expected_build: Some(&model.as_wir().build),
                },
                &|| false,
            ),
            Err(CodecError::BuildIdentityMismatch)
        );

        let parsed = parse_header(&encoded.bytes, &|| false).expect("parsed header");
        for stale in [11_u32, 12] {
            let mut stale_payload_flow = encoded.bytes.clone();
            stale_payload_flow[parsed.payload_start..parsed.payload_start + 4]
                .copy_from_slice(&stale.to_le_bytes());
            assert_eq!(
                codec.decode(
                    DecodeRequest {
                        bytes: &stale_payload_flow,
                        limits: CodecLimits::standard(),
                        expected_build: None,
                    },
                    &|| false,
                ),
                Err(CodecError::UnsupportedFlowWirVersion(stale))
            );
        }
        let semantic_version_offset = parsed.payload_start + 4 + 4 + "canonical-image".len();
        let mut stale_semantic_provenance = encoded.bytes.clone();
        stale_semantic_provenance[semantic_version_offset..semantic_version_offset + 4]
            .copy_from_slice(&10_u32.to_le_bytes());
        assert!(matches!(
            codec.decode(
                DecodeRequest {
                    bytes: &stale_semantic_provenance,
                    limits: CodecLimits::standard(),
                    expected_build: None,
                },
                &|| false,
            ),
            Err(CodecError::InvalidFlowWir(_))
        ));
        let mut invalid_payload_utf8 = encoded.bytes.clone();
        invalid_payload_utf8[parsed.payload_start + 8] = u8::MAX;
        assert_eq!(
            codec.decode(
                DecodeRequest {
                    bytes: &invalid_payload_utf8,
                    limits: CodecLimits::standard(),
                    expected_build: None,
                },
                &|| false,
            ),
            Err(CodecError::InvalidUtf8)
        );
        let type_id_offset = parsed.payload_start + 4 + 4 + "canonical-image".len() + 40 + 4;
        let mut invalid_model = encoded.bytes.clone();
        invalid_model[type_id_offset..type_id_offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            codec.decode(
                DecodeRequest {
                    bytes: &invalid_model,
                    limits: CodecLimits::standard(),
                    expected_build: Some(&model.as_wir().build),
                },
                &|| false,
            ),
            Err(CodecError::InvalidFlowWir(_))
        ));

        let mut invalid_tag = encoded.bytes.clone();
        invalid_tag[type_id_offset + 4] = u8::MAX;
        assert_eq!(
            codec.decode(
                DecodeRequest {
                    bytes: &invalid_tag,
                    limits: CodecLimits::standard(),
                    expected_build: None,
                },
                &|| false,
            ),
            Err(CodecError::InvalidEnumTag {
                kind: "FlowTypeKind",
                tag: 255
            })
        );
    }

    #[test]
    fn long_v8_payload_encode_and_decode_cancel_at_exact_copy_chunks() {
        let model = long_prefix_fixture();
        let codec = CanonicalFlowWirCodec;

        // Poll 53 precedes the third 64-KiB image-name copy chunk after the
        // fixed v8 header and the name's length prefix.
        let encode_polls = Cell::new(0_u32);
        let cancel_encode = || {
            let next = encode_polls.get() + 1;
            encode_polls.set(next);
            next == 53
        };
        assert!(matches!(
            codec.encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &cancel_encode,
            ),
            Err(CodecError::Cancelled)
        ));
        assert_eq!(encode_polls.get(), 53);

        let encoded = codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            )
            .expect("long canonical v8 frame");

        // Header parsing consumes polls 1..=17; poll 22 precedes the third
        // bounded image-name copy chunk in the model reader.
        let decode_polls = Cell::new(0_u32);
        let cancel_decode = || {
            let next = decode_polls.get() + 1;
            decode_polls.set(next);
            next == 22
        };
        assert_eq!(
            codec.decode(
                DecodeRequest {
                    bytes: &encoded.bytes,
                    limits: CodecLimits::standard(),
                    expected_build: None,
                },
                &cancel_decode,
            ),
            Err(CodecError::Cancelled)
        );
        assert_eq!(decode_polls.get(), 22);
    }

    #[test]
    fn canonical_frame_compare_polls_late_and_rejects_last_byte_substitution() {
        let model = long_prefix_fixture();
        let codec = CanonicalFlowWirCodec;
        let encoded = codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            )
            .expect("long canonical frame");
        assert!(encoded.bytes.len() > CANCELLABLE_CODEC_CHUNK_BYTES * 4);

        let all_polls = Cell::new(0_u32);
        decode_and_verify(
            &codec,
            DecodeRequest {
                bytes: &encoded.bytes,
                limits: CodecLimits::standard(),
                expected_build: Some(&model.as_wir().build),
            },
            &|| {
                all_polls.set(all_polls.get() + 1);
                false
            },
        )
        .expect("uncancelled canonical comparison");
        let cancel_at = all_polls.get() - 2;
        let late_polls = Cell::new(0_u32);
        assert_eq!(
            decode_and_verify(
                &codec,
                DecodeRequest {
                    bytes: &encoded.bytes,
                    limits: CodecLimits::standard(),
                    expected_build: Some(&model.as_wir().build),
                },
                &|| {
                    let next = late_polls.get() + 1;
                    late_polls.set(next);
                    next == cancel_at
                },
            ),
            Err(CodecError::Cancelled)
        );
        assert_eq!(late_polls.get(), cancel_at);

        let mut substituted = encoded.bytes;
        *substituted.last_mut().expect("canonical frame is nonempty") ^= 1;
        let repeated = codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            )
            .expect("repeat canonical frame");
        let compare_polls = Cell::new(0_u32);
        assert!(
            !crate::bytes_equal(&substituted, &repeated.bytes, &|| {
                compare_polls.set(compare_polls.get() + 1);
                false
            })
            .expect("bounded frame comparison")
        );
        let expected_compare_polls =
            u32::try_from(substituted.len().div_ceil(CANCELLABLE_CODEC_CHUNK_BYTES) + 1)
                .expect("fixture chunk count fits u32");
        assert_eq!(compare_polls.get(), expected_compare_polls);
    }

    #[test]
    fn sealed_encode_cancellation_has_an_exact_late_stop_and_no_candidate() {
        let model = long_prefix_fixture();
        let codec = CanonicalFlowWirCodec;
        let all_polls = Cell::new(0_u32);
        encode_and_verify(
            &codec,
            EncodeRequest {
                wir: &model,
                limits: CodecLimits::standard(),
            },
            &|| {
                all_polls.set(all_polls.get() + 1);
                false
            },
        )
        .expect("uncancelled sealed encode");

        // The final poll follows the last canonical-frame comparison. Two
        // checkpoints earlier is therefore still inside its last byte chunk.
        let cancel_at = all_polls.get() - 2;
        let late_polls = Cell::new(0_u32);
        let result = encode_and_verify(
            &codec,
            EncodeRequest {
                wir: &model,
                limits: CodecLimits::standard(),
            },
            &|| {
                let next = late_polls.get() + 1;
                late_polls.set(next);
                next == cancel_at
            },
        );
        assert!(matches!(result, Err(CodecError::Cancelled)));
        assert_eq!(late_polls.get(), cancel_at);
    }

    #[test]
    fn source_model_identity_rejects_a_canonical_last_byte_substitution() {
        let original = long_prefix_fixture();
        let mut substituted = original.clone().into_wir();
        substituted.peak_bytes |= 1_u64 << 56;
        let substituted = substituted
            .validate()
            .expect("last-byte-substituted model remains valid");
        let codec = SubstitutingCodec {
            model: &substituted,
        };
        assert!(matches!(
            encode_and_verify(
                &codec,
                EncodeRequest {
                    wir: &original,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            ),
            Err(CodecError::NonCanonical(
                "codec output differs from the canonical FlowWir v13 encoding"
            ))
        ));
    }

    #[test]
    fn repeated_canonical_encode_rejects_last_byte_nondeterminism() {
        let model = long_prefix_fixture();
        let codec = NondeterministicCodec {
            encode_calls: Cell::new(0),
        };
        assert!(matches!(
            encode_and_verify(
                &codec,
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            ),
            Err(CodecError::NonCanonical(
                "FlowWir encoder is nondeterministic"
            ))
        ));
        assert_eq!(codec.encode_calls.get(), 2);
    }

    #[test]
    fn real_v8_payload_and_frame_limits_accept_exact_and_reject_one_under() {
        let model = long_prefix_fixture();
        let codec = CanonicalFlowWirCodec;
        let not_cancelled = || false;

        let mut measured = Writer::new(CodecLimits::standard(), &not_cancelled);
        measured
            .build_identity(&model.as_wir().build)
            .expect("header identity measures");
        measured
            .flow_wir(model.as_wir())
            .expect("model strings measure");
        let exact_string_bytes =
            u32::try_from(measured.meter.string_bytes).expect("fixture string payload fits u32");
        let exact_strings = CodecLimits {
            string_bytes: exact_string_bytes,
            ..CodecLimits::standard()
        };
        codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: exact_strings,
                },
                &not_cancelled,
            )
            .expect("exact aggregate string payload is accepted");
        let one_under_strings = CodecLimits {
            string_bytes: exact_string_bytes - 1,
            ..CodecLimits::standard()
        };
        assert!(matches!(
            codec.encode(
                EncodeRequest {
                    wir: &model,
                    limits: one_under_strings,
                },
                &not_cancelled,
            ),
            Err(CodecError::ResourceLimit {
                resource: "aggregate string bytes",
                limit,
                actual,
            }) if limit == u64::from(exact_string_bytes - 1)
                && actual == u64::from(exact_string_bytes)
        ));

        let encoded = codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &not_cancelled,
            )
            .expect("measure exact frame");
        let exact_frame_bytes = u64::try_from(encoded.bytes.len()).expect("frame length fits u64");
        let exact_frame = CodecLimits {
            frame_bytes: exact_frame_bytes,
            ..CodecLimits::standard()
        };
        codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: exact_frame,
                },
                &not_cancelled,
            )
            .expect("exact frame limit is accepted");
        let one_under_frame = CodecLimits {
            frame_bytes: exact_frame_bytes - 1,
            ..CodecLimits::standard()
        };
        assert!(matches!(
            codec.encode(
                EncodeRequest {
                    wir: &model,
                    limits: one_under_frame,
                },
                &not_cancelled,
            ),
            Err(CodecError::ResourceLimit {
                resource: "FlowWir frame bytes",
                limit,
                actual,
            }) if limit == exact_frame_bytes - 1 && actual == exact_frame_bytes
        ));
    }

    #[test]
    fn utf8_copy_preserves_a_scalar_split_across_chunk_boundary() {
        let value = "a".repeat(CANCELLABLE_CODEC_CHUNK_BYTES - 1) + "🦀" + "tail";
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer.string(&value).expect("split UTF-8 string encodes");
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.string().expect("split UTF-8 string decodes"), value);
        reader.finish().expect("string consumes its exact bytes");

        let mut invalid = bytes;
        *invalid.last_mut().expect("encoded string has bytes") = u8::MAX;
        let mut reader = Reader::new(&invalid, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.string(), Err(CodecError::InvalidUtf8));
    }

    #[test]
    fn immediate_byte_copy_polls_exact_chunks_and_obeys_exact_item_bound() {
        let value = vec![0x5a; CANCELLABLE_CODEC_CHUNK_BYTES * 3 + 1];
        let exact_items = u32::try_from(value.len()).expect("fixture length fits u32");
        let exact = CodecLimits {
            vector_items: exact_items,
            ..CodecLimits::standard()
        };
        let not_cancelled = || false;
        let mut writer = Writer::new(exact, &not_cancelled);
        writer.bytes(&value).expect("exact byte-item bound");
        let encoded = writer.finish();

        let mut under_writer = Writer::new(
            CodecLimits {
                vector_items: exact_items - 1,
                ..CodecLimits::standard()
            },
            &not_cancelled,
        );
        assert!(matches!(
            under_writer.bytes(&value),
            Err(CodecError::ResourceLimit {
                resource: "aggregate vector items",
                limit,
                actual,
            }) if limit == u64::from(exact_items - 1) && actual == u64::from(exact_items)
        ));

        let polls = Cell::new(0_u32);
        let cancel_on_third_copy_chunk = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 5
        };
        let mut reader = Reader::new(
            &encoded,
            0,
            CodecLimits::standard(),
            &cancel_on_third_copy_chunk,
        );
        assert_eq!(reader.bytes(), Err(CodecError::Cancelled));
        assert_eq!(polls.get(), 5);

        let mut reader = Reader::new(&encoded, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.bytes().expect("long bytes decode"), value);
        reader.finish().expect("bytes consume exact encoding");
    }

    #[test]
    fn limits_and_mid_operation_cancellation_are_enforced() {
        let model = fixture();
        let codec = CanonicalFlowWirCodec;
        let tiny_strings = CodecLimits {
            string_bytes: 1,
            ..CodecLimits::standard()
        };
        assert!(matches!(
            codec.encode(
                EncodeRequest {
                    wir: &model,
                    limits: tiny_strings
                },
                &|| false
            ),
            Err(CodecError::ResourceLimit {
                resource: "aggregate string bytes",
                ..
            })
        ));
        let tiny_vectors = CodecLimits {
            vector_items: 1,
            ..CodecLimits::standard()
        };
        assert!(matches!(
            codec.encode(
                EncodeRequest {
                    wir: &model,
                    limits: tiny_vectors
                },
                &|| false
            ),
            Err(CodecError::ResourceLimit {
                resource: "aggregate vector items",
                ..
            })
        ));

        let frame = codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            )
            .expect("bounded frame");
        let exact_frame_bytes = u64::try_from(frame.bytes.len()).expect("frame length fits");
        let exact_frame = CodecLimits {
            frame_bytes: exact_frame_bytes,
            ..CodecLimits::standard()
        };
        codec
            .decode(
                DecodeRequest {
                    bytes: &frame.bytes,
                    limits: exact_frame,
                    expected_build: None,
                },
                &|| false,
            )
            .expect("exact frame-byte limit is accepted");
        let validation_limited = CodecLimits {
            validation_work: 1,
            ..CodecLimits::standard()
        };
        assert!(matches!(
            codec.decode(
                DecodeRequest {
                    bytes: &frame.bytes,
                    limits: validation_limited,
                    expected_build: None,
                },
                &|| false,
            ),
            Err(CodecError::ValidationResourceLimit {
                resource: "validation work",
                limit: 1,
            })
        ));
        let too_small_frame = CodecLimits {
            frame_bytes: exact_frame_bytes - 1,
            ..CodecLimits::standard()
        };
        assert!(matches!(
            codec.decode(
                DecodeRequest {
                    bytes: &frame.bytes,
                    limits: too_small_frame,
                    expected_build: None,
                },
                &|| false,
            ),
            Err(CodecError::ResourceLimit {
                resource: "FlowWir frame bytes",
                ..
            })
        ));

        let not_cancelled = || false;
        for (kind, limits, resource) in [
            (
                VectorKind::Functions,
                CodecLimits {
                    functions: 1,
                    ..CodecLimits::standard()
                },
                "functions",
            ),
            (
                VectorKind::Blocks,
                CodecLimits {
                    blocks: 1,
                    ..CodecLimits::standard()
                },
                "blocks",
            ),
            (
                VectorKind::Instructions,
                CodecLimits {
                    instructions: 1,
                    ..CodecLimits::standard()
                },
                "instructions",
            ),
        ] {
            let mut writer = Writer::new(limits, &not_cancelled);
            assert!(matches!(
                writer.vector(&[0_u8, 1], kind, |writer, value| writer.u8(*value)),
                Err(CodecError::ResourceLimit { resource: actual, .. }) if actual == resource
            ));
        }

        let nesting_one = CodecLimits {
            nesting_depth: 1,
            ..CodecLimits::standard()
        };
        let mut writer = Writer::new(nesting_one, &not_cancelled);
        assert!(matches!(
            writer.type_kind(&FlowTypeKind::Enum {
                variants: vec![vec![TypeId(0)]],
            }),
            Err(CodecError::ResourceLimit {
                resource: "nesting depth",
                ..
            })
        ));

        let exact_string = CodecLimits {
            string_bytes: 3,
            ..CodecLimits::standard()
        };
        let mut writer = Writer::new(exact_string, &not_cancelled);
        writer
            .string("abc")
            .expect("exact string limit is accepted");
        assert!(matches!(
            writer.string("d"),
            Err(CodecError::ResourceLimit {
                resource: "aggregate string bytes",
                ..
            })
        ));

        let polls = Cell::new(0_u32);
        let cancel_during_encode = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 6
        };
        assert!(matches!(
            codec.encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard()
                },
                &cancel_during_encode,
            ),
            Err(CodecError::Cancelled)
        ));

        let bytes = codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            )
            .expect("frame")
            .bytes;
        let polls = Cell::new(0_u32);
        let cancel_during_decode = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 6
        };
        assert_eq!(
            codec.decode(
                DecodeRequest {
                    bytes: &bytes,
                    limits: CodecLimits::standard(),
                    expected_build: None
                },
                &cancel_during_decode,
            ),
            Err(CodecError::Cancelled)
        );

        let polls = Cell::new(0_u32);
        codec
            .decode(
                DecodeRequest {
                    bytes: &bytes,
                    limits: CodecLimits::standard(),
                    expected_build: None,
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("uncancelled decode establishes deterministic poll count");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u32);
        assert_eq!(
            codec.decode(
                DecodeRequest {
                    bytes: &bytes,
                    limits: CodecLimits::standard(),
                    expected_build: None,
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next == cancel_at
                },
            ),
            Err(CodecError::Cancelled)
        );
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn wrapping_left_shift_uses_appended_binary_tag_and_rejects_the_next_tag() {
        let not_cancelled = || false;
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer
            .binary_op(BinaryOp::ShiftLeftWrapping)
            .expect("wrapping left shift encodes");
        let bytes = writer.finish();
        assert_eq!(bytes, [19]);

        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.binary_op(), Ok(BinaryOp::ShiftLeftWrapping));
        reader.finish().expect("binary tag consumes exactly");

        let mut reader = Reader::new(&[20], 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(
            reader.binary_op(),
            Err(CodecError::InvalidEnumTag {
                kind: "BinaryOp",
                tag: 20,
            })
        );
    }

    #[test]
    fn closed_enum_operations_use_appended_tags_and_reject_the_next_tag() {
        let not_cancelled = || false;
        let operations = [
            FlowOperation::MakeEnum {
                ty: TypeId(3),
                variant: 4,
                payload: Some(ValueId(5)),
            },
            FlowOperation::EnumTag { value: ValueId(5) },
            FlowOperation::EnumPayload { value: ValueId(5) },
        ];
        for (operation, expected_tag) in operations.iter().zip([49_u8, 50, 51]) {
            let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
            writer
                .operation(operation)
                .expect("closed enum operation encodes");
            let bytes = writer.finish();
            assert_eq!(bytes[0], expected_tag);
            let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
            assert_eq!(reader.operation(), Ok(operation.clone()));
            reader
                .finish()
                .expect("closed enum operation consumes exactly");
        }

        let operation = FlowOperation::Promote {
            value: ValueId(5),
            destination: RegionId(3),
            proof: ProofId(7),
        };
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer
            .operation(&operation)
            .expect("promotion operation encodes");
        let bytes = writer.finish();
        assert_eq!(bytes[0], 54);
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.operation(), Ok(operation));
        reader
            .finish()
            .expect("promotion operation consumes exactly");

        let mut reader = Reader::new(&[55], 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(
            reader.operation(),
            Err(CodecError::InvalidEnumTag {
                kind: "FlowOperation",
                tag: 55,
            })
        );
    }

    #[test]
    fn actor_state_address_uses_appended_tag_and_roundtrips_authority() {
        let not_cancelled = || false;
        let operation = FlowOperation::ActorStateAddress {
            actor: ActorId(2),
            region: RegionId(3),
            proof: ProofId(5),
        };
        let mut writer = Writer::new(CodecLimits::standard(), &not_cancelled);
        writer
            .operation(&operation)
            .expect("actor state address encodes");
        let bytes = writer.finish();
        assert_eq!(bytes[0], 53);
        let mut reader = Reader::new(&bytes, 0, CodecLimits::standard(), &not_cancelled);
        assert_eq!(reader.operation(), Ok(operation));
        reader
            .finish()
            .expect("actor state address consumes exactly");
    }
}
