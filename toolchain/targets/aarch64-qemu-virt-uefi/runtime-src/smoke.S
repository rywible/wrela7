/* Genuine UEFI/QEMU consumer for the target runtime.  This is never linked
 * into production images; smoke_runtime.py builds it in a private directory.
 */
    .text
    .p2align 4
    .globl wrela_image_entry
wrela_image_entry:
    sub     sp, sp, #32
    stp     x29, x30, [sp, #0]
    stp     x19, x20, [sp, #16]
    mov     x29, sp
    mov     x19, x0
    mov     x20, x1
    bl      wrela_rt_v2_image_enter
    cbnz    x0, .Lfailed

    bl      wrela_rt_v2_interrupt_mask
    bl      wrela_rt_v2_interrupt_restore
    bl      wrela_rt_v2_cpu_idle

    adrp    x0, .Lcache_probe
    add     x0, x0, :lo12:.Lcache_probe
    mov     x1, #64
    mov     w2, #0
    bl      wrela_rt_v2_cache_maintain

    mov     w0, #0x1234
    adrp    x1, .Lrecord_payload
    add     x1, x1, :lo12:.Lrecord_payload
    mov     x2, #5
    bl      wrela_rt_v2_record_event
    cbnz    x0, .Lfailed
    mov     w0, #0x1234
    adrp    x1, .Lreplay_payload
    add     x1, x1, :lo12:.Lreplay_payload
    mov     x2, #5
    bl      wrela_rt_v2_replay_event
    cmp     x0, #5
    b.ne    .Lfailed
    adrp    x8, .Lrecord_payload
    add     x8, x8, :lo12:.Lrecord_payload
    adrp    x9, .Lreplay_payload
    add     x9, x9, :lo12:.Lreplay_payload
    ldr     w10, [x8]
    ldr     w11, [x9]
    cmp     w10, w11
    b.ne    .Lfailed
    ldrb    w10, [x8, #4]
    ldrb    w11, [x9, #4]
    cmp     w10, w11
    b.ne    .Lfailed

    /* A record after the implicit first-replay freeze must fail closed. */
    mov     w0, #0x1234
    adrp    x1, .Lrecord_payload
    add     x1, x1, :lo12:.Lrecord_payload
    mov     x2, #5
    bl      wrela_rt_v2_record_event
    mov     x8, #15                  /* EFI_ACCESS_DENIED */
    movk    x8, #0x8000, lsl #48
    cmp     x0, x8
    b.ne    .Lfailed

    /* Corrupt input is rejected before the first UART delimiter is emitted. */
    adrp    x0, .Lbad_frame
    add     x0, x0, :lo12:.Lbad_frame
    mov     x1, #32
    bl      wrela_rt_v2_test_emit
    mov     x8, #33                  /* EFI_COMPROMISED_DATA */
    movk    x8, #0x8000, lsl #48
    cmp     x0, x8
    b.ne    .Lfailed

    /* A CRC-valid, structurally valid log containing only Unicode White_Space
     * is noncanonical under the shared host/guest codec.
     */
    adrp    x0, .Lwhitespace_frame
    add     x0, x0, :lo12:.Lwhitespace_frame
    mov     x1, #54
    bl      wrela_rt_v2_test_emit
    mov     x8, #33
    movk    x8, #0x8000, lsl #48
    cmp     x0, x8
    b.ne    .Lfailed

    adrp    x0, .Lrun_started_frame
    add     x0, x0, :lo12:.Lrun_started_frame
    mov     x1, #49
    bl      wrela_rt_v2_test_emit
    cbnz    x0, .Lfailed
    adrp    x0, .Ltest_started_frame
    add     x0, x0, :lo12:.Ltest_started_frame
    mov     x1, #49
    bl      wrela_rt_v2_test_emit
    cbnz    x0, .Lfailed

    /* Machine/codegen preserve the exact Flow function/instruction site in
     * detail while the distinct stable code selects the typed result-loss
     * outcome. The runtime emits TestFinished and RunFinished and resets.
     */
    mov     w0, #5
    mov     x1, #0x5678
    movk    x1, #0x1234, lsl #32
    b       wrela_rt_v2_fatal

.Lfailed:
    /* Returning a failure lets firmware report it; the smoke runner also
     * requires ResetSystem to terminate QEMU, so even a zero-valued comparison
     * accident cannot become a false pass.
     */
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp, #0]
    add     sp, sp, #32
    ret

/* Link-only ABI2 assertion edge. The passing smoke lifecycle never executes
 * this local block; it proves the compiler-only noreturn symbol resolves from
 * the same enrolled runtime object without fabricating an assertion outcome.
 */
    .p2align 2
.Lassertion_symbol_contract:
    b       wrela_rt_v2_test_assertion_fail

    .section .rdata,"dr"
    .p2align 3
.Lrun_started_frame:
    /* Canonical v1/v3 RunStarted(seq=0, test_count=1). */
    .byte 0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00
    .byte 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .byte 0x11, 0x00, 0x00, 0x00, 0xb0, 0x6d, 0x85, 0xe7
    .byte 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
.Ltest_started_frame:
    /* Canonical TestStarted(seq=1, test=0x0000dbc0). The active test ID
     * deliberately exercises both SLIP escape code points.
     */
    .byte 0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00
    .byte 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00
    .byte 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .byte 0x11, 0x00, 0x00, 0x00, 0xbf, 0x72, 0x9a, 0x25
    .byte 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
    .byte 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xdb, 0x00, 0x00
.Lrecord_payload:
    .byte 0x00, 0xc0, 0xdb, 0x7f, 0xff
.Lbad_frame:
    .zero 32
.Lwhitespace_frame:
    .byte 0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00
    .byte 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .byte 0x16, 0x00, 0x00, 0x00, 0x28, 0x46, 0x6e, 0x51
    .byte 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .byte 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x03
    .byte 0x00, 0x00, 0x00, 0xe3, 0x80, 0x80

    .section .bss,"bw"
    .p2align 6
.Lcache_probe:
    .zero 64
.Lreplay_payload:
    .zero 8
