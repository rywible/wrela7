/*
 * Wrela target runtime ABI v2 for aarch64-qemu-virt-uefi.
 *
 * This is freestanding AArch64 assembly.  It has no C runtime, stack protector,
 * allocator, default library, firmware import, or undefined symbol.  The only
 * mutable storage is the fixed-size state below.  All public entry points use
 * the AAPCS64 scalar calling convention selected by aarch64-unknown-uefi.
 *
 * Record/replay wire format (little endian):
 *
 *     u32 kind, u32 payload_bytes, u8 payload[payload_bytes]
 *
 * The 64 KiB log always reserves eight bytes for the explicit overflow marker
 * (kind 0xffffffff, length zero).  Record mode is the reset state.  The first
 * replay call atomically freezes the write extent and starts at offset zero.
 * A record after that transition returns EFI_ACCESS_DENIED.  Replay mismatch,
 * truncation, overflow marker, or invalid destination is target-fatal because
 * the ABI has no diagnostic result channel and continuing would diverge.
 *
 * Test frames are the complete unescaped CanonicalTestEventCodec frames.  The
 * runtime independently checks the fixed header, dense sequence, payload/event
 * identity, CRC32C, exact canonical tagged shape, UTF-8, and terminal state.
 * Valid frames are transported over the first non-secure QEMU virt PL011 at
 * 0x09000000 using RFC 1055 SLIP framing: END (c0) brackets every frame, END in
 * data becomes db dc, and ESC (db) becomes db dd.  UART polling and every
 * input-derived loop have fixed bounds.  A timed-out transmission deliberately
 * omits the closing END, so a host decoder cannot accept a partial frame.
 */

    .text
    .p2align 4

    /* EFI status values used at this closed boundary. */
    .equ WRELA_EFI_ERROR_TOP,       0x8000
    .equ WRELA_EFI_INVALID_PARAMETER, 2
    .equ WRELA_EFI_BAD_BUFFER_SIZE, 4
    .equ WRELA_EFI_OUT_OF_RESOURCES, 9
    .equ WRELA_EFI_ACCESS_DENIED,  15
    .equ WRELA_EFI_ABORTED,        21
    .equ WRELA_EFI_COMPROMISED_DATA, 33
    .equ WRELA_EFI_TIMEOUT,        18

    .equ WRELA_RUNTIME_COLD,       0
    .equ WRELA_RUNTIME_ENTERED,    1
    .equ WRELA_RUNTIME_EXITING,    2
    .equ WRELA_RUNTIME_FATAL,      3

    .equ WRELA_LOG_RECORD,         0
    .equ WRELA_LOG_REPLAY,         1
    .equ WRELA_LOG_OVERFLOWED,     2
    .equ WRELA_LOG_BYTES,          65536
    .equ WRELA_LOG_RECORD_LIMIT,   65528

    .equ WRELA_TEST_FRAME_MIN,     32
    .equ WRELA_TEST_FRAME_MAX,     1048576
    .equ WRELA_TEST_STRING_MAX,    262144
    .equ WRELA_TEST_FRAME_VERSION, 1
    .equ WRELA_TEST_EVENT_VERSION, 3
    .equ WRELA_TEST_EVENT_LIMIT,   1000000

    /* Stable RuntimeFatalCode values after the existing ABI-v2 classes. */
    .equ WRELA_FATAL_CHECKED_SHIFT_RESULT_LOSS, 5
    .equ WRELA_FATAL_INVALID_SHIFT_COUNT, 6
    .equ WRELA_LANGUAGE_FATAL_RESULT_LOSS, 0
    .equ WRELA_LANGUAGE_FATAL_INVALID_COUNT, 1
    .equ WRELA_FATAL_FRAME_BUFFER_BYTES, 64
    .equ WRELA_FATAL_TEST_FINISHED_PAYLOAD_BYTES, 19
    .equ WRELA_FATAL_RUN_FINISHED_PAYLOAD_BYTES, 21
    .equ WRELA_ASSERT_TEXT_MAX,       4096
    .equ WRELA_ASSERT_FRAME_BYTES,    8320
    .equ WRELA_ASSERT_DEFAULT_BYTES,  16

    .equ WRELA_PL011_BASE,         0x09000000
    .equ WRELA_PL011_DR,           0x00
    .equ WRELA_PL011_FR,           0x18
    .equ WRELA_PL011_TXFF_BIT,     5
    .equ WRELA_PL011_POLLS,        1000000
    .equ WRELA_SLIP_END,           0xc0
    .equ WRELA_SLIP_ESC,           0xdb
    .equ WRELA_SLIP_ESC_END,       0xdc
    .equ WRELA_SLIP_ESC_ESC,       0xdd

    .macro WRELA_ADDR reg, symbol
        adrp    \reg, \symbol
        add     \reg, \reg, :lo12:\symbol
    .endm

    .macro WRELA_EFI_ERROR reg, code
        mov     \reg, #\code
        movk    \reg, #WRELA_EFI_ERROR_TOP, lsl #48
    .endm

/* EFI_STATUS wrela_rt_v2_image_enter(void *image, void *system_table) */
    .globl wrela_rt_v2_image_enter
    .p2align 4
wrela_rt_v2_image_enter:
    cbz     x0, .Limage_enter_invalid
    cbz     x1, .Limage_enter_invalid
    tst     x0, #7
    b.ne    .Limage_enter_invalid
    tst     x1, #7
    b.ne    .Limage_enter_invalid

    /* EFI_SYSTEM_TABLE_SIGNATURE = 0x5453595320494249. */
    ldr     x2, [x1]
    movz    x3, #0x4249
    movk    x3, #0x2049, lsl #16
    movk    x3, #0x5953, lsl #32
    movk    x3, #0x5453, lsl #48
    cmp     x2, x3
    b.ne    .Limage_enter_invalid
    ldr     w2, [x1, #12]            /* EFI_TABLE_HEADER.HeaderSize */
    cmp     w2, #120
    b.lo    .Limage_enter_invalid

    WRELA_ADDR x2, .Lruntime_state
    ldar    w3, [x2]
    cbnz    w3, .Limage_enter_invalid
    WRELA_ADDR x4, .Limage_handle
    str     x0, [x4]
    WRELA_ADDR x4, .Lsystem_table
    str     x1, [x4]
    WRELA_ADDR x4, .Lrecord_write
    str     xzr, [x4]
    WRELA_ADDR x4, .Lrecord_read
    str     xzr, [x4]
    WRELA_ADDR x4, .Lrecord_mode
    str     wzr, [x4]
    WRELA_ADDR x4, .Ltest_sequence
    str     xzr, [x4]
    WRELA_ADDR x4, .Ltest_terminal
    str     wzr, [x4]
    WRELA_ADDR x4, .Ltest_terminal_passed
    str     wzr, [x4]
    WRELA_ADDR x4, .Ltest_terminal_failed
    str     wzr, [x4]
    WRELA_ADDR x4, .Ltest_active
    str     wzr, [x4]
    WRELA_ADDR x4, .Ltest_active_id
    str     wzr, [x4]
    WRELA_ADDR x4, .Ltest_declared_count
    str     wzr, [x4]
    WRELA_ADDR x4, .Ltest_started_count
    str     wzr, [x4]
    WRELA_ADDR x4, .Ltest_completed_passed
    str     wzr, [x4]
    dmb     ish
    mov     w3, #WRELA_RUNTIME_ENTERED
    stlr    w3, [x2]
    mov     x0, xzr
    ret
.Limage_enter_invalid:
    WRELA_EFI_ERROR x0, WRELA_EFI_INVALID_PARAMETER
    ret

/* noreturn void wrela_rt_v2_image_exit(EFI_STATUS status) */
    .globl wrela_rt_v2_image_exit
    .p2align 4
wrela_rt_v2_image_exit:
    mov     x8, x0
    msr     daifset, #0xf
    isb
    WRELA_ADDR x9, .Lruntime_state
    ldar    w10, [x9]
    cmp     w10, #WRELA_RUNTIME_ENTERED
    b.ne    .Limage_exit_bad_state
    mov     w10, #WRELA_RUNTIME_EXITING
    stlr    w10, [x9]

    /* ResetSystem(EfiResetShutdown, status, 0, NULL) remains callable post-EBS. */
    WRELA_ADDR x9, .Lsystem_table
    ldr     x9, [x9]
    cbz     x9, .Limage_exit_bad_state
    ldr     x9, [x9, #88]            /* EFI_SYSTEM_TABLE.RuntimeServices */
    cbz     x9, .Limage_exit_bad_state
    ldr     x9, [x9, #104]           /* EFI_RUNTIME_SERVICES.ResetSystem */
    cbz     x9, .Limage_exit_bad_state
    mov     x0, #2                   /* EfiResetShutdown */
    mov     x1, x8
    mov     x2, xzr
    mov     x3, xzr
    blr     x9
    mov     x1, x0                   /* A conforming successful reset never returns. */
    mov     w0, #0x102
    b       wrela_rt_v2_fatal
.Limage_exit_bad_state:
    mov     x1, x8
    mov     w0, #0x101
    b       wrela_rt_v2_fatal

/* noreturn void wrela_rt_v2_fatal(u32 code, u64 detail) */
    .globl wrela_rt_v2_fatal
    .p2align 4
wrela_rt_v2_fatal:
    msr     daifset, #0xf
    isb
    WRELA_ADDR x8, .Lfatal_code
    str     w0, [x8]
    WRELA_ADDR x8, .Lfatal_detail
    str     x1, [x8]

    /* Only explicit shift-specific producer codes become language-fatal test
     * outcomes. The packed provenance detail above remains byte-for-byte
     * intact for postmortem inspection; it is never repurposed as a cause.
     */
    cmp     w0, #WRELA_FATAL_CHECKED_SHIFT_RESULT_LOSS
    b.eq    .Lfatal_result_loss
    cmp     w0, #WRELA_FATAL_INVALID_SHIFT_COUNT
    b.ne    .Lfatal_mark_and_halt
    mov     w20, #WRELA_LANGUAGE_FATAL_INVALID_COUNT
    b       .Lfatal_maybe_emit
.Lfatal_result_loss:
    mov     w20, #WRELA_LANGUAGE_FATAL_RESULT_LOSS
.Lfatal_maybe_emit:
    WRELA_ADDR x8, .Lruntime_state
    ldar    w9, [x8]
    cmp     w9, #WRELA_RUNTIME_ENTERED
    b.ne    .Lfatal_mark_and_halt
    WRELA_ADDR x8, .Ltest_active
    ldar    w9, [x8]
    cmp     w9, #1
    b.ne    .Lfatal_mark_and_halt
    WRELA_ADDR x8, .Ltest_terminal
    ldar    w9, [x8]
    cbnz    w9, .Lfatal_mark_and_halt
    WRELA_ADDR x8, .Ltest_active_id
    ldr     w22, [x8]
    WRELA_ADDR x8, .Ltest_sequence
    ldr     x21, [x8]
    movz    x9, #0x4240
    movk    x9, #0x000f, lsl #16     /* ProtocolLimits::standard().events */
    add     x10, x21, #1
    cmp     x10, x9
    b.hs    .Lfatal_mark_and_halt      /* Both terminal events must fit. */

    /* The largest synthesized frame is 53 bytes. A fixed 64-byte stack
     * reservation keeps this path allocation-free and 16-byte aligned.
     */
    sub     sp, sp, #WRELA_FATAL_FRAME_BUFFER_BYTES
    mov     x19, sp

    /* TestFinished(active, LanguageFatal(cause)), event sequence x21. */
    movz    x8, #0x5257
    movk    x8, #0x4c45, lsl #16
    movk    x8, #0x5354, lsl #32
    movk    x8, #0x0054, lsl #48
    str     x8, [x19]
    mov     w8, #WRELA_TEST_FRAME_VERSION
    str     w8, [x19, #8]
    mov     w8, #WRELA_TEST_EVENT_VERSION
    str     w8, [x19, #12]
    str     x21, [x19, #16]
    mov     w8, #WRELA_FATAL_TEST_FINISHED_PAYLOAD_BYTES
    str     w8, [x19, #24]
    mov     w8, #WRELA_TEST_EVENT_VERSION
    str     w8, [x19, #32]
    stur    x21, [x19, #36]
    mov     w8, #4                    /* TestFinished */
    strb    w8, [x19, #44]
    stur    w22, [x19, #45]
    mov     w8, #3                    /* GuestTestOutcome::LanguageFatal */
    strb    w8, [x19, #49]
    strb    w20, [x19, #50]
    add     x0, x19, #32
    mov     x1, #WRELA_FATAL_TEST_FINISHED_PAYLOAD_BYTES
    bl      .Lcrc32c
    str     w0, [x19, #28]
    mov     x0, x19
    mov     x1, #51
    bl      .Lslip_send
    cbnz    w0, .Lfatal_stack_halt

    /* RunFinished(passed=0, failed=1), immediately following the fatal. */
    add     x21, x21, #1
    str     x21, [x19, #16]
    mov     w8, #WRELA_FATAL_RUN_FINISHED_PAYLOAD_BYTES
    str     w8, [x19, #24]
    mov     w8, #WRELA_TEST_EVENT_VERSION
    str     w8, [x19, #32]
    stur    x21, [x19, #36]
    mov     w8, #6                    /* RunFinished */
    strb    w8, [x19, #44]
    stur    wzr, [x19, #45]
    mov     w8, #1
    stur    w8, [x19, #49]
    add     x0, x19, #32
    mov     x1, #WRELA_FATAL_RUN_FINISHED_PAYLOAD_BYTES
    bl      .Lcrc32c
    str     w0, [x19, #28]
    mov     x0, x19
    mov     x1, #53
    bl      .Lslip_send
    cbnz    w0, .Lfatal_stack_halt

    WRELA_ADDR x8, .Ltest_sequence
    add     x21, x21, #1
    str     x21, [x8]
    WRELA_ADDR x8, .Ltest_active
    stlr    wzr, [x8]
    WRELA_ADDR x8, .Ltest_terminal_passed
    str     wzr, [x8]
    WRELA_ADDR x8, .Ltest_terminal_failed
    mov     w9, #1
    str     w9, [x8]
    dmb     ish
    WRELA_ADDR x8, .Ltest_terminal
    stlr    w9, [x8]
    add     sp, sp, #WRELA_FATAL_FRAME_BUFFER_BYTES
    mov     w0, #1
    b       wrela_rt_v2_test_finish

.Lfatal_stack_halt:
    add     sp, sp, #WRELA_FATAL_FRAME_BUFFER_BYTES
.Lfatal_mark_and_halt:
    WRELA_ADDR x8, .Lruntime_state
    mov     w9, #WRELA_RUNTIME_FATAL
    stlr    w9, [x8]
    dsb     sy
.Lfatal_halt:
    wfe
    b       .Lfatal_halt

/* void wrela_rt_v2_cpu_idle(void) */
    .globl wrela_rt_v2_cpu_idle
    .p2align 4
wrela_rt_v2_cpu_idle:
    dsb     sy
    wfi
    ret

/* u64 wrela_rt_v2_interrupt_mask(void) */
    .globl wrela_rt_v2_interrupt_mask
    .p2align 4
wrela_rt_v2_interrupt_mask:
    mrs     x0, daif
    msr     daifset, #3              /* Mask IRQ and FIQ; retain exact old DAIF. */
    isb
    ret

/* void wrela_rt_v2_interrupt_restore(u64 prior_daif) */
    .globl wrela_rt_v2_interrupt_restore
    .p2align 4
wrela_rt_v2_interrupt_restore:
    mov     x1, #0x3c0               /* D,A,I,F are the only defined token bits. */
    bic     x1, x0, x1
    cbnz    x1, .Linterrupt_restore_invalid
    msr     daif, x0
    isb
    ret
.Linterrupt_restore_invalid:
    mov     x1, x0
    mov     w0, #0x201
    b       wrela_rt_v2_fatal

/* void wrela_rt_v2_cache_maintain(void *address, usize bytes, u8 operation) */
    .globl wrela_rt_v2_cache_maintain
    .p2align 4
wrela_rt_v2_cache_maintain:
    and     w2, w2, #0xff            /* AbiType::U8 has only a defined low byte. */
    cbz     x1, .Lcache_done
    cbz     x0, .Lcache_invalid
    cmp     w2, #2                   /* 0 clean, 1 invalidate, 2 clean+invalidate */
    b.hi    .Lcache_invalid
    mov     x3, #0x1000000           /* Hard per-call bound: 16 MiB. */
    cmp     x1, x3
    b.hi    .Lcache_invalid
    adds    x3, x0, x1
    b.cs    .Lcache_invalid
    mrs     x4, ctr_el0
    ubfx    x4, x4, #16, #4          /* DminLine in 32-bit words. */
    mov     x5, #4
    lsl     x5, x5, x4
    sub     x6, x5, #1
    cbz     w2, .Lcache_alignment_ok
    tst     x0, x6                   /* Invalidating partial lines loses neighbors. */
    b.ne    .Lcache_invalid
    tst     x1, x6
    b.ne    .Lcache_invalid
.Lcache_alignment_ok:
    bic     x0, x0, x6
    dsb     osh                       /* Order prior ownership-side accesses. */
.Lcache_loop:
    cmp     x0, x3
    b.hs    .Lcache_barrier
    cbz     w2, .Lcache_clean
    cmp     w2, #1
    b.eq    .Lcache_invalidate
    dc      civac, x0
    b       .Lcache_next
.Lcache_clean:
    dc      cvac, x0
    b       .Lcache_next
.Lcache_invalidate:
    dc      ivac, x0
.Lcache_next:
    add     x0, x0, x5
    b       .Lcache_loop
.Lcache_barrier:
    dsb     osh
.Lcache_done:
    ret
.Lcache_invalid:
    mov     w0, #0x301
    mov     x1, xzr
    b       wrela_rt_v2_fatal

/* EFI_STATUS wrela_rt_v2_record_event(u32 kind, void *payload, usize bytes) */
    .globl wrela_rt_v2_record_event
    .p2align 4
wrela_rt_v2_record_event:
    mrs     x9, daif
    msr     daifset, #3
    isb
    WRELA_ADDR x10, .Lruntime_state
    ldar    w10, [x10]
    cmp     w10, #WRELA_RUNTIME_ENTERED
    b.ne    .Lrecord_invalid
    cbz     x2, .Lrecord_pointer_ok
    cbz     x1, .Lrecord_invalid
.Lrecord_pointer_ok:
    WRELA_ADDR x10, .Lrecord_mode
    ldar    w11, [x10]
    cbnz    w11, .Lrecord_denied
    WRELA_ADDR x12, .Lrecord_write
    ldr     x13, [x12]
    mov     x14, #WRELA_LOG_RECORD_LIMIT
    cmp     x13, x14
    b.hi    .Lrecord_corrupt
    adds    x15, x2, #8
    b.cs    .Lrecord_overflow
    adds    x16, x13, x15
    b.cs    .Lrecord_overflow
    cmp     x16, x14
    b.hi    .Lrecord_overflow
    WRELA_ADDR x17, .Lrecord_log
    add     x17, x17, x13
    str     w0, [x17]
    str     w2, [x17, #4]
    add     x17, x17, #8
    cbz     x2, .Lrecord_commit
.Lrecord_copy:
    ldrb    w3, [x1], #1
    strb    w3, [x17], #1
    subs    x2, x2, #1
    b.ne    .Lrecord_copy
.Lrecord_commit:
    dmb     ish
    str     x16, [x12]
    msr     daif, x9
    isb
    mov     x0, xzr
    ret
.Lrecord_overflow:
    /* Prior successful writes reserve enough space for this explicit marker. */
    WRELA_ADDR x17, .Lrecord_log
    add     x17, x17, x13
    mov     w3, #-1
    str     w3, [x17]
    str     wzr, [x17, #4]
    add     x13, x13, #8
    dmb     ish
    str     x13, [x12]
    mov     w11, #WRELA_LOG_OVERFLOWED
    stlr    w11, [x10]
    msr     daif, x9
    isb
    WRELA_EFI_ERROR x0, WRELA_EFI_OUT_OF_RESOURCES
    ret
.Lrecord_denied:
    msr     daif, x9
    isb
    WRELA_EFI_ERROR x0, WRELA_EFI_ACCESS_DENIED
    ret
.Lrecord_invalid:
    msr     daif, x9
    isb
    WRELA_EFI_ERROR x0, WRELA_EFI_INVALID_PARAMETER
    ret
.Lrecord_corrupt:
    msr     daif, x9
    isb
    mov     w0, #0x401
    mov     x1, x13
    b       wrela_rt_v2_fatal

/* usize wrela_rt_v2_replay_event(u32 kind, void *destination, usize capacity) */
    .globl wrela_rt_v2_replay_event
    .p2align 4
wrela_rt_v2_replay_event:
    mov     w3, w0
    mrs     x9, daif
    msr     daifset, #3
    isb
    WRELA_ADDR x10, .Lruntime_state
    ldar    w10, [x10]
    cmp     w10, #WRELA_RUNTIME_ENTERED
    b.ne    .Lreplay_bad_state
    WRELA_ADDR x10, .Lrecord_mode
    ldar    w11, [x10]
    cmp     w11, #WRELA_LOG_REPLAY
    b.eq    .Lreplay_mode_ready
    cmp     w11, #WRELA_LOG_RECORD
    b.eq    .Lreplay_freeze
    cmp     w11, #WRELA_LOG_OVERFLOWED
    b.ne    .Lreplay_bad_state
.Lreplay_freeze:
    WRELA_ADDR x12, .Lrecord_read
    str     xzr, [x12]
    dmb     ish
    mov     w11, #WRELA_LOG_REPLAY
    stlr    w11, [x10]
.Lreplay_mode_ready:
    WRELA_ADDR x12, .Lrecord_read
    ldr     x13, [x12]
    WRELA_ADDR x14, .Lrecord_write
    ldr     x14, [x14]
    cmp     x13, x14
    b.hi    .Lreplay_bad_state
    adds    x15, x13, #8
    b.cs    .Lreplay_bad_state
    cmp     x15, x14
    b.hi    .Lreplay_exhausted
    WRELA_ADDR x16, .Lrecord_log
    add     x16, x16, x13
    ldr     w17, [x16]
    ldr     w4, [x16, #4]
    cmn     w17, #1
    b.eq    .Lreplay_overflow_marker
    cmp     w17, w3
    b.ne    .Lreplay_kind_mismatch
    uxtw    x4, w4
    cmp     x4, x2
    b.hi    .Lreplay_small_destination
    cbz     x4, .Lreplay_extent
    cbz     x1, .Lreplay_bad_destination
.Lreplay_extent:
    adds    x15, x15, x4
    b.cs    .Lreplay_bad_state
    cmp     x15, x14
    b.hi    .Lreplay_bad_state
    add     x16, x16, #8
    mov     x5, x4
    cbz     x5, .Lreplay_commit
.Lreplay_copy:
    ldrb    w6, [x16], #1
    strb    w6, [x1], #1
    subs    x5, x5, #1
    b.ne    .Lreplay_copy
.Lreplay_commit:
    dmb     ish
    str     x15, [x12]
    mov     x0, x4
    msr     daif, x9
    isb
    ret
.Lreplay_exhausted:
    mov     w0, #0x410
    mov     x1, x13
    b       .Lreplay_fatal
.Lreplay_overflow_marker:
    mov     w0, #0x411
    mov     x1, x13
    b       .Lreplay_fatal
.Lreplay_kind_mismatch:
    mov     w0, #0x412
    lsl     x1, x3, #32
    orr     x1, x1, x17
    b       .Lreplay_fatal
.Lreplay_small_destination:
    mov     w0, #0x413
    lsl     x1, x2, #32
    orr     x1, x1, x4
    b       .Lreplay_fatal
.Lreplay_bad_destination:
    mov     w0, #0x414
    mov     x1, x4
    b       .Lreplay_fatal
.Lreplay_bad_state:
    mov     w0, #0x415
    mov     x1, xzr
.Lreplay_fatal:
    msr     daif, x9
    isb
    b       wrela_rt_v2_fatal

/* EFI_STATUS wrela_rt_v2_test_emit(void *frame, usize frame_bytes) */
    .globl wrela_rt_v2_test_emit
    .p2align 4
wrela_rt_v2_test_emit:
    sub     sp, sp, #80
    stp     x29, x30, [sp, #0]
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    mov     x29, sp
    mov     x19, x0
    mov     x20, x1
    mrs     x26, daif
    msr     daifset, #3
    isb
    WRELA_ADDR x8, .Lruntime_state
    ldar    w8, [x8]
    cmp     w8, #WRELA_RUNTIME_ENTERED
    b.ne    .Ltest_emit_invalid
    cbz     x19, .Ltest_emit_invalid
    cmp     x20, #WRELA_TEST_FRAME_MIN
    b.lo    .Ltest_emit_invalid
    mov     x8, #WRELA_TEST_FRAME_MAX
    cmp     x20, x8
    b.hi    .Ltest_emit_too_large
    WRELA_ADDR x8, .Ltest_terminal
    ldar    w8, [x8]
    cbnz    w8, .Ltest_emit_denied

    /* Header: "WRELTST\0", frame v1, event v3, sequence, size, CRC32C. */
    ldr     w8, [x19]
    movz    w9, #0x5257
    movk    w9, #0x4c45, lsl #16     /* 0x4c455257 */
    cmp     w8, w9
    b.ne    .Ltest_emit_corrupt
    ldr     w8, [x19, #4]
    movz    w9, #0x5354
    movk    w9, #0x0054, lsl #16     /* 0x00545354 */
    cmp     w8, w9
    b.ne    .Ltest_emit_corrupt
    ldr     w8, [x19, #8]
    cmp     w8, #WRELA_TEST_FRAME_VERSION
    b.ne    .Ltest_emit_corrupt
    ldr     w8, [x19, #12]
    cmp     w8, #WRELA_TEST_EVENT_VERSION
    b.ne    .Ltest_emit_corrupt
    ldr     x21, [x19, #16]
    WRELA_ADDR x8, .Ltest_sequence
    ldr     x9, [x8]
    cmp     x21, x9
    b.ne    .Ltest_emit_sequence
    movz    x8, #0x4240
    movk    x8, #0x000f, lsl #16     /* ProtocolLimits::standard().events */
    cmp     x21, x8
    b.hs    .Ltest_emit_corrupt
    ldr     w22, [x19, #24]
    add     x8, x22, #WRELA_TEST_FRAME_MIN
    cmp     x8, x20
    b.ne    .Ltest_emit_corrupt
    ldr     w23, [x19, #28]

    /* Payload repeats event version and sequence before its canonical tag. */
    add     x24, x19, #WRELA_TEST_FRAME_MIN
    cmp     x22, #13
    b.lo    .Ltest_emit_corrupt
    ldr     w8, [x24]
    cmp     w8, #WRELA_TEST_EVENT_VERSION
    b.ne    .Ltest_emit_corrupt
    ldur    x8, [x24, #4]
    cmp     x8, x21
    b.ne    .Ltest_emit_corrupt

    mov     x0, x24
    mov     x1, x22
    bl      .Ltest_validate_payload
    cbnz    w0, .Ltest_emit_corrupt
    mov     w25, w1                  /* validated event tag */
    mov     w20, w2                  /* terminal passed count, if tag 6 */
    mov     w21, w3                  /* terminal failed count, if tag 6 */

    /* TestEmit is compiler-pass authority only. Dynamic failures are emitted
     * exclusively by TestAssertionFail and fatal checked-operation paths.
     */
    cbz     w25, .Ltest_emit_check_run_start
    cmp     w25, #1                  /* TestStarted */
    b.eq    .Ltest_emit_check_start
    cmp     w25, #4                  /* TestFinished(Passed) */
    b.ne    .Ltest_emit_check_run_finished
    ldrb    w8, [x24, #17]           /* GuestTestOutcome tag */
    cbnz    w8, .Ltest_emit_corrupt
    b       .Ltest_emit_check_finish
.Ltest_emit_check_run_finished:
    cmp     w25, #6
    b.ne    .Ltest_emit_corrupt
    b       .Ltest_emit_check_inactive

    /* Track only successfully emitted test lifecycle boundaries. This gives
     * the fatal path an authoritative active test without accepting a host
     * guess, stale ID, or already-finished test.
     */
.Ltest_emit_check_run_start:
    WRELA_ADDR x8, .Ltest_sequence
    ldr     x8, [x8]
    cbnz    x8, .Ltest_emit_corrupt
    WRELA_ADDR x8, .Ltest_active
    ldar    w8, [x8]
    cbnz    w8, .Ltest_emit_corrupt
    ldur    w9, [x24, #13]
    cbz     w9, .Ltest_emit_corrupt
    b       .Ltest_emit_crc
.Ltest_emit_check_start:
    WRELA_ADDR x8, .Ltest_active
    ldar    w8, [x8]
    cbnz    w8, .Ltest_emit_corrupt
    WRELA_ADDR x8, .Ltest_started_count
    ldr     w9, [x8]
    WRELA_ADDR x8, .Ltest_declared_count
    ldr     w10, [x8]
    cmp     w9, w10
    b.hs    .Ltest_emit_corrupt
    b       .Ltest_emit_crc
.Ltest_emit_check_finish:
    WRELA_ADDR x8, .Ltest_active
    ldar    w8, [x8]
    cmp     w8, #1
    b.ne    .Ltest_emit_corrupt
    ldur    w9, [x24, #13]
    WRELA_ADDR x8, .Ltest_active_id
    ldr     w8, [x8]
    cmp     w8, w9
    b.ne    .Ltest_emit_corrupt
    b       .Ltest_emit_crc
.Ltest_emit_check_inactive:
    WRELA_ADDR x8, .Ltest_active
    ldar    w8, [x8]
    cbnz    w8, .Ltest_emit_corrupt
    cbnz    w21, .Ltest_emit_corrupt
    WRELA_ADDR x8, .Ltest_completed_passed
    ldr     w9, [x8]
    cmp     w20, w9
    b.ne    .Ltest_emit_corrupt
    WRELA_ADDR x8, .Ltest_started_count
    ldr     w10, [x8]
    cmp     w9, w10
    b.ne    .Ltest_emit_corrupt
    WRELA_ADDR x8, .Ltest_declared_count
    ldr     w10, [x8]
    cmp     w9, w10
    b.ne    .Ltest_emit_corrupt

.Ltest_emit_crc:
    mov     x0, x24
    mov     x1, x22
    bl      .Lcrc32c
    cmp     w0, w23
    b.ne    .Ltest_emit_corrupt

    mov     x0, x19
    mov     x1, x20                  /* x20 was overwritten above; recover frame bytes. */
    /* The terminal counts use w20/w21, so frame length is reconstructed. */
    add     x1, x22, #WRELA_TEST_FRAME_MIN
    bl      .Lslip_send
    cbnz    w0, .Ltest_emit_timeout

    WRELA_ADDR x8, .Ltest_sequence
    add     x9, x21, #1              /* x21 no longer holds header sequence for tag 6. */
    /* Reload the authoritative sequence to avoid the terminal-count register. */
    ldr     x9, [x8]
    add     x9, x9, #1
    str     x9, [x8]
    cmp     w25, #1
    b.eq    .Ltest_emit_commit_start
    cmp     w25, #4
    b.eq    .Ltest_emit_commit_finish
    cmp     w25, #6
    b.ne    .Ltest_emit_commit_run_start
    WRELA_ADDR x8, .Ltest_terminal_passed
    str     w20, [x8]
    WRELA_ADDR x8, .Ltest_terminal_failed
    str     w21, [x8]
    dmb     ish
    WRELA_ADDR x8, .Ltest_terminal
    mov     w9, #1
    stlr    w9, [x8]
    b       .Ltest_emit_success
.Ltest_emit_commit_run_start:
    cbnz    w25, .Ltest_emit_success
    ldur    w9, [x24, #13]
    WRELA_ADDR x8, .Ltest_declared_count
    str     w9, [x8]
    WRELA_ADDR x8, .Ltest_started_count
    str     wzr, [x8]
    WRELA_ADDR x8, .Ltest_completed_passed
    str     wzr, [x8]
    b       .Ltest_emit_success
.Ltest_emit_commit_start:
    ldur    w9, [x24, #13]
    WRELA_ADDR x8, .Ltest_active_id
    str     w9, [x8]
    dmb     ish
    WRELA_ADDR x8, .Ltest_active
    mov     w9, #1
    stlr    w9, [x8]
    WRELA_ADDR x8, .Ltest_started_count
    ldr     w9, [x8]
    add     w9, w9, #1
    str     w9, [x8]
    b       .Ltest_emit_success
.Ltest_emit_commit_finish:
    WRELA_ADDR x8, .Ltest_active
    stlr    wzr, [x8]
    WRELA_ADDR x8, .Ltest_completed_passed
    ldr     w9, [x8]
    add     w9, w9, #1
    str     w9, [x8]
.Ltest_emit_success:
    mov     x0, xzr
    b       .Ltest_emit_return
.Ltest_emit_invalid:
    WRELA_EFI_ERROR x0, WRELA_EFI_INVALID_PARAMETER
    b       .Ltest_emit_return
.Ltest_emit_too_large:
    WRELA_EFI_ERROR x0, WRELA_EFI_BAD_BUFFER_SIZE
    b       .Ltest_emit_return
.Ltest_emit_denied:
    WRELA_EFI_ERROR x0, WRELA_EFI_ACCESS_DENIED
    b       .Ltest_emit_return
.Ltest_emit_corrupt:
    WRELA_EFI_ERROR x0, WRELA_EFI_COMPROMISED_DATA
    b       .Ltest_emit_return
.Ltest_emit_sequence:
    WRELA_EFI_ERROR x0, WRELA_EFI_COMPROMISED_DATA
    b       .Ltest_emit_return
.Ltest_emit_timeout:
    WRELA_EFI_ERROR x0, WRELA_EFI_TIMEOUT
.Ltest_emit_return:
    msr     daif, x26
    isb
    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp, #0]
    add     sp, sp, #80
    ret

/* noreturn void wrela_rt_v2_test_assertion_fail(
 *     void *expression, usize expression_bytes,
 *     void *message, usize message_bytes,
 *     u32 file, u32 start, u32 end)
 */
    .globl wrela_rt_v2_test_assertion_fail
    .p2align 4
wrela_rt_v2_test_assertion_fail:
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     w23, w4
    mov     w24, w5
    mov     w25, w6
    msr     daifset, #0xf
    isb
    WRELA_ADDR x8, .Lruntime_state
    ldar    w8, [x8]
    cmp     w8, #WRELA_RUNTIME_ENTERED
    b.ne    .Lassert_invalid
    WRELA_ADDR x8, .Ltest_active
    ldar    w8, [x8]
    cmp     w8, #1
    b.ne    .Lassert_invalid
    WRELA_ADDR x8, .Ltest_terminal
    ldar    w8, [x8]
    cbnz    w8, .Lassert_invalid
    cbz     x19, .Lassert_invalid
    cbz     x20, .Lassert_invalid
    cmp     x20, #WRELA_ASSERT_TEXT_MAX
    b.hi    .Lassert_invalid
    adds    x8, x19, x20
    b.cs    .Lassert_invalid
    mov     x0, x19
    mov     x1, x20
    bl      .Lvalidate_utf8
    cbnz    w0, .Lassert_invalid
    mov     x0, x19
    mov     x1, x20
    bl      .Lcontains_non_whitespace
    cbz     w0, .Lassert_invalid
    cbnz    x22, .Lassert_message_present
    cbnz    x21, .Lassert_invalid
    b       .Lassert_message_valid
.Lassert_message_present:
    cbz     x21, .Lassert_invalid
    cmp     x22, #WRELA_ASSERT_TEXT_MAX
    b.hi    .Lassert_invalid
    adds    x8, x21, x22
    b.cs    .Lassert_invalid
    mov     x0, x21
    mov     x1, x22
    bl      .Lvalidate_utf8
    cbnz    w0, .Lassert_invalid
    mov     x0, x21
    mov     x1, x22
    bl      .Lcontains_non_whitespace
    cbz     w0, .Lassert_invalid
.Lassert_message_valid:
    cmp     w24, w25
    b.hi    .Lassert_invalid
    WRELA_ADDR x8, .Ltest_sequence
    ldr     x26, [x8]
    movz    x9, #0x4240
    movk    x9, #0x000f, lsl #16
    add     x10, x26, #2
    cmp     x10, x9
    b.hs    .Lassert_invalid
    WRELA_ADDR x8, .Ltest_active_id
    ldr     w27, [x8]
    WRELA_ADDR x8, .Ltest_completed_passed
    ldr     w28, [x8]
    WRELA_ADDR x8, .Ltest_declared_count
    ldr     w9, [x8]
    cmp     w9, #1
    b.ne    .Lassert_invalid
    WRELA_ADDR x8, .Ltest_started_count
    ldr     w9, [x8]
    cmp     w9, #1
    b.ne    .Lassert_invalid
    cbnz    w28, .Lassert_invalid
    cmp     x26, #2
    b.ne    .Lassert_invalid

    /* AssertionFailed(active, exact descriptor), sequence x26. */
    mov     x17, x19                 /* validated expression source */
    WRELA_ADDR x19, .Lassert_frame_buffer
    movz    x8, #0x5257
    movk    x8, #0x4c45, lsl #16
    movk    x8, #0x5354, lsl #32
    movk    x8, #0x0054, lsl #48
    str     x8, [x19]
    mov     w8, #WRELA_TEST_FRAME_VERSION
    str     w8, [x19, #8]
    mov     w8, #WRELA_TEST_EVENT_VERSION
    str     w8, [x19, #12]
    str     x26, [x19, #16]
    add     x8, x20, #37
    cbz     x22, .Lassert_payload_size_ready
    add     x8, x8, x22
    add     x8, x8, #4
.Lassert_payload_size_ready:
    str     w8, [x19, #24]
    mov     w9, #WRELA_TEST_EVENT_VERSION
    str     w9, [x19, #32]
    stur    x26, [x19, #36]
    mov     w9, #3
    strb    w9, [x19, #44]
    stur    w27, [x19, #45]
    stur    w20, [x19, #49]
    add     x10, x19, #53
    mov     x11, x20
    /* Compiler-sealed expression storage is copied into the owned frame. */
.Lassert_copy_expression:
    ldrb    w12, [x17], #1
    strb    w12, [x10], #1
    subs    x11, x11, #1
    b.ne    .Lassert_copy_expression
    cbz     x22, .Lassert_encode_no_message
    mov     w12, #1
    strb    w12, [x10], #1
    str     w22, [x10], #4
    mov     x11, x22
.Lassert_copy_message:
    ldrb    w12, [x21], #1
    strb    w12, [x10], #1
    subs    x11, x11, #1
    b.ne    .Lassert_copy_message
    b       .Lassert_encode_source
.Lassert_encode_no_message:
    strb    wzr, [x10], #1
.Lassert_encode_source:
    mov     w12, #1
    strb    w12, [x10], #1
    str     w23, [x10], #4
    str     w24, [x10], #4
    str     w25, [x10], #4
    strb    wzr, [x10], #1          /* expected = None */
    strb    wzr, [x10], #1          /* actual = None */
    mov     x25, x22                 /* retain optional message length */
    ldr     w22, [x19, #24]
    add     x0, x19, #32
    mov     x1, x22
    bl      .Lcrc32c
    str     w0, [x19, #28]
    mov     x0, x19
    add     x1, x22, #32
    bl      .Lslip_send
    cbnz    w0, .Lassert_transmit_failed

    /* Select the exact failure message for TestFinished. */
    cbnz    x25, .Lassert_use_user_message
    WRELA_ADDR x21, .Lassert_default_message
    mov     x22, #WRELA_ASSERT_DEFAULT_BYTES
    b       .Lassert_terminal_message_ready
.Lassert_use_user_message:
    /* The source pointer was advanced while copying; recover the owned copy.
     * Its start is derived from the assertion frame's canonical layout.
     */
    add     x21, x19, #58
    add     x21, x21, x20
    mov     x22, x25
.Lassert_terminal_message_ready:
    add     x26, x26, #1

    /* TestFinished(active, Failed(message)), sequence x26. */
    str     x26, [x19, #16]
    add     x8, x22, #22
    str     w8, [x19, #24]
    mov     w9, #WRELA_TEST_EVENT_VERSION
    str     w9, [x19, #32]
    stur    x26, [x19, #36]
    mov     w9, #4
    strb    w9, [x19, #44]
    stur    w27, [x19, #45]
    mov     w9, #1
    strb    w9, [x19, #49]
    stur    w22, [x19, #50]
    add     x10, x19, #54
    mov     x11, x22
.Lassert_copy_terminal_message:
    ldrb    w12, [x21], #1
    strb    w12, [x10], #1
    subs    x11, x11, #1
    b.ne    .Lassert_copy_terminal_message
    ldr     w22, [x19, #24]
    add     x0, x19, #32
    mov     x1, x22
    bl      .Lcrc32c
    str     w0, [x19, #28]
    mov     x0, x19
    add     x1, x22, #32
    bl      .Lslip_send
    cbnz    w0, .Lassert_transmit_failed

    /* RunFinished(previous passed tests, failed=1), sequence x26+1. */
    add     x26, x26, #1
    str     x26, [x19, #16]
    mov     w8, #WRELA_FATAL_RUN_FINISHED_PAYLOAD_BYTES
    str     w8, [x19, #24]
    mov     w8, #WRELA_TEST_EVENT_VERSION
    str     w8, [x19, #32]
    stur    x26, [x19, #36]
    mov     w8, #6
    strb    w8, [x19, #44]
    stur    w28, [x19, #45]
    mov     w8, #1
    stur    w8, [x19, #49]
    add     x0, x19, #32
    mov     x1, #WRELA_FATAL_RUN_FINISHED_PAYLOAD_BYTES
    bl      .Lcrc32c
    str     w0, [x19, #28]
    mov     x0, x19
    mov     x1, #53
    bl      .Lslip_send
    cbnz    w0, .Lassert_transmit_failed

    WRELA_ADDR x8, .Ltest_sequence
    add     x26, x26, #1
    str     x26, [x8]
    WRELA_ADDR x8, .Ltest_active
    stlr    wzr, [x8]
    WRELA_ADDR x8, .Ltest_terminal_passed
    str     w28, [x8]
    WRELA_ADDR x8, .Ltest_terminal_failed
    mov     w9, #1
    str     w9, [x8]
    dmb     ish
    WRELA_ADDR x8, .Ltest_terminal
    stlr    w9, [x8]
    mov     w0, #1
    b       wrela_rt_v2_test_finish

.Lassert_transmit_failed:
    mov     w0, #0x505
    mov     x1, x26
    b       wrela_rt_v2_fatal
.Lassert_invalid:
    mov     w0, #0x504
    mov     x1, xzr
    b       wrela_rt_v2_fatal

/* noreturn void wrela_rt_v2_test_finish(u32 aggregate_outcome) */
    .globl wrela_rt_v2_test_finish
    .p2align 4
wrela_rt_v2_test_finish:
    mov     w8, w0
    msr     daifset, #3
    isb
    cmp     w8, #1                   /* 0 passed, 1 failed; no invented count packing. */
    b.hi    .Ltest_finish_invalid
    WRELA_ADDR x9, .Ltest_terminal
    ldar    w10, [x9]
    cmp     w10, #1
    b.ne    .Ltest_finish_missing
    WRELA_ADDR x9, .Ltest_terminal_failed
    ldr     w10, [x9]
    cbz     w8, .Ltest_finish_pass
    cbz     w10, .Ltest_finish_mismatch
    WRELA_EFI_ERROR x0, WRELA_EFI_ABORTED
    b       wrela_rt_v2_image_exit
.Ltest_finish_pass:
    cbnz    w10, .Ltest_finish_mismatch
    mov     x0, xzr
    b       wrela_rt_v2_image_exit
.Ltest_finish_invalid:
    mov     w0, #0x501
    uxtw    x1, w8
    b       wrela_rt_v2_fatal
.Ltest_finish_missing:
    mov     w0, #0x502
    mov     x1, xzr
    b       wrela_rt_v2_fatal
.Ltest_finish_mismatch:
    mov     w0, #0x503
    lsl     x1, x8, #32
    orr     x1, x1, x10
    b       wrela_rt_v2_fatal

/* CRC32C (Castagnoli, reflected polynomial 0x82f63b78). */
    .p2align 4
.Lcrc32c:
    mvn     w2, wzr
    movz    w5, #0x3b78
    movk    w5, #0x82f6, lsl #16
    cbz     x1, .Lcrc_done
.Lcrc_byte:
    ldrb    w3, [x0], #1
    eor     w2, w2, w3
    mov     w4, #8
.Lcrc_bit:
    and     w3, w2, #1
    neg     w3, w3
    and     w3, w3, w5
    lsr     w2, w2, #1
    eor     w2, w2, w3
    subs    w4, w4, #1
    b.ne    .Lcrc_bit
    subs    x1, x1, #1
    b.ne    .Lcrc_byte
.Lcrc_done:
    mvn     w0, w2
    ret

/* Return w0=0 and w1=tag for a canonical payload; w0=1 on rejection.
 * For tag 6, w2/w3 return passed/failed counts.
 */
    .p2align 4
.Ltest_validate_payload:
    sub     sp, sp, #80
    stp     x29, x30, [sp, #0]
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    mov     x29, sp
    add     x19, x0, #12
    add     x20, x0, x1
    cmp     x19, x20
    b.hs    .Lpayload_invalid
    ldrb    w21, [x19], #1
    cmp     w21, #6
    b.hi    .Lpayload_invalid
    mov     w22, wzr
    mov     w23, wzr
    cmp     w21, #0
    b.eq    .Lpayload_fixed4
    cmp     w21, #1
    b.eq    .Lpayload_fixed4
    cmp     w21, #2
    b.eq    .Lpayload_log
    cmp     w21, #3
    b.eq    .Lpayload_assertion
    cmp     w21, #4
    b.eq    .Lpayload_test_finished
    cmp     w21, #5
    b.eq    .Lpayload_fixed8
    b       .Lpayload_run_finished
.Lpayload_fixed4:
    add     x19, x19, #4
    b       .Lpayload_exact
.Lpayload_fixed8:
    add     x19, x19, #8
    b       .Lpayload_exact
.Lpayload_log:
    cmp     x19, x20
    b.hs    .Lpayload_invalid
    ldrb    w8, [x19], #1
    cbz     w8, .Lpayload_log_level
    cmp     w8, #1
    b.ne    .Lpayload_invalid
    add     x19, x19, #4
.Lpayload_log_level:
    cmp     x19, x20
    b.hs    .Lpayload_invalid
    ldrb    w8, [x19], #1
    cmp     w8, #4
    b.hi    .Lpayload_invalid
    mov     x0, x19
    mov     x1, x20
    bl      .Lconsume_required_text
    cbz     x0, .Lpayload_invalid
    mov     x19, x0
    b       .Lpayload_exact
.Lpayload_assertion:
    add     x19, x19, #4             /* test ID */
    cmp     x19, x20
    b.hi    .Lpayload_invalid
    mov     x0, x19
    mov     x1, x20
    bl      .Lconsume_required_text
    cbz     x0, .Lpayload_invalid
    mov     x19, x0
    mov     x0, x19
    mov     x1, x20
    bl      .Lconsume_optional_string
    cbz     x0, .Lpayload_invalid
    mov     x19, x0
    cmp     x19, x20
    b.hs    .Lpayload_invalid
    ldrb    w8, [x19], #1            /* optional source */
    cbz     w8, .Lpayload_assertion_strings
    cmp     w8, #1
    b.ne    .Lpayload_invalid
    add     x8, x19, #12
    cmp     x8, x20
    b.hi    .Lpayload_invalid
    ldr     w9, [x19, #4]            /* start */
    ldr     w10, [x19, #8]           /* end */
    cmp     w9, w10
    b.hi    .Lpayload_invalid
    mov     x19, x8
.Lpayload_assertion_strings:
    mov     x0, x19
    mov     x1, x20
    bl      .Lconsume_optional_string
    cbz     x0, .Lpayload_invalid
    mov     x19, x0
    mov     x0, x19
    mov     x1, x20
    bl      .Lconsume_optional_string
    cbz     x0, .Lpayload_invalid
    mov     x19, x0
    b       .Lpayload_exact
.Lpayload_test_finished:
    add     x19, x19, #4             /* test ID */
    cmp     x19, x20
    b.hs    .Lpayload_invalid
    ldrb    w8, [x19], #1
    cbz     w8, .Lpayload_exact
    cmp     w8, #1
    b.eq    .Lpayload_test_failed
    cmp     w8, #2
    b.eq    .Lpayload_test_timeout
    cmp     w8, #3
    b.ne    .Lpayload_invalid
    cmp     x19, x20
    b.hs    .Lpayload_invalid
    ldrb    w8, [x19], #1            /* closed LanguageFatalKind tag */
    cmp     w8, #WRELA_LANGUAGE_FATAL_INVALID_COUNT
    b.hi    .Lpayload_invalid
    b       .Lpayload_exact
.Lpayload_test_timeout:
    add     x9, x19, #8
    cmp     x9, x20
    b.hi    .Lpayload_invalid
    ldr     x10, [x19]
    cbz     x10, .Lpayload_invalid
    add     x19, x19, #8
    b       .Lpayload_exact
.Lpayload_test_failed:
    mov     x0, x19
    mov     x1, x20
    bl      .Lconsume_required_text
    cbz     x0, .Lpayload_invalid
    mov     x19, x0
    b       .Lpayload_exact
.Lpayload_run_finished:
    add     x8, x19, #8
    cmp     x8, x20
    b.hi    .Lpayload_invalid
    ldr     w22, [x19]
    ldr     w23, [x19, #4]
    mov     x19, x8
.Lpayload_exact:
    cmp     x19, x20
    b.ne    .Lpayload_invalid
    mov     w0, wzr
    mov     w1, w21
    mov     w2, w22
    mov     w3, w23
    b       .Lpayload_return
.Lpayload_invalid:
    mov     w0, #1
    mov     w1, wzr
    mov     w2, wzr
    mov     w3, wzr
.Lpayload_return:
    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp, #0]
    add     sp, sp, #80
    ret

/* Consume a u32-length UTF-8 string.  Return the next cursor or zero. */
    .p2align 4
.Lconsume_string:
    sub     sp, sp, #48
    stp     x29, x30, [sp, #0]
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x29, sp
    mov     x19, x0
    mov     x20, x1
    add     x8, x19, #4
    cmp     x8, x20
    b.hi    .Lconsume_string_invalid
    ldr     w21, [x19]
    mov     x9, #WRELA_TEST_STRING_MAX
    cmp     x21, x9
    b.hi    .Lconsume_string_invalid
    add     x19, x19, #4
    adds    x22, x19, x21
    b.cs    .Lconsume_string_invalid
    cmp     x22, x20
    b.hi    .Lconsume_string_invalid
    mov     x0, x19
    uxtw    x1, w21
    bl      .Lvalidate_utf8
    cbnz    w0, .Lconsume_string_invalid
    mov     x0, x22
    b       .Lconsume_string_return
.Lconsume_string_invalid:
    mov     x0, xzr
.Lconsume_string_return:
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp, #0]
    add     sp, sp, #48
    ret

/* Consume a string required by canonical protocol rules to contain at least
 * one non-White_Space Unicode scalar.  Return the next cursor or zero.
 */
    .p2align 4
.Lconsume_required_text:
    sub     sp, sp, #64
    stp     x29, x30, [sp, #0]
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    mov     x29, sp
    mov     x19, x0
    mov     x20, x1
    add     x8, x19, #4
    cmp     x8, x20
    b.hi    .Lconsume_required_invalid
    ldr     w21, [x19]
    cbz     w21, .Lconsume_required_invalid
    mov     x0, x19
    mov     x1, x20
    bl      .Lconsume_string
    cbz     x0, .Lconsume_required_invalid
    mov     x22, x0
    add     x0, x19, #4
    uxtw    x1, w21
    bl      .Lcontains_non_whitespace
    cbz     w0, .Lconsume_required_invalid
    mov     x0, x22
    b       .Lconsume_required_return
.Lconsume_required_invalid:
    mov     x0, xzr
.Lconsume_required_return:
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp, #0]
    add     sp, sp, #64
    ret

/* Consume canonical option tag followed by a string when present. */
    .p2align 4
.Lconsume_optional_string:
    cmp     x0, x1
    b.hs    .Lconsume_optional_invalid
    ldrb    w8, [x0], #1
    cbz     w8, .Lconsume_optional_return
    cmp     w8, #1
    b.eq    .Lconsume_string
.Lconsume_optional_invalid:
    mov     x0, xzr
.Lconsume_optional_return:
    ret

/* Strict Unicode scalar UTF-8 validation.  Return 0 valid, 1 invalid. */
    .p2align 4
.Lvalidate_utf8:
    add     x2, x0, x1
.Lutf8_next:
    cmp     x0, x2
    b.hs    .Lutf8_valid
    ldrb    w3, [x0], #1
    cmp     w3, #0x80
    b.lo    .Lutf8_next
    cmp     w3, #0xc2
    b.lo    .Lutf8_invalid
    cmp     w3, #0xdf
    b.ls    .Lutf8_two
    cmp     w3, #0xef
    b.ls    .Lutf8_three
    cmp     w3, #0xf4
    b.ls    .Lutf8_four
    b       .Lutf8_invalid
.Lutf8_two:
    cmp     x0, x2
    b.hs    .Lutf8_invalid
    ldrb    w4, [x0], #1
    and     w5, w4, #0xc0
    cmp     w5, #0x80
    b.eq    .Lutf8_next
    b       .Lutf8_invalid
.Lutf8_three:
    sub     x4, x2, x0
    cmp     x4, #2
    b.lo    .Lutf8_invalid
    ldrb    w4, [x0], #1
    cmp     w3, #0xe0
    b.ne    .Lutf8_three_not_e0
    cmp     w4, #0xa0
    b.lo    .Lutf8_invalid
    b       .Lutf8_three_second_upper
.Lutf8_three_not_e0:
    cmp     w3, #0xed
    b.ne    .Lutf8_three_second_normal
    cmp     w4, #0x80
    b.lo    .Lutf8_invalid
    cmp     w4, #0x9f
    b.hi    .Lutf8_invalid
    b       .Lutf8_three_third
.Lutf8_three_second_normal:
    cmp     w4, #0x80
    b.lo    .Lutf8_invalid
.Lutf8_three_second_upper:
    cmp     w4, #0xbf
    b.hi    .Lutf8_invalid
.Lutf8_three_third:
    ldrb    w4, [x0], #1
    and     w5, w4, #0xc0
    cmp     w5, #0x80
    b.eq    .Lutf8_next
    b       .Lutf8_invalid
.Lutf8_four:
    sub     x4, x2, x0
    cmp     x4, #3
    b.lo    .Lutf8_invalid
    ldrb    w4, [x0], #1
    cmp     w3, #0xf0
    b.ne    .Lutf8_four_not_f0
    cmp     w4, #0x90
    b.lo    .Lutf8_invalid
    b       .Lutf8_four_second_upper
.Lutf8_four_not_f0:
    cmp     w3, #0xf4
    b.ne    .Lutf8_four_second_normal
    cmp     w4, #0x80
    b.lo    .Lutf8_invalid
    cmp     w4, #0x8f
    b.hi    .Lutf8_invalid
    b       .Lutf8_four_tail
.Lutf8_four_second_normal:
    cmp     w4, #0x80
    b.lo    .Lutf8_invalid
.Lutf8_four_second_upper:
    cmp     w4, #0xbf
    b.hi    .Lutf8_invalid
.Lutf8_four_tail:
    ldrb    w4, [x0], #1
    and     w5, w4, #0xc0
    cmp     w5, #0x80
    b.ne    .Lutf8_invalid
    ldrb    w4, [x0], #1
    and     w5, w4, #0xc0
    cmp     w5, #0x80
    b.eq    .Lutf8_next
.Lutf8_invalid:
    mov     w0, #1
    ret
.Lutf8_valid:
    mov     w0, wzr
    ret

/* Input has already passed strict UTF-8 validation.  Return one iff it
 * contains a scalar outside Rust/Unicode White_Space, matching the host codec.
 */
    .p2align 4
.Lcontains_non_whitespace:
    add     x2, x0, x1
.Lwhite_next:
    cmp     x0, x2
    b.hs    .Lwhite_only
    ldrb    w3, [x0], #1
    cmp     w3, #0x80
    b.lo    .Lwhite_classify
    cmp     w3, #0xdf
    b.hi    .Lwhite_decode_three
    and     w3, w3, #0x1f
    ldrb    w4, [x0], #1
    and     w4, w4, #0x3f
    lsl     w3, w3, #6
    orr     w3, w3, w4
    b       .Lwhite_classify
.Lwhite_decode_three:
    cmp     w3, #0xef
    b.hi    .Lwhite_decode_four
    and     w3, w3, #0x0f
    ldrb    w4, [x0], #1
    ldrb    w5, [x0], #1
    and     w4, w4, #0x3f
    and     w5, w5, #0x3f
    lsl     w3, w3, #12
    lsl     w4, w4, #6
    orr     w3, w3, w4
    orr     w3, w3, w5
    b       .Lwhite_classify
.Lwhite_decode_four:
    and     w3, w3, #0x07
    ldrb    w4, [x0], #1
    ldrb    w5, [x0], #1
    ldrb    w6, [x0], #1
    and     w4, w4, #0x3f
    and     w5, w5, #0x3f
    and     w6, w6, #0x3f
    lsl     w3, w3, #18
    lsl     w4, w4, #12
    lsl     w5, w5, #6
    orr     w3, w3, w4
    orr     w3, w3, w5
    orr     w3, w3, w6
.Lwhite_classify:
    cmp     w3, #0x20
    b.eq    .Lwhite_next
    cmp     w3, #0x09
    b.lo    .Lhas_non_whitespace
    cmp     w3, #0x0d
    b.ls    .Lwhite_next
    cmp     w3, #0x85
    b.eq    .Lwhite_next
    cmp     w3, #0xa0
    b.eq    .Lwhite_next
    mov     w4, #0x1680
    cmp     w3, w4
    b.eq    .Lwhite_next
    mov     w4, #0x2000
    cmp     w3, w4
    b.lo    .Lhas_non_whitespace
    add     w5, w4, #10
    cmp     w3, w5
    b.ls    .Lwhite_next
    mov     w4, #0x2028
    cmp     w3, w4
    b.eq    .Lwhite_next
    add     w4, w4, #1
    cmp     w3, w4
    b.eq    .Lwhite_next
    mov     w4, #0x202f
    cmp     w3, w4
    b.eq    .Lwhite_next
    mov     w4, #0x205f
    cmp     w3, w4
    b.eq    .Lwhite_next
    mov     w4, #0x3000
    cmp     w3, w4
    b.eq    .Lwhite_next
.Lhas_non_whitespace:
    mov     w0, #1
    ret
.Lwhite_only:
    mov     w0, wzr
    ret

/* Send one complete frame through an RFC 1055 SLIP envelope. */
    .p2align 4
.Lslip_send:
    sub     sp, sp, #48
    stp     x29, x30, [sp, #0]
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x29, sp
    mov     x19, x0
    mov     x20, x1
    mov     w0, #WRELA_SLIP_END
    bl      .Lpl011_putc
    cbnz    w0, .Lslip_timeout
    cbz     x20, .Lslip_end
.Lslip_byte:
    ldrb    w21, [x19], #1
    cmp     w21, #WRELA_SLIP_END
    b.eq    .Lslip_escape_end
    cmp     w21, #WRELA_SLIP_ESC
    b.eq    .Lslip_escape_esc
    mov     w0, w21
    bl      .Lpl011_putc
    cbnz    w0, .Lslip_timeout
    b       .Lslip_next
.Lslip_escape_end:
    mov     w0, #WRELA_SLIP_ESC
    bl      .Lpl011_putc
    cbnz    w0, .Lslip_timeout
    mov     w0, #WRELA_SLIP_ESC_END
    bl      .Lpl011_putc
    cbnz    w0, .Lslip_timeout
    b       .Lslip_next
.Lslip_escape_esc:
    mov     w0, #WRELA_SLIP_ESC
    bl      .Lpl011_putc
    cbnz    w0, .Lslip_timeout
    mov     w0, #WRELA_SLIP_ESC_ESC
    bl      .Lpl011_putc
    cbnz    w0, .Lslip_timeout
.Lslip_next:
    subs    x20, x20, #1
    b.ne    .Lslip_byte
.Lslip_end:
    mov     w0, #WRELA_SLIP_END
    bl      .Lpl011_putc
    b       .Lslip_return
.Lslip_timeout:
    mov     w0, #1
.Lslip_return:
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp, #0]
    add     sp, sp, #48
    ret

/* Bounded PL011 byte write.  Return 0 on transfer, 1 on timeout. */
    .p2align 4
.Lpl011_putc:
    mov     x1, #WRELA_PL011_BASE
    movz    w2, #0x4240
    movk    w2, #0x000f, lsl #16     /* WRELA_PL011_POLLS = 1,000,000 */
.Lpl011_wait:
    ldr     w3, [x1, #WRELA_PL011_FR]
    tbz     w3, #WRELA_PL011_TXFF_BIT, .Lpl011_ready
    subs    w2, w2, #1
    b.ne    .Lpl011_wait
    mov     w0, #1
    ret
.Lpl011_ready:
    str     w0, [x1, #WRELA_PL011_DR]
    dsb     oshst
    mov     w0, wzr
    ret

    .section .rdata,"dr"
    .p2align 3
/* Absolute anchor intentionally produces ARM64 ADDR64/base-relocation evidence. */
.Lruntime_relocation_anchor:
    .quad   wrela_rt_v2_image_enter
.Lassert_default_message:
    .ascii  "assertion failed"

    .section .bss,"bw"
    .p2align 4
.Lruntime_state:
    .zero   4
.Lrecord_mode:
    .zero   4
.Limage_handle:
    .zero   8
.Lsystem_table:
    .zero   8
.Lrecord_write:
    .zero   8
.Lrecord_read:
    .zero   8
.Ltest_sequence:
    .zero   8
.Ltest_terminal:
    .zero   4
.Ltest_terminal_passed:
    .zero   4
.Ltest_terminal_failed:
    .zero   4
.Ltest_active:
    .zero   4
.Ltest_active_id:
    .zero   4
.Ltest_declared_count:
    .zero   4
.Ltest_started_count:
    .zero   4
.Ltest_completed_passed:
    .zero   4
.Lfatal_code:
    .zero   4
.Lfatal_detail:
    .zero   8
    .p2align 4
.Lassert_frame_buffer:
    .zero   WRELA_ASSERT_FRAME_BYTES
    .p2align 6
.Lrecord_log:
    .zero   WRELA_LOG_BYTES
