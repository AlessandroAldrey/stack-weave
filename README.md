# Stack-Weave / Stack-Spoofer PoC

A signature-resistant, evasion-focused Windows x64 orchestration tool written in Rust. This project serves as a Proof of Concept (PoC) demonstrating how to bypass dynamic thread telemetry, behavioral hooks, and deep call stack inspection (Stack Unwinding) in modern Windows environments.

This crate provides a highly abstract, secure API to virtualize thread stack frames and execute Indirect Syscalls natively, adhering strictly to the Microsoft x64 Calling Convention.

---

## Architecture & Evasion Mechanics

When an EDR or security agent intercepts a system call, it performs an unwinding analysis of the calling thread's stack looking for unbacked memory pages (e.g., code executing outside of a legitimate, signed DLL). This library neutralizes that detection vector through a multi-stage pipeline:

1. **Synthetic Stack Frame Virtualization:** Invokes a hand-crafted `naked_asm!` orchestration layer that mirrors the Microsoft x64 Calling Convention. It preserves non-volatile registers (`RDI`), backs up the native `RSP`, and virtualizes a fake call stack pointing to trusted system anchors (e.g., `BaseThreadInitThunk`). The system call appears to originate entirely from legitimate Windows threads.
2. **Symmetric Stack Realignment:** Outfitted with an automated stack recovery process (`lea rax, [rsp + 8]`) ensuring that the backing structure retains mathematically exact CPU frames, preventing telemetry desynchronization or edge-case access violations (`0xC0000005`).

---

## Ecosystem Dependencies

This crate is designed to operate as a core component within an evasion ecosystem and depends on the following external libraries:

* **[raw-eat-parser](https://github.com/AlessandroAldrey/raw-eat-parser):** This library allows you to dynamically locate loaded modules in memory and manually parse the Export Address Table (EAT) of a Portable Executable (PE) image. This approach effectively bypasses conventional Windows API monitoring mechanisms such as hooks on GetModuleHandle and GetProcAddress.
* **[phantom-call](https://github.com/AlessandroAldrey/phantom-call):**  Rust library designed for executing indirect syscalls on Windows x86-64. It dynamically resolves System Service Numbers (SSNs) and locates execution gadgets within ntdll.dll to bypass user-mode hooks and interact with the NT kernel.

### Cargo.toml Integration
To include this library in your own workspace loader, add the following to your `Cargo.toml`:

```toml
[dependencies]
stack_weave = { git = "[https://github.com/AlessandroAldrey/stack-weave.git](https://github.com/AlessandroAldrey/stack-weave.git)" }

# Ensure the following core ecosystem crates are available in your toolchain
eat_walker = { git = "[https://github.com/AlessandroAldrey/raw-eat-parser.git](https://github.com/AlessandroAldrey/raw-eat-parser.git)" }
phantom_call = { git = "[https://github.com/AlessandroAldrey/phantom-call.git](https://github.com/AlessandroAldrey/phantom-call.git)" }