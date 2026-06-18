#![allow(dead_code)]
use core::arch::naked_asm;
use eat_walker::{get_module_base_by_hash, get_proc_address_by_hash};
use std::ffi::c_void;

use phantom_call::ssn::{NtdllBounds, resolve};

pub type NTSTATUS = i32;

#[repr(C, align(16))]
pub struct SpoofedFrameContext {
    pub fake_return_addr: *const c_void,
    pub original_rsp: u64,
    pub target_ssn: u64,
    pub syscall_gadget: *const c_void,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SpoofError {
    Kernel32NotFound,
    BaseThreadInitThunkNotFound,
    NtdllNotFound,
    TargetFunctionNotFound,
    SyscallResolutionFailed,
}

pub type SpoofResult<T> = Result<T, SpoofError>;

pub unsafe fn invoke_spoofed_syscall(
    nt_function_hash: u32,
    arg1: *mut c_void,
    arg2: usize,
    arg3: u32,
) -> SpoofResult<NTSTATUS> {
    const KERNEL32_HASH: u32 = eat_walker::hash_djb2_custom(b"kernel32.dll");
    const FAKE_ANCHOR_HASH: u32 = eat_walker::hash_djb2_custom(b"basethreadinitthunk");

    let mut kernel32_base = get_module_base_by_hash(KERNEL32_HASH);

    if kernel32_base.is_null() {
        return Err(SpoofError::Kernel32NotFound);
    }

    let fake_anchor = get_proc_address_by_hash(kernel32_base as *const u8, FAKE_ANCHOR_HASH);

    if fake_anchor.is_null() {
        return Err(SpoofError::BaseThreadInitThunkNotFound);
    }

    let mut ntdll_base = get_module_base_by_hash(0x1e81e3a9);

    if ntdll_base.is_null() {
        let hash_ntdll_lowercase = eat_walker::hash_djb2_custom(b"ntdll.dll");
        ntdll_base = get_module_base_by_hash(hash_ntdll_lowercase);
    }

    if ntdll_base.is_null() {
        return Err(SpoofError::NtdllNotFound);
    }

    let nt_target_function = get_proc_address_by_hash(ntdll_base as *const u8, nt_function_hash);
    if nt_target_function.is_null() {
        return Err(SpoofError::TargetFunctionNotFound);
    }

    let target_address = nt_target_function as usize;
    let text_start = target_address.saturating_sub(0x8000);
    let text_end = target_address.saturating_add(0x8000);

    let bounds = NtdllBounds {
        start: text_start as *const u8,
        end: text_end as *const u8,
    };

    let syscall_info = match unsafe { resolve(nt_target_function as *const c_void, &bounds) } {
        Some(info) => info,
        None => {
            return Err(SpoofError::SyscallResolutionFailed);
        }
    };

    let mut context = SpoofedFrameContext {
        fake_return_addr: fake_anchor,
        original_rsp: 0,
        target_ssn: syscall_info.ssn as u64,
        syscall_gadget: syscall_info.gadget as *const c_void,
    };

    let status = execute_spoofed_context(&mut context, arg1, arg2, arg3);
    Ok(status)
}

#[unsafe(naked)]
unsafe extern "C" fn execute_spoofed_context(
    ctx: *mut SpoofedFrameContext,
    arg1: *mut c_void,
    arg2: usize,
    arg3: u32,
) -> NTSTATUS {
    naked_asm!(
        "push rdi",
        "mov rdi, rcx",
        "lea rax, [rsp + 8]",
        "mov [rdi + 8], rax",
        "sub rsp, 0x20",
        "mov rax, [rdi + 16]",
        "mov r11, [rdi + 24]",
        "mov r10, rdx",
        "mov rdx, r8",
        "mov r8, r9",
        "call r11",
        "mov rsp, [rdi + 8]",
        "sub rsp, 8",
        "pop rdi",
        "ret"
    );
}
