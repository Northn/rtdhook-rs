use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::memoryapi::{VirtualProtect, VirtualAlloc, VirtualFree};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE};
use std::ptr::{write_bytes, copy_nonoverlapping};

pub struct JmpHook {
    is_enabled: bool,
    hook_size: usize,
    detour_address: usize,
    hook_address: usize,
    trampoline: usize,
    original_prologue: usize
}

impl JmpHook {
    #[allow(dead_code)]
    pub fn new(hook_address: usize, detour_address: usize, prologue_size: usize) -> JmpHook {
        if prologue_size < 5 {
            panic!("Prologue size is less than 5, I can't install JMP hook here!");
        }
        let mut hook = JmpHook {
            is_enabled: false,
            hook_size: prologue_size,
            detour_address: detour_address,
            hook_address: hook_address,
            trampoline: 0,
            original_prologue: 0
        };
        unsafe {
            let original_prologue = VirtualAlloc(0 as LPVOID, prologue_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as usize;
            let trampoline = VirtualAlloc(0 as LPVOID, prologue_size + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as usize;

            copy_nonoverlapping(hook_address as *const u8, original_prologue as *mut u8, prologue_size);
            copy_nonoverlapping(original_prologue as *const u8, trampoline as *mut u8, prologue_size);

            *((trampoline + prologue_size + 0) as *mut u8) = 0xE9;
            *((trampoline + prologue_size + 1) as *mut usize) = hook_address
                .wrapping_sub(trampoline)
                .wrapping_sub(prologue_size)
                .wrapping_add(prologue_size - 5);

            hook.trampoline = trampoline;
            hook.original_prologue = original_prologue;
        }
        
        hook
    }

    #[allow(dead_code)]
    fn drop(&mut self) {
        unsafe {
            self.uninstall();
            VirtualFree(self.trampoline as LPVOID, 0, MEM_RELEASE);
            VirtualFree(self.original_prologue as LPVOID, 0, MEM_RELEASE);
        }
    }

    #[allow(dead_code)]
    pub fn install(&mut self) -> bool {
        if self.is_enabled { return false; }
        self.is_enabled = true;

        let mut old_protection: DWORD = PAGE_EXECUTE_READWRITE;
        unsafe {
            VirtualProtect(self.hook_address as LPVOID, self.hook_size, old_protection, &mut old_protection);
            *((self.hook_address + 0) as *mut u8) = 0xE9;
            *((self.hook_address + 1) as *mut usize) = self.detour_address
                .wrapping_sub(self.hook_address)
                .wrapping_sub(5);
            
            write_bytes((self.hook_address + 5) as *mut u8, 0x90, self.hook_size - 5);

            VirtualProtect(self.hook_address as LPVOID, self.hook_size, old_protection, &mut old_protection);
        }
        true
    }

    #[allow(dead_code)]
    pub unsafe fn uninstall(&mut self) -> bool {
        if !self.is_enabled { return false; }
        self.is_enabled = false;

        let mut old_protection: DWORD = PAGE_EXECUTE_READWRITE;

        VirtualProtect(self.hook_address as LPVOID, self.hook_size, old_protection, &mut old_protection);

        copy_nonoverlapping(self.original_prologue as *const u8, self.hook_address as *mut u8, self.hook_size);

        VirtualProtect(self.hook_address as LPVOID, self.hook_size, old_protection, &mut old_protection);
        
        true
    }

    #[allow(dead_code)]
    pub fn trampoline(&self) -> usize {
        self.trampoline
    }

    #[allow(dead_code)]
    pub fn enabled(&self) -> bool {
        self.is_enabled
    }
}
