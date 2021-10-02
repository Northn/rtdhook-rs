use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

pub struct CallHook {
    is_enabled: bool,
    detour_address: usize,
    hook_address: usize,
    original_function_address: usize,
}

impl CallHook {
    #[allow(dead_code)]
    pub fn new(hook_address: usize, detour_address: usize) -> CallHook {
        unsafe {
            if *(hook_address as *const u8) != 0xE8 { panic!("Instruction at 0x{:X} isn't CALL. CALL hook can't be installed!", hook_address); }

            CallHook {
                is_enabled: false,
                detour_address: detour_address,
                hook_address: hook_address,
                original_function_address: *((hook_address + 1usize) as *const usize)
            }
        }
    }

    #[allow(dead_code)]
    fn drop(&mut self) { unsafe { self.uninstall(); } }

    #[allow(dead_code)]
    pub fn install(&mut self) -> bool {
        if self.is_enabled { return false; }
        self.is_enabled = true;

        let hook_address = (self.hook_address + 1) as LPVOID;
        let new_call_offset = self.detour_address.wrapping_sub(self.hook_address).wrapping_sub(5usize);
        let mut old_protection: DWORD = PAGE_EXECUTE_READWRITE;
        unsafe {
            VirtualProtect(hook_address, std::mem::size_of::<usize>(), old_protection, &mut old_protection);
            *(hook_address as *mut usize) = new_call_offset;
            VirtualProtect(hook_address, std::mem::size_of::<usize>(), old_protection, &mut old_protection);
        }
        true
    }

    #[allow(dead_code)]
    pub unsafe fn uninstall(&mut self) -> bool {
        if !self.is_enabled { return false; }
        self.is_enabled = false;

        let hook_address = (self.hook_address + 1) as LPVOID;
        let mut old_protection: DWORD = PAGE_EXECUTE_READWRITE;

        VirtualProtect(hook_address, std::mem::size_of::<usize>(), old_protection, &mut old_protection);
        *(hook_address as *mut usize) = self.original_function_address;
        VirtualProtect(hook_address, std::mem::size_of::<usize>(), old_protection, &mut old_protection);
        
        true
    }

    #[allow(dead_code)]
    pub fn function_ptr(&self) -> usize {
        self.original_function_address.wrapping_add(self.hook_address).wrapping_add(5usize)
    }
}
