use std::ptr;
use rustler::types::OwnedBinary;
use rustler::{Env, Error, Term, Binary};
// use rustler::{Atom, NifStruct, ResourceArc};
use std::io::Write;

// https://stackoverflow.com/questions/65969779/rust-ffi-with-windows-cryptounprotectdata
// https://users.rust-lang.org/t/how-can-i-use-cryptunprotectdata/79946/2


#[cfg(target_os = "windows")]
#[repr(C)]
pub struct Blob {
    cb_data: u32,
    pb_data: *const u8,
}

impl Blob {
    pub fn new(buffer: &[u8]) -> Blob {
        Blob {
            cb_data: buffer.len() as u32,
            pb_data: buffer.as_ptr(),
        }
    }

    pub fn slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pb_data, self.cb_data as usize) }
    }
}
 
impl Drop for Blob {
    fn drop(&mut self) {
        unsafe {
            let _ = winapi::um::winbase::LocalFree(self.pb_data as *mut winapi::ctypes::c_void); // std::ffi::c_void);
        }
    }
}

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct CryptProtectPromptStruct {
    cb_size: u32,
    dw_prompt_flags: u32,
    hwnd_app: winapi::shared::windef::HWND,
    sz_prompt: *const u16,
}

#[cfg(target_os = "windows")]
#[link(name = "crypt32")]
extern "system" {
    pub fn CryptUnprotectData(
        p_data_in: *const Blob,
        ppsz_data_descr: *mut *mut u16,
        p_optional_entropy: *const Blob,
        pv_reserved: *mut winapi::ctypes::c_void,
        p_prompt_struct: *const CryptProtectPromptStruct,
        dw_flags: u32,
        p_data_out: *mut Blob,
    ) -> i32;

    pub fn CryptProtectData(
        p_data_in: *const Blob,
        ppsz_data_descr: *mut *mut u16,
        p_optional_entropy: *const Blob,
        pv_reserved: *mut winapi::ctypes::c_void,
        p_prompt_struct: *const CryptProtectPromptStruct,
        dw_flags: u32,
        p_data_out: *mut Blob,
    ) -> i32;
}

#[cfg(target_os = "windows")]
pub fn dpapi_wrap(buffer: &[u8]) -> Result<Vec<u8>, ()> {
    let input = Blob::new(buffer);

    let mut output = Blob {
        cb_data: 0,
        pb_data: ptr::null(),
    };

    let mut desc_out: *mut u16 = ptr::null_mut();

    let success = unsafe {
        CryptProtectData(
            &input,
            &mut desc_out,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            1, // CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if success == 1 {
        Ok(output.slice().to_vec())
    } else {
        Err(())
    }
}

#[cfg(target_os = "windows")]
pub fn dpapi_unwrap(buffer: &[u8]) -> Result<Vec<u8>, ()> {
    let input = Blob::new(buffer);

    let mut output = Blob {
        cb_data: 0,
        pb_data: ptr::null(),
    };

    let mut desc_out: *mut u16 = ptr::null_mut();

    let success = unsafe {
        CryptUnprotectData(
            &input,
            &mut desc_out,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            1, // CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if success == 1 {
        Ok(output.slice().to_vec())
    } else {
        Err(())
    }
}

mod atoms {
    rustler::atoms! {
        ok,
        wrap_failed,
        unwrap_failed,
        only_available_on_windows
    }
}

fn load(_env: Env, _: Term) -> bool {
    // rustler::resource!(FileResource, env);
    true
}

#[cfg(target_os = "windows")]
#[rustler::nif]
fn nif_wrap<'a>(
    env: Env<'a>,
    input: Binary, 
) -> Result<Term<'a>, Error> {
    let data_in: &[u8] = input.as_slice();
    match dpapi_wrap(data_in) {
        Ok(data_out) => {
            let mut binary = OwnedBinary::new(data_out.len()).unwrap();
            let _ = binary.as_mut_slice().write_all(&data_out);
            Ok(binary.release(env).to_term(env))
        },
        Err(()) => {
            Ok(atoms::wrap_failed().to_term(env))
        }
    }
}

#[cfg(target_os = "windows")]
#[rustler::nif]
fn nif_unwrap<'a>(
    env: Env<'a>,
    input: Binary, 
) -> Result<Term<'a>, Error> {
    let data_in: &[u8] = input.as_slice();
    match dpapi_unwrap(data_in) {
        Ok(data_out) => {
            let mut binary = OwnedBinary::new(data_out.len()).unwrap();
            let _ = binary.as_mut_slice().write_all(&data_out);
            Ok(binary.release(env).to_term(env))
        },
        Err(()) => {
            Ok(atoms::unwrap_failed().to_term(env))
        }
    }
}

#[cfg(not(target_os = "windows"))]
#[rustler::nif]
fn nif_wrap<'a>(
    _env: Env<'a>,
    _input: Binary, 
) -> Result<Term<'a>, Error> {
    Ok(atoms::only_available_on_windows().to_term(env))
}


#[cfg(not(target_os = "windows"))]
#[rustler::nif]
fn nif_unwrap<'a>(
    _env: Env<'a>,
    _input: Binary, 
) -> Result<Term<'a>, Error> {
    Ok(atoms::only_available_on_windows().to_term(env))
}


rustler::init!("Elixir.Windows.API.DataProtection.Native", [nif_wrap, nif_unwrap], load = load);
