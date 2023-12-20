use std::ptr;

#[allow(unused_imports)]
use std::io::{self, Read, Write};
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use clap::{arg, command, value_parser};

use std::os::windows::io::AsRawHandle;
use winapi::um::winbase::FILE_TYPE_PIPE;
use winapi::um::consoleapi::GetConsoleMode;
use winapi::um::consoleapi::SetConsoleMode;
use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_PROCESSING;

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
        pv_reserved: *mut winapi::ctypes::c_void, // *mut std::ffi::c_void,
        p_prompt_struct: *const CryptProtectPromptStruct,
        dw_flags: u32,
        p_data_out: *mut Blob,
    ) -> i32;
}

#[repr(C)]
pub struct CryptProtectPromptStruct {
    cb_size: u32,
    dw_prompt_flags: u32,
    hwnd_app: winapi::shared::windef::HWND,
    sz_prompt: *const u16,
}

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

// fn round_trip(input: &[u8]) -> Result<Vec<u8>, ()> {
//     let encrypted = dpapi_wrap(input)?;
//     dpapi_unwrap(&encrypted)
// }

#[allow(dead_code)]
fn read_stdin() -> Result<Vec<u8>, std::io::Error> {
    const MAX_INPUT_SIZE: usize = 16 * 1024 * 1024;
    let mut input = Vec::with_capacity(MAX_INPUT_SIZE);
    std::io::stdin().read_to_end(&mut input)?;
    Ok(input)
}

#[allow(dead_code)]
fn set_binary_mode<W: AsRawHandle>(handle: &W) -> Result<(), io::Error> {
    #[cfg(windows)]
    {
        let handle = handle.as_raw_handle();
        let mut mode: u32 = 0;

        // Check if stdout is a pipe (not a file or console)
        let file_type = unsafe { winapi::um::fileapi::GetFileType(handle as _) };
        if file_type == FILE_TYPE_PIPE {
            let result = unsafe { GetConsoleMode(handle as _, &mut mode) };
            if result != 0 {
                let _ = unsafe { SetConsoleMode(handle as _, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) };
            } else {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

fn read_file_contents(file_path: Option<&PathBuf>) -> Result<Vec<u8>, io::Error> {
    match file_path {
        Some(path) => {
            let mut file = File::open(path)?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)?;
            Ok(contents)
        }
        None => {
            // Decide what to do when the path is None. For now, returning an empty Vec.
            Ok(Vec::new())
        }
    }
}

fn write_bytes_to_file(file_path: Option<&PathBuf>, data: &[u8]) -> io::Result<()> {
    match file_path {
        Some(path) => {
            fs::write(path, data)?;
        }
        None => {
            ()
        }
    }
    Ok(())
}

fn main() {
    let matches = command!()
    .arg(arg!(<MODE>).help("What mode to run the program in").value_parser(["wrap", "unwrap"]))
    .arg(arg!(--input <SPEC_IN> "input file").value_parser(value_parser!(PathBuf)))
    .arg(arg!(--output <SPEC_OUT> "output file").value_parser(value_parser!(PathBuf)))
    .get_matches();


    let input_path = matches.get_one::<PathBuf>("input");
    let input = read_file_contents(input_path.as_deref()).expect("Failed to read file");

    // let input = read_stdin().expect("Failed to read stdin");

    // Note, it's safe to call unwrap() because the arg is required
    let output = match matches
        .get_one::<String>("MODE")
        .expect("'MODE' is required and parsing will fail if its missing")
        .as_str()
    {
        "wrap" => dpapi_wrap(&input).expect("Encryption failed"),
        "unwrap" => dpapi_unwrap(&input).expect("Decryption failed"),
        _ => unreachable!(),
    };

    // std::io::stdout().write_all(&output).expect("Failed to write to stdout");

    // let stdout = std::io::stdout();
    // let mut handle = stdout.lock();
    // set_binary_mode(&handle).expect("Failed to set binary mode");
    // handle.write_all(&output).expect("Failed to write to stdout");

    let output_path = matches.get_one::<PathBuf>("output");
    match write_bytes_to_file(output_path, &output) {
        Ok(_) => println!("Data written to file successfully."),
        Err(err) => eprintln!("Error writing to file: {}", err),
    }
}
