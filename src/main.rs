use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;

fn array2ulong(b: &[u8]) -> u32 {
    ((b[3] as u32) << 24) | ((b[2] as u32) << 16) | ((b[1] as u32) << 8) | (b[0] as u32)
}

fn rva2foa(rva: u32, section_headers_va: &Vec<u32>, section_headers_size: &Vec<u32>, section_headers_ptr: &Vec<u32>) -> u32 {
    for i in 0..section_headers_va.len() {
        if rva >= section_headers_va[i] && rva <= section_headers_va[i] + section_headers_size[i] {
            return section_headers_ptr[i] + rva - section_headers_va[i];
        }
    }
    0
}

fn get_exports(file_name: &str) -> Result<Vec<String>, String> {
    let mut file = File::open(file_name).map_err(|e| format!("Failed to open file: {}", e))?;

    let mut read_buf1 = vec![0u8; 2048]; // general-purpose buffer

    // Read DOS header and check the MZ signature
    file.seek(SeekFrom::Start(0)).map_err(|e| format!("Failed to seek: {}", e))?;
    file.read_exact(&mut read_buf1).map_err(|e| format!("Failed to read: {}", e))?;

    if read_buf1[0] != 0x4D || read_buf1[1] != 0x5A {
        return Err("Wrong DOS header".to_string());
    }

    let address_of_new_exe_header = array2ulong(&read_buf1[0x3C..0x40]);

    // Read NT header and check the PE signature
    file.seek(SeekFrom::Start(address_of_new_exe_header as u64))
        .map_err(|e| format!("Failed to seek: {}", e))?;
    file.read_exact(&mut read_buf1).map_err(|e| format!("Failed to read: {}", e))?;

    if read_buf1[0] != 0x50 || read_buf1[1] != 0x45 {
        return Err("Wrong NT header".to_string());
    }

    let number_of_sections = (read_buf1[0x07] as u32) << 8 | (read_buf1[0x06] as u32);
    let size_of_optional_header = (read_buf1[0x15] as u32) << 8 | (read_buf1[0x14] as u32);

    if size_of_optional_header == 0 {
        return Err("No optional header".to_string());
    }

    if read_buf1[0x18] != 0x0B || read_buf1[0x19] != 0x02 {
        return Err("PE64 magic mismatch".to_string());
    }

    let export_va = array2ulong(&read_buf1[0x88..0x8C]);
    let export_size = array2ulong(&read_buf1[0x8C..0x90]);

    if export_va == 0 || export_size == 0 {
        return Err("No exports".to_string());
    }

    // Read section headers
    let start_of_section_headers = address_of_new_exe_header + 0x04 + 0x14 + size_of_optional_header;
    file.seek(SeekFrom::Start(start_of_section_headers as u64))
        .map_err(|e| format!("Failed to seek: {}", e))?;
    file.read_exact(&mut read_buf1).map_err(|e| format!("Failed to read: {}", e))?;

    let mut section_headers_va = vec![];
    let mut section_headers_size = vec![];
    let mut section_headers_ptr = vec![];

    for i in 0..number_of_sections {
        let offset = (i * 0x28) as usize;
        section_headers_va.push(array2ulong(&read_buf1[offset + 0x0C..offset + 0x10]));
        section_headers_size.push(array2ulong(&read_buf1[offset + 0x10..offset + 0x14]));
        section_headers_ptr.push(array2ulong(&read_buf1[offset + 0x14..offset + 0x18]));
    }

    // Convert RVA to FOA for export directory
    let export_foa = rva2foa(export_va, &section_headers_va, &section_headers_size, &section_headers_ptr);
    if export_foa == 0 {
        return Err("Can't convert RVA to FOA".to_string());
    }

    let mut export_data = vec![0u8; export_size as usize];
    file.seek(SeekFrom::Start(export_foa as u64))
        .map_err(|e| format!("Failed to seek: {}", e))?;
    file.read_exact(&mut export_data).map_err(|e| format!("Failed to read: {}", e))?;

    // Extract names RVA and convert it to FOA
    let names_rva = array2ulong(&export_data[0x0C..0x10]);
    let names_foa = rva2foa(names_rva, &section_headers_va, &section_headers_size, &section_headers_ptr);

    let number_of_names = array2ulong(&export_data[0x18..0x1C]);

    let mut buf_offset = (names_foa - export_foa) as usize;

    let mut names = vec![];
    let mut current_name = String::new();
    for _ in 0..number_of_names {
        while export_data[buf_offset] != 0 {
            current_name.push(export_data[buf_offset] as char);
            buf_offset += 1;
        }
        names.push(current_name.clone());
        current_name.clear();
        buf_offset += 1;
    }

    Ok(names)
}

fn main() {
    // Capture command line arguments
    let args: Vec<String> = env::args().collect();

    // Check if a filename was provided
    if args.len() != 2 {
        eprintln!("Usage: {} <path_to_pe_file>", args[0]);
        eprintln!("Example: {} C:\\Windows\\System32\\netsh.exe", args[0]);
        return;
    }

    let file_name = &args[1];

    // Call the get_exports function with the user-provided file
    match get_exports(file_name) {
        Ok(names) => {
            for name in names {
                println!("{}", name);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
