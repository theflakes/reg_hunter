extern crate tree_magic;        // needed to find MIME type of files
extern crate path_abs;          // needed to create absolute file paths from relative
extern crate md5;
extern crate lnk;


use crate::{data_defs::*, mutate::*, process_file, time::*};
use std::{fs::{self, File}, io::{self, BufRead, BufReader, Read}};
use path_abs::{PathAbs, PathInfo};
use lnk::{ShellLink};
use std::os::windows::prelude::*;


const MAX_FILE_SIZE: u64 = 256000000;

// return file mime type string
pub fn get_filetype(
                    buffer: &mut Vec<u8>
                ) -> String
{
    tree_magic::from_u8(buffer)
}

// get handle to a file
pub fn open_file(
                file_path: &std::path::Path
            ) -> std::io::Result<std::fs::File> 
{
    match File::open(&file_path) {
        Ok(f) => return Ok(f),
        Err(e) => return Err(e)
    }
}

// read all file content for examination for interesting strings
pub fn read_file_string(
                        file: &std::path::Path
                    ) -> std::io::Result<String> 
{
    match fs::read_to_string(file) {
        Ok(f) => Ok(f.replace('\u{0000}', " ").trim().to_string()),  // Unicode nulls are replaced with spaces (look for better solution)
        Err(_e) => Ok("".to_string())
    }
}

// read in file as byte vector
pub fn read_file_bytes(
                        mut file: &std::fs::File
                    ) -> std::io::Result<Vec<u8>> 
{
    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(f) => f,
        Err(_e) => return Ok(vec![])
    };
    Ok(buffer)
}

// get metadata for the file's content (md5, mime_type)
pub fn get_file_content_info(
                            file: &std::fs::File
                        ) -> std::io::Result<(String, String)> 
{
    let mut md5 = "".to_string();
    let mut mime_type ="".to_string();
    if file.metadata()?.len() != 0 { // don't bother with opening empty files
        if file.metadata()?.len() <= MAX_FILE_SIZE { // don't hash very large files
            let mut buffer = read_file_bytes(file)?;
            md5 = format!("{:x}", md5::compute(&buffer)).to_lowercase();
            mime_type = get_filetype(&mut buffer);
            drop(buffer);
        } 
    } else {
        md5 = "d41d8cd98f00b204e9800998ecf8427e".to_string(); // md5 of empty file
    }
    Ok((md5, mime_type))
}

// read file's lines into a string vec for parsing
pub fn file_to_vec(
                    filename: &str
                ) -> io::Result<Vec<String>> 
{
    let file_in = fs::File::open(filename)?;
    let file_reader = BufReader::new(file_in);
    Ok(file_reader.lines().filter_map(io::Result::ok).collect())
}

// is a file or directory hidden
pub fn is_hidden(
                file_path: &std::path::PathBuf
            ) -> std::io::Result<bool>  
{
    let metadata = fs::metadata(file_path)?;
    let attributes = metadata.file_attributes();
    
    // see: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
    if (attributes & 0x2) > 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}

// find the parent directory of a given dir or file
pub fn get_parent_dir(
                path: &std::path::Path
            ) -> &std::path::Path 
{
    match path.parent() {
        Some(d) => return d,
        None => return path
    };
}

// return the path that a symlink points to
fn resolve_link(
                    link_path: &std::path::Path,
                    file_path: &std::path::Path
                ) -> std::io::Result<std::path::PathBuf> 
{
    let parent_dir = get_parent_dir(link_path);
    match std::env::set_current_dir(parent_dir) {
        Ok(f) => f,
        Err(_e) => return Ok(std::path::PathBuf::new())
    };
    let abs = PathAbs::new(&file_path)?;
    Ok(dunce::simplified(&abs.as_path()).into())
}

// gather metadata for symbolic links
fn process_link(
                    pdt: &str,
                    link_path: String, 
                    file_path: String, 
                    hidden: bool,
                    arguments: String,
                    hotkey: String
                ) -> std::io::Result<()> 
{
    let metadata = match fs::metadata(&link_path) {
        Ok(m) => m,
        _ => return Ok(())
    };
    let mut ctime = get_epoch_start();  // Most linux versions do not support created timestamps
    if metadata.created().is_ok() {
        ctime = format_date(metadata.created()?.into())?;
    }
    let atime = format_date(metadata.accessed()?.into())?;
    let wtime = format_date(metadata.modified()?.into())?;
    let size = metadata.len();
    TxLink::new(pdt.to_string(), "ShellLink".to_string(), get_now()?, 
                            link_path, file_path, atime, wtime, 
                            ctime, size, hidden, arguments, hotkey).report_log();

    Ok(())
}

fn format_hotkey_text(
                    hotkey: String
                ) ->  std::io::Result<String>
{
    let mk = hotkey
        .replace("HotkeyFlags { low_byte: ", "")
        .replace(", high_byte: ", " ")
        .replace(" }", "");
    let keys: Vec<&str> = mk.split(' ').collect();
    let mut hk = match keys.len() {
        0 => String::new(),
        n => keys[n-1].to_string()
    };
    for k in keys.iter().rev().skip(1) {
        hk = format!("{}-{}", hk, k);
    }

    Ok(hk)
}

/*
    determine if a file is a symlink or not
    return parent data_type and path to file
    never return the path to a symnlink
*/
pub fn get_link_info(
                    pdt: &str, 
                    link_path: &std::path::Path,
                    already_seen: &mut Vec<String>
                ) -> std::io::Result<()> 
{
    let symlink= match ShellLink::open(&link_path) {
        Ok(l) => l,
        Err(_e) => return Ok(())
    };
    let file_path = match symlink.relative_path() {
        Some(p) => push_file_path(p, ""),
        None => std::path::PathBuf::new()
    };

    // translate link target path to absolute path
    let path = resolve_link(&link_path, &file_path)?;

    let arguments =  match symlink.arguments() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    let hotkey = format_hotkey_text(format!("{:?}", symlink.header().hotkey()))?;
    process_link(&pdt, 
        link_path.to_string_lossy().into(), 
        path.to_string_lossy().into(), 
            is_hidden(&link_path.into())?,
                arguments, hotkey)?;

    process_file("ShellLink", &path, already_seen)?;

    Ok(())
}