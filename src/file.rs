extern crate tree_magic;        // needed to find MIME type of files
extern crate path_abs;          // needed to create absolute file paths from relative
extern crate md5;
extern crate lnk;


use crate::{data_defs::*, mutate::*, time::*};
use std::{fs::{self, File}, io::{self, BufRead, BufReader, Read}};
use path_abs::{PathAbs, PathInfo};
use lnk::{ShellLink};
use std::os::windows::prelude::*;
use std::{str, env};
use regex::Regex;
use regex::Captures;


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

// harvest a file's metadata
pub fn process_file(
                pdt: &str, 
                file_path: &std::path::Path, 
                already_seen: &mut Vec<String>
            ) -> std::io::Result<()>
{
    let path = file_path.to_string_lossy();

    if !file_path.exists() 
        || !file_path.is_file() 
        || already_seen.contains(&path.to_string()) 
            { return Ok(()) }

    already_seen.push(path.to_string());    // track files we've processed so we don't process them more than once
    get_link_info(&pdt, file_path, already_seen)?;   // is this file a symlink? TRUE: get sysmlink info and path to linked file
    let metadata = match fs::metadata(dunce::simplified(&file_path)) {
        Ok(m) => m,
        _ => return Ok(())
    };
    let mut ctime = get_epoch_start();
    if metadata.created().is_ok() { 
        ctime = format_date(metadata.created()?.to_owned().into())?;
    }
    let atime = format_date(metadata.accessed()?.to_owned().into())?;
    let wtime = format_date(metadata.modified()?.to_owned().into())?;
    let size = metadata.len();
    let file = open_file(&file_path)?;
    let (md5, mime_type) = match get_file_content_info(&file) {
        Ok((m, t)) => (m, t),
        _ => ("".to_string(), "".to_string())
    };
    drop(file); // close file handle immediately after not needed to avoid too many files open error

    TxFile::new(pdt.to_string(), "File".to_string(), get_now()?, 
                path.to_string(), md5, mime_type, atime, wtime, 
                ctime, size, is_hidden(&file_path.to_path_buf())?).report_log();

    Ok(())
}

/*
    From: https://users.rust-lang.org/t/expand-win-env-var-in-string/50320/3
*/
pub fn expand_env_vars(
                        s: &str
                    ) -> std::io::Result<String>  
{
    lazy_static! {
        static ref ENV_VAR: Regex = Regex::new("%([[:word:]]*)%")
            .expect("Invalid Regex");
    }
    
    let result: String = ENV_VAR.replace_all(s, |c:&Captures| match &c[1] {
        "" => String::from("%"),
        varname => match env::var(varname) {
            Ok(v) => v,
            _ => varname.to_string()
        }.to_string()
    }).into();

    Ok(result)
}

/*
    brute force way of finding files
    can do better
*/
pub fn find_file(
                        pdt: &str, 
                        file_path: &std::path::Path,
                        already_seen: &mut Vec<String>
                    ) -> std::io::Result<()>
{
    lazy_static! {
        static ref JUST_FILENAME: Regex = Regex::new(r#"(?mix)
            ^[a-z0-9\x20_.$@!&\#%()^'\[\]+;~`{}=-]{1,255}\.[a-z][a-z0-9]{0,4}$
        "#).expect("Invalid Regex");
    }
    let empty_string = "";
    
    let possible_path = &file_path.to_string_lossy().to_owned().to_lowercase();
    let mut path: String = match expand_env_vars(&possible_path) {
        Ok(p) => p,
        _ => possible_path.to_string()
    };

    if JUST_FILENAME.is_match(&path) {
        for s in SYSTEM_PATHS.iter() {
            let p = &format!("{}{}{}", SYSTEM_DRIVE.to_string(), s, path);
            process_file(pdt, &push_file_path(p, &empty_string), already_seen)?;
        }
    } else {
        if path.starts_with("\\systemroot\\") {
            path = path.replace("\\systemroot\\", &SYSTEM_ROOT.to_string());
        } else if path.starts_with("system32\\") {
            path = path.replace("system32\\", &format!("{}{}", SYSTEM_ROOT.to_string(), "system32\\"));
        } else if path.starts_with("syswow64\\") {
            path = path.replace("syswow64\\", &format!("{}{}", SYSTEM_ROOT.to_string(), "syswow64\\"));
        } else if path.starts_with("sysnative\\") {
            path = path.replace("sysnative\\", &format!("{}{}", SYSTEM_ROOT.to_string(), "sysnative\\"));
        }
        process_file(pdt, &push_file_path(&path, &empty_string), already_seen)?;

        if path.contains("\\system32\\") {
            process_file(pdt, 
                &push_file_path(&path.replace("\\system32\\", "\\sysnative\\"), &empty_string), 
                already_seen)?;
        }

        if path.contains("\\syswow64\\") {
            process_file(pdt, 
                &push_file_path(&path.replace("\\syswow64\\", "\\sysnative\\"), &empty_string), 
                already_seen)?;
        }

        if path.contains("\\program files\\") {
            process_file(pdt, 
                &push_file_path(&path.replace("\\program files\\", "\\program files (x86)\\"), &empty_string), 
                already_seen)?;
        }

        if path.contains("\\program files (x86)\\") {
            process_file(pdt, 
                &push_file_path(&path.replace("\\program files (x86)\\", "\\program files\\"), &empty_string), 
                already_seen)?;
        }
    }

    Ok(())
}