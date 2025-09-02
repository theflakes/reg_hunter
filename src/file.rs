extern crate infer;
extern crate md5;
extern crate lnk;


use crate::{data_defs::*, mutate::*, time::*};
use std::{fs::{self, File}, io::{self, BufRead, BufReader, Read}, path::PathBuf};
use bstr::ByteSlice;
use path_abs::{PathAbs, PathInfo};
use lnk::{encoding::{self, WINDOWS_1252}, LinkInfo, ShellLink, extradata::ExtraDataBlock};
use std::os::windows::prelude::*;
use std::{str, env};
use regex::Regex;
use regex::Captures;


const MAX_FILE_SIZE: u64 = 256000000;

// return file mime type string
fn get_mimetype(buffer: &[u8]) -> String {
    let kind = infer::get(buffer);
    match kind {
        Some(k) => k.mime_type().to_string(),
        None => "".to_string()
    }
}

// get handle to a file
pub fn open_file(
                file_path: &std::path::Path
            ) -> std::io::Result<std::fs::File> 
{
    match File::options().read(true).write(false).open(&file_path) {
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
            mime_type = get_mimetype(&mut buffer);
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

// return the path that a symlink points to
fn resolve_link(
                    link_path: &std::path::Path,
                    file_path: &String
                ) -> std::io::Result<String> 
{
    let parent_dir = get_parent_dir(link_path);
    match std::env::set_current_dir(parent_dir) {
        Ok(f) => f,
        Err(_e) => {
            let p = file_path.to_owned();
            return Ok(p)
        }
    };
    let expanded_path = expand_env_vars(file_path)?;
    // Ok(expanded_path)
    let abs = PathAbs::new(&expanded_path)?;
    Ok(dunce::simplified(&abs.as_path()).to_string_lossy().into_owned())
}

/*
    return parent data_type and path to file
    never return the path to a symnlink
    REFACTOR
*/
pub fn get_link_info(
            pdt: &str, 
            link_path: &std::path::Path,
            already_seen: &mut Vec<String>
        ) -> std::io::Result<()> 
{
    let symlink= match ShellLink::open(&link_path, WINDOWS_1252) {
        Ok(l) => l,
        Err(_e) => return Ok(())
    };
    let working_dir = match symlink.string_data().working_dir() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    let metadata = match fs::metadata(&link_path) {
        Ok(m) => m,
        Err(_e) => return Ok(())
    };
    let mut rel_path = match symlink.string_data().relative_path() {
        Some(p) => p.to_string(),
        None => String::new()
    };

    let mut path = resolve_link(&link_path, &rel_path)?;
    if path.is_empty() {
        for block in symlink.extra_data().blocks() {
            match block {
                ExtraDataBlock::EnvironmentProps(target_id) => {
                    if let Some(unicode_target) = target_id.target_unicode() {
                        path = unicode_target.to_string();
                        break;
                    } else  {
                        path = target_id.target_ansi().to_string();
                        break;
                    }
                }
                _ => continue,
            }
        }
    }

    let arguments =  match symlink.string_data().command_line_arguments() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    let hotkey = format_hotkey_text(format!("{:?}", symlink.header().hotkey()))?;
    let mut ctime = get_epoch_start();
    if metadata.created().is_ok() {
        ctime = format_date(metadata.created()?.into())?;
    }
    let atime = format_date(metadata.accessed()?.into())?;
    let wtime = format_date(metadata.modified()?.into())?;
    let size = metadata.len();
    let icon_location = match symlink.string_data().icon_location() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    let comment = match symlink.string_data().name_string() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    let show_command = format!("{:?}", symlink.header().show_command());
    let flags = format!("{:?}", symlink.header().link_flags());
    // let volume = VolumeID::default();
    // let v = match i.volume_id() {
    //     Some(a) => a,
    //     None => &volume
    // };
    // let drive_type = format!("{:?}", v..drive_type());
    // let drive_serial_number = format!("{:?}", v.drive_serial_number());
    // let volume_label = format!("{:?}", v.volume_label());
    TxLink::new(pdt.to_string(), "ShellLink".to_string(), get_now()?, 
            link_path.to_string_lossy().into_owned(), path.clone(), 
                atime, wtime, ctime, size, 
                is_hidden(&link_path.into())?, arguments, hotkey, working_dir,
            icon_location, comment, show_command, flags).report_log();

    let mut pb = PathBuf::new();
    pb.push(path);
    process_file("ShellLink", &pb, already_seen)?;
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
    get_link_info(&pdt, file_path, already_seen)?;   // is this file a symlink? TRUE: get symlink info and path to linked file
    let metadata = match fs::metadata(dunce::simplified(&file_path)) {
        Ok(m) => m,
        Err(e) => return Err(e)
    };
    let mut ctime = get_epoch_start();
    if metadata.created().is_ok() { 
        ctime = format_date(metadata.created()?.to_owned().into())?;
    }
    let atime = format_date(metadata.accessed()?.to_owned().into())?;
    let wtime = format_date(metadata.modified()?.to_owned().into())?;
    let size = metadata.len();
    let file = match open_file(&file_path) {
        Ok(f) => f,
        Err(_e) => return Ok(()),
    };
    let (md5, mime_type) = match get_file_content_info(&file) {
        Ok((m, t)) => (m, t),
        Err(_e) => ("".to_string(), "".to_string())
    };
    drop(file); // close file handle immediately after not needed, to avoid too many files open error

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
            Err(_e) => c.get(0).map_or(String::new(), |m| m.as_str().to_string())
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
        Err(_e) => possible_path.to_string()
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