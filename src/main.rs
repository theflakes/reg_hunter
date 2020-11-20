/*
    Author: Brian Kellogg

    Purpose: Operational triage of Windows registry.

    I try to continue through all errors to allow the analysis to complete.
    But, no doubt, I missed some corner cases.
*/
extern crate winreg;            // Windows registry access
extern crate chrono;            // DateTime manipulation
extern crate regex;
extern crate dunce;             // used to convert Windows UNC paths to regular paths

#[macro_use] extern crate lazy_static;

mod data_defs;
mod file;
mod mutate;
mod time;
mod hunts;

use regex::Captures;
use {data_defs::*, file::*, time::*, mutate::*, hunts::*};
use std::{io, fs, str, env};
use winreg::enums::*;
use winreg::RegKey;
use regex::Regex;


/*
    regex's to find interesting strings
    capture and report the line that the interesting string is found in
*/
fn run_hunts(
                    key: &str,
                    value_name: &str,
                    value: &str
                ) -> std::io::Result<Results> 
{
    let mut t: Results = Results {result: false, tags: vec![]};

    if (ARGS.flag_everything || ARGS.flag_email) && found_email(value)? 
        { t.result = true; t.tags.push("Email".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_encoding) && found_encoding(value)? 
        { t.result = true; t.tags.push("Encoding".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_ip) && found_ipv4(value)? 
        { t.result = true; t.tags.push("IPv4".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_obfuscation) && found_obfuscation(value)? 
        { t.result = true; t.tags.push("Obfuscation".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_script) && found_script(value)? 
        { t.result = true; t.tags.push("Script".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_shell) && found_shell(value)? 
        { t.result = true; t.tags.push("Shell".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_shellcode) && found_shellcode(value)? 
        { t.result = true; t.tags.push("ShellCode".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_suspicious) && found_suspicious(value)?    
        { t.result = true; t.tags.push("Suspicious".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_unc) && found_unc(value)? 
        { t.result = true; t.tags.push("UNC".to_string()) }
    if (ARGS.flag_everything || ARGS.flag_url) && found_url(value)? 
        { t.result = true; t.tags.push("URL".to_string()) }

    // custom regex cmd line hunt
    if ARGS.flag_path || ARGS.flag_name || ARGS.flag_value {
        if ARGS.flag_regex != "$^" && found_custom(key, value_name, value)? 
            { t.result = true; t.tags.push("Custom".to_string()) }
    }
    
    Ok(t)
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
fn find_file(
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

/*
    identify files being referenced in the file content 
    this is so we can harvest the metadata on these files as well
*/
fn find_file_paths(
                    text: &str, 
                    already_seen: 
                    &mut Vec<String>
                ) -> std::io::Result<bool> 
{
    if !ARGS.flag_everything && !ARGS.flag_file { return Ok(false); }

    lazy_static! {
        static ref RE: Regex = Regex::new(r#"(?mix)
            (
                # file path
                (?:[a-z]:|%\S+%)\\(?:[a-z0-9\x20_.$@!&\#%()^',\[\]+;~`{}=-]{1,255}\\)*[a-z0-9\x20_.$@!&\#%()^',\[\]+;~`{}=-]{1,255}\.[a-z0-9]{1,5}|
                # partial path
                ^\\?(?:System32|Syswow64|SystemRoot)\\[a-z0-9\x20_.$@!&\#%()^',\[\]+;~`{}=-]{1,255}\.[a-z0-9]{1,5}|
                # just a file name
                ^[a-z0-9\x20_.$!&\#%()^'\[\]+;~`{}=-]{1,255}\.[a-z][a-z0-9]{0,4}$
            )
        "#).expect("Invalid Regex");
    }
    
    let mut result = false;
    for c in RE.captures_iter(text) {
        result = true;
        let path = std::path::Path::new(&c[1]);
        find_file("Registry", path, already_seen)?;
    }
    
    Ok(result)
}

fn find_interesting_stuff(
                            key: &str,
                            value_name: &str,
                            value: &str,
                            already_seen: &mut Vec<String>
                        )  -> std::io::Result<Results> {
    let found_path = find_file_paths(&value.trim().trim_start_matches('"').trim_end_matches('"'), already_seen)?;
    let found_interesting = run_hunts(&key, &value_name, &value)?;

    let mut t: Results = Results {result: false, tags: vec![]};
    if found_path {
        t.result = true;
        t.tags.push("File".to_string());
    } 
    if found_interesting.result {
        t.result = true;
        t.tags.extend(found_interesting.tags);
    }

    Ok(t)
}

// report out in json
fn print_value(
                pdt: &str,
                dt: &str,
                hive: &str, 
                key: &str, 
                mut value_name: String, 
                value: &str, 
                reg_type: String, 
                lwt: &str, 
                tags: Vec<String>
            ) -> std::io::Result<()> 
{
    if value.is_empty() || value.trim() == r#""""# { return Ok(()) }
    if value_name.is_empty() { value_name = "(Default)".to_string(); } // note: empty value name = (Default)
    TxRegistry::new(pdt.to_string(), dt.to_owned(), 
                    get_now()?, DEVICE_NAME.to_owned(), DEVICE_DOMAIN.to_owned(), 
                    DEVICE_TYPE.to_owned(), hive.to_string(), key.to_string(), 
                    value_name, reg_type, value.to_string(), 
                    lwt.to_string(), tags
                ).report_log();
    Ok(())
}

// find registry key last write time
fn get_reg_last_write_time(
                            key: &RegKey
                        ) -> Result<String, std::io::Error>    
{
    let info = key.query_info()?;
    let ts = info.get_last_write_time_system();
    let lwt = format!("{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}", 
        ts.wYear, ts.wMonth, ts.wDay, ts.wHour, ts.wMinute, ts.wSecond, ts.wMilliseconds);
    Ok(lwt)
}

// get a single value from a reg key given a specific value name
fn get_reg_value(
                    hive: &str, 
                    hkey: &RegKey, 
                    key: &str, 
                    values: &Vec<&str>, 
                    already_seen: &mut Vec<String>
                ) -> std::io::Result<()> 
{
    let n = match hkey.open_subkey(key) {
        Ok(n) => n,
        _ => return Ok(()),
    };
    for v in values {
        let _ = match n.get_raw_value(v) {
            Ok(t) => examine_name_value(hive, &n, key, &v, &t, true, already_seen)?,
            _ => return Ok(()),
        };
    }
    Ok(())
}

// collect all values from a given reg key
fn get_reg_values(
                    hive: &str, 
                    hkey: &RegKey, 
                    key: &str, 
                    always_print: bool,
                    already_seen: &mut Vec<String>
                ) -> std::io::Result<()> 
{
    let s = match hkey.open_subkey(key) {
        Ok(n) => n,
        _ => return Ok(()),
    };
    for value_result in s.enum_values() {
        let _ = match value_result {
            Ok((n, v)) => examine_name_value(hive, &s, key, &n, &v, always_print, already_seen)?,
            _ => continue, 
        };
    }
    Ok(())
}

// do we want to collect all values or just specific ones from a reg key
fn harvest_reg_key(
                    hive: &str, 
                    hkey: &RegKey, 
                    key: &str, 
                    values: &Vec<&str>, 
                    already_seen: &mut Vec<String>
                ) -> std::io::Result<()> 
{
    if std::vec::Vec::is_empty(values) {
        get_reg_values(hive, hkey, key, true, already_seen)?;
    } else {
        get_reg_value(hive, hkey, key, values, already_seen)?;
    }

    if ARGS.flag_limit { sleep() }
    Ok(())
}

// get all sub keys of a given key
fn recurse_reg_key(
                    hive: &str, 
                    hkey: &RegKey, 
                    key: &str, 
                    values: &Vec<&str>, 
                    suffixes: &Vec<&str>, 
                    already_seen: &mut Vec<String>
                ) -> std::io::Result<()> 
{
    let r = match hkey.open_subkey(key) {
        Ok(t) => t,
        _ => return Ok(()),
    };
    for key_result in r.enum_keys() {
        let k = match key_result {
            Ok(v) => v,
            _ => continue, 
        };
        if std::vec::Vec::is_empty(suffixes) {
            harvest_reg_key(hive, hkey, &format!("{}\\{}", key, k), values, already_seen)?;
        } else {
            for s in suffixes {
                harvest_reg_key(hive, hkey, &format!("{}\\{}{}", key, k, s), values, already_seen)?;
            }
        }
    }
    Ok(())
}

/*
    we want to handle a few reg keys differently
    for when we search the more interesting keys
*/
fn harvest_reg_keys(
                    hive: &str, 
                    hkey: &RegKey, 
                    key: &str, 
                    values: &Vec<&str>, 
                    already_seen: &mut Vec<String>
                ) -> std::io::Result<()> 
{
    let k = key.to_lowercase();
    if k.contains("system\\currentcontrolset\\services\\portproxy") {
        harvest_reg_key(hive, hkey, &format!("{}{}", k, "\\v4tov4\\tcp"), values, already_seen)?;
        harvest_reg_key(hive, hkey, &format!("{}{}", k, "\\v4tov4\\udp"), values, already_seen)?;
        harvest_reg_key(hive, hkey, &format!("{}{}", k, "\\v4tov6\\tcp"), values, already_seen)?;
        harvest_reg_key(hive, hkey, &format!("{}{}", k, "\\v4tov6\\udp"), values, already_seen)?;
        harvest_reg_key(hive, hkey, &format!("{}{}", k, "\\v6tov4\\tcp"), values, already_seen)?;
        harvest_reg_key(hive, hkey, &format!("{}{}", k, "\\v6tov4\\udp"), values, already_seen)?;
        harvest_reg_key(hive, hkey, &format!("{}{}", k, "\\v6tov6\\tcp"), values, already_seen)?;
        harvest_reg_key(hive, hkey, &format!("{}{}", k, "\\v6tov6\\udp"), values, already_seen)?;
    } else if k.contains("system\\currentcontrolset\\services\\") {
        harvest_reg_key(hive, hkey, key, values, already_seen)?;
        recurse_reg_key(hive, hkey, key, values, &[].to_vec(), already_seen)?;
    } else if k.contains("system\\currentcontrolset\\services") {
        recurse_reg_key(hive, hkey, key, values, &[].to_vec(), already_seen)?;
        recurse_reg_key(hive, hkey, key, &["servicedll"].to_vec(), &["\\parameters"].to_vec(), already_seen)?;
    } else if k.contains("\\ats") {
        recurse_reg_key(hive, hkey, key, values, &[].to_vec(), already_seen)?;
        recurse_reg_key(hive, hkey, key, values, &["\\debuginformation"].to_vec(), already_seen)?;
    } else if k.contains("\\classes\\clsid") {
        recurse_reg_key(hive, hkey, key, values, &["\\inprocserver32", "\\localserver32"].to_vec(), already_seen)?;
    } else if k.contains("software\\microsoft\\windows\\currentversion\\explorer\\fileexts") {
        recurse_reg_key(hive, hkey, key, values, &["\\openwithlist"].to_vec(), already_seen)?;
    } else if k.contains("software\\microsoft\\microsoft sql server") {
        recurse_reg_key(hive, hkey, key, values, &["\\tools\\shell\\addins"].to_vec(), already_seen)?;
    } else if k.contains("\\microsoft\\office\\") {
        harvest_reg_key(hive, hkey, key, values, already_seen)?;
        recurse_reg_key(hive, hkey, key, values, &[].to_vec(), already_seen)?;
    } else if k.contains("\\microsoft\\office") {
        recurse_reg_key(hive, hkey, key, values, &["\\outlook\\security"].to_vec(), already_seen)?;
    } else {
        harvest_reg_key(hive, hkey, key, values, already_seen)?;
        recurse_reg_key(hive, hkey, key, values, &[].to_vec(), already_seen)?;
    }
    Ok(())
}

// get more interesting HKLM keys
fn process_interesting_hklm(
                            hklm: &RegKey, 
                            already_seen: &mut Vec<String>
                        ) -> std::io::Result<()> 
{
    let hklm_key_values = hklm_init();
    for (key, values) in hklm_key_values.iter() {
        harvest_reg_keys(&"HKEY_LOCAL_MACHINE".to_string(), &hklm , key, values, already_seen)?;
    }
    Ok(())
}

/*
    get sub keys under HKU, these are the SIDs of all local and 
    domain users who have logged on locally
*/ 
fn get_sub_keys(
                key: &RegKey
            ) -> Result<Vec<String>, std::io::Error> 
{
    let mut keys: Vec<String> = [].to_vec();
    for key_result in key.enum_keys() {
        let k = match key_result {
            Ok(v) => v,
            _ => continue, 
        };
        keys.push(k);
    }
    return Ok(keys);
}

// get more interesting HKU keys
fn process_interesting_hku(
                            hku: &RegKey, 
                            already_seen: &mut Vec<String>
                        ) -> std::io::Result<()> 
{
    let hku_key_values = hku_init();
    let sids = get_sub_keys(&hku)?;
    for sid in sids {
        for (key, values) in hku_key_values.iter() {
            harvest_reg_keys(&"HKEY_USERS".to_string(), &hku, &format!("{}\\{}", sid, key), values, already_seen)?;
        } 
    }
    Ok(())
}

// find possible PE MZ header: 4d 5a 90 00
fn find_mz_header(
                    value: &Vec<u8>
                ) -> std::io::Result<Results> 
{
    let mut t: Results = Results {result: false, tags: vec![]};
    if (!ARGS.flag_everything && !ARGS.flag_binary) || value.len() < 32 { return Ok(t) }

    if value.windows(4).any(|s| matches!(s, [0x4D, 0x5A, 0x90, 0x00])) {
			t.result = true;
            t.tags.push("PossibleMzHeader".to_string());
	}

    Ok(t)
}

fn examine_name_value(
                        hive_name: &str, 
                        hkey: &RegKey, 
                        key: &str, 
                        name: &str,
                        value: &winreg::RegValue,
                        always_print: bool,
                        already_seen: &mut Vec<String>
                    ) -> std::io::Result<()> 
{
    let mut tags = vec![];
    
    let mz = find_mz_header(&value.bytes)?;

    /* 
        convert value to string, if conversion fails create an array of bytes
        if value cannot be converted to string, don't run regex' against it
    */
    let (converted, v) = value_to_string(&value.bytes)?;
    let mut interesting = Results {result: false, tags: vec![]};
    if converted {
        interesting = find_interesting_stuff(&key,&name,&v, already_seen)?;
    }

    // Null prefixed value names are an evasion/obfuscation tactic
    let mut null: Results = Results {result: false, tags: vec![]};
    if (ARGS.flag_everything || ARGS.flag_null) && name.starts_with('\u{0000}') {
        null.result = true;
        null.tags = vec!["NullPrefixedName".to_string()];
    }

    if always_print || mz.result || interesting.result || null.result {
        let lwt = get_reg_last_write_time(&hkey)?;
        if null.result {
            tags.extend(null.tags);
        } else if mz.result {
            tags.extend(mz.tags);
        } else if interesting.result {
            tags.extend(interesting.tags);
        }
        print_value("", "Registry", hive_name, key, name.to_string(), &v, format!("{:?}", value.vtype), &lwt, tags)?;
    }
    Ok(())
}

// recursively iterate through all registry keys
fn search_all_value_names(
                            hive: &str, 
                            hkey: &RegKey, 
                            key: &str, 
                            already_seen: &mut Vec<String>
                        ) -> std::io::Result<()> 
{
    let keys = get_sub_keys(&hkey)?;
    for k in keys {
        let mut reg_key: String = k.to_string();
        if ! key.is_empty() { reg_key = format!("{}\\{}", key, &reg_key); }
        get_reg_values(hive, hkey, &k, false, already_seen)?;
        let _ = match hkey.open_subkey(&k) {
            Ok(n) => search_all_value_names(hive, &n, &reg_key, already_seen)?,
            _ => continue,
        };
    }
    Ok(())
}

fn main() -> io::Result<()> 
{
    let mut already_seen: Vec<String> = vec![];  // cache directories and files already examined to avoid multiple touches and possible infinite loops

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hku = RegKey::predef(HKEY_USERS);
    let empty_string = "".to_string();

    // print help screen if no options specified
    if !(ARGS.flag_explicit || ARGS.flag_all) {
        println!("{}", USAGE);
    } else {
        if ARGS.flag_explicit {
            process_interesting_hklm(&hklm, &mut already_seen)?;
            process_interesting_hku(&hku, &mut already_seen)?;
        }
        
        if ARGS.flag_all {
            search_all_value_names(&"HKEY_LOCAL_MACHINE", &hklm, &empty_string, &mut already_seen)?;
            search_all_value_names(&"HKEY_USERS", &hku, &empty_string, &mut already_seen)?;
        }
    }

    Ok(())
}