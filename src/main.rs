/*
    Author: Brian Kellogg

    Purpose: Operational triage of Windows registry.

    I try to continue through all errors to allow the analysis to complete.
    But, no doubt, I missed some corner cases.

    Adding rust 32bit target:
        rustup toolchain install stable-i686-pc-windows-msvc
        rustup target add i686-pc-windows-msvc

    Compiling:
        x32: cargo build --release --target i686-pc-windows-msvc
        x64: cargo build --release --target x86_64-pc-windows-msvc
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

use {data_defs::*, time::*, mutate::*, hunts::*};
use std::{io, str};
use winreg::enums::*;
use winreg::RegKey;


/*
    Run our hunts
*/
fn run_hunts(
                key: &str,
                value_name: &str,
                value: &str,
                is_string: bool,    // was the reg value successfully converted to a string?
                bytes: &Vec<u8>,
                reg_type: &str,
                already_seen: &mut Vec<String>
            ) -> std::io::Result<Results> 
{
    let mut t: Results = Results {result: false, tags: vec![]};

    if is_string {
        if (ARGS.flag_everything || ARGS.flag_email) && found_email(value)? 
            { t.result = true; t.tags.push("Email".to_string()) }
        if (ARGS.flag_everything || ARGS.flag_encoding) && found_encoding(value)? 
            { t.result = true; t.tags.push("Encoding".to_string()) }
        if (ARGS.flag_everything || ARGS.flag_file) 
            && found_file(&value.trim().trim_start_matches('"').trim_end_matches('"'), already_seen)?
                { t.result = true; t.tags.push("File".to_string()) }
        if (ARGS.flag_everything || ARGS.flag_ip) && found_ipv4(value)? 
            { t.result = true; t.tags.push("IPv4".to_string()) }
        if (ARGS.flag_everything || ARGS.flag_null) && found_null(value_name)?
            { t.result = true; t.tags.push("NullPrefixedName".to_string()) }
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
        // custom regex cmd line hunts
        if (ARGS.flag_value && found_regex(value)?)
            || (ARGS.flag_path && found_regex(key)?) 
            || (ARGS.flag_name && found_regex(value_name)?)
                { t.result = true; t.tags.push("RegexHunt".to_string()) }
    } else {    // still want to run any custom hunt on path and value names if value conversion to string fails
        if (ARGS.flag_path && found_regex(key)?) 
            || (ARGS.flag_name && found_regex(value_name)?) 
                { t.result = true; t.tags.push("RegexHunt".to_string()) }
    }

    // binary searches
    if (ARGS.flag_everything || ARGS.flag_binary) 
        && (found_hex(bytes, &[0x4D, 0x5A, 0x90, 0x00].to_vec())? // did we find bytes that match a MZ header?
        || value.starts_with("TVq"))                             // If the string starts with TVq, assume base64 encoded MZ header 
            { t.result = true; t.tags.push("MzHeader".to_string()) }
    
    if (ARGS.flag_path && found_hex(&key.as_bytes().to_vec(), &FIND_HEX)?) 
        || (ARGS.flag_name && found_hex(&value_name.as_bytes().to_vec(), &FIND_HEX)?) 
        || (ARGS.flag_value && found_hex(&bytes, &FIND_HEX)?) 
            { t.result = true; t.tags.push("HexHunt".to_string()) }

    // hunt and mark registry symbolic links
    if ARGS.flag_link && reg_type.eq("REG_LINK") {
        t.result = true; t.tags.push("Link".to_string())
    }

    Ok(t)
}

fn find_interesting_stuff(
                            key: &str,
                            value_name: &str,
                            value: &str,
                            is_string: bool,    // was the reg value successfully converted to a string?
                            bytes: &Vec<u8>,
                            reg_type: &str,
                            already_seen: &mut Vec<String>
                        )  -> std::io::Result<Results> {
    let found_interesting = run_hunts(&key, &value_name, &value, is_string, bytes, reg_type, already_seen)?;

    let mut t: Results = Results {result: false, tags: vec![]};
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
                tags: Vec<String>,
                error: &str
            ) -> std::io::Result<()> 
{
    if (value.is_empty() || value.trim() == r#""""#) && !ARGS.flag_print { return Ok(()) }
    if value_name.is_empty() { value_name = "(Default)".to_string(); } // note: empty value name = (Default)
    TxRegistry::new(pdt.to_string(), dt.to_owned(), 
                    get_now()?, DEVICE_NAME.to_owned(), DEVICE_DOMAIN.to_owned(), 
                    DEVICE_TYPE.to_owned(), hive.to_string(), key.to_string(), 
                    value_name, reg_type, value.to_string(), 
                    lwt.to_string(), tags, error.to_string()
                ).report_log();
    Ok(())
}

/*
    Try and open a subkey.
    If the openeing the subkey errors, report it in a JSON log.
    NOTE: Will search for hidden reg keys and tag them with "HiddenKey" if found.
        Cannot open the keys created by the RegHide Sysinternal tool with WinReg create for some reason.
        In my testing so far if a key end with unicode \u0000, its malicious.
        RegHide tool: https://docs.microsoft.com/en-us/sysinternals/downloads/reghide
*/
fn open_key(
                hive_name: &str,
                hive: &RegKey,
                key: &str,
                key_path: &str
            ) -> Result<RegKey, std::io::Error>
{
    let _ = match hive.open_subkey_with_flags(key, KEY_READ) {
        Ok(s) => return Ok(s),
        Err(e) => {
                // intentionally hidden key found, always report this
                if key.ends_with('\u{0000}') {
                    print_value("Error", "Registry", hive_name, key_path, 
                    "ERROR_READING".to_string(), "ERROR_READING", 
                    "REG_ERROR".to_string(), "", 
                    vec!["HiddenKey".to_string()], &e.to_string())?;
                } else if ARGS.flag_debug {
                    print_value("Error", "Registry", hive_name, key_path, 
                    "ERROR_READING".to_string(), "ERROR_READING", 
                    "REG_ERROR".to_string(), "", 
                    vec!["Error".to_string()], &e.to_string())?;
                }
                return Err(e)
            }
    };
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
    for v in values {
        let _ = match hkey.get_raw_value(v) {
            Ok(t) => examine_name_value(hive, &hkey, key, &v, &t, true, already_seen)?,
            _ => return Ok(()),
        };
    }
    Ok(())
}

// collect all values from a given reg key
fn get_reg_values(
                    hive: &str, 
                    hkey: &RegKey,
                    key_path: &str,
                    always_print: bool,
                    already_seen: &mut Vec<String>
                ) -> std::io::Result<()> 
{
    for value_result in hkey.enum_values() {
        let _ = match value_result {
            Ok((n, v)) => examine_name_value(hive, &hkey, key_path, &n, &v, always_print, already_seen)?,
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
    let hk =  match open_key(hive, hkey, key, key) {
        Ok(k) => k,
        _ => return Ok(()),  
    };
    if std::vec::Vec::is_empty(values) {
        get_reg_values(hive, &hk, key,  true, already_seen)?;
    } else {
        get_reg_value(hive, &hk, key, values, already_seen)?;
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
    let k =  match open_key(hive, hkey, key, key) {
        Ok(k) => k,
        _ => return Ok(()),  
    };
    for key_result in k.enum_keys() {
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
    let mut k = key.to_lowercase();
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
        // handle different versions of Office, e.g. software\\microsoft\\office\\*.0\\
        if k.contains("*.0") {
            for v in 10..30 {
                k = k.replace("*", &v.to_string());
                recurse_reg_key(hive, hkey, key, values, &[].to_vec(), already_seen)?;
            }
        } else {
            harvest_reg_key(hive, hkey, key, values, already_seen)?;
            recurse_reg_key(hive, hkey, key, values, &[].to_vec(), already_seen)?;
        }
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
    // check if last_write_time is in the examination time window
    let lwt = get_reg_last_write_time(&hkey)?;
    if !in_time_window(&lwt)? { return Ok(()) }

    let mut tags = vec![];

    /* 
        convert value to string, if conversion fails create an array of bytes
        if value cannot be converted to string, don't run regex' against it
    */
    let (converted, v) = value_to_string(&value.bytes)?;
    let reg_type = format!("{:?}", value.vtype);
    let mut interesting = Results {result: false, tags: vec![]};
    if converted {
        interesting = find_interesting_stuff(&key,&name,&v, true, &value.bytes, &reg_type, already_seen)?;
    } else {
        interesting = find_interesting_stuff(&key,&name,&v, false, &value.bytes, &reg_type, already_seen)?;
    }

    if always_print || interesting.result || ARGS.flag_print {
        if interesting.result {
            tags.extend(interesting.tags);
        }
        print_value("", "Registry", hive_name, key, name.to_string(), &v, reg_type, &lwt, tags, "")?;
    }
    Ok(())
}

// recursively iterate through all registry keys
fn search_all_value_names(
                            hive_name: &str, 
                            hkey: &RegKey, 
                            key: &str, 
                            already_seen: &mut Vec<String>
                        ) -> std::io::Result<()> 
{
    get_reg_values(hive_name, hkey, &key, false, already_seen)?;
    let keys = get_sub_keys(&hkey)?;
    for k in keys {
        let mut key_path: String = k.to_string();
        if !key.is_empty() { 
            key_path = format!("{}\\{}", key, key_path); 
        }
        let _ =  match open_key(hive_name, hkey, &k, &key_path) {
            Ok(n) => search_all_value_names(hive_name, &n, &key_path, already_seen)?,
            _ => continue,  
        };
    }
    Ok(())
}

fn search_specific_key_hklm(
                            hive_name: &str, 
                            hive: &RegKey, 
                            key: &str, 
                            already_seen: &mut Vec<String>
                        ) -> std::io::Result<()> 
{
    let hk =  match open_key(hive_name, hive, key, key) {
        Ok(k) => k,
        _ => return Ok(()),  
    };
    search_all_value_names(hive_name, &hk, &key, already_seen)?;

    Ok(())
}

fn search_specific_key_hku(
                            hive_name: &str, 
                            hive: &RegKey, 
                            key: &str, 
                            already_seen: &mut Vec<String>
                        ) -> std::io::Result<()> 
{
    let keys = get_sub_keys(&hive)?;
    for k in keys {
        let key_path = format!("{}\\{}", k, key);
        let hk =  match open_key(hive_name, hive, &key_path, &key_path) {
            Ok(k) => k,
            _ => continue,
        };
        search_all_value_names(hive_name, &hk, &key_path, already_seen)?;
    }

    Ok(())
}

fn main() -> io::Result<()> 
{
    let mut already_seen: Vec<String> = vec![];  // cache directories and files already examined to avoid multiple touches and possible infinite loops

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hku = RegKey::predef(HKEY_USERS);
    let empty_string = String::new();

    // print help screen if no options specified
    if !(ARGS.flag_explicit || ARGS.flag_all) && ARGS.flag_key == "NONE" {
        println!("{}", USAGE);
    } else {
        if ARGS.flag_key != "NONE" {
            search_specific_key_hklm(&"HKEY_LOCAL_MACHINE", &hklm, &ARGS.flag_key, &mut already_seen)?;
            search_specific_key_hku(&"HKEY_USERS", &hku, &ARGS.flag_key, &mut already_seen)?;
        } else if ARGS.flag_explicit {
            process_interesting_hklm(&hklm, &mut already_seen)?;
            process_interesting_hku(&hku, &mut already_seen)?;
        } else if ARGS.flag_all {
            search_all_value_names(&"HKEY_LOCAL_MACHINE", &hklm, &empty_string, &mut already_seen)?;
            search_all_value_names(&"HKEY_USERS", &hku, &empty_string, &mut already_seen)?;
        }
    }

    Ok(())
}