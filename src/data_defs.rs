extern crate serde;             // needed for json serialization
extern crate serde_derive;      // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate docopt;
extern crate whoami;

use std::collections::HashMap;
use serde::Serialize;
use serde_derive::{Deserialize};
use std::io::prelude::{Write};
use docopt::Docopt;
use std::thread;
use std::env;

// do not like using "unwrap" here
lazy_static! {
    pub static ref USER_DIR: String = env::var("COMPUTERNAME").unwrap();
    pub static ref DEVICE_NAME: String = env::var("COMPUTERNAME").unwrap();
    pub static ref DEVICE_DOMAIN: String = env::var("USERDOMAIN").unwrap();
    pub static ref DEVICE_TYPE: String = whoami::distro();
    pub static ref SYSTEM_ROOT: String = format!("{}\\", env::var("SYSTEMROOT").unwrap());
    pub static ref SYSTEM_DRIVE: String = format!("{}\\", env::var("SYSTEMDRIVE").unwrap());
}

// where to search for files
pub const SYSTEM_PATHS: [&str; 35] = [
    "",
    "boot\\",
    "perflogs\\",
    "$recycle.bin\\",
    "windows\\",
    "windows\\apppatch\\",
    "windows\\inf\\",
    "windows\\system32\\",
    "windows\\syswow64\\",
    "windows\\sysnative\\",
    "windows\\system32\\wbem\\",
    "windows\\syswow64\\wbem\\",
    "windows\\sysnative\\wbem\\",
    "windows\\system32\\web\\",
    "windows\\syswow64\\web\\",
    "windows\\sysnative\\web\\",
    "windows\\system32\\sysprep\\",
    "windows\\syswow64\\sysprep\\",
    "windows\\sysnative\\sysprep\\",
    "windows\\system32\\grouppolicy\\machine\\scripts\\startup\\",
    "windows\\syswow64\\grouppolicy\\machine\\scripts\\startup\\",
    "windows\\sysnative\\grouppolicy\\machine\\scripts\\startup\\",
    "windows\\system32\\windowspowershell\\v1.0\\",
    "windows\\syswow64\\windowspowershell\\v1.0\\",
    "windows\\sysnative\\windowspowershell\\v1.0\\",
    "windows\\system32\\drivers\\",
    "windows\\syswow64\\drivers\\",
    "windows\\sysnative\\drivers\\",
    "windows\\temp\\",
    "programdata\\",
    "temp\\",
    "users\\",
    "users\\public\\",
    "users\\documents\\",
    "users\\desktop\\"
];

pub const USAGE: &'static str = "
Reg Hunter
    Author: Brian Kellogg
    License: MIT
    Many thanks: @Hexacorn and @SBousseaden
    Disclaimer: 
        This tool comes with no warranty or support. 
        If anyone chooses to use it, you accept all responsibility and liability.

Usage:
    reg_hunter [options]
    reg_hunter --explicit -f -n [--ip <ip> --port <port>]
    reg_hunter --all [-bcefimnorsuwyz] [--ip <ip> --port <port>] [--limit]
    reg_hunter --help
    reg_hunter -a [-bn] [--regex <regex> [--path | --name | --value]]

Options:
    Registry context (one required):
        -a, --all                   Examine all the registry; HKLM and HKU
        -x, --explicit              Examine only more often forensically interesting keys and values
                                        This option will always report out all 
                                        value names and values unless values are empty/null

    Hunts:
        -b, --binary                Find possible MZ headers in REG_BINARY values
        -c, --shell                 Find command shells (cmd.exe, powershell.exe, ...)
        -e, --encoding              Find possible encoded values
        -f, --file                  Find files referenced in registry values 
                                        and collect lnk/file metadata. If a lnk file is found, 
                                        metadata on both the lnk and file it points to will be 
                                        reported.
        -i, --ip                    Search for IPv4 addresses
        -m, --email                 Find email addresses
        -n, --null                  Hunt for null prefixed value names
        -o, --obfuscation           Find obfuscated values
        -r, --script                Find script files
        -s, --shellcode             Find possible shellcode
        -u, --unc                   Find possible UNC paths
        -w, --url                   Find URLs
        -y, --everything            Run ALL the hunts
        -z, --suspicious            Find various suspicious substrings
                                        e.g. iex, invoke-expression, etc.

    Custom hunt (regex required):
        -q, --regex <regex>         Custom regex [default: $^]
                                        Does not support look aheads/behinds/...
                                        Uses Rust regex crate (case insensitive and multiline)
                                        Any match will add 'Custom' to the tags field
        -k, --path                  Search reg key path
        -t, --name                  Search value name
        -v, --value                 Search reg value

    Network output:
        -d, --destination <ip>      IP address to send output to [default: NONE]
        -p, --port <port>           Destination port to send output to [default: 80]

    Misc:
        -h, --help                  Show this screen
        -l, --limit                 Try to minimize CPU use as much as possible

Note:
    If not run as an administrator some telemetry cannot be harvested.

    The output is mostly meant to be fed into some hunting backend. But,
    there are some built in hunts; --null, --binary, ...

    Depending on the options used, considerable output can be generated.
    
    To capture output remotely, start a netcat listener on your port of choice.
    Use the -k option with netcat to prevent netcat from closing after a TCP connection is closed.

    Files larger than 256MB will not be hashed.
";

#[derive(Debug, Deserialize)]
pub struct Args {
    // what to examine
    pub flag_all: bool,
    pub flag_explicit: bool,

    // built-in hunts
    pub flag_binary: bool,
    pub flag_encoding: bool,
    pub flag_email: bool,
    pub flag_everything: bool,
    pub flag_file: bool,
    pub flag_ip: bool,
    pub flag_null: bool,
    pub flag_obfuscation: bool,
    pub flag_script: bool,
    pub flag_shellcode: bool,
    pub flag_shell: bool,
    pub flag_suspicious: bool,
    pub flag_unc: bool,
    pub flag_url: bool,

    // custom regex search cmd line options
    pub flag_regex: String,
    pub flag_path: bool,
    pub flag_name: bool,
    pub flag_value: bool,

    // cmd line options for network output
    pub flag_destination: String,
    pub flag_port: u16,

    //misc.
    pub flag_limit: bool,
}

lazy_static! { 
    pub static ref ARGS: Args = Docopt::new(USAGE)
                    .and_then(|d| d.deserialize())
                    .unwrap_or_else(|e| e.exit());

    pub static ref CUSTOM_REGEX: String = format!("{}{}", "(?mi)".to_string(), ARGS.flag_regex);
}


pub struct Results {
    pub result: bool,
    pub tags: Vec<String>
}

pub fn sleep() 
{
    if ARGS.flag_limit {
        thread::sleep(std::time::Duration::from_millis(1));
    }
}

/*
    HKLM keys and values we are interested in.
    "" =  (Default)
    [] =  get all values and one level of subkeys and values
*/
pub fn hklm_init() -> HashMap<&'static str, Vec<&'static str>> {
    let mut hklm: HashMap<&str, Vec<&str>> = HashMap::new();

    hklm.insert("software", [].to_vec());
    hklm.insert("software\\classes\\allfilesystemobjects\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\classes\\allfilesystemobjects\\shellex\\dragdrophandlers", [].to_vec());
    hklm.insert("software\\classes\\allfilesystemobjects\\shellex\\propertysheethandlers", [].to_vec());
    hklm.insert("software\\classes\\clsid", ["", "serverexecutable"].to_vec());
    hklm.insert("software\\classes\\.cmd", [].to_vec());
    hklm.insert("software\\classes\\directory\\background\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\classes\\directory\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\classes\\directory\\shellex\\copyhookhandlers", [].to_vec());
    hklm.insert("software\\classes\\directory\\shellex\\dragdrophandlers", [].to_vec());
    hklm.insert("software\\classes\\directory\\shellex\\propertysheethandlers", [].to_vec());
    hklm.insert("software\\classes\\drive\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\classes\\exefile\\shell\\open\\command", [""].to_vec());
    hklm.insert("software\\classes\\.exe", [].to_vec());
    hklm.insert("software\\classes\\filter", [].to_vec());
    hklm.insert("software\\classes\\folder\\shellex\\columnhandlers", [].to_vec());
    hklm.insert("software\\classes\\folder\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\classes\\folder\\shellex\\dragdrophandlers", [].to_vec());
    hklm.insert("software\\classes\\folder\\shellex\\extshellfolderviews", [].to_vec());
    hklm.insert("software\\classes\\folder\\shellex\\propertysheethandlers", [].to_vec());
    hklm.insert("software\\classes\\htmlfile\\shell\\open\\command", [""].to_vec());
    hklm.insert("software\\classes\\protocols\\filter", [].to_vec());
    hklm.insert("software\\classes\\protocols\\handler", [].to_vec());
    hklm.insert("software\\classes\\*\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\classes\\*\\shellex\\propertysheethandlers", [].to_vec());
    hklm.insert("software\\clients\\mail", [].to_vec());
    hklm.insert("software\\microsoft\\active setup\\installed components", ["stubpath"].to_vec());
    hklm.insert("software\\microsoft\\bidinterface\\loader", [].to_vec());
    hklm.insert("software\\microsoft\\command processor", ["autorun"].to_vec());
    hklm.insert("software\\microsoft\\cryptography\\oid\\encodingtype 0\\cryptsipdllgetsigneddatamsg", [].to_vec());
    hklm.insert("software\\microsoft\\cryptography\\oid\\encodingtype 0\\cryptsipdllverifyindirectdata", [].to_vec());
    hklm.insert("software\\microsoft\\cryptography\\providers\\trust\\finalpolicy", [].to_vec());
    hklm.insert("software\\microsoft\\ctf\\langbaraddin", [].to_vec());
    hklm.insert("software\\microsoft\\internet explorer\\explorer bars", [].to_vec());
    hklm.insert("software\\microsoft\\internet explorer\\extensions", [].to_vec());
    hklm.insert("software\\microsoft\\internet explorer\\toolbar", [].to_vec());
    hklm.insert("software\\microsoft\\microsoft sql server", [].to_vec());
    //hklm.insert("software\\microsoft\\.netframework", [].to_vec());
    hklm.insert("software\\microsoft\\netsh", [].to_vec());
    hklm.insert("software\\microsoft\\office\\access\\addins", [].to_vec());
    hklm.insert("software\\microsoft\\office\\excel\\addins", [].to_vec());
    hklm.insert("software\\microsoft\\office\\outlook\\addins", [].to_vec());
    hklm.insert("software\\microsoft\\office\\powerpoint\\addins", [].to_vec());
    hklm.insert("software\\microsoft\\office\\word\\addins", [].to_vec());
    hklm.insert("software\\microsoft\\office test\\special\\perf", [].to_vec());
    hklm.insert("software\\microsoft\\terminal server client\\default", [].to_vec());
    hklm.insert("software\\microsoft\\vba\\monitors", [].to_vec());
    hklm.insert("software\\microsoft\\wbem\\ess", [].to_vec());
    hklm.insert("software\\microsoft\\windows ce services\\autostartonconnect", [].to_vec());
    hklm.insert("software\\microsoft\\windows ce services\\autostartondisconnect", [].to_vec());
    hklm.insert("software\\microsoft\\airdrop", ["dllname"].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion", ["debug"].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\app paths", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\authentication\\credential provider filters", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\authentication\\credential providers", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\authentication\\plap providers", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\control panel\\cpls", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\explorer\\sharedtaskscheduler", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\explorer\\shellexecutehooks", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\explorer\\shelliconoverlayidentifiers", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\explorer\\shellserviceobjects", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\explorer\\tbden", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\group policy\\scripts\\logoff", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\group policy\\scripts\\logon", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\group policy\\scripts\\shutdown", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\group policy\\scripts\\startup", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\policies\\explorer\\run", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\policies\\system", ["shell", "enablelua"].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\run", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\runonceex", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\runonce", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\runservices", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\runservicesonce", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\shell extensions\\approved", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\shellserviceobjectdelayload", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\windowsupdate\\test", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\wsman\\client", [].to_vec());
    hklm.insert("software\\microsoft\\windows\\currentversion\\wsman\\service", [].to_vec());
    hklm.insert("software\\microsoft\\wow64\\x86", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\accessibility\\ats", ["atexe", "description", "startexe", "simpleprofile"].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\aedebug", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\aedebugprotected", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\appcompatflags\\custom", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\appcompatflags\\installedsdb", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\drivers32", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\font drivers", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\knownmanageddebuggingdlls", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\image file execution options", ["debugger"].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\minidumpauxiliarydlls", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\silentprocessexit", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\systemrestore", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\terminal server\\install\\software\\microsoft\\windows\\currentversion\\run", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\terminal server\\install\\software\\microsoft\\windows\\currentversion\\runonceex", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\terminal server\\install\\software\\microsoft\\windows\\currentversion\\runonce", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\windows", ["appinit_dlls", "iconservicelib", "shell", "taskman", "userinit", "vmapplet", "load", "run"].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\winlogon\\alternateshells\\availableshells", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\winlogon\\gpextensions", [].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\winlogon", ["appsetup", "shell", "userinit"].to_vec());
    hklm.insert("software\\microsoft\\windows nt\\currentversion\\winlogon\\notify", [].to_vec());
    hklm.insert("software\\policies\\microsoft\\windows\\credentialsdelegation", ["allowdefaultcredentials"].to_vec());
    hklm.insert("software\\policies\\microsoft\\windows defender", ["disableantispyware", "disableroutinelytakingaction", "disablerealtimemonitoring", "noautoupdate", "auoptions"].to_vec());
    hklm.insert("software\\policies\\microsoft\\windows nt\\dnsclient", ["enablemulticast"].to_vec());
    hklm.insert("software\\policies\\microsoft\\windows\\system\\scripts\\logoff", [].to_vec());
    hklm.insert("software\\policies\\microsoft\\windows\\system\\scripts\\logon", [].to_vec());
    hklm.insert("software\\policies\\microsoft\\windows\\system\\scripts\\shutdown", [].to_vec());
    hklm.insert("software\\policies\\microsoft\\windows\\system\\scripts\\startup", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\allfilesystemobjects\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\allfilesystemobjects\\shellex\\dragdrophandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\allfilesystemobjects\\shellex\\propertysheethandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\clsid", ["", "serverexecutable"].to_vec());
    hklm.insert("software\\wow6432node\\classes\\directory\\background\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\directory\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\directory\\shellex\\copyhookhandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\directory\\shellex\\dragdrophandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\directory\\shellex\\propertysheethandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\folder\\shellex\\columnhandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\folder\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\folder\\shellex\\dragdrophandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\folder\\shellex\\extshellfolderviews", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\folder\\shellex\\propertysheethandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\*\\shellex\\contextmenuhandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\classes\\*\\shellex\\propertysheethandlers", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\active setup\\installed components", ["stubpath"].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\bidinterface\\loader", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\command processor", ["autorun"].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\cryptography\\oid\\encodingtype 0\\cryptsipdllgetsigneddatamsg", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\cryptography\\oid\\encodingtype 0\\cryptsipdllverifyindirectdata", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\cryptography\\providers\\trust\\finalpolicy", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\internet explorer\\explorer bars", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\internet explorer\\extensions", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\internet explorer\\toolbar", [].to_vec());
    //hklm.insert("software\\wow6432node\\microsoft\\.netframework", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\office\\access\\addins", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\office\\excel\\addins", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\office\\outlook\\addins", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\office\\powerpoint\\addins", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\office\\word\\addins", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows ce services\\autostartonconnect", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows ce services\\autostartondisconnect", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion", ["debug"].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\explorer\\browser helper objects", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\explorer\\sharedtaskscheduler", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\explorer\\shellexecutehooks", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\explorer\\shelliconoverlayidentifiers", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\explorer\\shellserviceobjects", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\policies\\explorer\\run", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\run", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\runonceex", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\runonce", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\runservices", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\runservicesonce", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\shareddlls", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\shell extensions\\approved", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\shellserviceobjectdelayload", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\aedebug", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\drivers32", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\knownmanageddebuggingdlls", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\image file execution options", ["debugger"].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\minidumpauxiliarydlls", [].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\windows", ["appinit_dlls", "iconservicelib", "shell", "taskman", "userinit", "vmapplet", "load", "run"].to_vec());
    hklm.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\winlogon\\specialaccounts\\userlist", [].to_vec());
    hklm.insert("software\\wow6432node\\policies\\microsoft\\windows defender", ["scheduledinstallday", "scheduledinstalltime", "dodownloadmode", "auoptions"].to_vec());
    hklm.insert("system\\controlset001\\services\\portproxy", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\bootverificationprogram", ["imagepath"].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\filesystem", ["ntfsencryptpagingfile"].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\lsa", ["security packages", "authentication packages", "notification packages", "security packages", "runasppl", "disablerestrictedadmin", "disablerestrictedadminoutboundcreds", "limitblankpassworduse", "lmcompatibilitylevel", "NtlmMinClientSec", "RestrictSendingNTLMTraffic", "RestrictReceivingNTLMTraffic"].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\networkprovider\\order", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\print\\monitors", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\print\\providers", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\safeboot", ["alternateshell"].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\securityproviders", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\servicecontrolmanagerextension", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\session manager", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\terminal server", ["fdenytsconnections", "fsinglesessionperuser"].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\terminal server\\addins", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\terminal server\\utilities", [].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\terminal server\\wds\\rdpwd", ["startupprograms"].to_vec());
    hklm.insert("system\\currentcontrolset\\control\\terminal server\\winstations\\rdp-tcp", ["initialprogram"].to_vec());
    hklm.insert("system\\currentcontrolset\\services", ["imagepath", "failurecommand", "start", "type"].to_vec());
    hklm.insert("system\\currentcontrolset\\services\\ntds", ["lsadbextpt", "directoryserviceextpt"].to_vec());
    hklm.insert("system\\currentcontrolset\\services\\portproxy", [].to_vec());
    hklm.insert("system\\currentcontrolset\\services\\winsock2\\parameters\\appid_catalog", ["librarypath", "protocolname"].to_vec());
    hklm.insert("system\\currentcontrolset\\services\\winsock2\\parameters\\namespace_catalog5\\catalog_entries64", ["librarypath", "protocolname"].to_vec());
    hklm.insert("system\\currentcontrolset\\services\\winsock2\\parameters\\protocol_catalog9\\catalog_entries64", ["librarypath", "protocolname"].to_vec());
    hklm.insert("system\\currentcontrolset\\services\\winsock2\\parameters\\protocol_catalog9\\catalog_entries", ["librarypath", "protocolname"].to_vec());
    hklm.insert("system\\setup\\cmdline", [].to_vec());

    return hklm;
}

pub fn hku_init() -> HashMap<&'static str, Vec<&'static str>> {
    let mut hku: HashMap<&str, Vec<&str>> = HashMap::new();

    hku.insert("control panel\\desktop", ["scrnsave.exe", "screensaveactive", "screensaverissecure", "screensavertimeout", "wallpaper"].to_vec());
    hku.insert("environment", [].to_vec());
    hku.insert("software\\alps alps touchpad", [].to_vec());
    hku.insert("software", [].to_vec());
    hku.insert("software\\classes\\activatableclasses\\package", ["", "debugpath"].to_vec());
    hku.insert("software\\classes\\allfilesystemobjects\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\classes\\allfilesystemobjects\\shellex\\dragdrophandlers", [].to_vec());
    hku.insert("software\\classes\\allfilesystemobjects\\shellex\\propertysheethandlers", [].to_vec());
    hku.insert("software\\classes\\clsid", ["", "serverexecutable"].to_vec());
    hku.insert("software\\classes\\.cmd", [].to_vec());
    hku.insert("software\\classes\\directory\\background\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\classes\\directory\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\classes\\directory\\shellex\\copyhookhandlers", [].to_vec());
    hku.insert("software\\classes\\directory\\shellex\\dragdrophandlers", [].to_vec());
    hku.insert("software\\classes\\directory\\shellex\\propertysheethandlers", [].to_vec());
    hku.insert("software\\classes\\exefile\\shell\\open\\command", [""].to_vec());
    hku.insert("software\\classes\\exefile\\shell\\runas\\command", [].to_vec());
    hku.insert("software\\classes\\.exe", [].to_vec());
    hku.insert("software\\classes\\filter", [].to_vec());
    hku.insert("software\\classes\\folder\\shellex\\columnhandlers", [].to_vec());
    hku.insert("software\\classes\\folder\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\classes\\folder\\shellex\\dragdrophandlers", [].to_vec());
    hku.insert("software\\classes\\folder\\shellex\\extshellfolderviews", [].to_vec());
    hku.insert("software\\classes\\folder\\shellex\\propertysheethandlers", [].to_vec());
    hku.insert("software\\classes\\htmlfile\\shell\\open\\command", [""].to_vec());
    hku.insert("software\\classes\\ms-settings\\shell\\open\\command", [].to_vec());
    hku.insert("software\\classes\\mscfile\\shell\\open\\command", [""].to_vec());
    hku.insert("software\\classes\\protocols\\filter", [].to_vec());
    hku.insert("software\\classes\\protocols\\handler", [].to_vec());
    hku.insert("software\\classes\\*\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\classes\\*\\shellex\\propertysheethandlers", [].to_vec());
    hku.insert("software\\google\\chrome\\preferencemacs\\default\\extensions.settings", [].to_vec());
    hku.insert("software\\microsoft\\command processor", ["autorun"].to_vec());
    hku.insert("software\\microsoft\\ctf\\langbaraddin", [].to_vec());
    hku.insert("software\\microsoft\\internet explorer\\desktop\\components", [].to_vec());
    hku.insert("software\\microsoft\\internet explorer\\explorer bars", [].to_vec());
    hku.insert("software\\microsoft\\internet explorer\\extensions", [].to_vec());
    hku.insert("software\\microsoft\\internet explorer\\urlsearchhooks", [].to_vec());
    hku.insert("software\\microsoft\\microsoft sql server", [].to_vec());
    hku.insert("software\\microsoft\\multimedia", [].to_vec());
    hku.insert("software\\microsoft\\office", ["EnableUnsafeClientMailRules"].to_vec());
    hku.insert("software\\microsoft\\office\\access\\addins", [].to_vec());
    hku.insert("software\\microsoft\\office\\excel\\addins", [].to_vec());
    hku.insert("software\\microsoft\\office\\outlook\\addins", [].to_vec());
    hku.insert("software\\microsoft\\office\\powerpoint\\addins", [].to_vec());
    hku.insert("software\\microsoft\\office\\word\\addins", [].to_vec());
    hku.insert("software\\microsoft\\office test\\special\\perf", [].to_vec());
    hku.insert("software\\microsoft\\terminal server client\\default", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion", ["debug"].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\app paths\\control.exe", [""].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\app paths", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\control panel\\cpls", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\explorer\\fileexts", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\explorer\\shelliconoverlayidentifiers", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\explorer\\shellserviceobjects", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\group policy\\scripts\\logoff", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\group policy\\scripts\\logon", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\group policy\\scripts\\shutdown", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\group policy\\scripts\\startup", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\internet settings", ["enablehttp2"].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\packagedappxdebug", ["", "debugpath"].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\policies\\explorer", ["noinstrumentation"].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\policies\\explorer\\run", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\policies\\system", ["shell", "enablelua"].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\run", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\runonceex", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\runonce", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\shell extensions\\approved", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\shell extensions\\cached", [].to_vec());
    hku.insert("software\\microsoft\\windows\\currentversion\\shellserviceobjectdelayload", [].to_vec());
    hku.insert("software\\microsoft\\windows nt\\currentversion\\accessibility", ["configuration"].to_vec());
    hku.insert("software\\microsoft\\windows nt\\currentversion\\notify", [].to_vec());
    hku.insert("software\\microsoft\\windows nt\\currentversion\\terminal server\\install\\software\\microsoft\\windows\\currentversion\\run", [].to_vec());
    hku.insert("software\\microsoft\\windows nt\\currentversion\\terminal server\\install\\software\\microsoft\\windows\\currentversion\\runonceex", [].to_vec());
    hku.insert("software\\microsoft\\windows nt\\currentversion\\terminal server\\install\\software\\microsoft\\windows\\currentversion\\runonce", [].to_vec());
    hku.insert("software\\microsoft\\windows nt\\currentversion\\windows", ["appinit_dlls", "iconservicelib", "shell", "taskman", "userinit", "vmapplet", "load", "run"].to_vec());
    hku.insert("software\\microsoft\\windows nt\\currentversion\\winlogon", ["appsetup", "shell", "userinit"].to_vec());
    hku.insert("software\\nico mak computing winzip", [].to_vec());
    hku.insert("software\\policies\\microsoft\\windows\\control panel\\desktop", ["scrnsave.exe", "screensaveactive", "screensaverissecure", "screensavertimeout", "wallpaper"].to_vec());
    hku.insert("software\\policies\\microsoft\\windows\\system\\scripts\\logoff", [].to_vec());
    hku.insert("software\\policies\\microsoft\\windows\\system\\scripts\\logon", [].to_vec());
    hku.insert("software\\policies\\microsoft\\windows\\system\\scripts\\shutdown", [].to_vec());
    hku.insert("software\\policies\\microsoft\\windows\\system\\scripts\\startup", [].to_vec());
    hku.insert("software\\synaptics\\syntpenh\\pluginconfig\\touchpadps2", [].to_vec());
    hku.insert("software\\synaptics\\syntp\\touchpadps2", [].to_vec());
    hku.insert("software\\sysinternals\\sdelete", [].to_vec());
    hku.insert("software\\winrar", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\allfilesystemobjects\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\allfilesystemobjects\\shellex\\dragdrophandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\allfilesystemobjects\\shellex\\propertysheethandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\clsid", ["", "serverexecutable"].to_vec());
    hku.insert("software\\wow6432node\\classes\\directory\\background\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\directory\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\directory\\shellex\\copyhookhandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\directory\\shellex\\dragdrophandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\directory\\shellex\\propertysheethandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\folder\\shellex\\columnhandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\folder\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\folder\\shellex\\dragdrophandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\folder\\shellex\\extshellfolderviews", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\folder\\shellex\\propertysheethandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\*\\shellex\\contextmenuhandlers", [].to_vec());
    hku.insert("software\\wow6432node\\classes\\*\\shellex\\propertysheethandlers", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\command processor", ["autorun"].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\internet explorer\\explorer bars", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\internet explorer\\extensions", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\office", ["EnableUnsafeClientMailRules"].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\office\\access\\addins", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\office\\excel\\addins", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\office\\outlook\\addins", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\office\\powerpoint\\addins", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\office\\word\\addins", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\windows\\currentversion", ["debug"].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\policies\\explorer\\run", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\run", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\runonceex", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\runonce", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\windows\\currentversion\\shell extensions\\approved", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\drivers32", [].to_vec());
    hku.insert("software\\wow6432node\\microsoft\\windows nt\\currentversion\\windows", ["appinit_dlls", "iconservicelib", "shell", "taskman", "userinit", "vmapplet", "load", "run"].to_vec());
    hku.insert("volatile environment", [].to_vec());

    return hku;
}

/*
    Help provided by Yandros on using traits: 
        https://users.rust-lang.org/t/refactor-struct-fn-with-macro/40093
*/
type Str = ::std::borrow::Cow<'static, str>;
trait Loggable : Serialize {
    /// convert struct to json
    fn to_log (self: &'_ Self) -> Str
    {
        ::serde_json::to_string(&self)
            .ok()
            .map_or("<failed to serialize>".into(), Into::into)
    }
    
    /// convert struct to json and report it out
    fn write_log (self: &'_ Self)
    {
        if !ARGS.flag_destination.eq("NONE") {
            let socket = format!("{}:{}", ARGS.flag_destination, ARGS.flag_port);
            let mut stream = ::std::net::TcpStream::connect(socket)
                .expect("Could not connect to server");
            writeln!(stream, "{}", self.to_log())
                .expect("Failed to write to server");
        } else {
            println!("{}", self.to_log());
        }
    }
}
impl<T : ?Sized + Serialize> Loggable for T {}

#[derive(Serialize)]
pub struct TxRegistry {
    pub parent_data_type: String,
    #[serde(default = "Registry")]
    pub data_type: String,
    pub timestamp: String,
    pub device_name: String,
    pub device_domain: String,
    pub device_type: String,
    pub registry_hive: String,
    pub registry_key: String,
    pub registry_value_name: String,
    pub registry_type: String,
    pub registry_value: String,
    pub last_write_time: String,
    pub tags: Vec<String>
}
impl TxRegistry {
    pub fn new(
        parent_data_type: String,
        data_type: String,
        timestamp: String,
        device_name: String,
        device_domain: String,
        device_type: String,
        registry_hive: String,
        registry_key: String,
        registry_value_name: String,
        registry_type: String,
        registry_value: String,
        last_write_time: String,
        tags: Vec<String>) -> TxRegistry {
        TxRegistry {
            parent_data_type,
            data_type,
            timestamp,
            device_name,
            device_domain,
            device_type,
            registry_hive,
            registry_key,
            registry_value_name,
            registry_type,
            registry_value,
            last_write_time,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

// holds file metadata info
#[derive(Serialize)]
pub struct TxFile {
    pub parent_data_type: String,
    pub data_type: String,
    pub timestamp: String,
    pub path: String, 
    pub md5: String, 
    pub mime_type: String,
    pub last_access_time: String, 
    pub last_write_time: String,
    pub creation_time: String,
    pub size: u64,
    pub hidden: bool
}
impl TxFile {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            md5: String, 
            mime_type: String,
            last_access_time: String, 
            last_write_time: String,
            creation_time: String,
            size: u64,
            hidden: bool) -> TxFile {
        TxFile {
            parent_data_type,
            data_type,
            timestamp,
            path,
            md5,
            mime_type,
            last_access_time,
            last_write_time,
            creation_time,
            size,
            hidden
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

#[derive(Serialize)]
pub struct TxFileContent {
    pub parent_data_type: String,
    #[serde(default = "FileContent")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub line: String,
    pub bytes: String,
    pub tags: Vec<String>
}
impl TxFileContent {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String,
            line: String,
            bytes: String,
            tags: Vec<String>) -> TxFileContent {
        TxFileContent {
            parent_data_type,
            data_type,
            timestamp,
            path,
            line,
            bytes,
            tags
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}

#[derive(Serialize)]
pub struct TxLink {
    pub parent_data_type: String,
    #[serde(default = "ShellLink")]
    pub data_type: String,
    pub timestamp: String,
    pub path: String,
    pub target_path: String,
    pub last_access_time: String,
    pub last_write_time: String,
    pub creation_time: String,
    pub size: u64,
    pub hidden: bool,
    pub arguments: String,
    pub hotkey: String
}
impl TxLink {
    pub fn new(
            parent_data_type: String,
            data_type: String,
            timestamp: String,
            path: String, 
            target_path: String,
            last_access_time: String, 
            last_write_time: String,
            creation_time: String,
            size: u64,
            hidden: bool,
            arguments: String,
            hotkey: String) -> TxLink {
        TxLink {
            parent_data_type,
            data_type,
            timestamp,
            path,
            target_path,
            last_access_time,
            last_write_time,
            creation_time,
            size,
            hidden,
            arguments,
            hotkey
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}