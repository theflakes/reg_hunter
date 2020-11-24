extern crate winreg;            // Windows registry access
extern crate chrono;            // DateTime manipulation
extern crate regex;
extern crate bstr;

use regex::Regex;
use crate::{data_defs::*, file::*};
use std::{io::Result, str};
use bstr::ByteSlice;

/* 
        use \x20 for matching spaces when using "x" directive that doesn't allow spaces in regex
        regex crate does not support look-(behind|ahead|etc.)
        fancy-regex crate does support these, but doesn't support captures_iter
            https://docs.rs/fancy-regex/0.4.0/fancy_regex/
            (?:$|\s|[/:@#&\(\]|=\\\}'\"><])
*/

pub fn found_email(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref EMAIL: Regex = Regex::new(r#"(?mix)
            (:?   
                [a-z0-9._%+-]+@[a-z0-9._-]+\.[a-z0-9-]{2,13}
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if EMAIL.is_match(text) { Ok(true) } else { Ok(false) }
}


pub fn found_encoding(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref ENCODING: Regex = Regex::new(r#"(?mix)
            (:?
                [a-z0-9=/+&]{300}
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if ENCODING.is_match(text) { Ok(true) } else { Ok(false) }
}

/*
    identify files being referenced in registry values
    this is so we can harvest the metadata on these files as well
*/
pub fn found_file(
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

pub fn found_hex(
                    bytes: &Vec<u8>,
                    find_this: &Vec<u8>
                ) -> Result<bool> 
{
    if find_this != &[0] && bytes.find(find_this).is_some() {
        Ok(true)
	} else {
        Ok(false)
    }
}


pub fn found_ipv4(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref IPV4: Regex = Regex::new(r#"(?mix)
            (:?
                (?:^|\s|[&/:<>\#({\[|'"=@]|[[:^alnum:]]\\)
                    (?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[1-9])                                          
                    (?:\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9]?[0-9])){3}
                (?:$|\s|[&/:<>\#)}\]|'"\\=@])
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if IPV4.is_match(text) { Ok(true) } else { Ok(false) }
}

pub fn found_null(
                    value_name: &str
                ) -> Result<bool>
{
    if value_name.starts_with('\u{0000}') {
        Ok(true)
    } else {
        Ok(false)
    }
}


pub fn found_obfuscation(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref OBFUSCATION: Regex = Regex::new(r#"(?mix)
            (:?
                \[char\]|
                \.replace|
                (?:'?\+'?.*){7}|
                (?:\^.*){7}|
                (?:`.*){7}|
                (?:\([a-z0-9 _.$@!&\#%^',\[\]+;~`{}=|*(-]*\).*){7}|
                (?:','.*){7}|
                (?:\{\d+\}){7}|
                (?:\$[{(].+[)}].*){7}|
                (?:,;,.*){7}|
                (?:["'](?:[^"']{0,4}["'][^"'].*)){6}
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if OBFUSCATION.is_match(text) { Ok(true) } else { Ok(false) }
}

// Custom regex hunt specified on command line
//ARGS.flag_path || ARGS.flag_name || ARGS.flag_value
pub fn found_regex(
                text: &str
            ) -> Result<bool> 
{   
    if ARGS.flag_regex != "$^" && CUSTOM_REGEX.is_match(text) { 
            Ok(true) 
        } else { 
            Ok(false) 
        }
}


pub fn found_script(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref SCRIPT: Regex = Regex::new(r#"(?mix)
            (:?
                [cw]script|mshta(?:\.exe)?|
                \.(?:bat|cmd|com|hta|jse?|vb[se]|ps1|ws[fh]?)(?:[,|\s'"><&]|$)|
                javascript|RunHTMLApplication|script:|
                WScript\.Shell|vbscript:|Shell\.Run|
                e:(?:vb|j)script|
                ShellExecute|ExecuteShellCommand
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if SCRIPT.is_match(text) { Ok(true) } else { Ok(false) }
}


pub fn found_shell(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref SHELL: Regex = Regex::new(r#"(?mix)
            (:?
                (?:cmd|powershell|sqlps)(?:\.exe)?|pwsh
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if SHELL.is_match(text) { Ok(true) } else { Ok(false) }
}



pub fn found_shellcode(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref SHELL_CODE: Regex = Regex::new(r#"(?mix)
            (:?
                (?:(?:[0\\]?x|\x20)?[a-f0-9]{2}[,\x20;:\\]){50}
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if SHELL_CODE.is_match(text) { Ok(true) } else { Ok(false) }
}



/*
    TODO: add aliases
*/
pub fn found_suspicious(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref SUSPICIOUS: Regex = Regex::new(r#"(?mix)
            (:?
                FromBase64String|ToBase64String|System\.Text\.Encoding|
                System\.Convert|securestringtoglobalallocunicode|
                [string]::join|\.GetString|

                /t(?:icket|arget)|
                ACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAk|                       # Empire RAT
                \x20-bxor|
                -(?:
                    e(?:c|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?
                    ComputerName|
                    CriticalProcess|
                    HttpStatus|
                    Keystrokes|
                    MasterBootRecord|
                    MicrophoneAudio|
                    Minidump|
                    Persistence|
                    Portscan|
                    processid|
                    ReverseDnsLookup|
                    SecurityPackages|
                    VolumeShadowCopy
                )|
                AVSignature|
                Add-(?:
                    Exfiltration|
                    Persistence|
                    RegBackdoor|
                    ScrnSaveBackdoor
                )|
                AdjustTokenPrivileges|
                Check-VM|
                CompressDLL|
                Control_RunDLL|
                CredentialInjection|
                dll(?:import|injection)|
                download(?:file|data|string)|
                OpenRead|
                WEBReQuEst|
                \.Download|
                Do-Exfiltration|
                ElevatedPersistenceOption|
                Enabled-DuplicateToken|
                EncodeCommand|
                EncryptedScript|
                Exploit-Jboss|
                Find-(?:
                    Fruit|
                    GPOLocation|
                    TrustedDocuments
                )|
                GPP(?:Autologon|Password)|
                Get-(?:
                    ApplicationHost|
                    ChromeDump|
                    ClipboardContents|
                    Content|
                    FoxDump|
                    GPPPassword|
                    IndexedItem|
                    Keystrokes|
                    LSASecret|
                    PassHashes|
                    RegAlwaysInstallElevated|
                    RegAutoLogon|
                    RickAstley|
                    Screenshot|
                    SecurityPackages|
                    ServiceFilePermission|
                    ServicePermission|
                    ServiceUnquoted|
                    SiteListPassword|
                    System|
                    TimedScreenshot|
                    UnattendedInstallFile|
                    Unconstrained|
                    VaultCredential|
                    VulnAutoRun|
                    VulnSchTask|
                    WebConfig
                )|
                Gupt-Backdoor|
                HTTP-Login|
                IMAGE_NT_OPTIONAL_HDR64_MAGIC|
                Install-(?:
                    SSP|
                    ServiceBinary
                )|
                Invoke-(?:
                    ACLScanner|
                    ADSBackdoor|
                    ARPScan|
                    BackdoorLNK|
                    Bloodhound|
                    BypassUAC|
                    Command|
                    CredentialInjection|
                    DCSync|
                    DllInjection|
                    DowngradeAccount|
                    EgressCheck|
                    Expression|iex|
                    Inveigh|
                    InveighRelay|
                    Mimikatz|
                    Mimikittenz|
                    NetRipper|
                    NinjaCopy|
                    PSInject|
                    Paranoia|
                    PortScan|
                    PoshRatHttp|
                    PostExfil|
                    PowerDump|
                    PowerShellTCP|
                    PowerShellWMI|
                    PsExec|
                    PsUaCme|
                    ReflectivePEInjection|
                    RestMethod|
                    ReverseDNSLookup|
                    RunAs|
                    SMBScanner|
                    SSHCommand|
                    ServiceAbuse|
                    ShellCode|
                    Tater|
                    ThunderStruck|
                    TokenManipulation|
                    UserHunter|
                    VoiceTroll|
                    WScriptBypassUAC|
                    WinEnum|
                    WmiCommand|
                    WmiMethod
                )|
                kerberos:|
                LSA_UNICODE_STRING|
                lsadump|
                MailRaider|
                Metasploit|
                Microsoft.Win32.UnsafeNativeMethods|
                Mimikatz|
                MiniDumpWriteDump|
                New-(?:
                    HoneyHash|
                    Object
                )|
                net\.webclient|
                NinjaCopy|
                Out-Minidump|
                PAGE_EXECUTE_READ|
                Port-Scan|
                Power(?:
                    Breach|
                    Up|
                    View
                )|
                procdump|
                ReadProcessMemory.Invoke|
                ReflectivePEInjection|
                Remove-Update|
                runtime\.interopservices\.marshal|
                SECURITY_DELEGATION|
                SE_PRIVILEGE_ENABLED|
                sekurlsa|
                Set-(?:
                    Alias|
                    MacAttribute|
                    Wallpaper
                )|
                ShellCode|
                Show-TargetScreen|
                Start-(?:
                    CaptureServer|
                    Process
                )|
                TOKEN_(?:
                    ADJUST_PRIVILEGES|
                    ALL_ACCESS|
                    ASSIGN_PRIMARY|
                    DUPLICATE|
                    ELEVATION|
                    IMPERSONATE|
                    INFORMATION_CLASS|
                    PRIVILEGES|
                    QUERY
                )|
                TimedScreenshot|
                TokenManipulation|
                UserPersistenceOption|
                VaultCredential|
                VolumeShadowCopyTools|
                WmiCommand|
                \(WCHAR\)|
                IncludeLiveDump="
            )(?:[|\s'"><&]|$)                                                                  
        "#).expect("Invalid Regex");
    }

    if SUSPICIOUS.is_match(text) { Ok(true) } else { Ok(false) }
}


pub fn found_unc(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref UNC: Regex = Regex::new(r#"(?mix)
            (:?
                \\\\[a-z0-9_.$-]+\\[a-z0-9_.$-]+
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if UNC.is_match(text) { Ok(true) } else { Ok(false) }
}


pub fn found_url(
                text: &str
            ) -> Result<bool> 
{
    lazy_static! {
        static ref URL: Regex = Regex::new(r#"(?mix)
            (:?
                (?:https?|ftp|smb|cifs)://
            )                                                                  
        "#).expect("Invalid Regex");
    }

    if URL.is_match(text) { Ok(true) } else { Ok(false) }
}