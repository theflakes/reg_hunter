# reg_hunter
Blueteam operational triage registry hunting/forensic tool.

I hope to incorporate more than just registry triage and hunting. I'd love to see this tool become a standalone triage / hunt tool for all Windows persistence mechanisms.

Demo and misc. information on Registry Hunter via Forensic Lunch podcast: https://www.youtube.com/watch?v=_lKinL7f7ak&t=2s

Thank you to https://twitter.com/Hexacorn and https://twitter.com/SBousseaden for their open research. Many of the explicit registry keys and values defined in this tool came from their graciously shared hard work.

Thanks to https://github.com/lilopkins and https://github.com/gentoo90 for the Lnk and Registry Rust crates.

Output is in JSON line delimited.

If you just want the tool, download the reg_hunter_x32.exe and/or reg_hunter_x64.exe binary. Note that you'll want to run the 64 bit binary on a 64 bit OS so that it will not be partially blinded by Windows WOW64 redirection.

Registry key "last_write_time" is included in Registry JSON logs.

The "tags" field is an array populated by any hunts that are a positive match.

I needed a self-contained tool, as when I'm triaging an event, the less files I have to push to a remote device the better. Adding in new hunts and recompiling is simple as well. I also wanted a tool that was not dependent on having a minimum .Net version installed.

NOTE: The "parent_data_type" field specifies the "data_type" that caused the generation of this data type. E.g. If a Lnk file was found in a registry value, this will generate a "ShellLink" data_type with a parent_data_type of "Registry". Then a data_type of "File" with a parent_data_type of "ShellLink" will be generated if the file that the Lnk file points to is found/exists. I.e. Registry --> ShellLink --> File

A file/lnk's meta data will only be collected once no matter how many times it is referenced in registry values.

Add Rust 32 bit target build environment:
```
    rustup toolchain install stable-i686-pc-windows-msvc
    rustup target add i686-pc-windows-msvc
```

To compile; install Rust and the MSVC 32 and/or 64 bit environment:
```
    x32: cargo build --release --target i686-pc-windows-msvc
    x64: cargo build --release --target x86_64-pc-windows-msvc
```

```
Reg Hunter
    Author: Brian Kellogg
    License: MIT
    Many thanks: @Hexacorn and @SBousseaden
    Disclaimer: 
        This tool comes with no warranty or support. 
        If anyone chooses to use it, you accept all responsibility and liability.

Usage:
    reg_hunter --help
    reg_hunter [options]
    reg_hunter --explicit -f -n [--ip <ip> --port <port>]
    reg_hunter --all [-bcefimnorsuwyz] [--ip <ip> --port <port>] [--limit]
    reg_hunter -a --regex <regex> --path --name --value
    reg_hunter -a -y [--start <start_time> --end <end_time>]

Options:
    Registry context (one required):
        -a, --all                   Examine all the registry; HKLM and HKU
        -x, --explicit              Examine only more often forensically interesting keys and values
                                        This option will always report out all 
                                        value names and values unless values are empty/null
        -k, --key <path>            Only examine a specified reg path. [default: NONE]
                                        All sub keys will be examined as well.
                                        Searches both HKLM and HKU hives
                                        format: SOFTWARE\Microsoft\Windows\CurrentVersion

    Hunts:
        -b, --binary                Find possible MZ headers in REG_BINARY values
                                        Tag: MzHeader
        -c, --shell                 Find command shells (cmd.exe, powershell.exe, ...)
                                        Tag: Shell
        -e, --encoding              Find possibly encoded values
                                        Tag: Encoding
        -f, --file                  Find files referenced in registry values 
                                        and collect lnk/file metadata. If a lnk file is found, 
                                        metadata on both the lnk and file it points to will be 
                                        reported.
                                        Tag: File
        -g, --link                  Hunt for registry symbolic links
        -i, --ip                    Search for IPv4 addresses
                                        Tag: IPv4
        -m, --email                 Find email addresses
                                        Tag: Email
        -n, --null                  Hunt for null prefixed value names
                                        Tag: NullPrefixedName
        -o, --obfuscation           Find possibly obfuscated values
                                        Tag: Obfuscation
        -r, --script                Find script files
                                        Tag: Script
        -s, --shellcode             Find possible shellcode
                                        Tag: Shellcode
        -u, --unc                   Find UNC paths
                                        Tag: UNC
        -w, --url                   Find URLs
                                        Tag: URL
        -y, --suspicious            Find various suspicious substrings
                                        e.g. iex, invoke-expression, etc.
                                        Tag: Suspicious
        -z, --everything            Run ALL the hunts

    Time window:
        This option will compare the specified date window to the registry key's 
        last_write_time and only output logs where the last_write_time falls 
        within that window. Window start is inclusive, window end is exclusive. 
        NOTE: key last_write_time can be timestomped.
        --start <UTC_start_time>        Start of time window: [default: 0000-01-01T00:00:00]
                                        format: YYYY-MM-DDTHH:MM:SS
        --end <UTC_end_time>            End of time window: [default: 9999-12-31T23:59:59]
                                        format: YYYY-MM-DDTHH:MM:SS

    Custom hunts (regex and/or hex required):
        NOTE: A limitation of the regex hunt is that only REG_BINARY values
        that can be successfully converted to a string will be searched.
        -q, --regex <regex>         Custom regex [default: $^]
                                        Does not support look aheads/behinds/...
                                        Uses Rust regex crate (case insensitive and multiline)
                                        Any match will add 'Custom' to the tags field
                                        Tag: RegexHunt
        --hex <string>              Hex search string [default: FF]
                                        Hex string length must be a multiple of two
                                        format: 0a1b2c3d4e5f
                                        Tag: HexHunt
        -j, --path                  Search reg key path
        -t, --name                  Search value name
        -v, --value                 Search reg value

    Network output:
        -d, --destination <ip>      IP address to send output to [default: NONE]
        -p, --port <port>           Destination port to send output to [default: 80]

    Misc:
        -h, --help                  Show this screen
        -l, --limit                 Try to minimize CPU use as much as possible
        --print                     Always output log whether a hunt matched or not
        --debug                     Print error logs
                                        e.g. access denied to a registry key
                                             failure opening a registry key

Note:
    If not run as an administrator some telemetry cannot be harvested.

    An error log with tag of 'HiddenKey' will be generated if any registry key
    that fails to open is identified as a maliciously hidden key.
        e.g. Key path ends with a unicode null character.

    The output is mostly meant to be fed into some hunting backend. But,
    there are some built in hunts; --null, --binary, ...

    Depending on the options used, considerable output can be generated.
    
    To capture output remotely, start a netcat listener on your port of choice.
    Use the -k option with netcat to prevent netcat from closing after a TCP connection is closed.

    Files larger than 256MB will not be hashed.
```


Example JSON logs:
```
{
  "parent_data_type": "",
  "data_type": "Registry",
  "timestamp": "2020-11-24T17:29:48.822",
  "device_name": "DESKTOP-NDPUHM4",
  "device_domain": "DESKTOP-NDPUHM4",
  "device_type": "Windows 10",
  "registry_hive": "HKEY_LOCAL_MACHINE",
  "registry_key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "registry_value_name": "evil_too",
  "registry_type": "REG_SZ",
  "registry_value": "C:\\Temp\\evil.txt.lnk",
  "last_write_time": "2020-11-24T17:24:30.515",
  "tags": [
    "File"
  ]
}

{
   "parent_data_type":"",
   "data_type":"Registry",
   "timestamp":"2020-11-24T17:29:48.813",
   "device_name":"DESKTOP-NDPUHM4",
   "device_domain":"DESKTOP-NDPUHM4",
   "device_type":"Windows 10",
   "registry_hive":"HKEY_LOCAL_MACHINE",
   "registry_key":"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
   "registry_value_name":"evil",
   "registry_type":"REG_BINARY",
   "registry_value":"[00, 00, 00, 4d, 5a, 90, 00, 00, 00, 00, 00]",
   "last_write_time":"2020-11-24T17:24:30.515",
   "tags":[
      "MzHeader",
      "HexHunt"
   ],
   "error":""
}

{
  "parent_data_type": "Registry",
  "data_type": "ShellLink",
  "timestamp": "2020-11-24T17:29:48.818",
  "path": "c:\\temp\\evil.txt.lnk",
  "target_path": "C:\\evil.txt",
  "last_access_time": "2020-11-24T17:29:48.818",
  "last_write_time": "2020-11-07T14:14:08.711",
  "creation_time": "2020-11-07T14:13:06.694",
  "size": 769,
  "hidden": true,
  "arguments": "",
  "hotkey": "NO_MODIFIER-NoKeyAssigned"
}

{
  "parent_data_type": "Registry",
  "data_type": "File",
  "timestamp": "2020-11-24T17:29:48.822",
  "path": "c:\\temp\\evil.txt.lnk",
  "md5": "0fcba6e9dd09e1cb497454f0b256b490",
  "mime_type": "application/octet-stream",
  "last_access_time": "2020-11-24T17:29:48.818",
  "last_write_time": "2020-11-07T14:14:08.711",
  "creation_time": "2020-11-07T14:13:06.694",
  "size": 769,
  "hidden": true
}

{
  "parent_data_type": "ShellLink",
  "data_type": "File",
  "timestamp": "2020-11-24T17:29:48.821",
  "path": "C:\\evil.txt",
  "md5": "1df1eae8c6c44484a840a40a0543cc59",
  "mime_type": "text/plain",
  "last_access_time": "2020-11-24T17:29:48.820",
  "last_write_time": "2020-11-24T17:23:26.245",
  "creation_time": "2020-11-24T17:23:17.173",
  "size": 16,
  "hidden": true
}

{
  "parent_data_type": "Error",
  "data_type": "Registry",
  "timestamp": "2020-12-06T20:56:42.113",
  "device_name": "DESKTOP-NDPUHM4",
  "device_domain": "DESKTOP-NDPUHM4",
  "device_type": "Windows 10",
  "registry_hive": "HKEY_LOCAL_MACHINE",
  "registry_key": "SOFTWARE\\WOW6432Node\\Systems Internals\\Can't touch me!\u0000",
  "registry_value_name": "ERROR_READING",
  "registry_type": "REG_ERROR",
  "registry_value": "ERROR_READING",
  "last_write_time": "",
  "tags": [
    "HiddenKey"
  ],
  "error": "The system cannot find the file specified. (os error 2)"
}
```
