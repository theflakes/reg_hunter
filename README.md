# reg_hunter
Blueteam operational triage registry hunting/forensic tool.

Thank you to https://twitter.com/Hexacorn and https://twitter.com/SBousseaden for their open research. Many of the explicit registry keys and values defined in this tool came from their graciously shared hard work.

Thanks to https://github.com/lilopkins and https://github.com/gentoo90 for the Lnk and Registry Rust crates.

Output is in JSON line delimited.

If you just want the tool, download the reg_hunter.exe binary.

Registry key "last_write_time" is included in Registry JSON logs.

The "tags" field is an array populated by any hunts that are a positive match.

I needed a selfcontained tool, as when I'm triaging an event, the less files I have to push to a remote device the better. Adding in new hunts and recompiling is simple as well. I also wanted a tool that was not dependent on having a minimum .Net version installed.

NOTE: The "parent_data_type" field specifies the "data_type" that caused the generation of this data type. E.g. If a Lnk file was found in a registry value, this will generate a "ShellLink" data_type with a parent_data_type of "Registry". Then a data_type of "File" with a parent_data_type of "ShellLink" will be generated if the file that the Lnk file points to is found/exists. I.e. Registry --> ShellLink --> File

A file/lnk's meta data will only be collected once no matter how many times it is referenced in registry values.

```
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

    Custom hunt (regex expression required):
        -q, --regex <regex>         Custom regex expression [default: NONE]
                                        Does not support look aheads/behinds/...
                                        Uses Rust regex crate (case insensitive)
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
```


Example JSON log:
```
{
   "parent_data_type":"",
   "data_type":"Registry",
   "timestamp":"2020-11-18T02:26:05.144",
   "device_name":"DESKTOP-NDPUZZM4",
   "device_domain":"DESKTOP-NDPUZZM4",
   "device_type":"Windows 10",
   "registry_hive":"HKEY_USERS",
   "registry_key":"Volatile",
   "registry_value_name":"MsaDevice",
   "registry_type":"REG_SZ",
   "registry_value":"t=GwAWAbuEBAAUPrSa9Xbh1D0J93uIPuLO4a+WXwAOZgAAEBTGT0K0Z4Yb1yQ+kp9BEdHgANLuAcfHOSjYFFBzGrBrLhP7Tn42DVLHomaP99kfluqc6pesVhV/Pwr486/KC0rhecROAWOfhfLOeIzcCP3ac+7Gd39nLfE3i0XBqwixziztwygu+xEFSlxrHSRLu0Rl1YWZ4rasrpcX+r43oj6PLzuVWtCkwq+mcFMKhjdC9394PnyoO4hh0oPxt9Gk3JZN784wc6D3AKMT8nntlvzhsBpN+nedTBBTzDmqDh3KiZCgGQTghwy/qXV4/wIg/2Hu1XXbe2f1EbymQeQ1+flMSoIzD15JRNDXITeFWljFcGwE=&p=",
   "last_write_time":"2020-11-16T12:36:21.928",
   "tags":[
      "Obfuscation",
      "Encoding"
   ]
}
```
