# reg_hunter
Blueteam operational triage registry hunting/forensic tool.

Thank you to https://twitter.com/Hexacorn and https://twitter.com/SBousseaden for their open research. Many of the explicit registry keys and values defined in this tool came from their graciously shared hard work.

Output is in JSON.

NOTE: The parent_data_type field specifies the data_type that caused the generation of this data type. E.g. If a Lnk file was found in a registry value, this will generate a "ShellLink" data_type with a parent_data_type of "Registry". Then a data_type of "File" with a parent_data_type of "ShellLink" will be generated if the file that the Lnk file points to is found/exists. I.e. Registry --> ShellLink --> File

```
Reg Hunter
    Author: Brian Kellogg
    License: MIT
    Disclaimer: 
        This tool comes with no warranty or support. 
        If anyone chooses to use it, you accept all responsibility and liability.

Usage:
    reg_hunter [options]
    reg_hunter --explicit -f -n [--ip <ip> --port <port>]
    reg_hunter --all --null [--ip <ip> --port <port>] [--limit]
    reg_hunter --all --explicit -b -f --limit
    reg_hunter --help

Switches:
    Registry context:
        -a, --all                   Examine all the registry; HKLM and HKU
        -x, --explicit              Examine only more often forensically interesting keys and values
                                        This option will always report out all 
                                        value names and values unless values are empty/null.

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
        -u, --unc                   Find possible UNC paths
        -r, --script                Find script files
        -s, --shellcode             Find possible shellcode
        -w, --url                   Find URLs
        -y, --everything            Run ALL forensics
        -z, --suspicious            Find various suspicious substrings
                                        e.g. iex, invoke-expression, etc.
        

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
