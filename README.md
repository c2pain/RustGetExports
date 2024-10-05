# RustGetExports (Exporting the exported function in Rust)

<p align="left">
	<a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/made%20with-Rust-red"></a>
	<a href="#"><img src="https://img.shields.io/badge/platform-windows-blueviolet"></a>
</p>

## Overview
Exporting the exported function rewritten in Rust. 

## Compile 
You need to compile the binary to run:
```
cargo build --release
```

## Usage
```
C:\Users\C2Pain\Desktop>RustGetExports.exe
Usage: RustGetExports.exe <path_to_pe_file>
Example: RustGetExports.exe C:\Windows\System32\netsh.exe

C:\Users\C2Pain\Desktop>RustGetExports.exe C:\Windows\System32\netsh.exe
NETSH.EXE
ConvertGuidToString
ConvertStringToGuid
DisplayMessageM
DisplayMessageToConsole
FreeQuotedString
FreeString
GenericMonitor
GetEnumString
InitializeConsole
MakeQuotedString
MakeString
MatchCmdLine
MatchEnumTag
MatchTagsInCmdLine
MatchToken
PreprocessCommand
PrintError
PrintMessage
PrintMessageFromModule
ProcessCommand
RefreshConsole
RegisterContext
```

## Reference
[Get-Exports.ps1](https://github.com/gtworek/PSBits/blob/master/Misc2/Get-Exports.ps1) by @gtworek
