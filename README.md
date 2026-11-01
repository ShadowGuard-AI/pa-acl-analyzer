# pa-acl-analyzer
Analyzes file system access control lists (ACLs) and reports on effective permissions for specified users or groups. Uses the 'os' and 'subprocess' modules to interact with system commands like 'getfacl' on Linux, can use 'icacls' on Windows. Output is JSON only. - Focused on Tools for analyzing and assessing file system permissions. Reports the effective permissions it finds for the paths that match the given patterns, using pathspec for matching of files and directories. On Linux, entries are combined per entity class: the empty entity entries are matched to the file owner and owning group named in the getfacl header, and the mask entry is applied to named user and group entries.

The run states how many paths were analysed. It exits 1 when the getfacl or icacls tool is not available, when the output file cannot be written, when nothing was analysed, and when the output path is the analysed file itself or, in directory mode, any file that was itself analysed, which it refuses to overwrite.

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-acl-analyzer`

## Usage
`./pa-acl-analyzer [params]`

## Parameters
- `-h`: Show help message and exit

## License
Copyright (c) ShadowStrikeHQ