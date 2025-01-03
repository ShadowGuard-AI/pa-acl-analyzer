# pa-acl-analyzer
Analyzes file system access control lists (ACLs) and reports on effective permissions for specified users or groups. Uses the 'os' and 'subprocess' modules to interact with system commands like 'getfacl' on Linux, can use 'icacls' on Windows. Outputs in easily parseable format, like JSON or CSV. - Focused on Tools for analyzing and assessing file system permissions. Focuses on identifying potential misconfigurations or over-permissive setups using path patterns. Uses pathspec for flexible matching of files and directories.

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-acl-analyzer`

## Usage
`./pa-acl-analyzer [params]`

## Parameters
- `-h`: Show help message and exit

## License
Copyright (c) ShadowStrikeHQ