# pa-acl-analyzer
Analyzes file system access control lists (ACLs) and reports on effective permissions for specified users or groups. Uses the 'os' and 'subprocess' modules to interact with system commands like 'getfacl' on Linux, can use 'icacls' on Windows. Output is JSON only. - Focused on Tools for analyzing and assessing file system permissions. Reports the effective permissions it finds for the paths that match the given patterns, using pathspec for matching of files and directories. On Linux, entries are combined per entity class: the empty entity entries are matched to the file owner and owning group named in the getfacl header, and the mask entry is applied to named user and group entries.

The run states how many paths were analysed. It exits 1 when the getfacl or icacls tool is not available, when the output file cannot be written, when nothing was analysed, and when the output path is the analysed file itself or, in directory mode, any file that was itself analysed, which it refuses to overwrite.

## Install
`git clone https://github.com/ShadowGuard-AI/pa-acl-analyzer`
`pip install -r requirements.txt`

## Usage
`python3 main.py --path PATH [options]`

## Parameters
- `-h`: Show help message and exit
- `--path`: The base path to analyze ACLs. Required.
- `--user`: The user to check effective permissions for. Cannot be used with --group.
- `--group`: The group to check effective permissions for. Cannot be used with --user.
- `--output`: The output file path for JSON results.
- `--patterns`: Path patterns to include in the analysis using pathspec syntax, comma separated (e.g., *.txt, dir/*, !excluded_dir/*). Default: *.
- `--list`: List all files and directories matching the pattern without analyzing permissions.
- `--debug`: Enable debug logging.

## Verified behavior
- `python3 -m py_compile main.py` passes, but `python3 main.py --help` fails in this sandbox at import: `pathspec` and `rich` are not installed, and installs are forbidden in this wave. The parameter list above is taken from the argument parser in `main.py`, and no live analysis is claimed here. A live run also needs `getfacl` on Linux or `icacls` on Windows, neither of which is present here.
- Exit 1 cases, read from the code: both --user and --group given, a nonexistent or invalid path, no paths matched, an unwritable output file, and an output path that is itself an analysed file, which the tool refuses to overwrite.

## License
See LICENSE.