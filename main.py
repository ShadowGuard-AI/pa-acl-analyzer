import argparse
import json
import logging
import os
import platform
import subprocess
import sys
from typing import Dict, List, Optional

from pathspec import PathSpec
from rich import print
from rich.logging import RichHandler

# Setup logging
logging.basicConfig(
    level="INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)
log = logging.getLogger("rich")


def setup_argparse():
    """Sets up the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Analyzes file system access control lists (ACLs) and reports on effective permissions.",
        epilog="Example usage: python main.py --path /home/user --user testuser --output output.json",
    )

    parser.add_argument(
        "--path",
        type=str,
        required=True,
        help="The base path to analyze ACLs.",
    )
    parser.add_argument(
        "--user",
        type=str,
        help="The user to check effective permissions for. Can't be used with --group.",
    )
    parser.add_argument(
        "--group",
        type=str,
        help="The group to check effective permissions for. Can't be used with --user.",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="The output file path for JSON results.",
    )
    parser.add_argument(
        "--patterns",
        type=str,
        default="*",
        help="Path patterns to include in the analysis using pathspec syntax. Comma separated. (e.g. *.txt, dir/*, !excluded_dir/*)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all files and directories matching the pattern without analyzing permissions.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def validate_args(args):
    """Validates the command-line arguments."""
    if args.user and args.group:
        log.error("Cannot specify both --user and --group.")
        sys.exit(1)

    if not os.path.exists(args.path):
        log.error(f"The specified path does not exist: {args.path}")
        sys.exit(1)

    if not os.path.isdir(args.path) and not os.path.isfile(args.path):
         log.error(f"The specified path is not a valid directory or file: {args.path}")
         sys.exit(1)


def get_acl(path: str) -> Optional[str]:
    """Gets the ACL for a given path."""
    if platform.system() == "Linux":
        try:
            result = subprocess.run(
                ["getfacl", "--absolute-names", path],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            log.debug(f"Error getting ACL for {path}: {e}")
            return None
    elif platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["icacls", path], capture_output=True, text=True, check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            log.debug(f"Error getting ACL for {path}: {e}")
            return None
    else:
        log.warning(f"Unsupported operating system: {platform.system()}")
        return None


def parse_acl(acl_output: str, user: Optional[str], group: Optional[str]) -> Dict:
    """Parses the ACL output for effective permissions."""
    permissions = {
        "read": False,
        "write": False,
        "execute": False,
        "full_control": False,
    }

    if not acl_output:
        return permissions

    if platform.system() == "Linux":
        acl_lines = acl_output.strip().split("\n")
        for line in acl_lines:
            if line.startswith("#") or not line:  # Skip comments and empty lines
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                entity_type, entity, perms = parts[0], parts[1], parts[2]
                if (user and entity == user and entity_type == "user") or (
                    group and entity == group and entity_type == "group"
                ) or (not user and not group):
                    permissions["read"] = "r" in perms
                    permissions["write"] = "w" in perms
                    permissions["execute"] = "x" in perms
                    permissions["full_control"] = "rwx" in perms
    elif platform.system() == "Windows":
        acl_lines = acl_output.strip().split("\n")
        for line in acl_lines:
             if " " not in line:
                 continue
             
             parts = line.split()
             
             if len(parts) < 3:
                 continue
                
             entity = parts[0].strip()
             if len(entity) == 0:
                continue

             if user and user.lower() == entity.lower():
                 perms = parts[1].strip()
                 permissions["read"] = "R" in perms
                 permissions["write"] = "W" in perms
                 permissions["execute"] = "X" in perms
                 permissions["full_control"] = "F" in perms

             elif group and group.lower() == entity.lower():
                 perms = parts[1].strip()
                 permissions["read"] = "R" in perms
                 permissions["write"] = "W" in perms
                 permissions["execute"] = "X" in perms
                 permissions["full_control"] = "F" in perms
             elif not user and not group:
                perms = parts[1].strip()
                permissions["read"] = "R" in perms
                permissions["write"] = "W" in perms
                permissions["execute"] = "X" in perms
                permissions["full_control"] = "F" in perms
    return permissions


def analyze_path(path: str, patterns: str, user: Optional[str], group: Optional[str]) -> List[Dict]:
    """Analyzes all files and directories under the given path that match the given patterns"""
    
    results = []
    if os.path.isfile(path):
        if not patterns or match_path(patterns, path):
            acl_output = get_acl(path)
            permissions = parse_acl(acl_output, user, group)
            results.append(
                {
                    "path": path,
                    "permissions": permissions,
                }
            )
        return results
    
    for root, _, files in os.walk(path):
        for filename in files:
            file_path = os.path.join(root, filename)
            if not patterns or match_path(patterns, file_path):
                 acl_output = get_acl(file_path)
                 permissions = parse_acl(acl_output, user, group)
                 results.append(
                     {
                         "path": file_path,
                         "permissions": permissions,
                     }
                 )

    for root, dirs, _ in os.walk(path):
        for dirname in dirs:
             dir_path = os.path.join(root, dirname)
             if not patterns or match_path(patterns, dir_path):
                 acl_output = get_acl(dir_path)
                 permissions = parse_acl(acl_output, user, group)
                 results.append(
                     {
                         "path": dir_path,
                         "permissions": permissions,
                     }
                 )

    return results

def match_path(patterns: str, path:str) -> bool:
    """Check if a given path matches the provided path patterns using pathspec."""
    try:
        path_patterns = patterns.split(',')
        spec = PathSpec.from_lines('gitwildmatch', path_patterns)
        return spec.match_file(path)
    except Exception as e:
        log.error(f"Error matching patterns with path '{path}'. Please check patterns: {e}")
        return False

def list_path(path: str, patterns: str) -> List[Dict]:
     """List all files and directories under the given path that match the given patterns"""
     results = []
     if os.path.isfile(path):
         if not patterns or match_path(patterns, path):
             results.append({
                 "path": path,
             })
         return results
    
     for root, _, files in os.walk(path):
         for filename in files:
             file_path = os.path.join(root, filename)
             if not patterns or match_path(patterns, file_path):
                 results.append(
                     {
                         "path": file_path,
                     }
                 )
     for root, dirs, _ in os.walk(path):
            for dirname in dirs:
                dir_path = os.path.join(root, dirname)
                if not patterns or match_path(patterns, dir_path):
                    results.append({
                         "path": dir_path,
                     })

     return results

def main():
    """Main function to run the ACL analyzer."""
    parser = setup_argparse()
    args = parser.parse_args()

    if args.debug:
         log.setLevel("DEBUG")
    
    validate_args(args)
    
    if args.list:
      results = list_path(args.path, args.patterns)
      if args.output:
            try:
                with open(args.output, "w") as outfile:
                    json.dump(results, outfile, indent=4)
                log.info(f"Results saved to: {args.output}")
            except Exception as e:
                log.error(f"Error writing to output file: {e}")
      else:
          print(json.dumps(results, indent=4))
      return
    
    results = analyze_path(args.path, args.patterns, args.user, args.group)

    if args.output:
        try:
            with open(args.output, "w") as outfile:
                json.dump(results, outfile, indent=4)
            log.info(f"Results saved to: {args.output}")
        except Exception as e:
            log.error(f"Error writing to output file: {e}")
    else:
       print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()