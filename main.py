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
        except OSError as e:
            log.error(f"The 'getfacl' tool is not available on this system: {e}")
            sys.exit(1)
    elif platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["icacls", path], capture_output=True, text=True, check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            log.debug(f"Error getting ACL for {path}: {e}")
            return None
        except OSError as e:
            log.error(f"The 'icacls' tool is not available on this system: {e}")
            sys.exit(1)
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
        owner = None
        owning_group = None
        entries = []
        mask_perms = None
        for line in acl_output.strip().split("\n"):
            if line.startswith("# owner:"):
                owner = line.split(":", 1)[1].strip()
                continue
            if line.startswith("# group:"):
                owning_group = line.split(":", 1)[1].strip()
                continue
            if line.startswith("#") or not line:  # Skip other comments and empty lines
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                entity_type, entity, perms = parts[0], parts[1], parts[2]
                if entity_type == "mask":
                    mask_perms = perms
                else:
                    entries.append((entity_type, entity, perms))

        def masked(perms):
            if mask_perms is None:
                return perms
            return "".join(c for c in perms if c in mask_perms)

        def combine(perms):
            permissions["read"] = permissions["read"] or "r" in perms
            permissions["write"] = permissions["write"] or "w" in perms
            permissions["execute"] = permissions["execute"] or "x" in perms

        matched = False
        if user:
            for entity_type, entity, perms in entries:
                if entity_type == "user" and entity == "" and user == owner:
                    # The owner entry is the one place I deliberately do not apply the mask: POSIX leaves owner permissions unmasked, while the named user entry just below goes through masked(). Swapping those two would misreport both.
                    combine(perms)
                    matched = True
                elif entity_type == "user" and entity == user:
                    combine(masked(perms))
                    matched = True
            # Once any user entry matches I stop here, and I never consult the groups this user belongs to at all. A user whose only real access comes through a group entry falls through to the other entry below and is reported with that, which understates group granted access.
            if not matched:
                for entity_type, entity, perms in entries:
                    if entity_type == "other":
                        combine(perms)
                        matched = True
        elif group:
            for entity_type, entity, perms in entries:
                if entity_type == "group" and entity == "" and group == owning_group:
                    combine(masked(perms))
                    matched = True
                elif entity_type == "group" and entity == group:
                    combine(masked(perms))
                    matched = True
            if not matched:
                for entity_type, entity, perms in entries:
                    if entity_type == "other":
                        combine(perms)
                        matched = True
        else:
            # With neither user nor group named I union every entry in the ACL into one result. That is a summary of what the ACL grants to anyone, not the effective access of any single principal, and it will show full control for a file where no one principal holds all three letters.
            for entity_type, entity, perms in entries:
                if entity_type in ("user", "group") and entity != "":
                    combine(masked(perms))
                else:
                    combine(perms)
        permissions["full_control"] = (
            permissions["read"] and permissions["write"] and permissions["execute"]
        )
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
                 # On the Windows side I assign instead of combining, so when icacls prints several lines for the same principal the last line wins and wipes whatever the earlier lines granted. The split above also assumes the principal name has no spaces, which names like a domain group with a space in it break.
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

    # This second walk is how directories get in at all, since the first walk only visits files. The starting directory itself appears in neither walk as an entry, so the root of the analysed tree never gets a row of its own.
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
        # I rebuild the whole PathSpec for every single path I test. That keeps match_path stateless, at the cost of reparsing the same patterns once per file on a large tree.
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

    if args.output:
        output_resolved = os.path.realpath(args.output)
        if os.path.isfile(args.path):
            analysed_resolved = [os.path.realpath(args.path)]
        else:
            analysed_resolved = [
                os.path.realpath(item["path"])
                for item in list_path(args.path, args.patterns)
            ]
        if output_resolved in analysed_resolved:
            log.error(
                "Refusing to write output over a file that is being analysed: "
                f"{args.output}"
            )
            sys.exit(1)

    if args.list:
      results = list_path(args.path, args.patterns)
      if args.output:
            try:
                with open(args.output, "w") as outfile:
                    json.dump(results, outfile, indent=4)
                log.info(f"Results saved to: {args.output}")
            except Exception as e:
                log.error(f"Error writing to output file: {e}")
                sys.exit(1)
      else:
          print(json.dumps(results, indent=4))
      return
    
    results = analyze_path(args.path, args.patterns, args.user, args.group)

    log.info(f"Analysed {len(results)} path(s).")
    if not results:
        log.error("Nothing was analysed: no paths matched.")
        sys.exit(1)

    if args.output:
        try:
            with open(args.output, "w") as outfile:
                json.dump(results, outfile, indent=4)
            log.info(f"Results saved to: {args.output}")
        except Exception as e:
            log.error(f"Error writing to output file: {e}")
            sys.exit(1)
    else:
       print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()