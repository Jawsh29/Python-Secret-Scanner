# This program is a command line tool that checks files for any potential passwords or hardcoded secrets
import os
import re
import argparse


def scan_file_for_secrets(file_path, secrets):
    """Scans file for secrets and returns list"""
    with open(file_path, 'r') as file:
        lines = file.readlines()

    secrets_found = []
    for line_number, line in enumerate(lines, 1):
        for secret in secrets:
            if re.search(secret, line, re.IGNORECASE):
                secrets_found.append((file_path, line_number, line.strip()))

    return secrets_found


def scan_directory_for_secrets(directory_path, secrets, extensions):
    """Scans directory for files to scan"""
    secrets_found = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                secrets_in_file = scan_file_for_secrets(file_path, secrets)
                secrets_found.extend(secrets_in_file)

    return secrets_found


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="Secret Scanner - Scans files for potential secret keys, tokens, and passwords."
    )
    parser.add_argument(
        "--dir",
        required=True,
        help="Directory to scan recursively."
    )
    parser.add_argument(
        "--ext",
        nargs="+",
        default=[".py"],
        help="File extensions to scan (e.g. --ext .py .txt .env). --ext all scans for all file types"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed scan results."
    )

    args = parser.parse_args()

    # Determine extensions to scan
    if args.ext == ["all"]:
        # Gather all unique file extensions
        all_exts = set()
        for root, _, files in os.walk(args.dir):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext:
                    all_exts.add(ext)
        extensions = sorted(all_exts)
        print(f"Detected extensions for scanning: {', '.join(extensions) if extensions else '(none)'}")
    else:
        extensions = args.ext

    # Regex Patterns to Scan
    secrets_patterns = [
        # General
        r'password\s*=\s*["\']([^"\']+)',
        r'api[_-]?key\s*=\s*["\']([^"\']+)',
        r'secret[_-]?key\s*=\s*["\']([^"\']+)',
        r'access[_-]?token\s*=\s*["\']([^"\']+)',
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
        r'(?i)aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        r'-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----',  # Private Keys
        r'ghp_[A-Za-z0-9]{36}',  # GitHub Personal Access Token
        r'xox[baprs]-[A-Za-z0-9-]+',  # Slack Token
        r'ya29\.[0-9A-Za-z\-_]+',  # Google OAuth Token
    ]

    target_directory = args.dir

    secrets_found = scan_directory_for_secrets(target_directory, secrets_patterns, extensions)

    if secrets_found:
        print("Secrets Found")
        for file_path, line_number, secret_line in secrets_found:
            print(f'{file_path}: {line_number} - {secret_line}')
        if args.verbose:
            print(f"\nTotal secrets found: {len(secrets_found)}")
    else:
        print("No Secrets Found")
