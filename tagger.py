#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

CARGO_TOML = Path("Cargo.toml")
PYPROJECT_TOML = Path("pyproject.toml")

def run(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(result.returncode)
    return result.stdout.strip()

def get_current_version():
    content = PYPROJECT_TOML.read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    return match.group(1) if match else None

def bump_version(version_str):
    major, minor, patch = map(int, version_str.split('.'))
    return f"{major}.{minor}.{patch + 1}"

def update_file(path, old_ver, new_ver):
    content = path.read_text()
    new_content = content.replace(f'version = "{old_ver}"', f'version = "{new_ver}"', 1)
    path.write_text(new_content)

def main():
    old_ver = get_current_version()
    if not old_ver:
        print("Could not find version.")
        sys.exit(1)
        
    new_ver = bump_version(old_ver)
    tag = f"v{new_ver}"
    print(f"Releasing {tag}...")
    
    update_file(CARGO_TOML, old_ver, new_ver)
    update_file(PYPROJECT_TOML, old_ver, new_ver)
    
    run("git add Cargo.toml pyproject.toml")
    run(f'git commit -m "chore: release {tag}"')
    run(f'git tag -a {tag} -m "Release {tag}"')
    
    branch = run("git rev-parse --abbrev-ref HEAD")
    print(f"Pushing {branch} and {tag}...")
    run(f"git push origin {branch} --follow-tags")
    
    print(f"\nSUCCESS: {tag} pushed. GitHub will now build and publish to PyPI.")

if __name__ == "__main__":
    main()
