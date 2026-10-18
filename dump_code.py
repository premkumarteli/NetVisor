"""
NetVisor Codebase & Directory Structure Exporter.

Scans the repository, builds a complete directory tree, and exports all code
and configuration files into a single consolidated file (`all_code.txt`).
"""

import os
import sys

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
OUTPUT_FILE = os.path.join(REPO_ROOT, 'all_code.txt')

EXCLUDED_DIRS = {
    '.git', '.venv', '.venv-1', 'venv', 'node_modules', '__pycache__',
    '.pytest_cache', '.pytest_tmp', 'dist', 'build', '.idea', '.vscode',
    'db_dump', 'runtime', 'keys', '.agents', 'tmp', '.vite'
}

EXCLUDED_FILES = {
    'all_code.txt', 'all_project_code.txt', '.env'
}

BINARY_EXTENSIONS = {
    '.exe', '.zip', '.mp4', '.pcap', '.pcapng', '.sqlite', '.db', '.pdf',
    '.docx', '.pyc', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff',
    '.woff2', '.ttf', '.eot', '.dll', '.sys', '.dump', '.tar', '.gz'
}

def try_read_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return None, 'binary'
    
    # Try reading as UTF-8
    for enc in ['utf-8', 'utf-8-sig', 'utf-16']:
        try:
            with open(filepath, 'r', encoding=enc) as f:
                content = f.read()
                return content, enc
        except (UnicodeDecodeError, UnicodeError):
            continue
        except Exception:
            return None, 'error'

    # Fallback to latin-1 if no null bytes
    try:
        with open(filepath, 'r', encoding='latin-1') as f:
            content = f.read()
            if '\x00' not in content:
                return content, 'latin-1'
            else:
                return None, 'binary'
    except Exception:
        return None, 'error'

def build_dir_tree(dir_path, prefix=''):
    entries = sorted(os.listdir(dir_path), key=lambda s: s.lower())
    dirs = []
    files = []
    for e in entries:
        full = os.path.join(dir_path, e)
        if os.path.isdir(full):
            if e in EXCLUDED_DIRS or e.startswith('.pytest_tmp'):
                continue
            dirs.append(e)
        else:
            if e in EXCLUDED_FILES:
                continue
            files.append(e)
            
    items = [(d, True) for d in dirs] + [(f, False) for f in files]
    lines = []
    for i, (name, is_dir) in enumerate(items):
        is_last = (i == len(items) - 1)
        connector = '└── ' if is_last else '├── '
        child_prefix = prefix + ('    ' if is_last else '│   ')
        if is_dir:
            lines.append(f'{prefix}{connector}{name}/')
            lines.extend(build_dir_tree(os.path.join(dir_path, name), child_prefix))
        else:
            lines.append(f'{prefix}{connector}{name}')
    return lines

def main():
    print(f"Scanning repository at: {REPO_ROOT}...")
    
    # Collect all valid files
    all_files = []
    for root, dirs, files in os.walk(REPO_ROOT):
        # prune excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith('.pytest_tmp')]
        dirs.sort(key=lambda s: s.lower())
        
        for f in sorted(files, key=lambda s: s.lower()):
            if f in EXCLUDED_FILES:
                continue
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, REPO_ROOT).replace('\\', '/')
            content, enc = try_read_file(full_path)
            if content is not None:
                all_files.append((rel_path, full_path, content, enc))

    all_files.sort(key=lambda x: x[0].lower())
    
    total_files = len(all_files)
    total_lines = sum(c.count('\n') + 1 for _, _, c, _ in all_files)
    total_chars = sum(len(c) for _, _, c, _ in all_files)
    
    print(f"Found {total_files} text/code files.")
    print(f"Total lines of code: {total_lines:,}")
    print(f"Total characters: {total_chars:,} (~{total_chars / (1024*1024):.2f} MB)")
    
    print("Generating directory tree...")
    tree_lines = ['Network/'] + build_dir_tree(REPO_ROOT)
    
    print(f"Writing to output file: {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8', errors='replace') as out:
        # Header
        out.write("=" * 80 + "\n")
        out.write("NETVISOR COMPLETE CODEBASE REPOSITORY DUMP & DIRECTORY STRUCTURE\n")
        out.write("=" * 80 + "\n\n")
        out.write(f"Repository Root : {REPO_ROOT}\n")
        out.write(f"Total Files     : {total_files}\n")
        out.write(f"Total Lines     : {total_lines:,}\n")
        out.write(f"Total Size      : {total_chars / (1024*1024):.2f} MB\n\n")
        
        out.write("EXCLUDED DIRECTORIES & FILES (for size, security, and cleanliness):\n")
        out.write("  - .git/                    : Git version control objects\n")
        out.write("  - .venv/, venv/            : Python virtual environment packages\n")
        out.write("  - node_modules/            : Frontend NPM library dependencies\n")
        out.write("  - dist/, build/            : Compiled frontend bundles and distribution packages\n")
        out.write("  - __pycache__/, *.pyc      : Python bytecode cache\n")
        out.write("  - .pytest_cache/, .pytest_tmp* : Pytest test caches\n")
        out.write("  - db_dump/                 : Database backups (~9.8 GB, 20,626 files)\n")
        out.write("  - runtime/                 : Runtime logs and device state data\n")
        out.write("  - keys/                    : Cryptographic certificates and private keys\n")
        out.write("  - .env                     : Production environment secrets (see .env.example instead)\n")
        out.write("  - *.zip, *.exe, *.mp4, *.pdf, *.pcap : Binary media and archives\n\n")
        
        # Directory Structure Section
        out.write("=" * 80 + "\n")
        out.write("DIRECTORY STRUCTURE\n")
        out.write("=" * 80 + "\n\n")
        for line in tree_lines:
            out.write(line + "\n")
        out.write("\n\n")
        
        # Files Content Section
        out.write("=" * 80 + "\n")
        out.write("SOURCE CODE & FILE CONTENTS\n")
        out.write("=" * 80 + "\n\n")
        
        for idx, (rel_path, full_path, content, enc) in enumerate(all_files, 1):
            file_lines = content.count('\n') + 1
            file_bytes = len(content.encode('utf-8', errors='replace'))
            out.write("\n" + "=" * 80 + "\n")
            out.write(f"[{idx}/{total_files}] FILE: {rel_path}\n")
            out.write(f"Lines: {file_lines:,} | Size: {file_bytes:,} bytes | Encoding: {enc}\n")
            out.write("=" * 80 + "\n\n")
            out.write(content)
            if not content.endswith('\n'):
                out.write('\n')
                
    out_size = os.path.getsize(OUTPUT_FILE)
    print(f"Successfully generated {OUTPUT_FILE} ({out_size:,} bytes, {out_size / (1024*1024):.2f} MB).")

if __name__ == '__main__':
    main()
