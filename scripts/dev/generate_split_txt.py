import os
from pathlib import Path

WORKSPACE = Path("c:/Users/prem/Network").resolve()
OUTPUT_FILE_1 = WORKSPACE / "all_part1.txt"
OUTPUT_FILE_2 = WORKSPACE / "all_part2.txt"
OUTPUT_FILE_CLEAN = WORKSPACE / "all_combined.txt"

EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "dist", "build",
    "__pycache__", ".pytest_cache", "old files", ".vscode", ".idea", "tmp", "runtime"
}

EXCLUDE_EXTS = {
    ".zip", ".7z", ".rar", ".db", ".sqlite", ".sqlite3", ".png", ".jpg",
    ".jpeg", ".gif", ".ico", ".pdf", ".docx", ".doc", ".pptx", ".ppt",
    ".exe", ".dll", ".so", ".dylib", ".pcap", ".pcapng", ".pyc", ".dat",
    ".woff", ".woff2", ".eot", ".ttf", ".mp3", ".mp4"
}

EXCLUDE_FILES = {
    "all.txt", "all_part1.txt", "all_part2.txt", "generate_all_txt.py", "generate_split_txt.py"
}

def generate_dir_tree(root_path):
    lines = []
    def _walk(path, prefix=""):
        try:
            entries = sorted(list(path.iterdir()), key=lambda x: (not x.is_dir(), x.name.lower()))
        except Exception:
            return
        
        # Filter entries
        entries = [e for e in entries if e.name not in EXCLUDE_DIRS and e.name not in EXCLUDE_FILES]
        
        for i, entry in enumerate(entries):
            is_last = (i == len(entries) - 1)
            connector = "└── " if is_last else "├── "
            
            # Skip excluded files
            if not entry.is_dir() and entry.suffix.lower() in EXCLUDE_EXTS:
                continue
                
            lines.append(f"{prefix}{connector}{entry.name}")
            
            if entry.is_dir():
                new_prefix = prefix + ("    " if is_last else "│   ")
                _walk(entry, new_prefix)
                
    lines.append(root_path.name)
    _walk(root_path)
    return "\n".join(lines)

def gather_files(root_path):
    file_list = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Filter directories in place
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fname in EXCLUDE_FILES:
                continue
            if fpath.suffix.lower() in EXCLUDE_EXTS:
                continue
            file_list.append(fpath)
            
    # Sort files by path for consistency
    file_list.sort(key=lambda p: str(p.relative_to(root_path)))
    return file_list

def main():
    print("Generating directory tree...")
    tree = generate_dir_tree(WORKSPACE)
    
    print("Gathering files...")
    files = gather_files(WORKSPACE)
    
    # Read all files to get contents and sizes
    file_contents = []
    total_files_size = 0
    
    for fpath in files:
        rel_path = fpath.relative_to(WORKSPACE)
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            content = f"[ERROR READING FILE: {e}]"
        
        formatted_content = (
            "================================================================================\n"
            f"FILE: {rel_path}\n"
            "================================================================================\n"
            f"{content}\n\n"
        )
        file_contents.append((rel_path, formatted_content, len(formatted_content)))
        total_files_size += len(formatted_content)
        
    print(f"Total files size: {total_files_size / 1024 / 1024:.2f} MB")
    
    # Gather DB schema content
    db_schema_content = ""
    db_dir = WORKSPACE / "infra" / "database"
    if db_dir.exists():
        init_sql = db_dir / "init.sql"
        if init_sql.exists():
            db_schema_content += f"--- DATABASE INIT SCHEMA: {init_sql.relative_to(WORKSPACE)} ---\n"
            db_schema_content += init_sql.read_text(encoding="utf-8", errors="replace") + "\n\n"
        
        migrations_dir = db_dir / "migrations"
        if migrations_dir.exists():
            migration_files = sorted(list(migrations_dir.glob("*.sql")), key=lambda p: p.name)
            for mig in migration_files:
                db_schema_content += f"--- MIGRATION: {mig.relative_to(WORKSPACE)} ---\n"
                db_schema_content += mig.read_text(encoding="utf-8", errors="replace") + "\n\n"
                
    db_schema_formatted = (
        "================================================================================\n"
        "DATABASE SCHEMA INFORMATION (SQL & MIGRATIONS)\n"
        "================================================================================\n\n"
        f"{db_schema_content}\n"
    )
    
    tree_formatted = (
        "================================================================================\n"
        "PROJECT DIRECTORY TREE STRUCTURE\n"
        "================================================================================\n\n"
        f"{tree}\n\n"
    )
    
    # Write the complete clean all.txt first
    print(f"Creating cleaned {OUTPUT_FILE_CLEAN}...")
    with open(OUTPUT_FILE_CLEAN, "w", encoding="utf-8", errors="replace") as out:
        out.write(tree_formatted)
        out.write(db_schema_formatted)
        out.write("================================================================================\n")
        out.write("PROJECT SOURCE FILES & DOCUMENTATION\n")
        out.write("================================================================================\n\n")
        for _, fc, _ in file_contents:
            out.write(fc)

    # Now split the files list by size
    half_size = total_files_size / 2
    part1_files = []
    part2_files = []
    accumulated_size = 0
    
    for rel_path, fc, size in file_contents:
        if accumulated_size < half_size:
            part1_files.append(fc)
            accumulated_size += size
        else:
            part2_files.append(fc)
            
    print(f"Part 1 size (files): {accumulated_size / 1024 / 1024:.2f} MB")
    print(f"Part 2 size (files): {(total_files_size - accumulated_size) / 1024 / 1024:.2f} MB")
    
    # Write Part 1
    print(f"Creating {OUTPUT_FILE_1}...")
    with open(OUTPUT_FILE_1, "w", encoding="utf-8", errors="replace") as out1:
        out1.write("================================================================================\n")
        out1.write("PROJECT CODEBASE SUMMARY - PART 1 of 2\n")
        out1.write("================================================================================\n\n")
        out1.write(tree_formatted)
        out1.write(db_schema_formatted)
        out1.write("================================================================================\n")
        out1.write("PROJECT SOURCE FILES & DOCUMENTATION - PART 1\n")
        out1.write("================================================================================\n\n")
        for fc in part1_files:
            out1.write(fc)
            
    # Write Part 2
    print(f"Creating {OUTPUT_FILE_2}...")
    with open(OUTPUT_FILE_2, "w", encoding="utf-8", errors="replace") as out2:
        out2.write("================================================================================\n")
        out2.write("PROJECT CODEBASE SUMMARY - PART 2 of 2\n")
        out2.write("================================================================================\n\n")
        out2.write(tree_formatted)
        out2.write("================================================================================\n")
        out2.write("PROJECT SOURCE FILES & DOCUMENTATION - PART 2\n")
        out2.write("================================================================================\n\n")
        for fc in part2_files:
            out2.write(fc)
            
    print("Done splitting and cleaning codebase files successfully!")

if __name__ == "__main__":
    main()
