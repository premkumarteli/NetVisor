import os
from pathlib import Path

WORKSPACE = Path("c:/Users/prem/Network").resolve()
OUTPUT_FILE = WORKSPACE / "all.txt"

EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "dist", "build",
    "__pycache__", ".pytest_cache", "old files", ".vscode", ".idea", "tmp"
}

EXCLUDE_EXTS = {
    ".zip", ".7z", ".rar", ".db", ".sqlite", ".sqlite3", ".png", ".jpg",
    ".jpeg", ".gif", ".ico", ".pdf", ".docx", ".doc", ".pptx", ".ppt",
    ".exe", ".dll", ".so", ".dylib", ".pcap", ".pcapng", ".pyc", ".dat",
    ".woff", ".woff2", ".eot", ".ttf", ".mp3", ".mp4"
}

EXCLUDE_FILES = {
    "all.txt", "generate_all_txt.py"
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
    
    with open(OUTPUT_FILE, "w", encoding="utf-8", errors="replace") as out:
        out.write("================================================================================\n")
        out.write("PROJECT DIRECTORY TREE STRUCTURE\n")
        out.write("================================================================================\n\n")
        out.write(tree)
        out.write("\n\n")
        
        # Write database schema section first
        out.write("================================================================================\n")
        out.write("DATABASE SCHEMA INFORMATION (SQL & MIGRATIONS)\n")
        out.write("================================================================================\n\n")
        
        # Find init.sql and migrations and output them
        db_dir = WORKSPACE / "infra" / "database"
        if db_dir.exists():
            init_sql = db_dir / "init.sql"
            if init_sql.exists():
                out.write(f"--- DATABASE INIT SCHEMA: {init_sql.relative_to(WORKSPACE)} ---\n")
                out.write(init_sql.read_text(encoding="utf-8", errors="replace"))
                out.write("\n\n")
            
            migrations_dir = db_dir / "migrations"
            if migrations_dir.exists():
                migration_files = sorted(list(migrations_dir.glob("*.sql")), key=lambda p: p.name)
                for mig in migration_files:
                    out.write(f"--- MIGRATION: {mig.relative_to(WORKSPACE)} ---\n")
                    out.write(mig.read_text(encoding="utf-8", errors="replace"))
                    out.write("\n\n")
        
        # Write all files content
        out.write("================================================================================\n")
        out.write("PROJECT SOURCE FILES & DOCUMENTATION\n")
        out.write("================================================================================\n\n")
        
        for fpath in files:
            rel_path = fpath.relative_to(WORKSPACE)
            out.write("================================================================================\n")
            out.write(f"FILE: {rel_path}\n")
            out.write("================================================================================\n")
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                out.write(content)
            except Exception as e:
                out.write(f"[ERROR READING FILE: {e}]\n")
            out.write("\n\n")
            
    print(f"Successfully created {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
