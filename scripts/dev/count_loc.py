import os
from collections import defaultdict

def count_lines_of_code():
    root_dir = r"c:\Users\prem\Network"
    exclude_dirs = {".git", ".venv", "node_modules", ".pytest_cache", "__pycache__", "dist", "build"}
    exclude_files = {"test_netvisor.txt", "package-lock.json"}
    
    stats = defaultdict(lambda: {"files": 0, "lines": 0})
    
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Prune excluded directories
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        
        for filename in filenames:
            if filename in exclude_files:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext in {".py", ".js", ".jsx", ".css", ".html", ".sql", ".sh", ".yml", ".yaml", ".json"}:
                filepath = os.path.join(dirpath, filename)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        stats[ext]["files"] += 1
                        stats[ext]["lines"] += len(lines)
                except Exception:
                    pass
                    
    print("Language/File Type Breakdown:")
    total_lines = sum(s["lines"] for s in stats.values())
    for ext, s in sorted(stats.items(), key=lambda item: item[1]["lines"], reverse=True):
        percentage = (s["lines"] / total_lines * 100) if total_lines > 0 else 0
        print(f"Extension: {ext:<6} Files: {s['files']:<5} Lines: {s['lines']:<7} Percentage: {percentage:.2f}%")

if __name__ == "__main__":
    count_lines_of_code()
