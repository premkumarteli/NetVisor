import os
import glob

def combine_test_files():
    tests_dir = r"c:\Users\prem\Network\tests"
    output_file = r"c:\Users\prem\Network\test_netvisor.txt"

    # Find all test_*.py files recursively
    pattern = os.path.join(tests_dir, "**", "test_*.py")
    test_files = glob.glob(pattern, recursive=True)

    # Sort the files alphabetically by path
    test_files.sort()

    print(f"Found {len(test_files)} test files to combine.")

    try:
        with open(output_file, "w", encoding="utf-8") as out:
            for filepath in test_files:
                rel_path = os.path.relpath(filepath, r"c:\Users\prem\Network")
                out.write(f"# ==========================================\n")
                out.write(f"# File: {rel_path}\n")
                out.write(f"# ==========================================\n\n")
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                        out.write(content)
                except Exception as e:
                    out.write(f"# Error reading file: {e}\n")
                out.write("\n\n")
        print(f"Successfully combined and wrote all files to: {output_file}")
    except Exception as e:
        print(f"Failed to write output file: {e}")

if __name__ == "__main__":
    combine_test_files()
