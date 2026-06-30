import os
import re

# The replacements ordered by specificity
REPLACEMENTS = [
    ("Aegis WAF", "jarsWAF"),
    ("AEGIS WAF", "jarsWAF"),
    ("aegis-waf", "jarswaf"),
    ("aegis_waf", "jarswaf"),
    ("Aegis", "jarsWAF"),
    ("aegis", "jarswaf"),
    ("AEGIS", "JARSWAF"),
]

def process_content(content):
    for old, new in REPLACEMENTS:
        content = content.replace(old, new)
    return content

def rename_in_files(directory):
    skip_dirs = {'.git', 'target', 'node_modules', 'dist', 'build', '.svelte-kit'}
    
    for root, dirs, files in os.walk(directory, topdown=True):
        # Modify dirs in-place to skip unwanted directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for file in files:
            # Skip non-text files and the script itself
            if file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.exe', '.dll', '.so', '.pyc')) or file == 'rename.py':
                continue
                
            file_path = os.path.join(root, file)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                new_content = process_content(content)
                
                if content != new_content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Updated content in: {file_path}")
            except (UnicodeDecodeError, PermissionError):
                # Probably a binary file or no permission
                pass

def rename_files_and_dirs(directory):
    skip_dirs = {'.git', 'target', 'node_modules', 'dist', 'build', '.svelte-kit'}
    
    for root, dirs, files in os.walk(directory, topdown=False):
        # Rename files
        for file in files:
            if file == 'rename.py':
                continue
            new_file = process_content(file)
            if new_file != file:
                old_path = os.path.join(root, file)
                new_path = os.path.join(root, new_file)
                os.rename(old_path, new_path)
                print(f"Renamed file: {old_path} -> {new_path}")
                
        # Rename directories
        for d in dirs:
            if d in skip_dirs:
                continue
            new_dir = process_content(d)
            if new_dir != d:
                old_path = os.path.join(root, d)
                new_path = os.path.join(root, new_dir)
                os.rename(old_path, new_path)
                print(f"Renamed directory: {old_path} -> {new_path}")

if __name__ == '__main__':
    target_dir = 'D:/Desktop/KERJA/aegis-waf'
    print("Starting content replacement...")
    rename_in_files(target_dir)
    print("Starting file and directory renaming...")
    rename_files_and_dirs(target_dir)
    print("Done!")
