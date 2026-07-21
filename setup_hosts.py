#!/usr/bin/env python3
import sys
import os
import platform
import ctypes

# Default entries to add
DEFAULT_ENTRIES = [
    ("127.0.0.1", "dev-waf.local"),
]

def is_admin():
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except Exception:
        return False

def get_hosts_path():
    system = platform.system()
    if system == "Windows":
        windir = os.environ.get("SystemRoot", "C:\\Windows")
        return os.path.join(windir, "System32", "drivers", "etc", "hosts")
    elif system in ("Linux", "Darwin"): # Darwin is macOS
        return "/etc/hosts"
    else:
        raise OSError(f"Unsupported operating system: {system}")

def setup_hosts():
    print("===================================================")
    print("      🛡️  jarsWAF hosts Configuration Helper  🛡️")
    print("===================================================\n")
    
    if not is_admin():
        print("[ERROR] Script ini memerlukan hak akses administrator/root.")
        if platform.system() == "Windows":
            print("Silakan jalankan Command Prompt / PowerShell sebagai 'Administrator'.")
        else:
            print("Silakan jalankan perintah ini dengan 'sudo':")
            print(f"sudo python3 {os.path.basename(__file__)}")
        sys.exit(1)
        
    try:
        hosts_path = get_hosts_path()
    except OSError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
        
    print(f"[INFO] Membaca file hosts dari: {hosts_path}")
    
    try:
        with open(hosts_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[ERROR] Gagal membaca file hosts: {e}")
        sys.exit(1)
        
    updated = False
    lines_to_add = []
    
    for ip, domain in DEFAULT_ENTRIES:
        # Check if domain already exists in the hosts file
        # We search for the domain name as a separate word to avoid partial matches
        domain_exists = False
        for line in content.splitlines():
            # Strip comments
            clean_line = line.split("#")[0].strip()
            tokens = clean_line.split()
            if domain in tokens:
                domain_exists = True
                print(f"[OK] Entry untuk '{domain}' sudah terdaftar ({tokens[0]} -> {domain}).")
                break
                
        if not domain_exists:
            entry_line = f"{ip:<15} {domain}"
            lines_to_add.append(entry_line)
            
    if lines_to_add:
        print("\n[INFO] Menambahkan entri berikut ke file hosts:")
        for line in lines_to_add:
            print(f"  + {line}")
            
        try:
            # We open with append mode
            # Ensure file ends with newline before appending
            newline_prefix = ""
            if content and not content.endswith("\n"):
                newline_prefix = "\n"
                
            with open(hosts_path, "a", encoding="utf-8") as f:
                f.write(newline_prefix + "\n# added by jarsWAF auto-configurator\n")
                for line in lines_to_add:
                    f.write(f"{line}\n")
            print("\n[SUCCESS] File hosts berhasil diperbarui.")
        except Exception as e:
            print(f"[ERROR] Gagal menulis ke file hosts: {e}")
            sys.exit(1)
    else:
        print("\n[INFO] Tidak ada perubahan yang diperlukan. File hosts Anda sudah siap.")

if __name__ == "__main__":
    setup_hosts()
