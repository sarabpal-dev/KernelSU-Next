#!/usr/bin/env python3
import sys
import struct
import hashlib
from pathlib import Path

def get_apk_cert_info(apk_path: Path):
    with open(apk_path, "rb") as f:
        f.seek(0, 2)
        file_size = f.tell()
        
        # Read the last 65557 bytes to find EOCD header
        read_len = min(file_size, 65557)
        f.seek(file_size - read_len)
        tail = f.read(read_len)
        
        eocd_idx = tail.rfind(b"\x50\x4b\x05\x06")
        if eocd_idx == -1:
            raise ValueError("EOCD header not found")
            
        eocd_offset = (file_size - read_len) + eocd_idx
        f.seek(eocd_offset + 16)
        cd_offset = struct.unpack("<I", f.read(4))[0]
        
        # Verify APK Sig Block magic
        f.seek(cd_offset - 16)
        magic = f.read(16)
        if magic != b"APK Sig Block 42":
            raise ValueError(f"APK Sig Block 42 magic not found (got {magic})")
            
        f.seek(cd_offset - 24)
        block_size_1 = struct.unpack("<Q", f.read(8))[0]
        
        sig_block_start = cd_offset - (block_size_1 + 8)
        f.seek(sig_block_start)
        block_size_2 = struct.unpack("<Q", f.read(8))[0]
        
        if block_size_1 != block_size_2:
            raise ValueError("Block sizes mismatch in APK Sig Block")
            
        pos = sig_block_start + 8
        end_pos = cd_offset - 16
        
        while pos < end_pos:
            f.seek(pos)
            entry_len = struct.unpack("<Q", f.read(8))[0]
            if entry_len == block_size_1:
                break
            entry_id = struct.unpack("<I", f.read(4))[0]
            
            if entry_id == 0x7109871a: # V2 Signature Scheme ID
                f.seek(pos + 12) # Skip entry_len & entry_id
                signers_seq_len = struct.unpack("<I", f.read(4))[0]
                signer_len = struct.unpack("<I", f.read(4))[0]
                signed_data_len = struct.unpack("<I", f.read(4))[0]
                
                digests_seq_len = struct.unpack("<I", f.read(4))[0]
                f.seek(digests_seq_len, 1) # Skip digests sequence
                
                certs_seq_len = struct.unpack("<I", f.read(4))[0]
                cert_len = struct.unpack("<I", f.read(4))[0]
                
                cert_data = f.read(cert_len)
                cert_sha256 = hashlib.sha256(cert_data).hexdigest()
                
                return cert_len, f"0x{cert_len:x}", cert_sha256
                
            pos += 8 + entry_len
            
    raise ValueError("V2 signature block (id 0x7109871a) not found in APK")

def update_ksu_next_kbuild(size_hex: str, cert_hash: str, repo_root: Path) -> bool:
    kbuild_candidates = [
        repo_root / "kernel" / "Kbuild",
        repo_root.parent / "KernelSU-Next" / "kernel" / "Kbuild",
        repo_root / "KernelSU-Next" / "kernel" / "Kbuild",
    ]
    kbuild_path = None
    for cand in kbuild_candidates:
        if cand.exists():
            kbuild_path = cand
            break
    if not kbuild_path:
        print(f"[WARN] KernelSU-Next Kbuild not found in candidates")
        return False
        
    content = kbuild_path.read_text(encoding="utf-8")
    
    import re
    new_content = re.sub(
        r"KSU_NEXT_MANAGER_SIZE\s*:=\s*0x[0-9a-fA-F]+",
        f"KSU_NEXT_MANAGER_SIZE := {size_hex}",
        content
    )
    new_content = re.sub(
        r"KSU_NEXT_MANAGER_HASH\s*:=\s*[0-9a-fA-F]+",
        f"KSU_NEXT_MANAGER_HASH := {cert_hash}",
        new_content
    )
    
    if new_content != content:
        kbuild_path.write_text(new_content, encoding="utf-8")
        print(f"Successfully updated KernelSU-Next Kbuild:\n  SIZE: {size_hex}\n  HASH: {cert_hash}")
    else:
        print(f"KernelSU-Next Kbuild is already up to date ({size_hex}).")
    return True

def main():
    repo_root = Path(__file__).resolve().parent.parent
    do_update = "--update" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--update"]
    
    apks = [
        ("Release APK", repo_root / "manager/app/build/outputs/apk/release/KernelSU_7d7322f_30001-release.apk"),
        ("Debug APK", repo_root / "manager/app/build/outputs/apk/debug/KernelSU_7d7322f_30001-debug.apk")
    ]
    
    if args:
        apks = [("Specified APK", Path(args[0]))]
        
    for name, apk_path in apks:
        print(f"=== {name} ===")
        print(f"File: {apk_path}")
        if not apk_path.exists():
            print("File not found!\n")
            continue
        try:
            size_dec, size_hex, cert_hash = get_apk_cert_info(apk_path)
            print(f"EXPECTED_MANAGER_SIZE : {size_hex} ({size_dec})")
            print(f"EXPECTED_MANAGER_HASH : {cert_hash}\n")
            if do_update:
                update_ksu_next_kbuild(size_hex, cert_hash, repo_root)
        except Exception as err:
            print(f"Error: {err}\n")

if __name__ == "__main__":
    main()

