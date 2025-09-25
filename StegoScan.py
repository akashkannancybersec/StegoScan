#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import random
from datetime import datetime
from zipfile import ZipFile, BadZipFile

from PIL import Image
from colorama import Fore, Style, init
from PyPDF2 import PdfReader

init(autoreset=True)

banner = r"""       __
                        .d$$b
                      .' TO$;\
                     /  : TP._;
                    / _.;  :Tb|
                   /   /   ;j$j
               _.-"       d$$$$
             .' ..       d$$$$;
             /  /P'      d$$$$P. |\
            /   "      .d$$$P' |\^"l
          .'           `---------  :
      _.'      _.'               ;
      `-.-".-'-' ._.       _.-"    -."
    `.-" _____  ._              .-"
   -( .g$$$$$$$b.              .'
     ""^^T$$$P^)            .(:
       _/  -"  /.'          /:/;
     ._.'-`-'  ")/          /;/;
`-.-"..--""   " /          /  ;
.-" ..--""      -'           :
..--""--.-"          (\      .-(\
  ..--""              `-\(\/;`
    _.                  :
                        ;`-
                       :\
                       ;
"""

SUSPICIOUS_KEYWORDS = ['flag', 'key', 'secret', 'password', 'token']
COLORS = [Fore.GREEN, Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.BLUE]
RED_ALERT = Fore.RED + Style.BRIGHT

def typing_print(text, color=Fore.WHITE, delay=0.05):
    for char in text:
        print(color + char + Style.RESET_ALL, end='', flush=True)
        time.sleep(delay)
    print()
    time.sleep(2)

def rand_color():
    return random.choice(COLORS)

def md5_hash(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    except Exception:
        return None
    return hash_md5.hexdigest()

def file_metadata(file_path):
    try:
        size = os.path.getsize(file_path)
        modified_ts = os.path.getmtime(file_path)
        modified = datetime.fromtimestamp(modified_ts).strftime('%a %b %d %Y %H:%M:%S')
        md5 = md5_hash(file_path)
        return size, modified, md5
    except Exception:
        return None, None, None

def detect_file_type(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    mapping = {
        '.png': 'Image',
        '.jpg': 'Image',
        '.jpeg': 'Image',
        '.bmp': 'Image',
        '.docx': 'Document',
        '.xlsx': 'Document',
        '.pdf': 'Document',
        '.mp4': 'Video',
        '.avi': 'Video',
        '.zip': 'Archive',
    }
    return mapping.get(ext, 'Unknown')

def extract_lsb_data_from_image(image_path):
    try:
        img = Image.open(image_path)
        img = img.convert('RGB')
        pixels = list(img.getdata())
        bits = []
        for pixel in pixels:
            for channel in pixel[:3]:
                bits.append(channel & 1)
        chars = []
        for b in range(0, len(bits), 8):
            byte = bits[b:b + 8]
            if len(byte) < 8:
                break
            value = 0
            for bit in byte:
                value = (value << 1) | bit
            if value == 0:
                break
            chars.append(chr(value))
        message = ''.join(chars)
        if len(message) > 3 and all(32 <= ord(c) <= 126 for c in message):
            return message.strip()
        return None
    except Exception:
        return None

def scan_pdf_for_keywords(file_path):
    found = []
    try:
        with open(file_path, 'rb') as f:
            reader = PdfReader(f)
            for page in reader.pages:
                text = page.extract_text() or ""
                for keyword in SUSPICIOUS_KEYWORDS:
                    if keyword.lower() in text.lower():
                        found.append(keyword)
        return list(set(found))
    except Exception:
        return []

def scan_office_for_embedded_objects(file_path):
    embedded_files = []
    try:
        with ZipFile(file_path, 'r') as z:
            for name in z.namelist():
                if 'embeddings/' in name or 'media/' in name:
                    embedded_files.append(name)
                if name.endswith('.exe') or name.endswith('.zip'):
                    embedded_files.append(name)
        return embedded_files
    except BadZipFile:
        return []
    except Exception:
        return []

def scan_video_for_flags(file_path):
    suspicious_found = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            if b'flag{' in data:
                suspicious_found.append('flag{...} pattern found')
            if b'KEY=' in data or b'key=' in data or b'SECRET' in data:
                suspicious_found.append('Potential key or secret marker')
        return suspicious_found
    except Exception:
        return []

def extract_and_list_zip(file_path):
    inner_contents = []
    try:
        with ZipFile(file_path, 'r') as zipf:
            inner_contents = zipf.namelist()
    except BadZipFile:
        return []
    except Exception:
        return []
    return inner_contents

def detect_executable_signature(file_path):
    try:
        with open(file_path, 'rb') as f:
            mz = f.read(2)
            if mz == b'MZ':
                return True
    except Exception:
        return False
    return False

def scan_and_collect_report(file_path, file_id):
    results = {
        'ID': file_id,
        'File Name': os.path.basename(file_path),
        'File Type': '-',
        'Suspicious Content': '',
        'Embedded EXEs': 'No',
        'Hidden Data': 'None',
        'Scan Result': 'Clean'
    }
    ftype = detect_file_type(file_path)
    results['File Type'] = ftype

    exe_found = detect_executable_signature(file_path)
    embedded_exes = []
    ext = os.path.splitext(file_path)[1].lower()
    if exe_found:
        results['Embedded EXEs'] = 'Yes'
        results['Scan Result'] = 'Alert'
        results['Suspicious Content'] = 'MZ Executable found'
        if ext in ['.docx', '.xlsx', '.zip']:
            try:
                with ZipFile(file_path, 'r') as z:
                    for name in z.namelist():
                        if name.endswith('.exe'):
                            embedded_exes.append(name)
                if embedded_exes:
                    results['Suspicious Content'] += f' ({", ".join(embedded_exes)})'
            except Exception:
                pass
    if ftype == 'Image':
        msg = extract_lsb_data_from_image(file_path)
        if msg:
            results['Hidden Data'] = msg[:16] + "..." if len(msg) > 16 else msg
            results['Scan Result'] = 'Alert'
    elif ftype == 'Document':
        if ext == '.pdf':
            keywords = scan_pdf_for_keywords(file_path)
            if keywords:
                results['Suspicious Content'] = f"Suspicious: {', '.join(keywords)}"
                results['Scan Result'] = 'Caution'
        elif ext in ('.docx', '.xlsx'):
            embedded = scan_office_for_embedded_objects(file_path)
            if embedded:
                results['Suspicious Content'] = "Embedded objects found"
                results['Scan Result'] = 'Alert'
    elif ftype == 'Video':
        suspicious = scan_video_for_flags(file_path)
        if suspicious:
            results['Suspicious Content'] = ", ".join(suspicious)
            results['Scan Result'] = 'Alert'
    elif ftype == 'Archive':
        contents = extract_and_list_zip(file_path)
        results['Hidden Data'] = ", ".join(contents[:2]) + ('...' if len(contents) > 2 else '') if contents else 'None'
    return results

def print_table(results):
    from tabulate import tabulate
    headers = results[0].keys()
    table_data = []
    colors = []
    for row in results:
        table_row = []
        for col in headers:
            val = row[col]
            if col == 'Scan Result':
                if val == 'Alert':
                    val = Fore.RED + val + Style.RESET_ALL
                elif val == 'Caution':
                    val = Fore.YELLOW + val + Style.RESET_ALL
                else:
                    val = Fore.GREEN + val + Style.RESET_ALL
            table_row.append(val)
        table_data.append(table_row)
    print(tabulate(table_data, headers=headers, tablefmt='grid'))

def typing_banner():
    print(Fore.CYAN + banner + Style.RESET_ALL)
    time.sleep(2)

def scan_single_file(interactive_path, file_id=1):
    typing_print(f"Scanning {interactive_path}", rand_color())
    res = scan_and_collect_report(interactive_path, file_id)
    for k, v in res.items():
        if k != "ID":
            typing_print(f"{k}: {v}", rand_color())
    typing_print("Scan complete.\n", rand_color())
    return [res]

def scan_folder(folder_path):
    file_results = []
    file_id = 1
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            fpath = os.path.join(root, file)
            typing_print(f"----- Scanning File #{file_id} -----", rand_color())
            res = scan_and_collect_report(fpath, file_id)
            for k, v in res.items():
                if k not in ["ID", "File Name"]:
                    typing_print(f"{k}: {v}", rand_color())
            typing_print("", rand_color())
            file_results.append(res)
            file_id += 1
    return file_results

def main():
    typing_banner()
    path = None
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = input(Fore.CYAN + "Enter path to scan (file or folder): " + Style.RESET_ALL).strip()
    if os.path.isdir(path):
        results = scan_folder(path)
        if results:
            typing_print("Batch scan complete. Summary table below:", rand_color())
            print_table(results)
    elif os.path.isfile(path):
        res = scan_single_file(path)
        print_table(res)
    else:
        typing_print("Path not found or not a file/folder.", RED_ALERT)

if __name__ == "__main__":
    main()
