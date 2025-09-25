# 🕵️‍♂️ File Security Scanner

A Python-based tool for scanning **files and folders** to detect suspicious content, hidden data, embedded executables, and potential secrets.  
Supports **images, documents, videos, and archives** with colored terminal output for alerts.

---

## ⚡ Features

- **Multi-file Scanning**: Scan single files or entire folders recursively.
- **File Type Detection**: Identifies Image, Document, Video, and Archive files.
- **Hidden Data Detection**:
  - Extracts **LSB data** from images.
  - Checks for suspicious keywords in PDFs (`flag`, `key`, `secret`, `password`, `token`).
  - Detects embedded objects in Office documents (`.docx`, `.xlsx`).
  - Analyzes ZIP archives for hidden contents.
  - Detects potential secrets in video files.
- **Executable Detection**: Flags MZ executables embedded in files.
- **MD5 Hashing & Metadata**: Shows file size, last modified date, and MD5 hash.
- **Color-coded Scan Results**:
  - **Alert** → Red
  - **Caution** → Yellow
  - **Clean** → Green
- **Interactive and Dynamic Output**: Animated typing effect for readability.
- **Report Table**: Summarizes scan results in a formatted table using `tabulate`.

---

## 📦 Requirements

Install the required Python packages:

```bash
pip install pillow colorama PyPDF2 tabulate

python file_scanner.py
# Then input the path when prompted

bash
```

Supported file types:

Images: .png, .jpg, .jpeg, .bmp

Documents: .pdf, .docx, .xlsx

Video: .mp4, .avi

Archives: .zip

🖼️ Example Output
+----+----------------+-----------+---------------------+----------------+---------------+
| ID | File Name      | File Type | Suspicious Content  | Embedded EXEs  | Scan Result   |
+----+----------------+-----------+---------------------+----------------+---------------+
| 1  | secret.pdf     | Document  | Suspicious: flag    | No             | Alert         |
| 2  | picture.png    | Image     | Hidden Data: flag...| No             | Alert         |
| 3  | video.mp4      | Video     | flag{...} pattern  | No             | Alert         |
| 4  | normal.docx    | Document  |                     | No             | Clean         |
+----+----------------+-----------+---------------------+----------------+---------------+


Red → Alert

Yellow → Caution

Green → Clean

🛡️ Notes

Designed for educational and authorized security testing only.

LSB extraction works only for RGB images with hidden text.

PDF keyword scanning is case-insensitive.

Handles ZIP archives and Office files to detect embedded executables or objects.

Batch folder scanning is supported, with summary output at the end.
