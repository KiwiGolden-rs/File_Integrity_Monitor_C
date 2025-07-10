# File_Integrity_Monitor_C

This project implements a basic file integrity monitoring tool written in C. It calculates and stores SHA-256 hashes of critical system files and verifies their integrity on subsequent checks. The tool is designed as part of a self-learning initiative to practice scripting in C, with an emphasis on cybersecurity applications.

---

## 🛡️ Purpose

- Detect unauthorized or accidental modifications to key system configuration files.
- Learn C programming practices in the context of cybersecurity.
- Understand file hashing, secure logging, and defensive programming.

---

## 📚 What I Learned

- How to interact with files and directories in C.
- Use of OpenSSL’s SHA-256 hashing functions (`EVP` interface).
- Defensive coding techniques: error handling, file permission checks, and logging.
- Structuring a CLI tool using flags (`--init`, `--check`) and modular design.
- The importance of baseline data in security monitoring.

---

## 🧩 Features

- ✅ Hashing with SHA-256 via OpenSSL
- ✅ Baseline generation of file hashes (`--init`)
- ✅ Logs alerts, warnings, and status in a log file
- ✅ Handles file read errors and missing files

---

## 📦 Dependencies

  - C compiler (e.g., `gcc`)

  - OpenSSL library (`libssl`, `libcrypto`)

  - Root privileges to access protected files

---

## 🛠️ Usage

### 🔹 Compile the tool

```bash
gcc main.c -o file_integrity_monitor -lssl -lcrypto
```

Make sure OpenSSL development libraries are installed (`libssl-dev` on Debian/Ubuntu).

### 🔹 Generate the initial hash baseline

```bash
sudo ./file_integrity_monitor --init
```

This stores the current hashes of sensitive files in:

`/var/lib/integrity_monitor/baseline.txt`

### 🔹 Perform an integrity check

```bash
sudo ./file_integrity_monitor
```

The result of the scan is logged in:

`/var/log/integrity_monitor.log`

If no changes are detected, the log will include:

```
[Timestamp] No file integrity issues detected.
```

### 🗂️ Files Monitored

By default, the following system files are monitored:

```c
const char *files_to_monitor[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/etc/ssh/sshd_config"
};
```

You can modify this list directly in the source code.

### 🧪 Example Log Output

```log
[Mon Jun 01 17:17:17 2025] ALERT: File modified: /etc/group
[Mon Jun 01 17:17:17 2025] WARNING: File missing or unreadable: /etc/ssh/sshd_config
[Mon Jun 01 17:17:17 2025] No file integrity issues detected.
```

---

## 🔐 Security Considerations

- Run the script with `sudo` to ensure access to protected files.

- Log files should be stored in root-only writable directories (`/var/log/` or `/var/lib/`).

- The program uses `fopen()` in secure mode and handles errors.

---

## 🧼 Cleanup

To remove the baseline and log:

```bash
sudo rm /var/lib/integrity_monitor/baseline.txt
sudo rm /var/log/integrity_monitor.log
```
---

## 📄 License

MIT License
