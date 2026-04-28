<p align="center">
  <img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" alt="Python">
  <img src="https://img.shields.io/badge/cybersecurity-magenta?style=for-the-badge&logo=generic" alt="Cybersecurity">
  <img src="https://img.shields.io/badge/Version-5.2_Stable-purple?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Author-D--666--V-white?style=for-the-badge" alt="Author">
</p>

<h1 align="center">⚔️ DOMAIN HIJACKER V5.2 ⚔️</h1>

<p align="center">
  <b>The Most Advanced Multithreaded DNS Recon Engine for Massive-Scale Domain Takeover Hunting.</b>
</p>

---

## 📜 OVERVIEW

**DOMAIN HIJACKER** is a specialized reconnaissance tool engineered for high-stakes bug hunting. It doesn't just scan; it hunts for dangling CNAME records that are ripe for exploitation. By utilizing **Native DNS Resolution Logic**, it bypasses standard detection lags and provides real-time verification of vulnerable assets.

---

## ⚡ KEY FEATURES

* 🌀 **Chaos-Ready Multithreading:** Powered by a high-concurrency engine that handles 15+ workers for lightning-fast results.
* 🛰️ **Native Resolver (Dig Logic):** Uses native DNS queries to confirm CNAME point-to-nowhere vulnerabilities.
* 🛡️ **Broad Service Coverage:** Pre-configured to detect takeovers on Cloudfront, S3, Heroku, GitHub, and Azure.
* 📟 **Elite Terminal UI:** A professional purple-themed interface with a precision progress tracker.

---

## 🛠️ INSTALLATION

git clone https://github.com/D-666-V/Domain-Hijacker.git

cd Domain-Hijacker

pip3 install -r requirements.txt --break-system-packages

---

## 📖 USAGE

# Standard Hunt
python3 test.py -i targets.txt

# Save Results to File
python3 test.py -i targets.txt -o confirmed_takeovers.txt

---

## 📊 PROOF OF WORK

<p align="center">
  <img src="https://github.com/user-attachments/assets/abf7a9d1-9cba-4070-aee5-c71e28affb84" width="900" alt="Domain Hijacker Live Results">
</p>

> **Note:** Captured live findings using the v5.2 engine. Optimized for accuracy and speed across massive infrastructures.

---

## ⚠️ LEGAL DISCLAIMER

This tool is strictly for **Educational Purposes** and **Authorized Security Testing** only. I, the developer (D-666-V), am not responsible for any unauthorized use or damage caused by this software. Respect the boundaries of responsible disclosure.

---

<p align="center">
  <b>Built by <a href="https://github.com/D-666-V">D-666-V</a> | For the Chaos. For the Loot.</b>
</p>
