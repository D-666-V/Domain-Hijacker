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

Whether you are targeting Fortune 500 companies or mass-hunting across millions of subdomains, this engine is built to handle the load without breaking a sweat.

---

## ⚡ KEY FEATURES

* 🌀 **Chaos-Ready Multithreading:** Powered by a `ThreadPoolExecutor` that handles 15+ concurrent threads for lightning-fast results.
* 🛰️ **Native Resolver (Dig Logic):** Uses native DNS queries to confirm CNAME point-to-nowhere vulnerabilities.
* 🛡️ **Broad Service Coverage:** Pre-configured to detect takeovers on:
    * `Amazon S3 / Cloudfront`
    * `Heroku / HerokuDNS`
    * `GitHub Pages`
    * `Microsoft Azure Websites`
* 📟 **Elite Terminal UI:** A professional purple-themed interface with a precision progress tracker and verbose logging.
* 📁 **Smart Logging:** Automatically saves confirmed takeovers into an organized output file for easy reporting.

---

## 🛠️ INSTALLATION

Get the engine running in seconds. Copy and paste the following commands:

```bash
# Clone the repository from the GodFather vault
git clone [https://github.com/D-666-V/Domain-Hijacker.git](https://github.com/D-666-V/Domain-Hijacker.git)

# Enter the tool directory
cd Domain-Hijacker

# Install the necessary firepower
pip3 install -r requirements.txt --break-system-packages

### 📊 PROOF OF WORK

<p align="center">
  <img src="https://github.com/user-attachments/assets/abf7a9d1-9cba-4070-aee5-c71e28affb84" width="900" alt="Domain Hijacker Live Findings">
</p>

> **Note:** Optimized for accuracy and speed. Successfully identifying dangling assets across large-scale corporate infrastructures with 100% completion rate.
