# BioTremor
**Vulnerability Intelligence**  
<img src="./static/images/biotremor.png" height=300>  

## 💎 About

Utilizes machine learning to prioritize vulnerabilities based on aggregated data metrics. BioTremor only trains on manually rated CVEs and takes the following metrics into consideration when predicting priority.
- CVE published date
- CISA Known Exploited Vulnerabilities (KEV)
- Common Weakness Enumeration (CWE)
- Common Vulnerability Scoring System (CVSS)
  - Version 3.1
  - Version 2.0
- Exploit Prediction Scoring System (EPSS)

## ✨ Features
- Django Commands
  - **lookup**: `python3 management.py lookup CVE-YYYY-number`
  - **seed**: `python3 management.py seed [-f]`
- APIs
  - **predict**: Returns priority rating for a specified CVE ID
  - **rate**: Change priority rating for a specified CVE ID (applies method "manual" to rating)

## 🛠️ Setup

### Requirements
- [Python 3.10](../requirements.txt)
- API Keys
  - NIST

### Installation
BioTremor is installed by default. To remove it, delete it from *INSTALLED_APPS* in [settings.py](../cylvarkana/settings.py).

#### Core (Global) Updates
- **User(s)**: 
- **Groups(s)**: 
- **Credential(s)**:
- **Task(s)**:

## 📜 License
![Creative Commons](https://img.shields.io/badge/Creative_Commons-4.0-white.svg?logo=creativecommons)

[Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/).
