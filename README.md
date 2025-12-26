# SOC Analysis & Threat Intel Dashboard

## Overview
This project is a professional-grade **Security Operations Center (SOC) Dashboard** built with Python. It allows security analysts to upload raw log files (like `auth.log` or `syslog`), automatically extract IP addresses using Regex, and cross-reference them with **VirusTotal** to identify potential threats in real-time.

As a former **Full Stack Developer** transitioning into **Cybersecurity**, I designed this tool to bridge the gap between data visualization and incident response automation.



---

## Key Features
* **Log Parsing:** Automated extraction of IPv4 addresses from unstructured text files using optimized Regular Expressions.
* **Data Visualization:** Interactive bar charts powered by Streamlit and Pandas to identify brute-force patterns.
* **Threat Intelligence:** Direct integration with the **VirusTotal API v3** to check the reputation of suspicious IPs.
* **Secure Credential Management:** Sidebar integration for API keys to ensure sensitive data is not hardcoded.
* **Performance:** Capable of processing large log files (tested with 10MB+ logs) efficiently.

---

## Technologies Used
* **Language:** Python 3.12
* **Framework:** Streamlit (Web Interface)
* **Data Analysis:** Pandas
* **API Integration:** Requests (VirusTotal API)
* **Regex:** Python `re` module

---

## Getting Started

### Prerequisites
* Python 3.x installed
* A VirusTotal API Key (Free tier works)

### Installation
1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/SOC-Dashboard.git](https://github.com/your-username/SOC-Dashboard.git)
    cd SOC-Dashboard
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the application:**
    ```bash
    streamlit run app.py
    ```

---

## Project Structure

```
├── app.py                
├── requirements.txt      
├── LICENSE               
├── README.md             
├── analysis_report.md    
├── venv/                 
└── EVIDENCE/
    └── dashboard_preview.png  
```    
