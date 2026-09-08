# VirusTotal Context Generator

A Python utility that computes file hashes for all binaries/samples in a target directory, queries VirusTotal API v3 for static analysis and dynamic sandbox behavior, and generates optimized, structured JSON payloads ready to be fed directly into an AI model for threat analysis.

## Features

- **Folder-Wide Scanning:** Automatically processes any binary, script, or document within a specified directory.
- **Combined Analysis:** Fetches static attributes, engine verdicts, YARA rules, PE info, and dynamic behavior (process creation, CLI execution, registry persistence, C2 traffic).
- **AI Context Optimization:** Trims clean engine noise to save context tokens while retaining malicious indicators and MITRE ATT&CK techniques.
- **Robust Exception Handling:** Gracefully handles missing sandbox data and includes rate-limiting controls to prevent free API key throttling (4 requests/min).

## Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/k3rnelcallz/virustotal_context_generator.git
   cd your-repo-name
	```
2. **Install dependencies:**
	```bash
	pip install requests python-dotenv
	```
3. **Configure API Key:**
   **Create a .env file in the root directory and add your VirusTotal API key:**
	```bash
	VT_API_KEY=your_virustotal_api_key_here
 	```

## Usage
 **Place your target binaries or suspicious files into the ./samples_folder directory.**

 Run the analysis script:

```bash
	python analyze_vt.py
```
   **Processed JSON dumps will be saved to the ./vt_ai_dumps/ directory, ready to copy/paste or upload to an AI model for malware triage.**
