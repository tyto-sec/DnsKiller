## DNS Killer

A powerful and automated Python-based tool for scanning domain lists for potential Subdomain Takeover and Email Spoofing vulnerabilities. This scanner performs comprehensive enumeration, filtering, and targeted vulnerability scanning using popular open-source tools like `subfinder`, `dnsx`, `httpx`, and `nuclei`.

### Features

*   **Automated Enumeration:** Uses `subfinder` to recursively discover subdomains and `dnsx` to extract CNAME and TXT records.
*   **Targeted Filtering:** Filters CNAME records against a curated list of external services (`CNAME_FINGERPRINTS`).
*   **Permissive SPF Detection:** Identifies domains with permissive SPF records (`~all` or `?all`), which can be an indicator for email spoofing.
*   **Liveness Check:** Uses `httpx` to verify which potential targets are currently online/responsive.
*   **Intelligent Nuclei Scan:** Based on the identified CNAME target, the scanner dynamically selects and executes the exact `nuclei` template for the corresponding service.
*   **Structured Output:** Saves all intermediate and final results, including a summary CSV report.

### Prerequisites

This script relies on several external command-line tools. You must have them installed and accessible in your system's `PATH`.

*   **`subfinder`**
*   **`dnsx`**
*   **`httpx`**
*   **`nuclei`**

The `nuclei-templates` repository must be cloned, and the `NUCLEI_TEMPLATE_DIR` variable must point to the correct location (default is `~/nuclei-templates/http/takeovers`).

### Installation (Docker Recommended)

The provided `Dockerfile` and `docker-compose.yml` offer the simplest way to set up the environment with all dependencies included.

**1. Prepare Files**

Ensure you have the following files in your project directory:

*   `dns_killer.py` (The main script)
*   `constants.py` (Containing `CNAME_FINGERPRINTS` and `TAKEOVER_MAP`)
*   `domains.txt` (Your list of target domains)
*   `Dockerfile`, `install.sh`, `ssh_setup.sh`, `docker-compose.yml` (Included for environment setup)

**2. Build and Run**

```bash
# Build the Docker image
$ docker-compose build

# Run the scanner
$ docker-compose up
```

The results will be available in the locally created `output` directory.

### Usage (Standalone)

If you prefer to run the script directly on a system where you have installed all prerequisites:

```bash
$ python3 takeover_scanner.py -f <path_to_your_domains_file>
```

**Example:**

```bash
$ python3 takeover_scanner.py -f domains.txt
```

