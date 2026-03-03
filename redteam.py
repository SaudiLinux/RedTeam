import socket
import ssl
import requests
import random
import sys
import os
import datetime
import threading
import subprocess
import json

# ==========================
# Developer Information
# ==========================
DEVELOPER_NAME = "SayerLinux"
DEVELOPER_EMAIL = "SayerLinux1@gmail.com"

print(f"Tool developed by: {DEVELOPER_NAME} ({DEVELOPER_EMAIL})")

requests.packages.urllib3.disable_warnings()

VERSION = "3.0"

# ==========================
# Logging System
# ==========================
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE = os.path.join(LOG_DIR, f"session_{timestamp}.txt")

def log(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.now()}] {message}\n")

# ==========================
# CVE Lookup & Cache Functions
# ==========================
def load_cve_cache():
    if os.path.exists("cve_cache.json"):
        with open("cve_cache.json", "r") as f:
            return json.load(f)
    return {}

def save_cve_cache(cve_data):
    with open("cve_cache.json", "w") as f:
        json.dump(cve_data, f, indent=4)

def lookup_cves(product_name):
    print(f"[+] Searching CVEs for: {product_name}")
    log(f"CVE Lookup for {product_name}")

    # Load cache to speed up future lookups
    cve_cache = load_cve_cache()
    if product_name in cve_cache:
        print(f"[+] Found {product_name} in cache.")
        return cve_cache[product_name]

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": product_name,
            "resultsPerPage": 5
        }

        r = requests.get(url, params=params, timeout=15)
        data = r.json()

        cves = []

        if "vulnerabilities" in data:
            for item in data["vulnerabilities"]:
                cve_id = item["cve"]["id"]
                description = item["cve"]["descriptions"][0]["value"][:150]
                cvss_score = item.get("impact", {}).get("baseMetricV2", {}).get("score", 0)
                severity = "Low"

                # Determine Severity based on CVSS Score
                if cvss_score >= 9.0:
                    severity = "Critical"
                elif cvss_score >= 7.0:
                    severity = "High"
                elif cvss_score >= 4.0:
                    severity = "Medium"
                else:
                    severity = "Low"

                # Filter CVEs with score >= 7 (High and Critical)
                if cvss_score >= 7.0:
                    cves.append({
                        "id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "severity": severity
                    })

        # Cache the results for future use
        cve_cache[product_name] = cves
        save_cve_cache(cve_cache)

        return cves

    except Exception as e:
        log(f"CVE Lookup Error: {e}")
        return []

def lookup_exploit_db(cve_id):
    print(f"[+] Searching Exploit-DB for: {cve_id}")
    log(f"Exploit-DB lookup for {cve_id}")

    try:
        url = f"https://www.exploit-db.com/search?query={cve_id}"
        response = requests.get(url)
        
        # Check if a valid exploit link is found in the response
        if response.status_code == 200:
            return f"Exploit-DB Link: {url}"
        return None
    except Exception as e:
        log(f"Exploit-DB Error: {e}")
        return None

# ==========================
# Attack Graph Structure
# ==========================
attack_graph = {
    "targets": [],
    "relationships": []
}

# ==========================
# Banner
# ==========================
def banner():
    print(r"""
██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝

Red Team Interactive Console v{}
Authorized Testing Only
""".format(VERSION))

    log("Session Started")

# ==========================
# Modules
# ==========================
def module_smuggle(target):
    payload = f"""POST / HTTP/1.1
Host: {target}
Content-Length: 13
Transfer-Encoding: chunked

0

G"""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                ssock.sendall(payload.encode())
                response = ssock.recv(1024).decode(errors="ignore")
                print(f"[{target}] Response received")
                log(f"{target} - Smuggle test sent")
    except:
        print(f"[{target}] Error")
        log(f"{target} - Smuggle ERROR")

def module_waf(target):
    try:
        r = requests.get(target, verify=False, timeout=10)
        headers = r.headers

        if "cf-ray" in headers:
            print(f"[{target}] Cloudflare detected")
            log(f"{target} - Cloudflare detected")
        elif "x-amzn-requestid" in headers:
            print(f"[{target}] AWS WAF detected")
            log(f"{target} - AWS WAF detected")
        else:
            print(f"[{target}] Unknown WAF")
            log(f"{target} - Unknown WAF")

    except Exception as e:
        print(f"[{target}] Error during WAF detection")
        log(f"{target} - WAF ERROR: {e}")

def module_stealth(target):
    UA = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (X11; Linux x86_64)"
    ]
    headers = {"User-Agent": random.choice(UA)}

    try:
        r = requests.get(target, headers=headers, verify=False, timeout=10)
        print(f"[{target}] Status: {r.status_code}")
        log(f"{target} - Status {r.status_code}")
    except:
        print(f"[{target}] Error")
        log(f"{target} - Stealth ERROR")

def module_auto_multi(target):
    print(f"[{target}] Starting Auto Assessment...")
    log(f"{target} - Auto Assessment Started")

    risk_score = 0
    target_node = {
        "target": target,
        "findings": [],
        "risk_score": 0
    }

    try:
        # Step 1 - Basic HTTP Probe
        r = requests.get(target, verify=False, timeout=10)
        status = r.status_code

        print(f"[{target}] Status: {status}")
        log(f"{target} - Status {status}")

        if status >= 500:
            risk_score += 2
            target_node["findings"].append("Server Error Response (5xx)")

        # Step 2 - Header Analysis
        headers = r.headers

        if "Content-Security-Policy" not in headers:
            print(f"[{target}] Missing CSP")
            log(f"{target} - Missing CSP")
            risk_score += 1
            target_node["findings"].append("Missing CSP")

        if "X-Frame-Options" not in headers:
            print(f"[{target}] Missing X-Frame-Options")
            log(f"{target} - Missing X-Frame-Options")
            risk_score += 1
            target_node["findings"].append("Missing X-Frame-Options")

        # Step 3 - WAF Detection
        if "cf-ray" in headers:
            print(f"[{target}] Cloudflare detected")
            log(f"{target} - Cloudflare detected")
            target_node["findings"].append("Cloudflare WAF")

        elif "x-amzn-requestid" in headers:
            print(f"[{target}] AWS WAF detected")
            log(f"{target} - AWS WAF detected")
            target_node["findings"].append("AWS WAF")

        # Step 4 - Server Fingerprint
        server = headers.get("Server", "Unknown")
        print(f"[{target}] Server: {server}")
        log(f"{target} - Server {server}")
        target_node["findings"].append(f"Server: {server}")

        # Step 5 - Common Endpoint Recon
        test_paths = ["/admin", "/login", "/dashboard"]

        for path in test_paths:
            try:
                test_url = target.rstrip("/") + path
                resp = requests.get(test_url, verify=False, timeout=5)

                if resp.status_code == 200:
                    print(f"[{target}] Interesting endpoint found: {path}")
                    log(f"{target} - Found {path}")
                    risk_score += 1
                    target_node["findings"].append(f"Exposed Endpoint: {path}")

            except:
                pass

        # Final Risk Score
        target_node["risk_score"] = risk_score

        print(f"[{target}] Risk Score: {risk_score}/10")
        log(f"{target} - Risk Score {risk_score}/10")

        # Add Relationship if risk is high
        if risk_score >= 3:
            attack_graph["relationships"].append({
                "target": target,
                "risk_level": "Elevated",
                "score": risk_score
            })

        # Add target to graph
        attack_graph["targets"].append(target_node)

    except Exception as e:
        print(f"[{target}] Error during auto assessment")
        log(f"{target} - Auto ERROR: {e}")

# ==========================
# Console Logic
# ==========================
def show_modules():
    print("""
Available Modules:
  smuggle   - HTTP Request Smuggling Test
  waf       - WAF Fingerprinting
  stealth   - Stealth HTTP Probe
  auto      - Automated Recon Chain
""")

def run_module():
    if not current_module:
        print("No module selected.")
        return
    if not targets_list:
        print("No targets set.")
        return

    print(f"[+] Running {current_module} against {len(targets_list)} target(s)\n")
    log(f"Running module {current_module} on {targets_list}")

    threads = []

    for tgt in targets_list:
        t = threading.Thread(target=execute_module, args=(tgt,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\n[+] Scan Completed\n")

def execute_module(target):
    try:
        if current_module == "smuggle":
            module_smuggle(target)
        elif current_module == "waf":
            module_waf(target)
        elif current_module == "stealth":
            module_stealth(target)
        elif current_module == "auto":
            module_auto_multi(target)
    except Exception as e:
        print(f"[{target}] Error: {e}")

# ==========================
# Main
# ==========================
current_module = None
targets_list = []

banner()