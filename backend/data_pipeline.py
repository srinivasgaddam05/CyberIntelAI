# backend/data_pipeline.py
import requests
import json
import datetime
import re
from dateutil import parser as dateparser
from tqdm import tqdm
import os

OUT_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "seed.jsonl")

# ----------------------
# Utilities
# ----------------------
def extract_iocs(text):
    # basic IOC extraction: IPs, domains, filenames, CVE ids
    iocs = []
    # IPs
    iocs += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    # CVE IDs
    iocs += re.findall(r"\bCVE-\d{4}-\d+\b", text, flags=re.IGNORECASE)
    # domains (simple)
    iocs += re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|ru|cn|in|gov|edu)\b", text)
    # filenames (exe, dll, zip)
    iocs += re.findall(r"\b[\w\-/\\\.]+\.(?:exe|dll|zip|bin|js|docx?)\b", text, flags=re.IGNORECASE)
    return list(set(iocs))

def guess_attack_vector(text):
    txt = text.lower()
    if "email" in txt or "click" in txt or "invoice" in txt:
        return "Email"
    if "remote code execution" in txt or "rce" in txt or "remote" in txt:
        return "Network/Remote"
    if "local" in txt or "privilege" in txt:
        return "Local"
    if "attachment" in txt or ".exe" in txt or "download" in txt:
        return "File"
    return "Unknown"

def severity_from_cvss(score):
    try:
        s = float(score)
    except Exception:
        return "Medium"
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low"

# ----------------------
# NVD ingestion (light)
# ----------------------
def fetch_nvd(limit=25):
    # lightweight access (no API key) - will fetch a small page; may be rate-limited
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={limit}"
    print("Fetching from NVD:", url)
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        out = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "unknown")
            descs = cve.get("descriptions", [])
            desc = descs[0]["value"] if descs else ""
            # try to extract cvss v3 score if present
            metrics = item.get("cve", {}).get("metrics", {})
            cvss_score = None
            # attempt common metric locations
            for key in metrics:
                try:
                    ms = metrics[key]
                    cvss_score = ms.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
                    if cvss_score is not None:
                        break
                except Exception:
                    continue
            attack_vector = guess_attack_vector(desc)
            iocs = extract_iocs(desc)
            entry = {
                "id": cve_id,
                "source": "nvd",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "title": cve_id,
                "text": desc,
                "threat_category": "Vulnerability Exploit",
                "attack_vector": attack_vector,
                "severity": severity_from_cvss(cvss_score),
                "cvss_score": cvss_score if cvss_score is not None else None,
                "ioc": iocs,
                "tags": [cve_id],
                "explanation": desc[:500]  # short explanation
            }
            out.append(entry)
        return out
    except Exception as e:
        print("NVD fetch failed:", str(e))
        return []

# ----------------------
# Synthetic curated seed (fallback or supplement)
# ----------------------
def synthetic_seed():
    print("Using curated synthetic seed examples.")
    examples = [
        {
            "id": "SYN-001",
            "source": "email",
            "timestamp": "2025-09-17T08:00:00Z",
            "title": "Credential harvesting phishing",
            "text": "Urgent: Your mailbox will be deactivated. Click https://secure-login.example.com to verify credentials.",
            "threat_category": "Phishing",
            "attack_vector": "Email",
            "severity": "High",
            "cvss_score": None,
            "ioc": ["secure-login.example.com"],
            "tags": ["phishing", "credential-harvest", "email"],
            "explanation": "Phishing URL impersonating mailbox provider to harvest credentials."
        },
        {
            "id": "SYN-002",
            "source": "cve",
            "timestamp": "2024-11-02T04:00:00Z",
            "title": "CVE-2024-9999 - Buffer overflow RCE",
            "text": "CVE-2024-9999: Buffer overflow in ABC service allows remote code execution via crafted packet.",
            "threat_category": "Vulnerability Exploit",
            "attack_vector": "Network/Remote",
            "severity": "Critical",
            "cvss_score": 9.8,
            "ioc": ["CVE-2024-9999"],
            "tags": ["rce","buffer-overflow","CVE-2024-9999"],
            "explanation": "Remote code execution possible via crafted packet in ABC service."
        },
        {
            "id": "SYN-003",
            "source": "blog",
            "timestamp": "2025-03-09T12:30:00Z",
            "title": "New ransomware campaign",
            "text": "A new ransomware family 'LockIt' encrypts files and drops ransom_note.txt; observed contacting 203.0.113.45.",
            "threat_category": "Ransomware",
            "attack_vector": "File",
            "severity": "High",
            "cvss_score": None,
            "ioc": ["ransom_note.txt", "203.0.113.45"],
            "tags": ["ransomware","lockit"],
            "explanation": "Ransomware that encrypts files and contacts command-and-control IP."
        },
        {
            "id": "SYN-004",
            "source": "mail",
            "timestamp": "2024-08-21T09:10:00Z",
            "title": "Malicious attachment trojan",
            "text": "Invoice attached invoice_638.exe — contains trojan that opens backdoor.",
            "threat_category": "Trojan/Backdoor",
            "attack_vector": "File",
            "severity": "High",
            "cvss_score": None,
            "ioc": ["invoice_638.exe"],
            "tags": ["trojan","malware","attachment"],
            "explanation": "Attachment drops a backdoor Trojan when executed."
        },
        {
            "id": "SYN-005",
            "source": "research",
            "timestamp": "2025-05-14T14:00:00Z",
            "title": "APT group exploiting zero-day",
            "text": "State actor group exploits 0-day in VPN gateway to persist on networks.",
            "threat_category": "Advanced Persistent Threat",
            "attack_vector": "Network/Remote",
            "severity": "Critical",
            "cvss_score": None,
            "ioc": [],
            "tags": ["apt","zero-day"],
            "explanation": "Long-term targeted intrusion using a zero-day in VPN gateway."
        },
        # more examples can be appended...
    ]
    return examples

# ----------------------
# Main pipeline
# ----------------------
def main():
    out = []
    nvd_data = fetch_nvd(limit=20)
    if nvd_data:
        print(f"Fetched {len(nvd_data)} NVD entries.")
        out.extend(nvd_data)
    else:
        print("No NVD data fetched.")

    # always include synthetic curated examples
    synth = synthetic_seed()
    out.extend(synth)

    # post-process: ensure required fields, add tags from text
    for e in out:
        e.setdefault("id", "NA-"+str(abs(hash(e.get("text",""))))[:8])
        e.setdefault("source", "unknown")
        e.setdefault("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
        e.setdefault("title", e.get("id"))
        e.setdefault("text", "")
        e.setdefault("threat_category", "Generic Malware")
        e.setdefault("attack_vector", guess_attack_vector(e.get("text","")))
        if "ioc" not in e:
            e["ioc"] = extract_iocs(e.get("text",""))
        if "tags" not in e:
            e["tags"] = []
        # auto-add some tags from iocs and title
        for i in e.get("ioc", []):
            if i.upper().startswith("CVE-"):
                e["tags"].append(i.upper())
        # dedupe tags
        e["tags"] = list(dict.fromkeys(e["tags"]))
    # save
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for e in out:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print("Saved", OUT_FILE)
    print("Total records:", len(out))

if __name__ == "__main__":
    main()
