# Data schema (seed.jsonl)
Each line is a JSON object with fields:
- id, source, timestamp, title, text
- threat_category (e.g. Phishing, Ransomware, Vulnerability Exploit)
- attack_vector (Email, Network/Remote, File, Local)
- severity (Critical/High/Medium/Low)
- cvss_score (float or null)
- ioc (list of indicators)
- tags (list)
- explanation (short human summary)
