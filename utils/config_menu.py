import os
import sys
from typing import Dict
from pathlib import Path

# List of free services to recommend
RECOMMENDED_SERVICES = [
    {
        "name": "VirusTotal",
        "url": "https://www.virustotal.com/gui/join-us",
        "desc": "Analyzes files and URLs (Free Tier: 4 requests/min)",
        "env_var": "VIRUSTOTAL_API_KEY"
    },
    {
        "name": "AbuseIPDB",
        "url": "https://www.abuseipdb.com/register",
        "desc": "IP address abuse reports (Free Tier: 3000 checks/day)",
        "env_var": "ABUSEIPDB_API_KEY"
    },
    {
        "name": "AlienVault OTX",
        "url": "https://otx.alienvault.com/",
        "desc": "Open Threat Exchange (Free access)",
        "env_var": "OTX_API_KEY"
    },
    {
        "name": "URLScan.io",
        "url": "https://urlscan.io/user/signup",
        "desc": "Website scanner (Free Tier available)",
        "env_var": "URLSCAN_API_KEY"
    },
    {
        "name": "Google Safe Browsing",
        "url": "https://developers.google.com/safe-browsing/",
        "desc": "Check URLs against Google's lists",
        "env_var": "GOOGLE_SAFE_BROWSING_KEY"
    }
]

def load_env_file(filepath: Path) -> Dict[str, str]:
    env_vars = {}
    if filepath.exists():
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars

def save_env_file(filepath: Path, env_vars: Dict[str, str]):
    with open(filepath, "w") as f:
        for key, value in env_vars.items():
            f.write(f"{key}={value}\n")
    print(f"\n[+] Configuration saved to {filepath}")

def run_configuration_wizard():
    print("\n" + "="*50)
    print("   ThreatIntel Aggregator - Configuration Menu")
    print("="*50 + "\n")

    print("This wizard will help you configure API keys for external services.")
    print("These services help validate malicious indicators (enrichment).")

    print("\n[?] Recommended Free Services to Sign Up For:")
    for service in RECOMMENDED_SERVICES:
        print(f" - {service['name']:<20} {service['desc']}")
        print(f"   Sign up: {service['url']}")
        print("-" * 50)

    print("\nStarting configuration...\n")

    env_path = Path(".env")
    current_env = load_env_file(env_path)
    updated_env = current_env.copy()

    # Iterate primarily over services we explicitly support in code first, then others
    # Currently supported in code: VT, AbuseIPDB
    # We will loop through the recommended list to gather keys

    for service in RECOMMENDED_SERVICES:
        key_name = service['env_var']
        current_val = current_env.get(key_name, "")

        display_default = f"{current_val[:4]}...{current_val[-4:]}" if len(current_val) > 8 else current_val
        if not display_default:
            display_default = "None"

        print(f"\nConfiguration for {service['name']} ({key_name})")
        print(f"Current Value: {display_default}")

        new_val = input(f"Enter new API Key (Press Enter to keep current): ").strip()

        if new_val:
            updated_env[key_name] = new_val
            print(f"-> Set {key_name}")
        else:
            print("-> Kept current value")

    # Save changes
    if updated_env != current_env:
        save_env_file(env_path, updated_env)
    else:
        print("\n[!] No changes made.")

    print("\nConfiguration complete. You can run the tool normally now.")
