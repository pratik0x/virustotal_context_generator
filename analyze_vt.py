import hashlib
import json
import os
import time
import requests
from dotenv import load_dotenv

# Reads .env automatically
load_dotenv()

# Fetches your key into Python
VT_API_KEY = os.getenv("VT_API_KEY")
HEADERS = {"x-apikey": VT_API_KEY, "accept": "application/json"}


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of any binary/file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_static_metadata(file_hash):
    """Fetch static attributes, engine scores, and metadata from VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    res = requests.get(url, headers=HEADERS)
    return res.json().get("data", {}).get("attributes", {}) if res.status_code == 200 else {}


def get_dynamic_behavior(file_hash):
    """Fetch process execution, command lines, and network connections safely."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
    res = requests.get(url, headers=HEADERS)
    
    if res.status_code != 200:
        return {}

    # Prevent NoneType crash if 'data' is None
    json_resp = res.json()
    b_data = json_resp.get("data") if json_resp and json_resp.get("data") else {}

    return {
        "process_execution": {
            "processes_created": b_data.get("processes_created", []) or [],
            "command_executions": b_data.get("command_executions", []) or [],
            "processes_injected": b_data.get("processes_injected", []) or [],
            "shell_commands": b_data.get("shell_commands", []) or [],
        },
        "system_changes": {
            "registry_keys_set": b_data.get("registry_keys_set", []) or [],
            "files_written": [
                f for f in (b_data.get("files_written") or [])
                if isinstance(f, str) and f.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".tmp", ".sys"))
            ],
            "services_created": b_data.get("services_created", []) or [],
        },
        "network_activity": {
            "dns_lookups": b_data.get("dns_lookups", []) or [],
            "ip_traffic": [
                {"ip": c.get("destination_ip"), "port": c.get("destination_port")}
                for c in (b_data.get("ip_traffic") or []) if isinstance(c, dict)
            ],
            "http_conversations": [
                {"url": h.get("url"), "method": h.get("request_method")}
                for h in (b_data.get("http_conversations") or []) if isinstance(h, dict)
            ],
        },
        "mitre_attack_techniques": [
            {"id": t.get("id"), "signature": t.get("signature_description")}
            for t in (b_data.get("mitre_attack_techniques") or []) if isinstance(t, dict)
        ],
    }


def analyze_directory(folder_path, output_dir="vt_ai_dumps", rate_limit_delay=15):
    """Scan all files in a target folder and produce AI context payloads."""
    if not os.path.exists(folder_path):
        print(f"Directory not found: {folder_path}")
        return

    os.makedirs(output_dir, exist_ok=True)

    # Gather all files in the directory (ignoring subdirectories and existing outputs)
    all_files = [
        os.path.join(folder_path, f) for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f)) and not f.endswith(".json")
    ]

    if not all_files:
        print("No files found to process.")
        return

    print(f"Found {len(all_files)} file(s) to process in '{folder_path}'...\n")

    for index, file_path in enumerate(all_files):
        filename = os.path.basename(file_path)
        print(f"[{index + 1}/{len(all_files)}] Processing: {filename}")

        file_hash = calculate_sha256(file_path)
        print(f" -> SHA-256: {file_hash}")

        # Fetch VirusTotal Data
        static_attr = get_static_metadata(file_hash)
        if not static_attr:
            print(f" -> Not found on VT or API error for '{filename}'. Skipping.\n")
            continue

        dynamic_attr = get_dynamic_behavior(file_hash)

        # Build combined AI payload
        ai_payload = {
            "local_file_name": filename,
            "file_identity": {
                "sha256": file_hash,
                "md5": static_attr.get("md5"),
                "ssdeep": static_attr.get("ssdeep"),
                "tlsh": static_attr.get("tlsh"),
                "vhash": static_attr.get("vhash"),
                "meaningful_name": static_attr.get("meaningful_name"),
                "type_description": static_attr.get("type_description"),
                "size_bytes": static_attr.get("size"),
                "magic_header": static_attr.get("magic"),
                "first_seen": static_attr.get("first_submission_date"),
                "tags": static_attr.get("tags", []),
            },
            "compilation_and_signature": {
                "creation_date": static_attr.get("creation_date"),
                "signature_info": static_attr.get("signature_info", {}),
            },
            "static_analysis": {
                "pe_info": {
                    "imphash": static_attr.get("pe_info", {}).get("imphash"),
                    "entry_point": static_attr.get("pe_info", {}).get("entry_point"),
                    "sections": [
                        {"name": s.get("name"), "entropy": s.get("entropy")}
                        for s in static_attr.get("pe_info", {}).get("sections", [])
                    ],
                },
                "crowdsourced_yara": static_attr.get("crowdsourced_yara_results", []),
            },
            "detections_and_verdicts": {
                "detection_summary": static_attr.get("last_analysis_stats"),
                "suggested_threat_label": static_attr.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "sandbox_verdicts": static_attr.get("sandbox_verdicts", {}),
                "flagged_engine_results": {
                    engine: {"category": res.get("category"), "result": res.get("result")}
                    for engine, res in static_attr.get("last_analysis_results", {}).items()
                    if res.get("category") in ["malicious", "suspicious"]
                },
            },
            "dynamic_behavior": dynamic_attr,
            "community_reputation": {
                "score": static_attr.get("reputation"),
                "votes": static_attr.get("total_votes"),
            },
        }

        # Dump output JSON per file
        out_filename = os.path.join(output_dir, f"{filename}_{file_hash[:8]}_ai_ctx.json")
        with open(out_filename, "w", encoding="utf-8") as out_f:
            json.dump(ai_payload, out_f, indent=2)

        print(f" -> Dumped context to: {out_filename}\n")

        # Rate-limiting delay for free VirusTotal API key (4 requests/min)
        if index < len(all_files) - 1 and rate_limit_delay > 0:
            time.sleep(rate_limit_delay)


if __name__ == "__main__":
    # Specify folder containing binaries/files
    target_directory = "./samples_folder"

    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        print("Set your VirusTotal API key in VT_API_KEY before running.")
    else:
        analyze_directory(target_directory)
