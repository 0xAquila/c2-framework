"""
MITRE ATT&CK technique tags for common C2 commands.
Used to annotate tasks with the relevant technique ID and name
so the operator can see the ATT&CK context in the dashboard.
"""

# Maps substrings of command strings to (technique_id, technique_name, tactic)
_RULES = [
    # Discovery
    ("whoami",         "T1033", "System Owner/User Discovery",       "Discovery"),
    ("net user",       "T1087.001", "Local Account Discovery",       "Discovery"),
    ("net localgroup", "T1069.001", "Local Groups Discovery",        "Discovery"),
    ("net group",      "T1069.002", "Domain Groups Discovery",       "Discovery"),
    ("net view",       "T1135",  "Network Share Discovery",          "Discovery"),
    ("ipconfig",       "T1016",  "System Network Config Discovery",  "Discovery"),
    ("ifconfig",       "T1016",  "System Network Config Discovery",  "Discovery"),
    ("systeminfo",     "T1082",  "System Information Discovery",     "Discovery"),
    ("tasklist",       "T1057",  "Process Discovery",                "Discovery"),
    ("netstat",        "T1049",  "System Network Connections",       "Discovery"),
    ("arp",            "T1016",  "System Network Config Discovery",  "Discovery"),
    ("route print",    "T1016",  "System Network Config Discovery",  "Discovery"),
    ("dir ",           "T1083",  "File and Directory Discovery",     "Discovery"),
    ("ls ",            "T1083",  "File and Directory Discovery",     "Discovery"),
    ("find ",          "T1083",  "File and Directory Discovery",     "Discovery"),
    ("reg query",      "T1012",  "Query Registry",                   "Discovery"),
    ("env",            "T1082",  "System Information Discovery",     "Discovery"),
    ("privs",          "T1069",  "Permission Groups Discovery",      "Discovery"),
    # Collection
    ("screenshot",     "T1113",  "Screen Capture",                   "Collection"),
    ("keylogger",      "T1056.001", "Keylogging",                    "Collection"),
    ("clipboard",      "T1115",  "Clipboard Data",                   "Collection"),
    ("download",       "T1005",  "Data from Local System",           "Collection"),
    # Exfiltration / C2
    ("upload",         "T1105",  "Ingress Tool Transfer",            "Command and Control"),
    ("sleep",          "T1029",  "Scheduled Transfer",               "Command and Control"),
    # Persistence
    ("persist",        "T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
    # Privilege Escalation
    ("runas",          "T1548",  "Abuse Elevation Control Mechanism","Privilege Escalation"),
    # Impact
    ("kill",           "T1489",  "Service Stop",                     "Impact"),
    # Lateral Movement
    ("psexec",         "T1021.002", "SMB/Windows Admin Shares",      "Lateral Movement"),
    ("wmic",           "T1047",  "Windows Management Instrumentation","Execution"),
    ("powershell",     "T1059.001", "PowerShell",                    "Execution"),
    ("cmd",            "T1059.003", "Windows Command Shell",         "Execution"),
    ("sysinfo",        "T1082",  "System Information Discovery",     "Discovery"),
]

# Tactic colour map (for dashboard badges)
TACTIC_COLORS = {
    "Discovery":          "#00d4ff",
    "Collection":         "#ffd700",
    "Command and Control":"#00ff41",
    "Persistence":        "#ff8c00",
    "Privilege Escalation":"#ff4444",
    "Lateral Movement":   "#c084fc",
    "Execution":          "#fb923c",
    "Impact":             "#f87171",
}


def tag(command: str) -> dict | None:
    """Return ATT&CK tag dict for the given command string, or None."""
    cmd_lower = command.lower()
    for keyword, tech_id, tech_name, tactic in _RULES:
        if keyword in cmd_lower:
            return {
                "id":     tech_id,
                "name":   tech_name,
                "tactic": tactic,
                "color":  TACTIC_COLORS.get(tactic, "#888"),
                "url":    f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
            }
    return None
