"""
Configuration and constants for Threat Type APT project
"""

import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TRAINING_DATA_DIR = DATA_DIR / "training_data"
OUTPUT_DIR = DATA_DIR / "outputs"

# Ensure directories exist
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# GPT Configuration
GPT_CONFIG = {
    "model": "gpt-4",  # or "gpt-3.5-turbo"
    "temperature": 0.7,
    "max_tokens": 2000,
    "timeout": 30,
    # Get API key from environment variable
    "api_key": os.getenv("OPENAI_API_KEY", ""),
}

# Threat Analysis Thresholds
THREAT_THRESHOLDS = {
    "CRITICAL": 85,
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 0
}

# Entropy ranges for threat classification
ENTROPY_RANGES = {
    "very_low": (0, 1.5),      # Plain text / uncompressed
    "low": (1.5, 3.5),         # Weakly compressed
    "medium": (3.5, 5.5),      # Moderately compressed
    "high": (5.5, 7),          # Highly compressed / obfuscated
    "very_high": (7, 8)        # Maximum entropy / packed
}

# Suspicious API patterns
SUSPICIOUS_APIS = {
    "process_injection": [
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "SetWindowsHookEx"
    ],
    "registry_modification": [
        "RegSetValueEx",
        "RegCreateKeyEx",
        "RegDeleteKeyEx",
        "RegSetKeyValue"
    ],
    "file_operations": [
        "CreateFileA",
        "CreateFileW",
        "WriteFile",
        "DeleteFileA",
        "DeleteFileW"
    ],
    "network": [
        "InternetOpenA",
        "InternetOpenW",
        "InternetConnectA",
        "InternetConnectW",
        "WinHttpOpen"
    ],
    "privilege_escalation": [
        "CreateProcessAsUserA",
        "CreateProcessAsUserW",
        "ImpersonateLoggedOnUser",
        "DuplicateToken"
    ],
    "persistence": [
        "SetValue",
        "ShellExecute",
        "CreateService",
        "ScheduleJob"
    ]
}

# Attacker profiles based on entropy levels
ATTACKER_PROFILES = {
    "script_kiddie": {
        "entropy_range": (0, 3.5),
        "characteristics": [
            "Uses publicly available tools",
            "Minimal obfuscation",
            "Simple malware variants",
            "Low code complexity"
        ],
        "techniques": ["WinExec", "basic_shell_commands", "simple_injection"]
    },
    "amateur_attacker": {
        "entropy_range": (3.5, 5.5),
        "characteristics": [
            "Basic obfuscation techniques",
            "Moderate code complexity",
            "Uses some custom tools",
            "Basic anti-analysis"
        ],
        "techniques": ["UPX_packing", "simple_encryption", "basic_api_hooking"]
    },
    "professional_attacker": {
        "entropy_range": (5.5, 7),
        "characteristics": [
            "Advanced obfuscation",
            "Complex control flow",
            "Custom payloads",
            "Strong anti-analysis"
        ],
        "techniques": ["polymorphism", "metamorphism", "code_virtualization", "anti_debugging"]
    },
    "apt_actor": {
        "entropy_range": (7, 8),
        "characteristics": [
            "Maximum obfuscation",
            "Highly sophisticated techniques",
            "Zero-day exploits",
            "Multi-stage infection",
            "Advanced evasion"
        ],
        "techniques": ["advanced_packing", "multi_layer_encryption", "anti_forensics", "privilege_escalation"]
    }
}

# Malware behavior indicators
BEHAVIOR_INDICATORS = {
    "suspicious_registry": [
        "Run",
        "RunOnce",
        "CurrentVersion",
        "Software\\Classes",
        "Shell Open Command"
    ],
    "suspicious_files": [
        ".sys",
        ".dll",
        ".exe",
        ".scr",
        ".bat",
        ".cmd"
    ],
    "suspicious_processes": [
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "regsvcs.exe"
    ],
    "network_indicators": [
        "C2_communication",
        "Data_exfiltration",
        "DNS_tunneling",
        "HTTP_beaconing"
    ]
}

# GPT prompt templates
GPT_PROMPT_TEMPLATES = {
    "attacker_profile": """
Based on the malware analysis results below, create a detailed attacker profile including:
1. Likely skill level (script kiddie, amateur, professional, APT actor)
2. Probable objectives and motivations
3. Expected attack methodology
4. Recommended defensive measures

Malware Metrics:
- Threat Score: {threat_score:.2f}/100
- Entropy: {entropy}
- Packages: {packages}
- Control Flow Complexity: {controlflow}
- String Visibility: {string_visibility}
- Code Reuse: {code_reuse}
- API Suspicion: {api_suspicion}

Threat Classification: {threat_level}
""",
    
    "ioc_prediction": """
Based on these malware indicators, predict potential Indicators of Compromise (IoCs):

Threat Score: {threat_score:.2f}/100
Threat Level: {threat_level}

Provide:
1. Likely C2 communication patterns
2. Potential file paths used
3. Registry keys that might be modified
4. Network signatures
5. Process names and behaviors
""",
    
    "attribution": """
Based on this malware's characteristics, suggest possible attribution:

Threat Score: {threat_score:.2f}/100
Threat Level: {threat_level}
Entropy Level: {entropy}

Consider:
1. Known malware families
2. Attribution to specific threat actors/groups
3. Similarity to previous campaigns
4. Geographic origin indicators
""",
    
    "mitigation_strategy": """
Create a comprehensive mitigation strategy for this threat:

Threat Score: {threat_score:.2f}/100
Threat Level: {threat_level}

Include:
1. Immediate containment steps
2. Detection mechanisms
3. Eradication procedures
4. Long-term prevention
5. Security hardening recommendations
"""
}
