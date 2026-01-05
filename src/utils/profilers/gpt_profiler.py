"""
GPT-based Attacker Profile Generation

OpenAI GPT API integration for detailed attacker profiles based on malware metrics.
"""

import json
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import os

from ..core.config import (
    GPT_CONFIG,
    ENTROPY_RANGES,
    ATTACKER_PROFILES,
    GPT_PROMPT_TEMPLATES
)


@dataclass
class AttackerProfile:
    """Generated attacker profile"""
    
    profile_type: str
    threat_score: float
    sophistication: str
    objectives: str
    methodologies: str
    defensive_measures: str
    predicted_iocs: Optional[Dict] = None
    attribution: Optional[Dict] = None
    mitigation_strategy: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "profile_type": self.profile_type,
            "threat_score": self.threat_score,
            "sophistication": self.sophistication,
            "objectives": self.objectives,
            "methodologies": self.methodologies,
            "defensive_measures": self.defensive_measures,
            "predicted_iocs": self.predicted_iocs,
            "attribution": self.attribution,
            "mitigation_strategy": self.mitigation_strategy
        }

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


class PromptGenerator:
    """Generate dynamic prompts based on threat metrics"""
    
    @staticmethod
    def get_entropy_context(entropy: float) -> str:
        """
        Get contextual information about entropy level
        
        Args:
            entropy: Entropy value
        
        Returns:
            Description of entropy significance
        """
        if entropy <= ENTROPY_RANGES["low"][1]:
            return "Low entropy indicates minimal obfuscation - typical of legitimate software"
        elif entropy <= ENTROPY_RANGES["medium"][1]:
            return "Medium entropy suggests compression or weak obfuscation"
        elif entropy <= ENTROPY_RANGES["high"][1]:
            return "High entropy indicates advanced obfuscation/packing techniques"
        else:
            return "Very high entropy suggests maximum obfuscation or multi-layer encryption"

    @staticmethod
    def generate_attacker_profile_prompt(
        threat_score: float,
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        code_reuse: float = 0.0,
        api_suspicion: float = 0.0
    ) -> str:
        """
        Generate attacker profile prompt for GPT
        
        Args:
            threat_score: Overall threat score
            entropy: Entropy value
            packages: Package count
            controlflow: Control flow complexity
            string_visibility: String visibility ratio
            code_reuse: Code reuse ratio
            api_suspicion: API suspicion score
        
        Returns:
            Formatted prompt for GPT
        """
        entropy_context = PromptGenerator.get_entropy_context(entropy)
        
        prompt = f"""
You are a cybersecurity expert specializing in malware analysis and threat intelligence.
Based on the following malware analysis metrics, generate a detailed attacker profile.

{entropy_context}

MALWARE ANALYSIS METRICS:
• Threat Score: {threat_score:.2f}/100
• Entropy: {entropy:.2f}/8 (Code obfuscation level)
• Imported Packages: {packages}
• Control Flow Complexity: {controlflow:.2f}/10 (Instruction complexity)
• String Visibility: {string_visibility:.2f} (0=hidden, 1=visible)
• Code Reuse Ratio: {code_reuse:.2f} (0=unique, 1=known malware)
• API Suspicion: {api_suspicion:.2f}/100 (System API misuse)

ANALYSIS REQUIRED:
1. **Attacker Skill Level**: Determine if this is likely work of script kiddie, amateur, professional, or APT actor
2. **Attack Objectives**: Based on the characteristics, what are the likely goals?
   - Financial theft
   - Corporate espionage
   - Data theft
   - System destruction
   - Network control/botnet
3. **Attack Methodology**: How would this attacker approach a target?
   - Social engineering approach
   - Technical sophistication level
   - Likely attack vectors
   - Target profile (individuals, businesses, governments)
4. **Modus Operandi**: What are the attacker's preferred techniques?
   - Malware deployment method
   - Persistence mechanisms
   - Communication with C2
5. **Defensive Measures**: What security measures would be most effective?
   - Detection mechanisms
   - Prevention strategies
   - Incident response considerations

Provide a comprehensive 2-3 paragraph analysis for each section.
"""
        return prompt

    @staticmethod
    def generate_ioc_prompt(
        threat_score: float,
        threat_level: str,
        entropy: float
    ) -> str:
        """
        Generate IOC prediction prompt
        
        Args:
            threat_score: Overall threat score
            threat_level: Threat classification
            entropy: Entropy value
        
        Returns:
            Formatted prompt for IOC prediction
        """
        prompt = f"""
As a threat intelligence analyst, predict potential Indicators of Compromise (IoCs) for this malware:

THREAT PROFILE:
• Threat Score: {threat_score:.2f}/100
• Threat Level: {threat_level}
• Obfuscation Level: {entropy:.2f}/8

PREDICT THE FOLLOWING:
1. **Network IoCs**:
   - Likely C2 domains or IPs
   - Communication patterns (HTTP, HTTPS, DNS, etc.)
   - Port numbers used
   
2. **File IoCs**:
   - Typical file paths and names
   - File extensions
   - Registry keys modified
   
3. **Process IoCs**:
   - Parent-child process relationships
   - Command-line parameters
   - Process names and paths
   
4. **Memory IoCs**:
   - API calls in sequence
   - DLL loading patterns
   - Memory signatures

5. **Behavioral Signatures**:
   - Network connection patterns
   - File access sequences
   - Registry modification patterns

Provide specific, actionable IoCs that security teams can use for detection.
"""
        return prompt

    @staticmethod
    def generate_attribution_prompt(
        threat_score: float,
        threat_level: str,
        entropy: float
    ) -> str:
        """
        Generate threat attribution prompt
        
        Args:
            threat_score: Overall threat score
            threat_level: Threat classification
            entropy: Entropy value
        
        Returns:
            Formatted prompt for attribution analysis
        """
        prompt = f"""
Analyze this malware for potential threat actor attribution:

CHARACTERISTICS:
• Threat Score: {threat_score:.2f}/100
• Threat Level: {threat_level}
• Technical Sophistication: {entropy:.2f}/8

ATTRIBUTION ANALYSIS:
1. **Known Malware Family Matches**:
   - What existing malware families does this resemble?
   - Similarities and differences
   - Evolution patterns
   
2. **Threat Actor Attribution**:
   - Which threat groups use similar techniques?
   - Nation-state indicators
   - Cybercrime group profiles
   
3. **Campaign Association**:
   - Part of known campaigns?
   - Temporal indicators
   - Victim targeting patterns
   
4. **Geographic Indicators**:
   - Likely origin country
   - Operational timezone
   - Language/locale hints
   
5. **Motivation Indicators**:
   - Financial vs. cyber warfare
   - Espionage indicators
   - Destructive intent signals

Provide justified attribution assessment with confidence levels.
"""
        return prompt

    @staticmethod
    def generate_mitigation_prompt(
        threat_score: float,
        threat_level: str
    ) -> str:
        """
        Generate mitigation strategy prompt
        
        Args:
            threat_score: Overall threat score
            threat_level: Threat classification
        
        Returns:
            Formatted prompt for mitigation strategy
        """
        prompt = f"""
Develop a comprehensive mitigation strategy for this threat:

THREAT PROFILE:
• Threat Score: {threat_score:.2f}/100
• Threat Level: {threat_level}

PROVIDE DETAILED STRATEGY FOR:
1. **Immediate Response (0-1 hour)**:
   - Emergency containment steps
   - Isolation procedures
   - Communication protocols
   
2. **Short-term Response (1-24 hours)**:
   - Investigation and forensics
   - System hardening
   - Detection and blocking
   
3. **Eradication (1-7 days)**:
   - Complete malware removal
   - System restoration
   - Backup verification
   
4. **Recovery (1-4 weeks)**:
   - Business continuity restoration
   - Data validation
   - System normalization
   
5. **Long-term Prevention**:
   - Security architecture review
   - Patch management strategy
   - Employee training and awareness
   - Detection capability enhancement
   - Threat intelligence integration

Include specific tools, techniques, and best practices for each phase.
"""
        return prompt


class GPTProfiler:
    """GPT-based threat profiler"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize GPT profiler
        
        Args:
            api_key: OpenAI API key (if None, uses environment variable)
        """
        self.api_key = api_key or GPT_CONFIG.get("api_key")
        self.model = GPT_CONFIG.get("model", "gpt-4")
        self.temperature = GPT_CONFIG.get("temperature", 0.7)
        self.max_tokens = GPT_CONFIG.get("max_tokens", 2000)
        self.has_api = bool(self.api_key)
        
        if self.has_api:
            try:
                import openai
                openai.api_key = self.api_key
                self.openai = openai
            except ImportError:
                self.has_api = False
                print("Warning: openai package not installed. GPT profiler disabled.")

    def generate_profile(
        self,
        threat_score: float,
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        code_reuse: float = 0.0,
        api_suspicion: float = 0.0,
        threat_level: str = "UNKNOWN"
    ) -> Optional[AttackerProfile]:
        """
        Generate attacker profile using GPT
        
        Args:
            threat_score: Overall threat score
            entropy: Entropy value
            packages: Package count
            controlflow: Control flow complexity
            string_visibility: String visibility ratio
            code_reuse: Code reuse ratio
            api_suspicion: API suspicion score
            threat_level: Threat classification
        
        Returns:
            AttackerProfile object or None if API unavailable
        """
        if not self.has_api:
            return self._generate_local_profile(
                threat_score=threat_score,
                entropy=entropy,
                packages=packages,
                controlflow=controlflow,
                string_visibility=string_visibility,
                code_reuse=code_reuse,
                api_suspicion=api_suspicion,
                threat_level=threat_level
            )
        
        prompt = PromptGenerator.generate_attacker_profile_prompt(
            threat_score=threat_score,
            entropy=entropy,
            packages=packages,
            controlflow=controlflow,
            string_visibility=string_visibility,
            code_reuse=code_reuse,
            api_suspicion=api_suspicion
        )
        
        try:
            response = self.openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in malware analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=GPT_CONFIG.get("timeout", 30)
            )
            
            analysis_text = response.choices[0].message.content
            
            # Determine profile type based on threat metrics
            profile_type = self._determine_profile_type(
                threat_score=threat_score,
                entropy=entropy,
                code_reuse=code_reuse,
                api_suspicion=api_suspicion
            )
            
            sophistication = self._estimate_sophistication(threat_score)
            
            profile = AttackerProfile(
                profile_type=profile_type,
                threat_score=threat_score,
                sophistication=sophistication,
                objectives=analysis_text[:500],  # First part as objectives
                methodologies=analysis_text[500:1000],  # Middle part as methodologies
                defensive_measures=analysis_text[1000:],  # Rest as defensive measures
            )
            
            return profile
            
        except Exception as e:
            print(f"GPT API Error: {e}")
            return self._generate_local_profile(
                threat_score=threat_score,
                entropy=entropy,
                packages=packages,
                controlflow=controlflow,
                string_visibility=string_visibility,
                code_reuse=code_reuse,
                api_suspicion=api_suspicion,
                threat_level=threat_level
            )

    def _generate_local_profile(
        self,
        threat_score: float,
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        code_reuse: float,
        api_suspicion: float,
        threat_level: str
    ) -> AttackerProfile:
        """
        Generate profile without GPT (fallback)
        
        Uses local heuristics and rule-based analysis
        """
        profile_type = self._determine_profile_type(
            threat_score=threat_score,
            entropy=entropy,
            code_reuse=code_reuse,
            api_suspicion=api_suspicion
        )
        
        sophistication = self._estimate_sophistication(threat_score)
        
        profile_data = ATTACKER_PROFILES.get(profile_type, ATTACKER_PROFILES["script_kiddie"])
        
        objectives = self._generate_objectives(profile_type, threat_score)
        methodologies = self._generate_methodologies(profile_type, entropy)
        defensive_measures = self._generate_defensive_measures(profile_type, threat_score)
        
        return AttackerProfile(
            profile_type=profile_type,
            threat_score=threat_score,
            sophistication=sophistication,
            objectives=objectives,
            methodologies=methodologies,
            defensive_measures=defensive_measures
        )

    @staticmethod
    def _determine_profile_type(
        threat_score: float,
        entropy: float,
        code_reuse: float,
        api_suspicion: float
    ) -> str:
        """Determine attacker profile type"""
        if threat_score > 80 and entropy > 6.5 and api_suspicion > 70:
            return "apt_actor"
        elif threat_score > 65 and entropy > 5 and (api_suspicion > 60 or code_reuse > 0.5):
            return "professional_attacker"
        elif threat_score > 40 and entropy > 3:
            return "amateur_attacker"
        else:
            return "script_kiddie"

    @staticmethod
    def _estimate_sophistication(threat_score: float) -> str:
        """Estimate sophistication level"""
        if threat_score > 85:
            return "Critical - APT/Ransomware Level"
        elif threat_score > 70:
            return "Advanced - Professional Cybercriminals"
        elif threat_score > 50:
            return "Intermediate - Organized Groups"
        elif threat_score > 30:
            return "Basic - Script Kiddies"
        else:
            return "Minimal - Benign"

    @staticmethod
    def _generate_objectives(profile_type: str, threat_score: float) -> str:
        """Generate attacker objectives"""
        objectives_map = {
            "apt_actor": "Nation-state level objectives: cyber espionage, critical infrastructure disruption, long-term persistence",
            "professional_attacker": "Financial gain through data theft, ransomware, and credential harvesting. Multi-stage attacks.",
            "amateur_attacker": "Learning-based attacks, simple financial theft, attention-seeking. Limited operational security.",
            "script_kiddie": "Casual attacks using pre-made tools, learning programming, minor vandalism."
        }
        return objectives_map.get(profile_type, "Unknown objectives")

    @staticmethod
    def _generate_methodologies(profile_type: str, entropy: float) -> str:
        """Generate attacker methodologies"""
        methodologies_map = {
            "apt_actor": f"Multi-stage attacks with custom malware, zero-day exploits, supply chain compromise. Entropy level: {entropy:.2f} indicates advanced obfuscation.",
            "professional_attacker": f"Spear-phishing, credential theft, lateral movement. Moderate obfuscation (entropy: {entropy:.2f})",
            "amateur_attacker": "Mass malware distribution, dictionary attacks, exploit kits",
            "script_kiddie": "Using existing tools without modification, basic social engineering"
        }
        return methodologies_map.get(profile_type, "Unknown methodologies")

    @staticmethod
    def _generate_defensive_measures(profile_type: str, threat_score: float) -> str:
        """Generate defensive recommendations"""
        measures_map = {
            "apt_actor": "Advanced EDR, threat hunting, incident response team, threat intelligence sharing. Assume breach mentality.",
            "professional_attacker": "Multi-factor authentication, network segmentation, behavior-based detection, employee training",
            "amateur_attacker": "Standard antivirus, regular patching, basic firewall rules, user awareness",
            "script_kiddie": "Basic antivirus, regular updates, simple security hygiene"
        }
        return measures_map.get(profile_type, "Standard security measures recommended")
