"""
Threat Analysis Engine

Malware behavior analysis using fuzzy logic and behavioral indicators.
"""

from typing import Dict, Tuple, List
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime

from ..core.fuzzy_system import FuzzyInference, ThreatClassifier
from ..core.config import (
    THREAT_THRESHOLDS,
    SUSPICIOUS_APIS,
    BEHAVIOR_INDICATORS,
    ATTACKER_PROFILES,
    ENTROPY_RANGES
)


@dataclass
class ThreatAnalysisResult:
    """Container for threat analysis results"""
    
    sample_name: str
    threat_score: float
    threat_level: str
    confidence: str
    entropy: float
    packages: int
    controlflow: float
    string_visibility: float
    code_reuse: float
    api_suspicion: float
    attacker_profile: str
    behavioral_indicators: List[str]
    detected_apis: Dict[str, List[str]]
    registry_indicators: List[str]
    network_indicators: List[str]
    membership_details: Dict
    analysis_timestamp: str

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "sample_name": self.sample_name,
            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "confidence": self.confidence,
            "entropy": self.entropy,
            "packages": self.packages,
            "controlflow": self.controlflow,
            "string_visibility": self.string_visibility,
            "code_reuse": self.code_reuse,
            "api_suspicion": self.api_suspicion,
            "attacker_profile": self.attacker_profile,
            "behavioral_indicators": self.behavioral_indicators,
            "detected_apis": self.detected_apis,
            "registry_indicators": self.registry_indicators,
            "network_indicators": self.network_indicators,
            "analysis_timestamp": self.analysis_timestamp
        }

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class BehavioralAnalyzer:
    """Analyze malware behavioral indicators"""
    
    @staticmethod
    def detect_api_usage(
        api_suspicion: float,
        threat_score: float
    ) -> Dict[str, List[str]]:
        """
        Predict likely API usage based on threat metrics
        
        Args:
            api_suspicion: API suspicion score (0-100)
            threat_score: Overall threat score (0-100)
        
        Returns:
            Dict of detected API categories and samples
        """
        detected = {}
        
        # High API suspicion indicates process injection
        if api_suspicion > 70:
            detected["process_injection"] = SUSPICIOUS_APIS["process_injection"][:2]
            detected["privilege_escalation"] = SUSPICIOUS_APIS["privilege_escalation"][:2]
        
        # Medium-high threat indicates registry/persistence
        if threat_score > 60:
            detected["registry_modification"] = SUSPICIOUS_APIS["registry_modification"][:2]
            detected["persistence"] = SUSPICIOUS_APIS["persistence"][:2]
        
        # High threat indicates network communication
        if threat_score > 70:
            detected["network"] = SUSPICIOUS_APIS["network"][:2]
        
        # Any threat indicates file operations
        if threat_score > 40:
            detected["file_operations"] = SUSPICIOUS_APIS["file_operations"][:2]
        
        return detected

    @staticmethod
    def detect_behavioral_indicators(
        threat_score: float,
        entropy: float,
        code_reuse: float,
        api_suspicion: float
    ) -> List[str]:
        """
        Detect behavioral indicators based on metrics
        
        Args:
            threat_score: Overall threat score
            entropy: Entropy value
            code_reuse: Code reuse ratio
            api_suspicion: API suspicion score
        
        Returns:
            List of detected behavioral indicators
        """
        indicators = []
        
        # Entropy-based indicators
        if entropy > 7:
            indicators.append("Advanced obfuscation/packing detected")
            indicators.append("Possible polymorphic/metamorphic malware")
        elif entropy > 5.5:
            indicators.append("Code obfuscation techniques present")
            indicators.append("Likely anti-analysis mechanisms")
        
        # Code reuse indicators
        if code_reuse > 0.7:
            indicators.append("High code reuse - matches known malware patterns")
            indicators.append("Likely derivative of existing malware family")
        elif code_reuse > 0.4:
            indicators.append("Moderate code reuse detected")
            indicators.append("Possible known malware variant")
        
        # API suspicion indicators
        if api_suspicion > 80:
            indicators.append("Critical API suspicion - code injection techniques")
            indicators.append("Likely process hollowing or DLL injection")
        elif api_suspicion > 60:
            indicators.append("High API suspicion - privilege escalation attempt")
            indicators.append("Suspicious system-level operations detected")
        
        # Overall threat indicators
        if threat_score > 85:
            indicators.append("APT-level sophistication detected")
            indicators.append("Multi-stage infection chain likely")
        elif threat_score > 70:
            indicators.append("Advanced malware characteristics")
            indicators.append("Professional attack infrastructure")
        
        return indicators

    @staticmethod
    def predict_registry_indicators(threat_score: float) -> List[str]:
        """
        Predict likely registry modifications
        
        Args:
            threat_score: Overall threat score
        
        Returns:
            List of likely registry indicators
        """
        if threat_score < 40:
            return []
        
        indicators = []
        
        if threat_score > 70:
            indicators.append("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            indicators.append("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
            indicators.append("HKLM\\Software\\Classes\\\\Shell\\Open\\Command")
        
        if threat_score > 60:
            indicators.append("HKCU\\Software\\Microsoft\\Internet Explorer")
            indicators.append("HKLM\\System\\CurrentControlSet\\Services")
        
        if threat_score > 50:
            indicators.append("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")
        
        return indicators

    @staticmethod
    def predict_network_indicators(
        threat_score: float,
        api_suspicion: float
    ) -> List[str]:
        """
        Predict likely network indicators
        
        Args:
            threat_score: Overall threat score
            api_suspicion: API suspicion score
        
        Returns:
            List of likely network indicators
        """
        if threat_score < 50:
            return []
        
        indicators = []
        
        if threat_score > 80:
            indicators.append("C2 communication over HTTPS/TLS")
            indicators.append("Data exfiltration via DNS tunneling")
            indicators.append("Fast-flux network infrastructure")
        
        if threat_score > 70:
            indicators.append("Periodic beaconing to C2 server")
            indicators.append("HTTP POST to suspicious domains")
        
        if threat_score > 60:
            indicators.append("DNS requests to suspicious domains")
            indicators.append("Potential botnet activity")
        
        return indicators


class AttackerProfiler:
    """Identify attacker profile based on threat metrics"""
    
    @staticmethod
    def profile_attacker(
        entropy: float,
        threat_score: float,
        code_reuse: float,
        api_suspicion: float
    ) -> str:
        """
        Determine attacker profile based on analysis
        
        Args:
            entropy: Entropy value
            threat_score: Overall threat score
            code_reuse: Code reuse ratio
            api_suspicion: API suspicion score
        
        Returns:
            Attacker profile category
        """
        # APT actor detection
        if threat_score > 80 and entropy > 6.5:
            if api_suspicion > 70:
                return "apt_actor"
        
        # Professional attacker
        if threat_score > 65 and entropy > 5:
            if api_suspicion > 60 or code_reuse > 0.5:
                return "professional_attacker"
        
        # Amateur attacker
        if threat_score > 40 and entropy > 3:
            return "amateur_attacker"
        
        # Script kiddie
        return "script_kiddie"

    @staticmethod
    def get_profile_description(profile_type: str) -> Dict:
        """
        Get description of attacker profile
        
        Args:
            profile_type: Type of profile
        
        Returns:
            Profile description dictionary
        """
        return ATTACKER_PROFILES.get(
            profile_type,
            ATTACKER_PROFILES["script_kiddie"]
        )

    @staticmethod
    def estimate_sophistication_level(threat_score: float) -> str:
        """
        Estimate sophistication level
        
        Args:
            threat_score: Overall threat score
        
        Returns:
            Sophistication level description
        """
        if threat_score > 85:
            return "Critical - APT/Ransomware Level"
        elif threat_score > 70:
            return "Advanced - Professional Cybercriminals"
        elif threat_score > 50:
            return "Intermediate - Organized Groups"
        elif threat_score > 30:
            return "Basic - Script Kiddies / Variants"
        else:
            return "Minimal - Benign or Simple"


class ThreatAnalyzer:
    """Main threat analysis engine"""
    
    def __init__(self):
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.attacker_profiler = AttackerProfiler()

    def analyze(
        self,
        sample_name: str,
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        code_reuse: float = 0.0,
        api_suspicion: float = 0.0
    ) -> ThreatAnalysisResult:
        """
        Perform comprehensive threat analysis
        
        Args:
            sample_name: Name/identifier of the sample
            entropy: Shannon entropy (0-8)
            packages: Number of imported packages
            controlflow: Control flow complexity (0-10)
            string_visibility: String visibility ratio (0-1)
            code_reuse: Code reuse ratio (0-1) [optional]
            api_suspicion: API suspicion score (0-100) [optional]
        
        Returns:
            ThreatAnalysisResult object with detailed analysis
        """
        # Run fuzzy inference
        threat_score, membership_details = FuzzyInference.evaluate_threat(
            entropy=entropy,
            packages=packages,
            controlflow=controlflow,
            string_visibility=string_visibility,
            code_reuse=code_reuse,
            api_suspicion=api_suspicion
        )
        
        # Classify threat
        threat_level, _ = ThreatClassifier.classify(threat_score)
        confidence = ThreatClassifier.confidence_level(threat_score)
        
        # Detect behavioral indicators
        behavioral_indicators = self.behavioral_analyzer.detect_behavioral_indicators(
            threat_score=threat_score,
            entropy=entropy,
            code_reuse=code_reuse,
            api_suspicion=api_suspicion
        )
        
        # Detect API usage
        detected_apis = self.behavioral_analyzer.detect_api_usage(
            api_suspicion=api_suspicion,
            threat_score=threat_score
        )
        
        # Predict registry indicators
        registry_indicators = self.behavioral_analyzer.predict_registry_indicators(
            threat_score=threat_score
        )
        
        # Predict network indicators
        network_indicators = self.behavioral_analyzer.predict_network_indicators(
            threat_score=threat_score,
            api_suspicion=api_suspicion
        )
        
        # Profile attacker
        attacker_profile = self.attacker_profiler.profile_attacker(
            entropy=entropy,
            threat_score=threat_score,
            code_reuse=code_reuse,
            api_suspicion=api_suspicion
        )
        
        # Create result object
        result = ThreatAnalysisResult(
            sample_name=sample_name,
            threat_score=threat_score,
            threat_level=threat_level,
            confidence=confidence,
            entropy=entropy,
            packages=packages,
            controlflow=controlflow,
            string_visibility=string_visibility,
            code_reuse=code_reuse,
            api_suspicion=api_suspicion,
            attacker_profile=attacker_profile,
            behavioral_indicators=behavioral_indicators,
            detected_apis=detected_apis,
            registry_indicators=registry_indicators,
            network_indicators=network_indicators,
            membership_details=membership_details,
            analysis_timestamp=datetime.now().isoformat()
        )
        
        return result
