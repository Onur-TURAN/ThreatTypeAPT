"""
Fuzzy Logic System for Advanced Malware Threat Detection

Handles fuzzy membership functions, set operations, and inference rules
for comprehensive malware behavior analysis.
"""

import math
from typing import Dict, Tuple, List
from enum import Enum


class ThreatLevel(Enum):
    """Threat level classification"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class MembershipFunction:
    """Base class for membership functions"""
    
    @staticmethod
    def triangular(x: float, a: float, b: float, c: float) -> float:
        """
        Triangular membership function
        
        Args:
            x: Input value
            a: Left point (0 membership)
            b: Peak point (1 membership)
            c: Right point (0 membership)
        
        Returns:
            Membership degree [0, 1]
        """
        if x <= a or x >= c:
            return 0.0
        elif x == b:
            return 1.0
        elif x < b:
            return (x - a) / (b - a) if (b - a) != 0 else 0.0
        else:
            return (c - x) / (c - b) if (c - b) != 0 else 0.0

    @staticmethod
    def trapezoidal(x: float, a: float, b: float, c: float, d: float) -> float:
        """
        Trapezoidal membership function
        
        Args:
            x: Input value
            a: Left slope start
            b: Left slope end (1 membership)
            c: Right slope start (1 membership)
            d: Right slope end
        
        Returns:
            Membership degree [0, 1]
        """
        if x <= a or x >= d:
            return 0.0
        elif a < x < b:
            return (x - a) / (b - a) if (b - a) != 0 else 0.0
        elif b <= x <= c:
            return 1.0
        else:  # c < x < d
            return (d - x) / (d - c) if (d - c) != 0 else 0.0

    @staticmethod
    def gaussian(x: float, mean: float, sigma: float) -> float:
        """
        Gaussian membership function
        
        Args:
            x: Input value
            mean: Center of the distribution
            sigma: Standard deviation
        
        Returns:
            Membership degree [0, 1]
        """
        return math.exp(-((x - mean) ** 2) / (2 * sigma ** 2))


class FuzzyInput:
    """Handles fuzzy input membership calculations"""
    
    @staticmethod
    def entropy_membership(e: float) -> Dict[str, float]:
        """
        Entropy membership levels
        
        High entropy indicates code obfuscation/packing
        
        Args:
            e: Entropy value (0-8)
        
        Returns:
            Dict with membership degrees for each level
        """
        return {
            "Low": MembershipFunction.triangular(e, 0, 1.5, 3.5),
            "Medium": MembershipFunction.triangular(e, 2.5, 4.5, 6.5),
            "High": MembershipFunction.triangular(e, 5.5, 7, 8)
        }

    @staticmethod
    def package_membership(p: float) -> Dict[str, float]:
        """
        Package/library count membership levels
        
        Many packages indicate complex behavior or dependency injection
        
        Args:
            p: Package count
        
        Returns:
            Dict with membership degrees for each level
        """
        return {
            "Few": MembershipFunction.triangular(p, 0, 2, 5),
            "Moderate": MembershipFunction.triangular(p, 3, 9, 15),
            "Many": MembershipFunction.triangular(p, 12, 25, 40)
        }

    @staticmethod
    def controlflow_membership(c: float) -> Dict[str, float]:
        """
        Control flow complexity membership levels
        
        Complex control flow suggests anti-analysis techniques
        
        Args:
            c: Control flow complexity metric
        
        Returns:
            Dict with membership degrees for each level
        """
        return {
            "Simple": MembershipFunction.triangular(c, 0, 1, 2.5),
            "Moderate": MembershipFunction.triangular(c, 1.5, 4, 6.5),
            "Complex": MembershipFunction.triangular(c, 5.5, 8, 10)
        }

    @staticmethod
    def string_visibility_membership(v: float) -> Dict[str, float]:
        """
        String visibility ratio membership levels
        
        Low visibility indicates string obfuscation
        
        Args:
            v: String visibility ratio (0-1)
        
        Returns:
            Dict with membership degrees for each level
        """
        return {
            "Low": MembershipFunction.triangular(v, 0.0, 0.1, 0.3),
            "Medium": MembershipFunction.triangular(v, 0.2, 0.5, 0.8),
            "High": MembershipFunction.triangular(v, 0.6, 0.85, 1.0)
        }

    @staticmethod
    def code_reuse_membership(r: float) -> Dict[str, float]:
        """
        Code reuse patterns membership levels
        
        High reuse of suspicious patterns indicates intentional malware
        
        Args:
            r: Code reuse ratio (0-1)
        
        Returns:
            Dict with membership degrees for each level
        """
        return {
            "Low": MembershipFunction.triangular(r, 0.0, 0.1, 0.25),
            "Medium": MembershipFunction.triangular(r, 0.15, 0.4, 0.65),
            "High": MembershipFunction.triangular(r, 0.5, 0.8, 1.0)
        }

    @staticmethod
    def api_suspicion_membership(a: float) -> Dict[str, float]:
        """
        API suspicion level membership
        
        Suspicious APIs: CreateRemoteThread, WriteProcessMemory, RegSetValueEx, etc.
        
        Args:
            a: API suspicion score (0-100)
        
        Returns:
            Dict with membership degrees for each level
        """
        return {
            "Low": MembershipFunction.triangular(a, 0, 15, 35),
            "Medium": MembershipFunction.triangular(a, 25, 50, 75),
            "High": MembershipFunction.triangular(a, 60, 85, 100)
        }


class FuzzyInference:
    """Fuzzy inference engine with rule-based threat assessment"""
    
    # Fuzzy rules weight matrix
    RULE_WEIGHTS = {
        "R1": {"condition": "High_Entropy + Low_StringVisibility", "weight": 95},
        "R2": {"condition": "Medium_Entropy + Many_Packages", "weight": 88},
        "R3": {"condition": "Complex_ControlFlow + High_ApiSuspicion", "weight": 92},
        "R4": {"condition": "Low_StringVisibility + High_CodeReuse", "weight": 85},
        "R5": {"condition": "Low_Entropy + High_StringVisibility", "weight": 10},
        "R6": {"condition": "Simple_ControlFlow + Few_Packages", "weight": 8},
        "R7": {"condition": "High_ApiSuspicion + High_CodeReuse", "weight": 90},
        "R8": {"condition": "Medium_Entropy + High_ControlFlow", "weight": 70},
        "R9": {"condition": "High_StringVisibility + Low_ApiSuspicion", "weight": 5},
        "R10": {"condition": "Low_ApiSuspicion + Low_CodeReuse", "weight": 12},
    }

    @staticmethod
    def defuzzify(rules: List[float]) -> float:
        """
        Defuzzify fuzzy inference results
        
        Uses centroid method for defuzzification
        
        Args:
            rules: List of rule activation values
        
        Returns:
            Defuzzified output (0-100)
        """
        if not rules or sum(rules) == 0:
            return 0.0
        
        return sum(rules) / len(rules)

    @staticmethod
    def evaluate_threat(
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        code_reuse: float = 0.0,
        api_suspicion: float = 0.0
    ) -> Tuple[float, Dict[str, float]]:
        """
        Comprehensive threat evaluation using fuzzy inference
        
        Args:
            entropy: Shannon entropy (0-8)
            packages: Number of imported packages
            controlflow: Control flow complexity (0-10)
            string_visibility: String visibility ratio (0-1)
            code_reuse: Code reuse ratio (0-1) [optional]
            api_suspicion: API suspicion score (0-100) [optional]
        
        Returns:
            Tuple of (threat_score, membership_details)
        """
        # Get membership values
        e = FuzzyInput.entropy_membership(entropy)
        p = FuzzyInput.package_membership(packages)
        c = FuzzyInput.controlflow_membership(controlflow)
        v = FuzzyInput.string_visibility_membership(string_visibility)
        r = FuzzyInput.code_reuse_membership(code_reuse)
        a = FuzzyInput.api_suspicion_membership(api_suspicion)

        rules = []

        # Fuzzy threat assessment with weighted rule activation
        # Each rule combines multiple indicators using both AND and OR operators
        
        # Weight factors (higher = more influence)
        entropy_weight = 0.25
        api_weight = 0.25
        reuse_weight = 0.20
        visibility_weight = 0.15
        control_weight = 0.15

        # Rule 1: High entropy (obfuscation/packing)
        r1 = e["High"] * 100
        rules.append(r1)

        # Rule 2: High API suspicion (system abuse)
        r2 = a["High"] * 95
        rules.append(r2)

        # Rule 3: High code reuse (known malware)
        r3 = r["High"] * 90
        rules.append(r3)

        # Rule 4: Low string visibility (obfuscated strings)
        r4 = (1 - v["Low"]) * 85
        rules.append(r4)

        # Rule 5: Complex control flow (anti-analysis)
        r5 = c["Complex"] * 80
        rules.append(r5)

        # Rule 6: Combination: High entropy + High API suspicion
        r6 = (e["High"] + a["High"]) / 2 * 92
        rules.append(r6)

        # Rule 7: Combination: High code reuse + Low visibility
        r7 = (r["High"] + (1 - v["Low"])) / 2 * 88
        rules.append(r7)

        # Rule 8: Combination: Complex control flow + High API
        r8 = (c["Complex"] + a["High"]) / 2 * 85
        rules.append(r8)

        # Rule 9: Combination: Many packages + High entropy
        r9 = (p["Many"] + e["High"]) / 2 * 80
        rules.append(r9)

        # Rule 10: Benign case (all low indicators)
        r10 = min(e["Low"], (1 - a["Low"]), v["High"]) * 25
        rules.append(r10)

        # Calculate weighted average threat score
        threat_score = sum(rules) / len(rules) if rules else 0
        threat_score = min(100, max(0, threat_score))  # Clamp to 0-100

        membership_details = {
            "entropy": e,
            "packages": p,
            "controlflow": c,
            "string_visibility": v,
            "code_reuse": r,
            "api_suspicion": a,
            "active_rules": len([x for x in rules if x > 0]),
            "total_weight": sum(rules)
        }

        return threat_score, membership_details


class ThreatClassifier:
    """Classify threat level based on fuzzy score"""
    
    THRESHOLDS = {
        "CRITICAL": 85,
        "HIGH": 70,
        "MEDIUM": 40,
        "LOW": 0
    }
    
    THREAT_DESCRIPTIONS = {
        "CRITICAL": "Advanced Persistent Threat (APT) / Ransomware",
        "HIGH": "Advanced Malware / Trojan",
        "MEDIUM": "Commodity Malware",
        "LOW": "Benign / Simple / Suspicious Activity"
    }

    @staticmethod
    def classify(score: float) -> Tuple[str, str]:
        """
        Classify threat level from fuzzy score
        
        Args:
            score: Fuzzy threat score (0-100)
        
        Returns:
            Tuple of (threat_level, description)
        """
        if score >= ThreatClassifier.THRESHOLDS["CRITICAL"]:
            return "CRITICAL", ThreatClassifier.THREAT_DESCRIPTIONS["CRITICAL"]
        elif score >= ThreatClassifier.THRESHOLDS["HIGH"]:
            return "HIGH", ThreatClassifier.THREAT_DESCRIPTIONS["HIGH"]
        elif score >= ThreatClassifier.THRESHOLDS["MEDIUM"]:
            return "MEDIUM", ThreatClassifier.THREAT_DESCRIPTIONS["MEDIUM"]
        else:
            return "LOW", ThreatClassifier.THREAT_DESCRIPTIONS["LOW"]

    @staticmethod
    def confidence_level(score: float) -> str:
        """
        Get confidence level of the classification
        
        Args:
            score: Fuzzy threat score (0-100)
        
        Returns:
            Confidence level description
        """
        if score >= 80 or score <= 20:
            return "Very High"
        elif score >= 60 or score <= 40:
            return "High"
        else:
            return "Medium"
