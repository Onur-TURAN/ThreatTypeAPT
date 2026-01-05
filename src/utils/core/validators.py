"""
Input validation and utility functions
"""

from typing import Tuple, Dict, List
import re


class ValidationError(Exception):
    """Custom validation error"""
    pass


class InputValidator:
    """Validates input parameters for threat analysis"""
    
    @staticmethod
    def validate_entropy(entropy: float) -> bool:
        """Validate entropy value (0-8)"""
        return isinstance(entropy, (int, float)) and 0 <= entropy <= 8

    @staticmethod
    def validate_packages(packages: int) -> bool:
        """Validate package count (0-1000)"""
        return isinstance(packages, int) and 0 <= packages <= 1000

    @staticmethod
    def validate_controlflow(controlflow: float) -> bool:
        """Validate control flow complexity (0-10)"""
        return isinstance(controlflow, (int, float)) and 0 <= controlflow <= 10

    @staticmethod
    def validate_string_visibility(visibility: float) -> bool:
        """Validate string visibility ratio (0-1)"""
        return isinstance(visibility, (int, float)) and 0 <= visibility <= 1

    @staticmethod
    def validate_code_reuse(code_reuse: float) -> bool:
        """Validate code reuse ratio (0-1)"""
        return isinstance(code_reuse, (int, float)) and 0 <= code_reuse <= 1

    @staticmethod
    def validate_api_suspicion(api_suspicion: float) -> bool:
        """Validate API suspicion score (0-100)"""
        return isinstance(api_suspicion, (int, float)) and 0 <= api_suspicion <= 100

    @staticmethod
    def validate_sample_name(name: str) -> bool:
        """Validate sample name format"""
        # Allow alphanumeric, underscore, hyphen, dot
        return bool(re.match(r"^[a-zA-Z0-9._-]+$", name)) and len(name) > 0

    @staticmethod
    def validate_all_inputs(
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        code_reuse: float = 0.0,
        api_suspicion: float = 0.0,
        sample_name: str = "malware_sample"
    ) -> Tuple[bool, List[str]]:
        """
        Validate all input parameters
        
        Args:
            entropy: Shannon entropy value
            packages: Package count
            controlflow: Control flow complexity
            string_visibility: String visibility ratio
            code_reuse: Code reuse ratio
            api_suspicion: API suspicion score
            sample_name: Sample identifier name
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        if not InputValidator.validate_entropy(entropy):
            errors.append(f"Entropy must be between 0 and 8, got {entropy}")
        
        if not InputValidator.validate_packages(packages):
            errors.append(f"Packages must be between 0 and 1000, got {packages}")
        
        if not InputValidator.validate_controlflow(controlflow):
            errors.append(f"Control flow must be between 0 and 10, got {controlflow}")
        
        if not InputValidator.validate_string_visibility(string_visibility):
            errors.append(f"String visibility must be between 0 and 1, got {string_visibility}")
        
        if not InputValidator.validate_code_reuse(code_reuse):
            errors.append(f"Code reuse must be between 0 and 1, got {code_reuse}")
        
        if not InputValidator.validate_api_suspicion(api_suspicion):
            errors.append(f"API suspicion must be between 0 and 100, got {api_suspicion}")
        
        if not InputValidator.validate_sample_name(sample_name):
            errors.append(f"Sample name is invalid: {sample_name}")
        
        return len(errors) == 0, errors


class DataNormalizer:
    """Normalize input data for consistency"""
    
    @staticmethod
    def normalize_entropy(entropy: float, from_max: float = 8) -> float:
        """
        Normalize entropy to 0-8 range
        
        Args:
            entropy: Entropy value
            from_max: Maximum value in current scale
        
        Returns:
            Normalized entropy (0-8)
        """
        if from_max == 0:
            return 0.0
        return min(8.0, max(0.0, (entropy / from_max) * 8))

    @staticmethod
    def normalize_packages(packages: int, from_max: int = 100) -> int:
        """Normalize package count"""
        return min(1000, max(0, packages))

    @staticmethod
    def normalize_visibility(visibility: float) -> float:
        """Ensure visibility is between 0-1"""
        return min(1.0, max(0.0, visibility))

    @staticmethod
    def round_for_display(value: float, decimals: int = 2) -> float:
        """Round value for display"""
        return round(value, decimals)


class FormatHelper:
    """Format output for display"""
    
    @staticmethod
    def format_threat_report(
        sample_name: str,
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        threat_score: float,
        threat_level: str,
        code_reuse: float = 0.0,
        api_suspicion: float = 0.0,
        confidence: str = "High"
    ) -> str:
        """
        Format threat analysis report
        
        Returns:
            Formatted report string
        """
        report = f"""
╔════════════════════════════════════════════════════════════════════════╗
║                     THREAT TYPE APT ANALYSIS REPORT                    ║
╚════════════════════════════════════════════════════════════════════════╝

Sample: {sample_name}

┌─ BINARY METRICS ─────────────────────────────────────────────────────┐
│ Entropy:                    {entropy:.2f} / 8
│ Package Count:              {packages}
│ Control Flow Complexity:    {controlflow:.2f} / 10
│ String Visibility Ratio:    {string_visibility:.2f}
│ Code Reuse Ratio:          {code_reuse:.2f}
│ API Suspicion Score:       {api_suspicion:.2f} / 100
└──────────────────────────────────────────────────────────────────────┘

┌─ THREAT ASSESSMENT ──────────────────────────────────────────────────┐
│ Malware Suspicion Score:    {threat_score:.2f} / 100
│ Threat Level:               {threat_level}
│ Confidence Level:           {confidence}
└──────────────────────────────────────────────────────────────────────┘
"""
        return report

    @staticmethod
    def format_json_output(
        sample_name: str,
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        threat_score: float,
        threat_level: str,
        code_reuse: float = 0.0,
        api_suspicion: float = 0.0,
        confidence: str = "High"
    ) -> Dict:
        """Format threat analysis as JSON"""
        return {
            "sample_name": sample_name,
            "metrics": {
                "entropy": entropy,
                "package_count": packages,
                "control_flow_complexity": controlflow,
                "string_visibility": string_visibility,
                "code_reuse": code_reuse,
                "api_suspicion": api_suspicion
            },
            "threat_assessment": {
                "score": threat_score,
                "level": threat_level,
                "confidence": confidence
            }
        }
