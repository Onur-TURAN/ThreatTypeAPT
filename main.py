"""
Threat Type APT - Main Entry Point

Advanced malware analysis system combining fuzzy logic inference
with GPT-based attacker profiling for comprehensive threat intelligence.

Usage:
    python main.py [--sample SAMPLE_NAME] [--json] [--profile] [--api-key API_KEY]
    
    python main.py
        Run with example malware sample
    
    python main.py --json
        Output results as JSON
    
    python main.py --profile
        Generate detailed attacker profile using GPT
    
    python main.py --sample my_malware --api-key YOUR_API_KEY
        Analyze specific sample with GPT profiling
"""

import json
import argparse
from pathlib import Path
from typing import Optional
import sys
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from utils import (
    # Core imports
    ThreatAnalyzer,
    InputValidator,
    FormatHelper,
    DataNormalizer,
    OUTPUT_DIR,
    # Profiler imports
    GPTProfiler,
    PromptGenerator
)


class ThreatAnalysisCLI:
    """Command-line interface for threat analysis"""
    
    def __init__(self):
        self.analyzer = ThreatAnalyzer()
        self.output_dir = OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze_sample(
        self,
        sample_name: str,
        entropy: float,
        packages: int,
        controlflow: float,
        string_visibility: float,
        code_reuse: float = 0.0,
        api_suspicion: float = 0.0
    ) -> dict:
        """
        Analyze a malware sample
        
        Returns:
            Analysis result as dictionary
        """
        # Validate inputs
        is_valid, errors = InputValidator.validate_all_inputs(
            entropy=entropy,
            packages=packages,
            controlflow=controlflow,
            string_visibility=string_visibility,
            code_reuse=code_reuse,
            api_suspicion=api_suspicion,
            sample_name=sample_name
        )
        
        if not is_valid:
            print("❌ Validation Errors:")
            for error in errors:
                print(f"  • {error}")
            return None
        
        # Run threat analysis
        print(f"\n🔍 Analyzing: {sample_name}")
        result = self.analyzer.analyze(
            sample_name=sample_name,
            entropy=entropy,
            packages=packages,
            controlflow=controlflow,
            string_visibility=string_visibility,
            code_reuse=code_reuse,
            api_suspicion=api_suspicion
        )
        
        return result

    def display_threat_report(self, result) -> None:
        """Display formatted threat report"""
        
        print(f"""
╔════════════════════════════════════════════════════════════════════════╗
║                   THREAT TYPE APT ANALYSIS REPORT                      ║
╚════════════════════════════════════════════════════════════════════════╝

📋 Sample Information:
   Name: {result.sample_name}
   Analysis Time: {result.analysis_timestamp}

┌─ BINARY METRICS ──────────────────────────────────────────────────────┐
│ • Entropy:                      {result.entropy:.2f} / 8.00
│ • Package Count:                {result.packages} packages
│ • Control Flow Complexity:      {result.controlflow:.2f} / 10.00
│ • String Visibility Ratio:      {result.string_visibility:.2f}
│ • Code Reuse Ratio:            {result.code_reuse:.2f}
│ • API Suspicion Score:         {result.api_suspicion:.2f} / 100.00
└──────────────────────────────────────────────────────────────────────┘

┌─ THREAT ASSESSMENT ───────────────────────────────────────────────────┐
│ ⚠️  Malware Suspicion Score:    {result.threat_score:.2f} / 100.00
│ 🎯 Threat Level:               {result.threat_level}
│ 📊 Confidence:                 {result.confidence}
│ 👤 Attacker Profile:          {result.attacker_profile.replace('_', ' ').title()}
└──────────────────────────────────────────────────────────────────────┘

┌─ BEHAVIORAL INDICATORS ───────────────────────────────────────────────┐""")
        
        if result.behavioral_indicators:
            for indicator in result.behavioral_indicators:
                print(f"│ ▶ {indicator}")
        else:
            print("│ (No significant behavioral indicators detected)")
        
        print("└──────────────────────────────────────────────────────────────────────┘")

        if result.detected_apis:
            print(f"\n┌─ DETECTED API PATTERNS ───────────────────────────────────────────┐")
            for category, apis in result.detected_apis.items():
                print(f"│ {category.replace('_', ' ').title()}:")
                for api in apis:
                    print(f"│   • {api}")
            print("└──────────────────────────────────────────────────────────────────────┘")

        if result.registry_indicators:
            print(f"\n┌─ REGISTRY INDICATORS ─────────────────────────────────────────────┐")
            for reg in result.registry_indicators:
                print(f"│ • {reg}")
            print("└──────────────────────────────────────────────────────────────────────┘")

        if result.network_indicators:
            print(f"\n┌─ NETWORK INDICATORS ──────────────────────────────────────────────┐")
            for net in result.network_indicators:
                print(f"│ • {net}")
            print("└──────────────────────────────────────────────────────────────────────┘")

        # Recommendation based on threat level
        print(f"\n┌─ RECOMMENDED ACTIONS ─────────────────────────────────────────────┐")
        if result.threat_score >= 85:
            print("│ 🚨 CRITICAL: Immediate incident response required")
            print("│    1. Isolate affected systems immediately")
            print("│    2. Engage incident response team")
            print("│    3. Begin forensic investigation")
            print("│    4. Contact threat intelligence services")
        elif result.threat_score >= 70:
            print("│ ⚠️  HIGH: Urgent containment needed")
            print("│    1. Isolate affected systems")
            print("│    2. Block network traffic to IOCs")
            print("│    3. Begin forensic analysis")
            print("│    4. Monitor for lateral movement")
        elif result.threat_score >= 40:
            print("│ ℹ️  MEDIUM: Enhanced monitoring recommended")
            print("│    1. Monitor system behavior")
            print("│    2. Review system logs")
            print("│    3. Check for signs of compromise")
            print("│    4. Prepare isolation procedures")
        else:
            print("│ ✅ LOW: Standard security practices sufficient")
            print("│    1. Maintain regular monitoring")
            print("│    2. Keep systems patched")
            print("│    3. Follow standard procedures")
        print("└──────────────────────────────────────────────────────────────────────┘\n")

    def generate_attacker_profile(
        self,
        result,
        api_key: Optional[str] = None
    ) -> Optional[dict]:
        """Generate detailed attacker profile using GPT"""
        
        print(f"\n🤖 Generating attacker profile with GPT...")
        
        profiler = GPTProfiler(api_key=api_key)
        
        profile = profiler.generate_profile(
            threat_score=result.threat_score,
            entropy=result.entropy,
            packages=result.packages,
            controlflow=result.controlflow,
            string_visibility=result.string_visibility,
            code_reuse=result.code_reuse,
            api_suspicion=result.api_suspicion,
            threat_level=result.threat_level
        )
        
        if profile:
            print(f"""
╔════════════════════════════════════════════════════════════════════════╗
║                     ATTACKER PROFILE ANALYSIS                          ║
╚════════════════════════════════════════════════════════════════════════╝

👤 Profile Type:          {profile.profile_type.replace('_', ' ').title()}
📈 Threat Score:          {profile.threat_score:.2f} / 100
💪 Sophistication Level:  {profile.sophistication}

📌 Objectives:
{self._format_text(profile.objectives)}

🎯 Methodologies:
{self._format_text(profile.methodologies)}

🛡️  Defensive Measures:
{self._format_text(profile.defensive_measures)}
""")
            return profile.to_dict()
        else:
            print("⚠️  Could not generate GPT profile. Using local heuristics instead.")
            return result.to_dict()

    @staticmethod
    def _format_text(text: str, width: int = 70, indent: int = 3) -> str:
        """Format text for display"""
        indent_str = " " * indent
        lines = []
        current_line = ""
        
        for word in text.split():
            if len(current_line) + len(word) + 1 > width:
                if current_line:
                    lines.append(indent_str + current_line)
                current_line = word
            else:
                current_line += (" " + word if current_line else word)
        
        if current_line:
            lines.append(indent_str + current_line)
        
        return "\n".join(lines)

    def save_output(
        self,
        result,
        profile: Optional[dict] = None,
        as_json: bool = False
    ) -> str:
        """Save analysis results to file"""
        
        output_data = {
            "analysis": result.to_dict(),
            "attacker_profile": profile
        }
        
        output_file = self.output_dir / f"{result.sample_name}_analysis.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Analysis saved to: {output_file}")
        return str(output_file)


def create_example_samples() -> list:
    """Create example malware samples for demonstration"""
    
    return [
        {
            "name": "ransomware_variant",
            "entropy": 7.6,
            "packages": 22,
            "controlflow": 8.5,
            "string_visibility": 0.12,
            "code_reuse": 0.85,
            "api_suspicion": 92.0,
            "description": "Advanced Ransomware Variant"
        },
        {
            "name": "trojan_stealer",
            "entropy": 6.2,
            "packages": 18,
            "controlflow": 6.8,
            "string_visibility": 0.28,
            "code_reuse": 0.62,
            "api_suspicion": 75.0,
            "description": "Banking Trojan with Stealing Capabilities"
        },
        {
            "name": "benign_software",
            "entropy": 2.5,
            "packages": 5,
            "controlflow": 1.8,
            "string_visibility": 0.89,
            "code_reuse": 0.05,
            "api_suspicion": 10.0,
            "description": "Benign/Legitimate Software"
        }
    ]


def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="Threat Type APT - Advanced Malware Threat Intelligence System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                           # Run with demo samples
  python main.py --json                    # Output as JSON
  python main.py --profile                 # Generate GPT profiles
  python main.py --api-key YOUR_KEY        # Use OpenAI API key
        """
    )
    
    parser.add_argument(
        "--sample",
        type=str,
        default=None,
        help="Specific sample name to analyze"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="Generate detailed attacker profile using GPT"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="OpenAI API key for GPT profiling"
    )
    parser.add_argument(
        "--entropy",
        type=float,
        default=None,
        help="Entropy value (0-8)"
    )
    parser.add_argument(
        "--packages",
        type=int,
        default=None,
        help="Package count"
    )
    
    args = parser.parse_args()
    
    cli = ThreatAnalysisCLI()
    
    # Get samples to analyze
    if args.entropy is not None and args.packages is not None:
        # Custom sample provided via CLI
        samples = [{
            "name": args.sample or "custom_sample",
            "entropy": args.entropy,
            "packages": args.packages,
            "controlflow": 5.0,
            "string_visibility": 0.5,
            "code_reuse": 0.3,
            "api_suspicion": 50.0
        }]
    else:
        # Use example samples
        samples = create_example_samples()
    
    print("""
╔════════════════════════════════════════════════════════════════════════╗
║          Threat Type APT - Malware Threat Intelligence System          ║
║                 Powered by Fuzzy Logic & GPT Analysis                  ║
╚════════════════════════════════════════════════════════════════════════╝
""")
    
    # Analyze samples
    for sample in samples:
        result = cli.analyze_sample(
            sample_name=sample["name"],
            entropy=sample["entropy"],
            packages=sample["packages"],
            controlflow=sample.get("controlflow", 5.0),
            string_visibility=sample.get("string_visibility", 0.5),
            code_reuse=sample.get("code_reuse", 0.3),
            api_suspicion=sample.get("api_suspicion", 50.0)
        )
        
        if result:
            # Display report
            if args.json:
                print(result.to_json())
            else:
                cli.display_threat_report(result)
            
            # Generate profile if requested
            profile = None
            if args.profile:
                profile = cli.generate_attacker_profile(result, api_key=args.api_key)
            
            # Save output
            cli.save_output(result, profile=profile)
            print("-" * 76)


if __name__ == "__main__":
    main()
