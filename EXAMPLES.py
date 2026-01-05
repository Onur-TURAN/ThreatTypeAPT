#!/usr/bin/env python3
"""
Threat Type APT - Usage Examples

Proje kullanım örnekleri.
"""

# EXAMPLE 1: Basic Analysis

from src.utils import ThreatAnalyzer, FormatHelper

def example_basic_analysis():
    """Basit malware analizi"""
    
    analyzer = ThreatAnalyzer()
    
    # Örnek malware sample
    entropy = 7.6
    packages = 22
    controlflow = 8.5
    string_visibility = 0.12
    code_reuse = 0.85
    api_suspicion = 92.0
    
    # Analiz yap
    result = analyzer.analyze(
        sample_name="ransomware_sample",
        entropy=entropy,
        packages=packages,
        controlflow=controlflow,
        string_visibility=string_visibility,
        code_reuse=code_reuse,
        api_suspicion=api_suspicion
    )
    
    # Sonuç
    print(f"Threat Score: {result.threat_score:.2f}/100")
    print(f"Threat Level: {result.threat_level}")
    print(f"Attacker Profile: {result.attacker_profile}")


# EXAMPLE 2: Full Analysis with All Indicators

def example_full_analysis():
    """Tüm behavioral indicators ile analiz"""
    
    analyzer = ThreatAnalyzer()
    
    result = analyzer.analyze(
        sample_name="trojan_stealer",
        entropy=6.2,
        packages=18,
        controlflow=6.8,
        string_visibility=0.28,
        code_reuse=0.62,
        api_suspicion=75.0
    )
    
    # Detailed output
    print("\n=== THREAT ANALYSIS RESULT ===")
    print(f"Sample: {result.sample_name}")
    print(f"Threat Score: {result.threat_score:.2f}/100")
    print(f"Threat Level: {result.threat_level}")
    print(f"Confidence: {result.confidence}")
    print(f"Attacker Profile: {result.attacker_profile}")
    
    print("\n=== BEHAVIORAL INDICATORS ===")
    for indicator in result.behavioral_indicators:
        print(f"  • {indicator}")
    
    print("\n=== DETECTED APIs ===")
    for category, apis in result.detected_apis.items():
        print(f"  {category}:")
        for api in apis:
            print(f"    - {api}")
    
    print("\n=== REGISTRY INDICATORS ===")
    if result.registry_indicators:
        for reg in result.registry_indicators:
            print(f"  • {reg}")
    else:
        print("  (None)")
    
    print("\n=== NETWORK INDICATORS ===")
    if result.network_indicators:
        for net in result.network_indicators:
            print(f"  • {net}")
    else:
        print("  (None)")


# EXAMPLE 3: GPT-Based Attacker Profiling

from src.utils import GPTProfiler

def example_gpt_profiling():
    """GPT ile saldırgan profili oluşturma"""
    
    analyzer = ThreatAnalyzer()
    
    # Malware analizi
    result = analyzer.analyze(
        sample_name="apt_malware",
        entropy=7.8,
        packages=25,
        controlflow=9.0,
        string_visibility=0.08,
        code_reuse=0.92,
        api_suspicion=96.0
    )
    
    # GPT profiler
    profiler = GPTProfiler(api_key="your-api-key-here")
    
    # Profile oluştur
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
        print(f"Profile Type: {profile.profile_type}")
        print(f"Sophistication: {profile.sophistication}")
        print(f"\nObjectives:\n{profile.objectives}")
        print(f"\nMethodologies:\n{profile.methodologies}")
        print(f"\nDefensive Measures:\n{profile.defensive_measures}")


# EXAMPLE 4: Input Validation

from src.utils import InputValidator

def example_input_validation():
    """Input parametrelerinin doğrulanması"""
    
    # Geçerli inputs
    entropy = 7.6
    packages = 22
    controlflow = 8.5
    string_visibility = 0.12
    code_reuse = 0.85
    api_suspicion = 92.0
    
    is_valid, errors = InputValidator.validate_all_inputs(
        entropy=entropy,
        packages=packages,
        controlflow=controlflow,
        string_visibility=string_visibility,
        code_reuse=code_reuse,
        api_suspicion=api_suspicion,
        sample_name="test_sample"
    )
    
    if is_valid:
        print("✅ All inputs are valid!")
    else:
        print("❌ Validation errors:")
        for error in errors:
            print(f"  • {error}")


# EXAMPLE 5: Batch Analysis

def example_batch_analysis():
    """Birden fazla sample'ı toplu olarak analiz etme"""
    
    analyzer = ThreatAnalyzer()
    
    # Birden fazla sample
    samples = [
        {
            "name": "ransomware_a",
            "entropy": 7.6,
            "packages": 22,
            "controlflow": 8.5,
            "string_visibility": 0.12,
            "code_reuse": 0.85,
            "api_suspicion": 92.0
        },
        {
            "name": "trojan_b",
            "entropy": 6.2,
            "packages": 18,
            "controlflow": 6.8,
            "string_visibility": 0.28,
            "code_reuse": 0.62,
            "api_suspicion": 75.0
        },
        {
            "name": "benign_c",
            "entropy": 2.5,
            "packages": 5,
            "controlflow": 1.8,
            "string_visibility": 0.89,
            "code_reuse": 0.05,
            "api_suspicion": 10.0
        }
    ]
    
    results = []
    
    for sample in samples:
        result = analyzer.analyze(
            sample_name=sample["name"],
            entropy=sample["entropy"],
            packages=sample["packages"],
            controlflow=sample["controlflow"],
            string_visibility=sample["string_visibility"],
            code_reuse=sample["code_reuse"],
            api_suspicion=sample["api_suspicion"]
        )
        results.append(result)
    
    # Summary report
    print("\n=== BATCH ANALYSIS SUMMARY ===")
    critical = sum(1 for r in results if r.threat_score >= 85)
    high = sum(1 for r in results if 70 <= r.threat_score < 85)
    medium = sum(1 for r in results if 40 <= r.threat_score < 70)
    low = sum(1 for r in results if r.threat_score < 40)
    
    print(f"Total Samples: {len(results)}")
    print(f"Critical: {critical}")
    print(f"High: {high}")
    print(f"Medium: {medium}")
    print(f"Low: {low}")
    
    print("\nDetailed Results:")
    for result in results:
        print(f"  {result.sample_name}: {result.threat_score:.2f} ({result.threat_level})")


# EXAMPLE 6: Data Normalization

from src.utils import DataNormalizer

def example_data_normalization():
    """Veri normalizasyonu örneği"""
    
    normalizer = DataNormalizer()
    
    # Farklı ölçekten entropy'yi normalize et
    entropy_raw = 6.5  # Max 8 skala
    entropy_norm = normalizer.normalize_entropy(entropy_raw, from_max=8)
    
    print(f"Original Entropy: {entropy_raw}")
    print(f"Normalized Entropy: {entropy_norm:.2f}")
    
    # Visibility normalizasyonu
    visibility_raw = 0.45
    visibility_norm = normalizer.normalize_visibility(visibility_raw)
    
    print(f"\nOriginal Visibility: {visibility_raw}")
    print(f"Normalized Visibility: {visibility_norm:.2f}")


# EXAMPLE 7: Custom JSON Output

import json

def example_json_export():
    """Analiz sonuçlarını JSON'a aktarma"""
    
    analyzer = ThreatAnalyzer()
    
    result = analyzer.analyze(
        sample_name="export_test",
        entropy=7.0,
        packages=20,
        controlflow=7.5,
        string_visibility=0.15,
        code_reuse=0.80,
        api_suspicion=88.0
    )
    
    # To JSON
    json_output = result.to_json()
    
    print("JSON Output:")
    print(json_output)
    
    # Save to file
    with open("output.json", "w") as f:
        f.write(json_output)
    
    print("\n✅ Saved to output.json")


# EXAMPLE 8: Fuzzy Membership Inspection

from src.utils import FuzzyInput

def example_fuzzy_membership():
    """Fuzzy membership values'ı inspect etme"""
    
    entropy = 7.6
    
    # Membership values
    membership = FuzzyInput.entropy_membership(entropy)
    
    print(f"Entropy: {entropy}")
    print(f"Membership Levels:")
    for level, value in membership.items():
        print(f"  {level}: {value:.4f}")
    
    # Interpretation
    highest_level = max(membership, key=membership.get)
    print(f"\nStrongest Membership: {highest_level}")


# EXAMPLE 9: Attacker Profile Inspection

from src.utils import ATTACKER_PROFILES

def example_attacker_profiles():
    """Saldırgan profilleri inceleme"""
    
    for profile_type, profile_data in ATTACKER_PROFILES.items():
        print(f"\n=== {profile_type.upper()} ===")
        print(f"Entropy Range: {profile_data['entropy_range']}")
        print("Characteristics:")
        for char in profile_data['characteristics']:
            print(f"  • {char}")
        print("Techniques:")
        for tech in profile_data['techniques']:
            print(f"  • {tech}")


# EXAMPLE 10: Config Management

from src.utils import GPT_CONFIG, THREAT_THRESHOLDS, ENTROPY_RANGES

def example_config_inspection():
    """Konfigürasyon ayarlarını inceleme"""
    
    print("=== GPT CONFIG ===")
    for key, value in GPT_CONFIG.items():
        if key != "api_key":  # API key'i gösterme
            print(f"{key}: {value}")
    
    print("\n=== THREAT THRESHOLDS ===")
    for level, threshold in THREAT_THRESHOLDS.items():
        print(f"{level}: {threshold}")
    
    print("\n=== ENTROPY RANGES ===")
    for level, range_ in ENTROPY_RANGES.items():
        print(f"{level}: {range_}")


# ============================================================================
# Main function - Run examples
# ============================================================================

if __name__ == "__main__":
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║        Threat Type APT - Usage Examples                       ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    
    # Uncomment to run examples:
    
    print("\n\n1. BASIC ANALYSIS")
    print("-" * 60)
    example_basic_analysis()
    
    print("\n\n2. FULL ANALYSIS WITH INDICATORS")
    print("-" * 60)
    example_full_analysis()
    
    print("\n\n3. INPUT VALIDATION")
    print("-" * 60)
    example_input_validation()
    
    print("\n\n4. BATCH ANALYSIS")
    print("-" * 60)
    example_batch_analysis()
    
    print("\n\n5. DATA NORMALIZATION")
    print("-" * 60)
    example_data_normalization()
    
    print("\n\n6. FUZZY MEMBERSHIP INSPECTION")
    print("-" * 60)
    example_fuzzy_membership()
    
    print("\n\n7. ATTACKER PROFILES")
    print("-" * 60)
    example_attacker_profiles()
    
    print("\n\n8. CONFIG INSPECTION")
    print("-" * 60)
    example_config_inspection()
    
    # GPT Profiling ve JSON export sadece manuel olarak çalıştırılabilir
    # example_gpt_profiling()
    # example_json_export()
