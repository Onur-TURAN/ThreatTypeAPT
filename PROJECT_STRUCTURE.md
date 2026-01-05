# Threat Type APT - Proje Yapısı ve Kullanım Kılavuzu

## Klasör Hiyerarşisi

```
ThreatTypeAPT/
│
├── main.py                          # Ana giriş noktası (sadece utils import eder)
├── README.md                        # Proje belgesi
├── requirements.txt                 # Python bağımlılıkları
│
├── src/                            # Kaynak kod kütüphanesi
│   └── utils/                      # Tüm utils kütüphanesi
│       ├── __init__.py             # utils paketini export eder
│       │
│       ├── core/                   # Temel fonksiyonlar
│       │   ├── __init__.py
│       │   ├── fuzzy_system.py     # Fuzzy logic (250+ satır)
│       │   │   ├── MembershipFunction: Triangular, Trapezoidal, Gaussian
│       │   │   ├── FuzzyInput: 6 input membership level
│       │   │   ├── FuzzyInference: 10+ inference rule
│       │   │   └── ThreatClassifier: Threat level classification
│       │   │
│       │   ├── config.py           # Konfigürasyon (150+ satır)
│       │   │   ├── GPT_CONFIG: OpenAI ayarları
│       │   │   ├── ENTROPY_RANGES: Entropy seviyeleri
│       │   │   ├── SUSPICIOUS_APIS: API kategorileri
│       │   │   ├── ATTACKER_PROFILES: 4 profil tipi
│       │   │   └── GPT_PROMPT_TEMPLATES: Dinamik prompt'lar
│       │   │
│       │   └── validators.py       # Doğrulama ve formatting (150+ satır)
│       │       ├── InputValidator: 6+ validation method
│       │       ├── DataNormalizer: Veri normalizasyonu
│       │       └── FormatHelper: Report formatting
│       │
│       ├── models/                 # 📊 Threat analiz modelleri
│       │   ├── __init__.py
│       │   └── threat_analyzer.py  # Analiz motoru (300+ satır)
│       │       ├── ThreatAnalysisResult: Dataclass
│       │       ├── BehavioralAnalyzer: API detection, behavioral patterns
│       │       ├── AttackerProfiler: Attacker profil belirleme
│       │       └── ThreatAnalyzer: Ana analiz engine
│       │
│       └── profilers/              # GPT-tabanlı profiler
│           ├── __init__.py
│           └── gpt_profiler.py     # GPT entegrasyonu (400+ satır)
│               ├── AttackerProfile: Dataclass
│               ├── PromptGenerator: Dinamik prompt oluşturma
│               └── GPTProfiler: OpenAI API entegrasyon
│
└── data/                           # Data yönetimi
    ├── training_data/              # Training verisi
    │   └── sample_malware_dataset.json
    │       └── 10 malware sample (entropy: 3.8-7.9)
    │
    └── outputs/                    # 📊 Analiz çıktıları
        ├── README.json             # Output formatı açıklama
        ├── ransomware_variant_analysis.json
        ├── trojan_stealer_analysis.json
        └── benign_software_analysis.json
```

## Modüler Yapı Detayları

### Core Module (`utils/core/`)

#### fuzzy_system.py
- **MembershipFunction**: Üç membership function türü
  - `triangular()`: Triangular membership
  - `trapezoidal()`: Trapezoidal membership
  - `gaussian()`: Gaussian membership
  
- **FuzzyInput**: 6 input kategorisi
  - Entropy (Low/Medium/High)
  - Packages (Few/Moderate/Many)
  - Control Flow (Simple/Moderate/Complex)
  - String Visibility (Low/Medium/High)
  - Code Reuse (Low/Medium/High)
  - API Suspicion (Low/Medium/High)

- **FuzzyInference**: 10+ inference kuralı
  - Weighted rule activation
  - Fuzzy conjunction (AND) ve disjunction (OR)
  - Centroid defuzzification

- **ThreatClassifier**: Score → Level mapping
  - CRITICAL (85-100)
  - HIGH (70-84)
  - MEDIUM (40-69)
  - LOW (0-39)

#### config.py
- **GPT_CONFIG**: API ayarları
- **THREAT_THRESHOLDS**: Classification threshold'ları
- **ENTROPY_RANGES**: Entropy seviyeleri
- **SUSPICIOUS_APIS**: 6 API kategorisi
- **ATTACKER_PROFILES**: 4 profil tipi
- **BEHAVIOR_INDICATORS**: Behavioral patterns
- **GPT_PROMPT_TEMPLATES**: 4 prompt template

#### validators.py
- **InputValidator**: Parametre validasyonu
- **DataNormalizer**: Veri normalizasyonu
- **FormatHelper**: Report ve JSON formatting

### Models Module (`utils/models/`)

#### threat_analyzer.py
- **ThreatAnalysisResult**: Dataclass (12 field)
- **BehavioralAnalyzer**:
  - `detect_api_usage()`: API pattern detection
  - `detect_behavioral_indicators()`: Behavior detection
  - `predict_registry_indicators()`: Registry prediction
  - `predict_network_indicators()`: Network pattern prediction

- **AttackerProfiler**:
  - `profile_attacker()`: Profil belirleme
  - `get_profile_description()`: Profil açıklama
  - `estimate_sophistication_level()`: Sophistic level

- **ThreatAnalyzer**:
  - `analyze()`: Comprehensive threat analysis

### Profilers Module (`utils/profilers/`)

#### gpt_profiler.py
- **AttackerProfile**: Result dataclass
- **PromptGenerator**: Dinamik prompt oluşturma
  - `get_entropy_context()`: Entropy seviyesi açıklaması
  - `generate_attacker_profile_prompt()`: Profile prompt
  - `generate_ioc_prompt()`: IoC prediction prompt
  - `generate_attribution_prompt()`: Attribution prompt
  - `generate_mitigation_prompt()`: Mitigation prompt

- **GPTProfiler**: GPT entegrasyonu
  - `generate_profile()`: Profile generation (with fallback)
  - `_generate_local_profile()`: Fallback heuristic profiling
  - `_determine_profile_type()`: Profile type belirleme
  - `_generate_objectives()`: Objectives creation
  - `_generate_methodologies()`: Methodology creation
  - `_generate_defensive_measures()`: Defense recommendations

## main.py Yapısı

```python
main.py
├── ThreatAnalysisCLI sınıfı
│   ├── analyze_sample()        # Sample analizi
│   ├── display_threat_report() # Rapor gösterimi
│   ├── generate_attacker_profile() # GPT profiling
│   └── save_output()           # Çıktı kaydetme
│
├── create_example_samples()    # 3 örnek sample
└── main() ile argparse CLI    # Command-line interface
    ├── --sample: Özel sample
    ├── --json: JSON output
    ├── --profile: GPT profiling
    ├── --api-key: OpenAI key
    ├── --entropy: Custom entropy
    └── --packages: Custom packages
```

## Veri Akışı

```
Input Parametreler
    ↓
InputValidator (doğrulama)
    ↓
ThreatAnalyzer.analyze()
    ├─→ FuzzyInference.evaluate_threat()
    │   ├─→ FuzzyInput.membership_functions()
    │   ├─→ 10+ Fuzzy rules
    │   └─→ Threat score (0-100)
    │
    ├─→ ThreatClassifier.classify()
    │   └─→ Threat level + Confidence
    │
    ├─→ BehavioralAnalyzer
    │   ├─→ detect_api_usage()
    │   ├─→ detect_behavioral_indicators()
    │   ├─→ predict_registry_indicators()
    │   └─→ predict_network_indicators()
    │
    ├─→ AttackerProfiler.profile_attacker()
    │   └─→ Profile type (4 seviye)
    │
    └─→ ThreatAnalysisResult (dataclass)
        
    ↓
    GPTProfiler.generate_profile() [OPTIONAL]
    ├─→ PromptGenerator (entropy'e göre)
    └─→ OpenAI API / Local fallback
        
    ↓
Output
├─→ Console report (formatted)
├─→ JSON file (data/outputs/)
└─→ GPT profile [OPTIONAL]
```

## Import Hiyerarşisi

```
main.py (entry point)
    ↓
sys.path: src/ klasörü eklenir
    ↓
from utils import (...)
    ↓
utils/__init__.py
├─→ from .core import (...)
├─→ from .models import (...)
└─→ from .profilers import (...)
    
    ↓
    
core/__init__.py
├─→ fuzzy_system
├─→ config
└─→ validators

models/__init__.py
└─→ threat_analyzer

profilers/__init__.py
└─→ gpt_profiler
```

## Data Formatı

### Input Parameters
```python
{
    "sample_name": "malware_name",
    "entropy": 7.6,           # 0-8
    "packages": 22,            # 0-1000
    "controlflow": 8.5,        # 0-10
    "string_visibility": 0.12, # 0-1
    "code_reuse": 0.85,        # 0-1
    "api_suspicion": 92.0      # 0-100
}
```

### Output JSON
```json
{
    "analysis": {
        "threat_score": 40.83,
        "threat_level": "MEDIUM",
        "attacker_profile": "amateur_attacker",
        "behavioral_indicators": [...],
        "detected_apis": {...},
        "registry_indicators": [...],
        "network_indicators": [...]
    },
    "attacker_profile": {
        "profile_type": "amateur_attacker",
        "sophistication": "Intermediate",
        "objectives": "...",
        "methodologies": "...",
        "defensive_measures": "..."
    }
}
```

## Kullanım Örnekleri

### 1. Temel Kullanım
```bash
python main.py
```
3 örnek malware sample'ı analiz eder

### 2. JSON Output
```bash
python main.py --json
```
Analiz sonuçlarını JSON formatında gösterir

### 3. GPT Profiling
```bash
python main.py --profile --api-key "sk-..."
```
Detaylı saldırgan profili GPT ile oluşturur

### 4. Özel Sample
```bash
python main.py --entropy 7.6 --packages 22 --sample my_malware
```
Özel parametreler ile analiz

## Bağımlılıklar

- **Core**: Python 3.8+ (built-in libraries only)
- **Optional**: openai >= 0.27.0 (GPT profiling için)

## Proje Özellikleri (Detaylandırma)

1. **Fuzzy Logic**: 10+ rules, 3 membership function types
2. **Modular Code**: 3 sub-packages (core, models, profilers)
3. **6 Input Metrics**: Comprehensive binary analysis
4. **4 Attacker Profiles**: Script kiddie to APT actor
5. **API Detection**: 6 suspicious API categories
6. **Behavioral Analysis**: Registry, network, process indicators
7. **GPT Integration**: OpenAI API with fallback
8. **Dynamic Prompts**: Entropy-based prompt generation
9. **Data Management**: Training data ve output directories
10. **Comprehensive Output**: Console reports, JSON, GPT profiles

---

Not: Proje üretim ortamına uygun olacak şekilde modüler tasarlandı.
