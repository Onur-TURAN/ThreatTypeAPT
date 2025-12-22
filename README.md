# 🛡️ Threat Type APT - Advanced Malware Threat Intelligence System

Entropy'e göre fuzzy logic ve GPT tabanlı saldırgan profili analizi yapan ileri malware tehdit analiz sistemi.

## 📋 Proje Özeti

**Threat Type APT**, statik malware analiz metriklerini kullanarak comprehensive threat assessment yapan bir sistemdir. Fuzzy logic inference, GPT tabanlı profiling ve behavioral analytics'i kombine ederek APT seviyesi tehditleri tespit eder.

### 🎯 Ana Özellikler

- **Fuzzy Logic Inference**: 10+ fuzzy rule ile threat score hesaplaması
- **Behavioral Analysis**: Suspicious API patterns, registry indicators, network signatures
- **Attacker Profiling**: Script kiddie'den APT actor'a kadar profil oluşturma
- **GPT Integration**: Entropy'e göre dinamik prompt'lar ile saldırgan profili analizi
- **Comprehensive Output**: JSON, formatlanmış rapor ve detaylı IoC prediction
- **Modular Architecture**: core, models, profilers alt kütüphaneleri

## 📁 Proje Yapısı

```
ThreatTypeAPT/
├── main.py                          # Ana entry point
├── src/
│   └── utils/
│       ├── __init__.py              # Utils paketi
│       ├── core/                    # Temel fonksiyonlar
│       │   ├── __init__.py
│       │   ├── fuzzy_system.py      # Fuzzy logic (membership functions)
│       │   ├── config.py            # Konfigürasyon ve sabitler
│       │   └── validators.py        # Input validation ve formatting
│       ├── models/                  # Analiz modelleri
│       │   ├── __init__.py
│       │   └── threat_analyzer.py   # Threat analysis engine
│       └── profilers/               # Profil oluşturucular
│           ├── __init__.py
│           └── gpt_profiler.py      # GPT tabanlı profiler
└── data/
    ├── training_data/
    │   └── sample_malware_dataset.json
    └── outputs/                     # Analiz çıktıları
```

## 🚀 Kurulum ve Kullanım

### Gereksinimler

```bash
python >= 3.8
openai >= 0.27.0  # GPT profiling için (opsiyonel)
```

### Temel Kullanım

```bash
# Örnek malware sample'ları ile çalıştır
python main.py

# JSON output olarak
python main.py --json

# GPT ile saldırgan profili oluştur
python main.py --profile --api-key YOUR_OPENAI_KEY

# Özel sample analiz et
python main.py --entropy 7.6 --packages 22 --sample my_malware
```

## 📊 Analiz Parametreleri

| Parametre | Aralık | Açıklama |
|-----------|--------|----------|
| **Entropy** | 0-8 | Kod şifreleme/obfuscation seviyesi |
| **Packages** | 0-1000 | İmport edilen kütüphane sayısı |
| **Control Flow** | 0-10 | Kontrol akışı karmaşıklığı |
| **String Visibility** | 0-1 | String'lerin görünürlüğü (0=gizli) |
| **Code Reuse** | 0-1 | Bilinen malware'e benzerlik |
| **API Suspicion** | 0-100 | Suspicious API kullanımı |

## 🔍 Fuzzy Logic Rules

Sistem 10+ fuzzy rule kullanarak threat score hesaplar:

```
Rule 1: High Entropy → Obfuscation/Packing detected
Rule 2: High API Suspicion → System API abuse
Rule 3: High Code Reuse → Known malware variant
Rule 4: Low String Visibility → Obfuscated strings
Rule 5: Complex Control Flow → Anti-analysis techniques
Rule 6: High Entropy + High API → Critical threat
Rule 7: Code Reuse + Low Visibility → Advanced malware
Rule 8: Control Flow + High API → Sophisticated attack
Rule 9: Many Packages + High Entropy → Complex behavior
Rule 10: Low indicators → Benign software
```

## 👤 Attacker Profiles

Sistem 4 seviye saldırgan profili oluşturur:

### 1. **Script Kiddie** (Threat: 0-40)
- Pre-made tools kullanma
- Minimal obfuscation
- Basit malware variants

### 2. **Amateur Attacker** (Threat: 40-60)
- Temel obfuscation
- Orta seviye kod karmaşıklığı
- Custom tool adaptasyonu

### 3. **Professional Attacker** (Threat: 60-80)
- İleri obfuscation
- Kompleks kontrol akışı
- Custom payloads
- Güçlü anti-analysis

### 4. **APT Actor** (Threat: 80-100)
- Maximum obfuscation
- Sophisticated techniques
- Zero-day exploits
- Multi-stage infections

## 📈 Threat Score Değerlendirmesi

| Score | Level | Recommendation |
|-------|-------|----------------|
| **85-100** | CRITICAL | Incident response başlat |
| **70-84** | HIGH | Sistemleri izole et |
| **40-69** | MEDIUM | Enhanced monitoring |
| **0-39** | LOW | Standart güvenlik |

## 🔐 Çıktı Örneği

```
╔════════════════════════════════════════════════════════════════════════╗
║                   THREAT TYPE APT ANALYSIS REPORT                      ║
╚════════════════════════════════════════════════════════════════════════╝

📋 Sample Information:
   Name: ransomware_variant
   
┌─ THREAT ASSESSMENT ───────────────────────────────────────────────────┐
│ ⚠️  Malware Suspicion Score:    86.41 / 100.00
│ 🎯 Threat Level:               HIGH (Advanced Malware)
│ 📊 Confidence:                 Very High
│ 👤 Attacker Profile:          Professional Attacker
└──────────────────────────────────────────────────────────────────────┘

┌─ BEHAVIORAL INDICATORS ───────────────────────────────────────────────┐
│ ▶ Advanced obfuscation/packing detected
│ ▶ High code reuse - matches known malware patterns
│ ▶ Critical API suspicion - code injection techniques
└──────────────────────────────────────────────────────────────────────┘
```

## 🧬 GPT Profiling

`--profile` flag'i ile GPT API'ı kullanarak detaylı saldırgan profili oluşturulabilir:

```python
# Dinamik prompt'lar entropy'e göre
- **Low Entropy**: Legitimate software VS simple malware
- **Medium Entropy**: Commodity malware, known variants
- **High Entropy**: Professional attacks, APT indicators
- **Very High Entropy**: Nation-state level sophistication
```

## 📊 Data Yönetimi

### Training Data
`data/training_data/` klasörü 10 malware sample'ı içeren dataset sağlar:
- Entropy levels: 3.8 - 7.9
- Threat categories: Script kiddie to APT

### Output
Analiz sonuçları JSON formatında `data/outputs/` klasörüne kaydedilir.

## 🛠️ Modular Architecture

### Core Module (`utils/core/`)
- **fuzzy_system.py**: Membership functions ve inference engine
- **config.py**: Global konfigürasyon ve prompt templates
- **validators.py**: Input validation ve formatting

### Models Module (`utils/models/`)
- **threat_analyzer.py**: Behavioral analysis ve threat assessment

### Profilers Module (`utils/profilers/`)
- **gpt_profiler.py**: GPT integration ve profil oluşturma

## 🔗 API Integration

OpenAI API key'i ayarlama:

```bash
# Environment variable
export OPENAI_API_KEY="your-api-key"

# Veya CLI argument olarak
python main.py --profile --api-key "your-api-key"
```

## 📝 JSON Output Format

```json
{
  "sample_name": "ransomware_variant",
  "threat_score": 86.41,
  "threat_level": "HIGH",
  "entropy": 7.6,
  "packages": 22,
  "api_suspicion": 92.0,
  "attacker_profile": "professional_attacker",
  "behavioral_indicators": [...],
  "detected_apis": {...},
  "registry_indicators": [...],
  "network_indicators": [...],
  "analysis_timestamp": "2025-12-22T13:35:56.768309"
}
```

## 🚨 Advanced Features

### 1. **IoC Prediction**
Malware davranışına göre tahmin edilen:
- Network IoCs (C2 domains, ports)
- File IoCs (paths, extensions)
- Process IoCs (parent-child relationships)
- Registry modifications
- Behavioral signatures

### 2. **Threat Attribution**
- Known malware family matching
- Threat actor attribution
- Campaign association
- Geographic indicators

### 3. **Mitigation Strategy**
- Immediate response steps
- Investigation procedures
- Eradication techniques
- Long-term prevention

## 🎯 Gelecek Geliştirmeler

- [ ] Machine Learning model entegrasyonu
- [ ] YARA rule generation
- [ ] Behavioral graph analysis
- [ ] Threat intelligence feed entegrasyonu
- [ ] Real-time malware monitoring
- [ ] Collaborative threat sharing

## 📄 Lisans

MIT License

## 👨‍💻 Yazarlar

Threat Type APT - Advanced Malware Analysis System

---

**Not**: Bu sistem eğitim ve araştırma amaçlı geliştirilmiştir. Fuzzy logic ve GPT modeli kombinasyonu ile malware tehdidi değerlendirmesi yapılmaktadır.
