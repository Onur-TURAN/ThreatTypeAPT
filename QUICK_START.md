# 🚀 Threat Type APT - Quick Start Guide

## ⚡ 5-Minute Setup

### 1. Gereksinimler
```bash
python >= 3.8
```

### 2. Projeyi Çalıştır
```bash
cd ThreatTypeAPT
python main.py
```

### 3. Sonuçları Gör
```
╔════════════════════════════════════════════════════════════════════════╗
║                   THREAT TYPE APT ANALYSIS REPORT                      ║
╚════════════════════════════════════════════════════════════════════════╝

📋 Sample Information:
   Name: ransomware_variant
   Analysis Time: 2025-12-22T13:35:56.768309

┌─ THREAT ASSESSMENT ───────────────────────────────────────────────────┐
│ ⚠️  Malware Suspicion Score:    40.83 / 100.00
│ 🎯 Threat Level:               MEDIUM
│ 📊 Confidence:                 Medium
│ 👤 Attacker Profile:          Amateur Attacker
└──────────────────────────────────────────────────────────────────────┘
```

## 📚 Temel Komutlar

### Normal Çalıştırma
```bash
python main.py
```
3 örnek malware'i analiz eder

### JSON Output
```bash
python main.py --json
```
Sonuçları JSON formatında gösterir

### GPT Profiling (Opsiyonel)
```bash
python main.py --profile --api-key "sk-..."
```
OpenAI API ile saldırgan profili oluşturur

### Özel Sample
```bash
python main.py --entropy 7.6 --packages 22
```
Kendi parametrelerinizle analiz yapabilirsiniz

## 📊 Çıktı Dosyaları

Analiz sonuçları otomatik olarak kaydedilir:
```
data/outputs/
├── ransomware_variant_analysis.json
├── trojan_stealer_analysis.json
└── benign_software_analysis.json
```

## 💡 Python Kodda Kullanım

```python
from src.utils import ThreatAnalyzer

# Analyzer oluştur
analyzer = ThreatAnalyzer()

# Malware analiz et
result = analyzer.analyze(
    sample_name="my_malware",
    entropy=7.6,           # 0-8
    packages=22,           # 0-1000
    controlflow=8.5,       # 0-10
    string_visibility=0.12,# 0-1
    code_reuse=0.85,       # 0-1
    api_suspicion=92.0     # 0-100
)

# Sonuçları kullan
print(f"Score: {result.threat_score:.2f}")
print(f"Level: {result.threat_level}")
print(f"Profile: {result.attacker_profile}")
```

## 🎯 Threat Score Seviyesi

| Score | Level | Durum |
|-------|-------|-------|
| 85-100 | CRITICAL | Acil müdahale gerekli |
| 70-84 | HIGH | Sistemleri izole et |
| 40-69 | MEDIUM | Geliştirilmiş izleme |
| 0-39 | LOW | Standart güvenlik |

## 🔧 Modüler Yapı

```
src/utils/
├── core/          # Fuzzy logic, config, validators
├── models/        # Threat analysis engine
└── profilers/     # GPT integration
```

Her modül bağımsız olarak kullanılabilir.

## 🤖 GPT Profiling

OpenAI API key almak için:
1. https://platform.openai.com adresine git
2. API key oluştur
3. `--api-key` argument ile kullan

```bash
python main.py --profile --api-key "sk-your-key-here"
```

## 📖 Daha Fazla Bilgi

- **README.md**: Detaylı proje belgesi
- **PROJECT_STRUCTURE.md**: Mimari ve dosya yapısı
- **EXAMPLES.py**: 10 farklı kullanım örneği

## ❓ Sorun Giderme

### ModuleNotFoundError: No module named 'utils'
```python
# main.py otomatik olarak src/ path'ını ekler
# Eğer direkt Python kodu yazıyorsanız:
import sys
sys.path.insert(0, 'src')
from utils import ThreatAnalyzer
```

### OpenAI API hatası
```bash
# API key'ini environment variable olarak ayarla
export OPENAI_API_KEY="sk-..."
python main.py --profile
```

### JSON parsing hatası
```bash
# Çıktı dosyalarını kontrol et
cat data/outputs/sample_analysis.json
```

## 🎯 Sonraki Adımlar

1. ✅ Projeyiruntime'da çalıştır: `python main.py`
2. ✅ JSON output'ı incele: `python main.py --json`
3. ✅ Özel sample'lar ekle: Modifiye et ve çalıştır
4. ✅ GPT profiling dene: API key ile `--profile` flag'i kullan
5. ✅ EXAMPLES.py'i çalıştır: Daha fazla örnek gör

## 📞 İletişim

Proje hakkında sorularınız varsa, README.md'de daha fazla bilgi bulabilirsiniz.

---

**Hoşgeldiniz! Threat Type APT sisteminizi keşfetmeye başlayın! 🛡️**
