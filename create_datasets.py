"""
Dataset Creation Script - Stream-based CSV Processing
Safely extracts training/test data from large CSV files without loading into memory.

WARNING: DO NOT open large files directly - use streaming only!
- archive/train_features.csv: 5.97 GB
- malware-classification/trainLabels.csv: 271 KB
"""

import csv
import random
import sys
from pathlib import Path

# Increase CSV field size limit for large fields (10 MB should be enough)
csv.field_size_limit(10 * 1024 * 1024)


def stream_archive_data(archive_path, sample_count=5000):
    """
    Stream data from archive/train_features.csv (5.97 GB).
    Memory-safe: reads row-by-row without loading full file.
    
    Args:
        archive_path: Path to train_features.csv
        sample_count: Number of samples to extract (default 5000)
    
    Yields:
        dict: {name, entropy, packages, controlflow, string_visibility, code_reuse, api_suspicion}
    """
    print(f"[STREAM] Opening archive: {archive_path}")
    
    with open(archive_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        # Get column names from first row
        first_row = next(reader)
        columns = list(first_row.keys())
        print(f"[INFO] Archive columns ({len(columns)}): {columns[:10]}...")
        
        # Process first row
        if 'entropy' in first_row:
            yield extract_features_from_archive(first_row)
        
        count = 1
        for row in reader:
            if count >= sample_count:
                break
            
            if 'entropy' in row and row['entropy']:
                yield extract_features_from_archive(row)
                count += 1
            
            if count % 1000 == 0:
                print(f"[PROGRESS] Extracted {count} samples from archive...")
    
    print(f"[DONE] Archive extraction: {count} samples")


def extract_features_from_archive(row):
    """
    Extract relevant features from archive CSV row.
    Maps 49 columns → 7 core features.
    """
    try:
        # Core metrics
        entropy = float(row.get('entropy', 6.5))
        
        # Approximate package/import count from column presence
        packages = sum([
            int(row.get('import_address', 0) or 0) > 0,
            int(row.get('import_section', 0) or 0) > 0,
            int(row.get('import_size', 0) or 0) > 0,
        ]) * 50  # Rough estimate
        
        # Control flow complexity
        sections = int(row.get('number_of_sections', 5) or 5)
        controlflow = min(sections, 10)  # Normalize to 0-10
        
        # String visibility (from characteristics)
        string_visibility = 1.0 if int(row.get('characteristics', 0) or 0) > 0 else 0.5
        
        # Code reuse (from size_code vs size_image)
        size_code = int(row.get('size_code', 1000) or 1000)
        size_image = int(row.get('size_image', 10000) or 10000)
        code_reuse = min(size_code / max(size_image, 1), 1.0)
        
        # API suspicion (from resource characteristics)
        resource_size = int(row.get('resource_size', 0) or 0)
        api_suspicion = min((resource_size / 10000) * 100, 100)
        
        return {
            'name': row.get('name', 'unknown'),
            'entropy': entropy,
            'packages': packages,
            'controlflow': controlflow,
            'string_visibility': string_visibility,
            'code_reuse': code_reuse,
            'api_suspicion': api_suspicion,
            'description': 'extracted_from_archive'
        }
    except Exception as e:
        print(f"[WARNING] Failed to parse row: {e}")
        return None


def stream_malware_labels(labels_path):
    """
    Stream data from malware-classification/trainLabels.csv (271 KB).
    Memory-safe: reads row-by-row.
    
    Yields:
        dict: {name, entropy, packages, controlflow, string_visibility, code_reuse, api_suspicion}
    """
    print(f"[STREAM] Opening labels: {labels_path}")
    
    with open(labels_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        count = 0
        for row in reader:
            # Generate synthetic features based on malware class
            yield generate_features_from_label(row)
            count += 1
            
            if count % 2000 == 0:
                print(f"[PROGRESS] Extracted {count} samples from labels...")
    
    print(f"[DONE] Label extraction: {count} samples")


def generate_features_from_label(row):
    """
    Generate synthetic features from trainLabels.csv.
    Uses malware class (1-9) to create realistic threat metrics.
    """
    try:
        sample_id = row.get('Id', 'unknown')
        malware_class = int(row.get('Class', 5))
        
        # Map malware class to threat characteristics
        # Higher class = more sophisticated malware
        base_entropy = 5.5 + (malware_class * 0.3)
        base_packages = 100 + (malware_class * 50)
        base_api = 50 + (malware_class * 5)
        
        # Add randomness for realism
        return {
            'name': sample_id,
            'entropy': base_entropy + random.uniform(-0.5, 0.5),
            'packages': int(base_packages + random.uniform(-30, 30)),
            'controlflow': random.uniform(3, 8),
            'string_visibility': random.uniform(0.3, 1.0),
            'code_reuse': random.uniform(0.1, 0.8),
            'api_suspicion': base_api + random.uniform(-10, 10),
            'description': f'malware_class_{malware_class}'
        }
    except Exception as e:
        print(f"[WARNING] Failed to parse label row: {e}")
        return None


def write_csv(output_path, samples):
    """
    Write samples to CSV file.
    
    Args:
        output_path: Output CSV file path
        samples: List of sample dicts
    """
    fieldnames = ['name', 'entropy', 'packages', 'controlflow', 
                  'string_visibility', 'code_reuse', 'api_suspicion', 'description']
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(samples)
    
    print(f"[SAVED] {len(samples)} samples → {output_path}")


def main():
    """
    Main execution: Extract from both sources and create train/test split.
    """
    print("\n" + "="*80)
    print("DATASET CREATION - STREAM-BASED PROCESSING")
    print("="*80 + "\n")
    
    # Paths
    base_dir = Path(__file__).parent / 'data'
    archive_csv = base_dir / 'archive' / 'train_features.csv'
    labels_csv = base_dir / 'malware-classification' / 'trainLabels.csv'
    
    train_output = base_dir / 'training_data' / 'train_data.csv'
    test_output = base_dir / 'training_data' / 'test_data.csv'
    
    # Verify files exist
    if not archive_csv.exists():
        print(f"[ERROR] Archive not found: {archive_csv}")
        return
    if not labels_csv.exists():
        print(f"[ERROR] Labels not found: {labels_csv}")
        return
    
    print(f"[SOURCE 1] {archive_csv} ({archive_csv.stat().st_size / 1e9:.2f} GB)")
    print(f"[SOURCE 2] {labels_csv} ({labels_csv.stat().st_size / 1e6:.2f} MB)")
    print()
    
    # Collect all samples (streaming)
    all_samples = []
    
    print("[PHASE 1] Extracting from archive (stream-based)...")
    for sample in stream_archive_data(archive_csv, sample_count=5000):
        if sample:
            all_samples.append(sample)
    
    print(f"\n[PHASE 2] Extracting from malware labels (stream-based)...")
    for sample in stream_malware_labels(labels_csv):
        if sample:
            all_samples.append(sample)
    
    print(f"\n[TOTAL] Collected {len(all_samples)} samples")
    
    # Shuffle for random distribution
    random.seed(42)
    random.shuffle(all_samples)
    
    # Split: 80% train, 20% test
    split_idx = int(len(all_samples) * 0.8)
    train_samples = all_samples[:split_idx]
    test_samples = all_samples[split_idx:]
    
    print(f"\n[SPLIT] Train: {len(train_samples)}, Test: {len(test_samples)}")
    
    # Write outputs
    write_csv(train_output, train_samples)
    write_csv(test_output, test_samples)
    
    print("\n" + "="*80)
    print("✓ DATASET CREATION COMPLETE")
    print("="*80)
    print(f"\nTrain dataset: {train_output}")
    print(f"Test dataset: {test_output}")
    print(f"\nTotal samples: {len(all_samples)}")
    print(f"  - From archive: ~5000")
    print(f"  - From malware-classification: ~{len(all_samples) - 5000}")
    print("\nMemory-safe streaming used - no large file loaded into RAM!")


if __name__ == '__main__':
    main()
