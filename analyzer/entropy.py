import math
from typing import Dict, Any, Tuple


def calculate_shannon_entropy(file_path: str) -> float:
    """
    Calculate Shannon entropy of a file.
    Shannon entropy measures the randomness or uncertainty in the data.
    Range: 0.0 (completely predictable) to 8.0 (completely random for bytes).
    
    Formula: H = -sum(p(x) * log2(p(x))) for all possible byte values
    where p(x) is the probability of byte x occurring in the file.
    """
    try:
        # Read file bytes
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Handle empty file
        if len(data) == 0:
            return 0.0
        
        # Count frequency of each byte value (0-255)
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate probability of each byte
        total_bytes = len(data)
        probabilities = [count / total_bytes for count in byte_counts if count > 0]
        
        # Calculate Shannon entropy
        entropy = 0.0
        for p in probabilities:
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
        
    except Exception:
        return 0.0


def classify_entropy(entropy_value: float) -> Tuple[str, str]:
    """
    Classify entropy value into severity category.
    Returns tuple of (category, explanation).
    
    Categories:
    - LOW (0.0 - 3.0): Highly structured data (e.g., text, configuration files)
    - NORMAL (3.0 - 5.0): Typical files (e.g., documents, images)
    - ELEVATED (5.0 - 7.0): Compressed, packed, or partially encrypted data
    - HIGH (7.0 - 8.0): Highly random data (e.g., encrypted, packed executables)
    """
    if entropy_value < 3.0:
        category = 'LOW'
        explanation = 'Highly structured data. Common in text files, configuration files, and source code.'
    elif entropy_value < 5.0:
        category = 'NORMAL'
        explanation = 'Typical file entropy. Common in documents, images, and standard file formats.'
    elif entropy_value < 7.0:
        category = 'ELEVATED'
        explanation = 'Elevated entropy. May indicate compression, packing, or partial encryption. Requires investigation.'
    else:
        category = 'HIGH'
        explanation = 'High entropy. May indicate encryption, heavy packing, or obfuscation. NOT proof of malware - investigate further.'
    
    return category, explanation


def analyze_entropy(file_path: str) -> Dict[str, Any]:
    """
    Perform complete entropy analysis.
    Returns dictionary with entropy value, classification, and explanation.
    """
    # Calculate entropy
    entropy_value = calculate_shannon_entropy(file_path)
    
    # Classify entropy
    category, explanation = classify_entropy(entropy_value)
    
    # Build analysis result
    analysis = {
        'entropy': round(entropy_value, 2),
        'max_entropy': 8.0,
        'category': category,
        'explanation': explanation,
        'note': 'High entropy can indicate compression, packing, encryption, or obfuscation. This is NOT proof of malware and requires further investigation.'
    }
    
    return analysis


def calculate_block_entropy(file_path: str, block_size: int = 4096) -> list:
    """
    Calculate entropy for each block of the file.
    Useful for identifying packed or encrypted sections within files.
    Returns list of entropy values for each block.
    """
    try:
        block_entropies = []
        
        with open(file_path, 'rb') as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                
                # Count frequency of each byte in block
                byte_counts = [0] * 256
                for byte in block:
                    byte_counts[byte] += 1
                
                # Calculate entropy for this block
                total_bytes = len(block)
                if total_bytes == 0:
                    block_entropies.append(0.0)
                    continue
                
                probabilities = [count / total_bytes for count in byte_counts if count > 0]
                entropy = 0.0
                for p in probabilities:
                    if p > 0:
                        entropy -= p * math.log2(p)
                
                block_entropies.append(entropy)
        
        return block_entropies
        
    except Exception:
        return []
