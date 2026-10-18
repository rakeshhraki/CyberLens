import re
from typing import List, Dict, Set, Any


def extract_ascii_strings(file_path: str, min_length: int = 4) -> List[str]:
    """
    Extract ASCII strings from a file.
    Reads file bytes and finds sequences of printable ASCII characters.
    """
    strings = []
    current_string = ""
    
    try:
        with open(file_path, 'rb') as f:
            while True:
                byte = f.read(1)
                if not byte:
                    break
                
                # Check if byte is printable ASCII (32-126)
                char_code = ord(byte)
                if 32 <= char_code <= 126:
                    current_string += chr(char_code)
                else:
                    # End of string
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""
            
            # Don't forget the last string if file ends with printable chars
            if len(current_string) >= min_length:
                strings.append(current_string)
                
    except Exception:
        return []
    
    return strings


def extract_unicode_strings(file_path: str, min_length: int = 4) -> List[str]:
    """
    Extract basic Unicode strings from a file.
    Reads UTF-16 encoded strings (common in Windows executables).
    """
    strings = []
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
            # Try to decode as UTF-16LE
            try:
                decoded = data.decode('utf-16le', errors='ignore')
                # Extract printable strings
                current_string = ""
                for char in decoded:
                    if char.isprintable() and ord(char) < 128:
                        current_string += char
                    else:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ""
                
                if len(current_string) >= min_length:
                    strings.append(current_string)
                    
            except Exception:
                pass
                
    except Exception:
        return []
    
    return strings


def extract_all_strings(file_path: str, min_length: int = 4) -> List[str]:
    """
    Extract all strings (ASCII and Unicode) from a file.
    Returns combined list with duplicates removed.
    """
    ascii_strings = extract_ascii_strings(file_path, min_length)
    unicode_strings = extract_unicode_strings(file_path, min_length)
    
    # Combine and remove duplicates while preserving order
    all_strings = []
    seen = set()
    
    for s in ascii_strings + unicode_strings:
        if s not in seen:
            all_strings.append(s)
            seen.add(s)
    
    return all_strings


def categorize_suspicious_strings(strings: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Categorize strings into suspicious categories.
    Returns dictionary with categories and matching strings with evidence.
    """
    categories = {
        'NETWORK': [],
        'EXECUTION': [],
        'PERSISTENCE': [],
        'CREDENTIAL': [],
        'DOWNLOAD': [],
        'UPLOAD': [],
        'SCRIPTING': []
    }
    
    # Network indicators
    network_patterns = [
        r'https?://[^\s]+',
        r'ftp://[^\s]+',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        r'smb://[^\s]+',
        r'\\\\[^\s]+\\[^\s]+'  # UNC paths
    ]
    
    # Execution indicators
    execution_patterns = [
        r'powershell\.exe',
        r'cmd\.exe',
        r'wscript\.exe',
        r'cscript\.exe',
        r'mshta\.exe',
        r'rundll32\.exe',
        r'regsvr32\.exe',
        r'svchost\.exe'
    ]
    
    # Persistence indicators
    persistence_patterns = [
        r'startup',
        r'runonce',
        r'autorun',
        r'services',
        r'scheduled\s*task',
        r'registry\s*key',
        r'hkey_local_machine',
        r'hkey_current_user'
    ]
    
    # Credential indicators
    credential_patterns = [
        r'password',
        r'credential',
        r'token',
        r'login',
        r'username',
        r'passwd',
        r'auth',
        r'secret',
        r'api[_-]?key'
    ]
    
    # Download indicators
    download_patterns = [
        r'download',
        r'urldownloadtofile',
        r'wget',
        r'curl',
        r'fetch',
        r'get[-_]?request'
    ]
    
    # Upload indicators
    upload_patterns = [
        r'upload',
        r'ftp\s*upload',
        r'sftp',
        r'post\s*file',
        r'send[-_]?file'
    ]
    
    # Scripting indicators
    scripting_patterns = [
        r'vbscript',
        r'jscript',
        r'javascript',
        r'eval\s*\(',
        r'exec\s*\(',
        r'system\s*\(',
        r'shell[_-]?exec'
    ]
    
    # Compile all patterns
    pattern_map = {
        'NETWORK': [re.compile(p, re.IGNORECASE) for p in network_patterns],
        'EXECUTION': [re.compile(p, re.IGNORECASE) for p in execution_patterns],
        'PERSISTENCE': [re.compile(p, re.IGNORECASE) for p in persistence_patterns],
        'CREDENTIAL': [re.compile(p, re.IGNORECASE) for p in credential_patterns],
        'DOWNLOAD': [re.compile(p, re.IGNORECASE) for p in download_patterns],
        'UPLOAD': [re.compile(p, re.IGNORECASE) for p in upload_patterns],
        'SCRIPTING': [re.compile(p, re.IGNORECASE) for p in scripting_patterns]
    }
    
    # Categorize each string
    for string in strings:
        for category, patterns in pattern_map.items():
            for pattern in patterns:
                if pattern.search(string):
                    categories[category].append({
                        'string': string,
                        'pattern': pattern.pattern,
                        'match': pattern.search(string).group()
                    })
                    break  # Only add to first matching category
    
    return categories


def search_strings(strings: List[str], query: str) -> List[str]:
    """
    Search strings for a query.
    Case-insensitive search.
    """
    query_lower = query.lower()
    return [s for s in strings if query_lower in s.lower()]


def analyze_strings(file_path: str, min_length: int = 4) -> Dict[str, Any]:
    """
    Perform complete string analysis.
    Returns total strings, suspicious categories, and search capability.
    """
    # Extract all strings
    all_strings = extract_all_strings(file_path, min_length)
    
    # Categorize suspicious strings
    suspicious = categorize_suspicious_strings(all_strings)
    
    # Build analysis result
    analysis = {
        'total_strings': len(all_strings),
        'min_length': min_length,
        'strings_sample': all_strings[:100],  # First 100 strings for preview
        'suspicious_categories': suspicious,
        'suspicious_count': sum(len(v) for v in suspicious.values())
    }
    
    return analysis
