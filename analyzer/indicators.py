from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Indicator:
    """Represents a security indicator with evidence and score."""
    id: str
    name: str
    category: str
    severity: str
    description: str
    evidence: str
    score: int


class IndicatorEngine:
    """
    Modular indicator detection engine.
    Detects suspicious indicators from file analysis results.
    """
    
    def __init__(self):
        self.indicators = self._initialize_indicators()
    
    def _initialize_indicators(self) -> List[Indicator]:
        """
        Initialize all indicators.
        Each indicator represents a suspicious characteristic.
        """
        indicators = [
            # File Type Indicators
            Indicator(
                id='IND-001',
                name='Executable File',
                category='FILE_TYPE',
                severity='LOW',
                description='File is an executable type (EXE, DLL, etc.)',
                evidence='Executable file detected',
                score=5
            ),
            
            # Filename Indicators
            Indicator(
                id='IND-002',
                name='Double Extension',
                category='FILENAME',
                severity='MEDIUM',
                description='Filename contains double extension (e.g., invoice.pdf.exe)',
                evidence='Double extension detected in filename',
                score=15
            ),
            
            # Network Indicators
            Indicator(
                id='IND-003',
                name='Network URL',
                category='NETWORK',
                severity='LOW',
                description='File contains network URL (http, https, ftp)',
                evidence='Network URL found in strings',
                score=8
            ),
            Indicator(
                id='IND-004',
                name='IP Address',
                category='NETWORK',
                severity='LOW',
                description='File contains IP address',
                evidence='IP address found in strings',
                score=6
            ),
            
            # Execution Indicators
            Indicator(
                id='IND-005',
                name='PowerShell Reference',
                category='EXECUTION',
                severity='MEDIUM',
                description='File references PowerShell (powershell.exe)',
                evidence='powershell.exe found in strings',
                score=12
            ),
            Indicator(
                id='IND-006',
                name='CMD Reference',
                category='EXECUTION',
                severity='MEDIUM',
                description='File references Command Prompt (cmd.exe)',
                evidence='cmd.exe found in strings',
                score=10
            ),
            Indicator(
                id='IND-007',
                name='Script Interpreter',
                category='EXECUTION',
                severity='MEDIUM',
                description='File references script interpreter (wscript, cscript, mshta)',
                evidence='Script interpreter found in strings',
                score=10
            ),
            
            # Persistence Indicators
            Indicator(
                id='IND-008',
                name='Startup Reference',
                category='PERSISTENCE',
                severity='LOW',
                description='File contains startup-related keywords',
                evidence='Startup keyword found in strings',
                score=5
            ),
            Indicator(
                id='IND-009',
                name='Registry Reference',
                category='PERSISTENCE',
                severity='LOW',
                description='File contains registry-related keywords',
                evidence='Registry keyword found in strings',
                score=5
            ),
            
            # Credential Indicators
            Indicator(
                id='IND-010',
                name='Credential Keyword',
                category='CREDENTIAL',
                severity='MEDIUM',
                description='File contains credential-related keywords (password, token, etc.)',
                evidence='Credential keyword found in strings',
                score=10
            ),
            
            # Download Indicators
            Indicator(
                id='IND-011',
                name='Download Keyword',
                category='DOWNLOAD',
                severity='LOW',
                description='File contains download-related keywords',
                evidence='Download keyword found in strings',
                score=6
            ),
            
            # Entropy Indicators
            Indicator(
                id='IND-012',
                name='High Entropy',
                category='ENTROPY',
                severity='MEDIUM',
                description='File has high entropy (>7.0), may indicate encryption or packing',
                evidence='High entropy detected',
                score=10
            ),
            Indicator(
                id='IND-013',
                name='Elevated Entropy',
                category='ENTROPY',
                severity='LOW',
                description='File has elevated entropy (>5.0), may indicate compression',
                evidence='Elevated entropy detected',
                score=5
            ),
            
            # PE Section Indicators
            Indicator(
                id='IND-014',
                name='Writable Executable Section',
                category='PE_SECTION',
                severity='MEDIUM',
                description='PE file has writable + executable section (suspicious)',
                evidence='Writable+executable section detected',
                score=15
            ),
            Indicator(
                id='IND-015',
                name='High Entropy Section',
                category='PE_SECTION',
                severity='MEDIUM',
                description='PE file has high entropy section (>6.0)',
                evidence='High entropy section detected',
                score=10
            ),
            Indicator(
                id='IND-016',
                name='Suspicious Section Name',
                category='PE_SECTION',
                severity='LOW',
                description='PE file has non-standard section name',
                evidence='Suspicious section name detected',
                score=5
            ),
            
            # PE API Indicators
            Indicator(
                id='IND-017',
                name='Suspicious API: VirtualAlloc',
                category='PE_API',
                severity='MEDIUM',
                description='PE file imports VirtualAlloc (memory allocation)',
                evidence='VirtualAlloc API found in imports',
                score=15
            ),
            Indicator(
                id='IND-018',
                name='Suspicious API: VirtualProtect',
                category='PE_API',
                severity='MEDIUM',
                description='PE file imports VirtualProtect (memory protection modification)',
                evidence='VirtualProtect API found in imports',
                score=15
            ),
            Indicator(
                id='IND-019',
                name='Suspicious API: CreateRemoteThread',
                category='PE_API',
                severity='HIGH',
                description='PE file imports CreateRemoteThread (process injection)',
                evidence='CreateRemoteThread API found in imports',
                score=20
            ),
            Indicator(
                id='IND-020',
                name='Suspicious API: WriteProcessMemory',
                category='PE_API',
                severity='HIGH',
                description='PE file imports WriteProcessMemory (process memory modification)',
                evidence='WriteProcessMemory API found in imports',
                score=20
            ),
            Indicator(
                id='IND-021',
                name='Suspicious API: WinExec',
                category='PE_API',
                severity='MEDIUM',
                description='PE file imports WinExec (command execution)',
                evidence='WinExec API found in imports',
                score=15
            ),
            Indicator(
                id='IND-022',
                name='Suspicious API: ShellExecute',
                category='PE_API',
                severity='MEDIUM',
                description='PE file imports ShellExecute (command execution)',
                evidence='ShellExecute API found in imports',
                score=15
            ),
            Indicator(
                id='IND-023',
                name='Suspicious API: URLDownloadToFile',
                category='PE_API',
                severity='HIGH',
                description='PE file imports URLDownloadToFile (file download)',
                evidence='URLDownloadToFile API found in imports',
                score=20
            ),
        ]
        
        return indicators
    
    def detect_indicators(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect indicators from file analysis data.
        Returns list of detected indicators with their evidence.
        """
        detected = []
        
        # Check file type indicators
        if analysis_data.get('identification', {}).get('is_executable'):
            self._add_indicator(detected, 'IND-001', analysis_data['identification']['extension'])
        
        # Check filename indicators
        if analysis_data.get('identification', {}).get('has_double_extension'):
            self._add_indicator(detected, 'IND-002', analysis_data['identification']['filename'])
        
        # Check string analysis indicators
        strings = analysis_data.get('strings', {})
        if strings:
            # Network indicators
            network_count = len(strings.get('suspicious_categories', {}).get('NETWORK', []))
            if network_count > 0:
                for network_ind in strings['suspicious_categories']['NETWORK']:
                    detected.append({
                        'id': 'IND-003',
                        'name': 'Network URL',
                        'category': 'NETWORK',
                        'severity': 'LOW',
                        'description': 'File contains network URL (http, https, ftp)',
                        'evidence': network_ind['match'],
                        'score': 8
                    })
            
            # Execution indicators
            execution_count = len(strings.get('suspicious_categories', {}).get('EXECUTION', []))
            if execution_count > 0:
                for exec_ind in strings['suspicious_categories']['EXECUTION']:
                    if 'powershell' in exec_ind['match'].lower():
                        self._add_indicator(detected, 'IND-005', exec_ind['match'])
                    elif 'cmd' in exec_ind['match'].lower():
                        self._add_indicator(detected, 'IND-006', exec_ind['match'])
                    else:
                        detected.append({
                            'id': 'IND-007',
                            'name': 'Script Interpreter',
                            'category': 'EXECUTION',
                            'severity': 'MEDIUM',
                            'description': 'File references script interpreter',
                            'evidence': exec_ind['match'],
                            'score': 10
                        })
            
            # Persistence indicators
            persistence_count = len(strings.get('suspicious_categories', {}).get('PERSISTENCE', []))
            if persistence_count > 0:
                for pers_ind in strings['suspicious_categories']['PERSISTENCE']:
                    if 'startup' in pers_ind['match'].lower() or 'runonce' in pers_ind['match'].lower():
                        self._add_indicator(detected, 'IND-008', pers_ind['match'])
                    elif 'registry' in pers_ind['match'].lower():
                        self._add_indicator(detected, 'IND-009', pers_ind['match'])
            
            # Credential indicators
            credential_count = len(strings.get('suspicious_categories', {}).get('CREDENTIAL', []))
            if credential_count > 0:
                for cred_ind in strings['suspicious_categories']['CREDENTIAL']:
                    self._add_indicator(detected, 'IND-010', cred_ind['match'])
            
            # Download indicators
            download_count = len(strings.get('suspicious_categories', {}).get('DOWNLOAD', []))
            if download_count > 0:
                for dl_ind in strings['suspicious_categories']['DOWNLOAD']:
                    self._add_indicator(detected, 'IND-011', dl_ind['match'])
        
        # Check entropy indicators
        entropy = analysis_data.get('entropy', {})
        if entropy:
            entropy_value = entropy.get('entropy', 0)
            if entropy_value >= 7.0:
                self._add_indicator(detected, 'IND-012', f'Entropy: {entropy_value}')
            elif entropy_value >= 5.0:
                self._add_indicator(detected, 'IND-013', f'Entropy: {entropy_value}')
        
        # Check PE analysis indicators
        pe_analysis = analysis_data.get('pe_analysis', {})
        if pe_analysis and pe_analysis.get('is_pe'):
            # Section indicators
            section_analysis = pe_analysis.get('section_analysis', {})
            if section_analysis:
                if section_analysis.get('writable_executable_sections'):
                    self._add_indicator(detected, 'IND-014', ', '.join(section_analysis['writable_executable_sections']))
                
                if section_analysis.get('high_entropy_sections'):
                    for section in section_analysis['high_entropy_sections']:
                        detected.append({
                            'id': 'IND-015',
                            'name': 'High Entropy Section',
                            'category': 'PE_SECTION',
                            'severity': 'MEDIUM',
                            'description': 'PE file has high entropy section (>6.0)',
                            'evidence': f"Section {section['name']} with entropy {section['entropy']}",
                            'score': 10
                        })
                
                if section_analysis.get('suspicious_section_names'):
                    for name in section_analysis['suspicious_section_names']:
                        detected.append({
                            'id': 'IND-016',
                            'name': 'Suspicious Section Name',
                            'category': 'PE_SECTION',
                            'severity': 'LOW',
                            'description': 'PE file has non-standard section name',
                            'evidence': f"Section name: {name}",
                            'score': 5
                        })
            
            # API indicators
            suspicious_apis = pe_analysis.get('suspicious_apis', [])
            api_map = {
                'VirtualAlloc': 'IND-017',
                'VirtualProtect': 'IND-018',
                'CreateRemoteThread': 'IND-019',
                'WriteProcessMemory': 'IND-020',
                'WinExec': 'IND-021',
                'ShellExecute': 'IND-022',
                'URLDownloadToFile': 'IND-023'
            }
            
            for api_info in suspicious_apis:
                api_name = api_info.get('api', '')
                if api_name in api_map:
                    indicator_id = api_map[api_name]
                    self._add_indicator(detected, indicator_id, f"{api_name} from {api_info.get('dll', 'unknown')}")
        
        return detected
    
    def _add_indicator(self, detected: List[Dict[str, Any]], indicator_id: str, evidence: str):
        """Add an indicator to the detected list."""
        indicator = next((ind for ind in self.indicators if ind.id == indicator_id), None)
        if indicator:
            detected.append({
                'id': indicator.id,
                'name': indicator.name,
                'category': indicator.category,
                'severity': indicator.severity,
                'description': indicator.description,
                'evidence': evidence,
                'score': indicator.score
            })
    
    def calculate_total_score(self, detected_indicators: List[Dict[str, Any]]) -> int:
        """
        Calculate total risk score from detected indicators.
        Sum of all indicator scores.
        """
        return sum(ind['score'] for ind in detected_indicators)
    
    def get_indicators_by_category(self, detected_indicators: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group detected indicators by category.
        """
        categories = {}
        for ind in detected_indicators:
            category = ind['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(ind)
        return categories
    
    def get_indicators_by_severity(self, detected_indicators: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group detected indicators by severity.
        """
        severities = {}
        for ind in detected_indicators:
            severity = ind['severity']
            if severity not in severities:
                severities[severity] = []
            severities[severity].append(ind)
        return severities


def detect_all_indicators(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform complete indicator detection.
    Returns dictionary with detected indicators, total score, and categorization.
    """
    engine = IndicatorEngine()
    detected = engine.detect_indicators(analysis_data)
    total_score = engine.calculate_total_score(detected)
    by_category = engine.get_indicators_by_category(detected)
    by_severity = engine.get_indicators_by_severity(detected)
    
    return {
        'detected_indicators': detected,
        'total_score': total_score,
        'indicator_count': len(detected),
        'by_category': by_category,
        'by_severity': by_severity
    }
