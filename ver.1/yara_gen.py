import json
import re
from datetime import datetime

class YaraGenerator:
    def __init__(self):
        pass
    
    # 1단계: strings에서 의미있는 패턴 추출
    def extract_meaningful_strings(self, strings_list):
        """strings 리스트에서 YARA 룰에 사용할 의미있는 문자열 추출"""
        meaningful = []
        
        for s in strings_list:
            # 길이 필터 (너무 짧거나 긴 것 제외)
            if 4 <= len(s) <= 50:
                # 의미있는 패턴 확인
                if self.is_meaningful_string(s):
                    meaningful.append(s)
        
        return meaningful[:10]  # 상위 10개만
    
    def is_meaningful_string(self, s):
        """의미있는 문자열인지 판별"""
        # URL, 파일 확장자, 경로 등
        indicators = ['.exe', '.dll', '.com', 'http', 'www', '\\\\', 'HKEY', 'temp', 'system']
        
        for indicator in indicators:
            if indicator.lower() in s.lower():
                return True
                
        # 특수한 패턴 (길이가 적당하고 영숫자가 섞인)
        if re.match(r'^[a-zA-Z0-9+/=]{6,}$', s):
            return True
            
        return False
    
    # 2단계: YARA 룰 생성
    def generate_yara_rule(self, json_data):
        """CAPE JSON에서 YARA 룰 생성"""
        target_file = json_data.get('target', {}).get('file', {})
        
        strings_list = target_file.get('strings', [])
        file_hash = target_file.get('sha256', 'unknown')
        file_type = target_file.get('type', 'unknown')
        
        # 의미있는 문자열 추출
        meaningful_strings = self.extract_meaningful_strings(strings_list)
        
        # YARA 룰 생성
        yara_rule = f'''rule CAPE_Generated_{file_hash[:8]}
{{
    meta:
        description = "Auto-generated from CAPE analysis"
        hash = "{file_hash}"
        filetype = "{file_type}"
        strings_count = {len(strings_list)}
        
    strings:
'''
        
        # 문자열 추가
        for i, string in enumerate(meaningful_strings):
            escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')
            yara_rule += f'        $s{i} = "{escaped_string}"\n'
        
        yara_rule += f'''        
    condition:
        {max(1, len(meaningful_strings)//3)} of them
}}'''
        
        return yara_rule

# 실행 부분
if __name__ == "__main__":
    generator = YaraGenerator()
    
    with open('9_report.json', 'r') as f:
        cape_data = json.load(f)
    
    print("1단계: JSON 로드 완료")
    
    strings_list = cape_data['target']['file']['strings']
    print(f"2단계: strings 추출 완료 (총 {len(strings_list)}개)")
    print(f"처음 10개: {strings_list[:10]}")
    
    yara_rule = generator.generate_yara_rule(cape_data)
    print("\n3단계: YARA 룰 생성 완료")
    print("="*50)
    print(yara_rule)