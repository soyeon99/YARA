import json
import os
import glob
from datetime import datetime

class BatchYaraGenerator:
    def __init__(self):
        self.rules = []
        self.all_strings = []
    
    def extract_meaningful_strings(self, strings_list, limit=5):
        """의미있는 문자열 추출 (개별 파일당)"""
        meaningful = []
        
        for s in strings_list:
            if 4 <= len(s) <= 80:
                # 의미있는 패턴들
                if any(pattern in s.lower() for pattern in [
                    'http', 'www.', '.exe', '.dll', '.bat', '.js', '.zip',
                    'temp', 'system', 'windows', 'program', 'user',
                    'hkey', 'software', 'registry', 'appdata'
                ]) or len([c for c in s if c.isalnum()]) / len(s) > 0.6:
                    meaningful.append(s)
        
        return meaningful[:limit]  # 상위 5개만
    
    def generate_single_rule(self, json_data, file_name):
        """개별 JSON에서 YARA 룰 생성"""
        target_file = json_data.get('target', {}).get('file', {})
        
        # 기본 정보 추출
        file_hash = target_file.get('sha256', 'unknown')
        file_type = target_file.get('type', 'unknown')
        strings_list = target_file.get('strings', [])
        file_size = target_file.get('size', 0)
        
        # 의미있는 문자열 추출
        meaningful_strings = self.extract_meaningful_strings(strings_list)
        
        # 룰 이름 생성 (파일명 기반)
        rule_name = f"CAPE_{file_name.replace('.json', '').replace('-', '_')}"
        
        yara_rule = f'''rule {rule_name}
{{
    meta:
        description = "Auto-generated from CAPE: {file_name}"
        hash = "{file_hash}"
        filetype = "{file_type}"
        filesize = {file_size}
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        
    strings:
        $hash = "{file_hash}"
'''
        
        # 문자열 추가
        for i, string in enumerate(meaningful_strings):
            escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')
            yara_rule += f'        $s{i} = "{escaped_string}"\n'
        
        yara_rule += '''        
    condition:
        $hash or 2 of ($s*)
}'''
        
        return yara_rule
    
    def process_all_jsons(self, folder_path="./cape_reports"):
        """폴더 내 모든 JSON 파일 처리"""
        json_files = glob.glob(f"{folder_path}/*.json")
        
        print(f"총 {len(json_files)}개 JSON 파일 발견")
        
        for json_file in json_files:
            file_name = os.path.basename(json_file)
            print(f"처리중: {file_name}")
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    cape_data = json.load(f)
                
                # 룰 생성
                rule = self.generate_single_rule(cape_data, file_name)
                self.rules.append(rule)
                
                print(f"✅ {file_name} 처리 완료")
                
            except Exception as e:
                print(f"❌ {file_name} 처리 실패: {e}")
        
        return self.rules
    
    def save_all_rules(self, output_file="malware_detection.yar"):
        """모든 룰을 하나의 .yar 파일로 저장"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"// Auto-generated YARA rules from CAPE analysis\n")
            f.write(f"// Generated on: {datetime.now()}\n")
            f.write(f"// Total rules: {len(self.rules)}\n\n")
            
            for rule in self.rules:
                f.write(rule + "\n\n")
        
        print(f"🎉 {len(self.rules)}개 룰이 {output_file}에 저장되었습니다!")

# 실행
if __name__ == "__main__":
    generator = BatchYaraGenerator()
    
    # cape_reports 폴더의 모든 JSON 처리
    rules = generator.process_all_jsons("./cape_reports")
    
    print(f"\n📊 처리 결과:")
    print(f"- 총 {len(rules)}개 YARA 룰 생성")
    
    # .yar 파일로 저장
    generator.save_all_rules("cape_malware_rules.yar")