# yara_parser.py 파일 생성
import re
import json
from datetime import datetime

class SimpleYaraParser:
    def parse_yara_content(self, content):
        """YARA 룰 파싱 - 정규식 기반"""
        rules = []
        
        # rule 단위로 분리
        rule_pattern = r'rule\s+(\w+)\s*\{(.*?)\n\}'
        matches = re.finditer(rule_pattern, content, re.DOTALL)
        
        for match in matches:
            rule_name = match.group(1)
            rule_body = match.group(2)
            
            parsed_rule = {
                'id': len(rules) + 1,
                'rule_name': rule_name,
                'author': self._extract_meta_field(rule_body, 'author'),
                'description': self._extract_meta_field(rule_body, 'description'),
                'date': self._extract_meta_field(rule_body, 'date'),
                'reference': self._extract_meta_field(rule_body, 'reference'),
                'strings_count': self._count_strings(rule_body),
                'complexity': self._analyze_complexity(rule_body),
                'created_at': datetime.now().isoformat(),
                'file_source': 'uploaded'
            }
            
            rules.append(parsed_rule)
            
        return rules
    
    def _extract_meta_field(self, rule_body, field_name):
        """메타데이터에서 특정 필드 추출"""
        pattern = rf'{field_name}\s*=\s*"([^"]*)"'
        match = re.search(pattern, rule_body)
        return match.group(1) if match else ""
    
    def _count_strings(self, rule_body):
        """문자열 패턴 개수 세기"""
        string_pattern = r'\$\w+\s*='
        return len(re.findall(string_pattern, rule_body))
    
    def _analyze_complexity(self, rule_body):
        """룰 복잡도 분석"""
        condition_section = re.search(r'condition:\s*(.*)', rule_body, re.DOTALL)
        if not condition_section:
            return "low"
            
        condition = condition_section.group(1)
        and_count = condition.lower().count('and')
        or_count = condition.lower().count('or')
        
        if and_count + or_count > 3:
            return "high"
        elif and_count + or_count > 1:
            return "medium"
        return "low"

    
    
    
    def convert_json_to_yara_info(self, json_data):
        """JSON 데이터를 YARA 룰 정보로 변환"""
        yara_rules = []
        
        # JSON이 리스트인지 체크
        items = json_data if isinstance(json_data, list) else [json_data]
        
        for i, item in enumerate(items):
            rule_info = {
                'id': i + 1,
                'rule_name': self._generate_rule_name(item),
                'author': item.get('author', 'Unknown'),
                'description': item.get('description', ''),
                'source': 'json_import'
            }
            yara_rules.append(rule_info)
            
        return yara_rules
    
    
    def _generate_rule_name(self, item):
        """JSON 아이템에서 룰 이름 생성"""
        if 'md5' in item:
            return f"rule_{item['md5'][:8]}"
        return f"rule_unknown_{len(str(item))}"

# 테스트 함수 부분
def test_with_json_files():
    parser = SimpleYaraParser()
    
    # 문자열이 아닌 파일명 직접 사용
    filename = '9_report.json'
    
    print(f"🔍 {filename} 테스트 중...")
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"✅ JSON 로드 성공!")
        print(f"📊 데이터 타입: {type(data)}")
        
        # JSON 구조 확인
        if isinstance(data, list):
            print(f"📋 아이템 개수: {len(data)}")
            if len(data) > 0:
                print(f"🔑 첫 번째 아이템 키들: {list(data[0].keys())}")
        else:
            print(f"🔑 최상위 키들: {list(data.keys())}")
        
        # YARA 정보로 변환
        yara_info = parser.convert_json_to_yara_info(data)
        print(f"🎯 생성된 룰 개수: {len(yara_info)}")
        
        # 첫 번째 룰 출력
        if yara_info:
            print(f"\n📄 첫 번째 YARA 룰:")
            print(json.dumps(yara_info[0], indent=2, ensure_ascii=False))
        
    except Exception as e:
        print(f"❌ 에러: {e}")


if __name__ == "__main__":
    test_with_json_files()