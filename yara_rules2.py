import json
import os
import glob
import re
from datetime import datetime
from colorama import init, Fore, Style

init()

class CapeScanner:
    def __init__(self, rules_file="yara_rules2.yar"):
        self.rules = []
        self.matches = []
        self.load_rules(rules_file)
    
    def load_rules(self, rules_file):
        """YARA 룰 로드"""
        print(f"{Fore.YELLOW}📋 YARA 룰 로딩 중...{Style.RESET_ALL}")
        
        with open(rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 룰별로 분리
        rule_blocks = re.findall(r'rule\s+(\w+)\s*\{(.*?)\}', content, re.DOTALL)
        
        for rule_name, rule_content in rule_blocks:
            # strings 섹션 추출
            strings_match = re.search(r'strings:(.*?)condition:', rule_content, re.DOTALL)
            strings = []
            
            if strings_match:
                for line in strings_match.group(1).split('\n'):
                    if '$' in line and '=' in line:
                        var_name = line.strip().split('=')[0].strip()
                        string_value = re.findall(r'"([^"]*)"', line)
                        if string_value:
                            strings.append((var_name, string_value[0]))
            
            # condition 추출
            condition_match = re.search(r'condition:\s*(.*)', rule_content, re.DOTALL)
            condition = condition_match.group(1).strip() if condition_match else ""
            
            self.rules.append({
                'name': rule_name,
                'strings': strings,
                'condition': condition
            })
        
        print(f"   ✅ {Fore.GREEN}{len(self.rules)}개{Style.RESET_ALL} 룰 로드 완료")
    
    def check_json_file(self, json_file):
        """JSON 파일 검사"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 타겟 파일 정보 추출
            target = data.get('target', {}).get('file', {})
            file_type = target.get('type', '')
            file_hash = target.get('sha256', '')
            strings_list = target.get('strings', [])
            
            # 모든 룰에 대해 검사
            for rule in self.rules:
                matched_items = self.get_matches(rule, file_type, file_hash, strings_list)
                if self.evaluate_condition(rule, matched_items):
                    self.matches.append({
                        'json_file': os.path.basename(json_file),
                        'rule_name': rule['name'],
                        'file_type': file_type,
                        'file_hash': file_hash,
                        'matched_items': matched_items
                    })
                    
                    # 즉시 알림
                    print(f"      🚨 {Fore.RED}매치!{Style.RESET_ALL} → {Fore.YELLOW}{rule['name']}{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"      ❌ 오류: {e}")
    
    def get_matches(self, rule, file_type, file_hash, strings_list):
        """매치된 패턴들 찾기"""
        matches = []
        
        for var_name, pattern in rule['strings']:
            # 파일 타입에서 검색
            if pattern.lower() in file_type.lower():
                matches.append(f"{var_name}: '{pattern}' (filetype)")
                continue
            
            # 해시에서 검색
            if pattern.lower() in file_hash.lower():
                matches.append(f"{var_name}: '{pattern}' (hash)")
                continue
            
            # strings 리스트에서 검색
            for s in strings_list:
                if pattern.lower() in s.lower():
                    matches.append(f"{var_name}: '{pattern}' (strings)")
                    break
        
        return matches
    
    def evaluate_condition(self, rule, matched_items):
        """조건 평가"""
        condition = rule['condition'].lower()
        match_count = len(matched_items)
        
        if 'any of' in condition:
            return match_count > 0
        elif '2 of' in condition:
            return match_count >= 2
        elif '1 of' in condition:
            return match_count >= 1
        elif 'and' in condition:
            # 간단한 AND 조건 처리
            required_vars = len([s for s in rule['strings']])
            return match_count >= min(2, required_vars)
        else:
            return match_count > 0
    
    def scan_folder(self, folder_path):
        """폴더 스캔"""
        print(f"\n{Fore.CYAN}🔍 CAPE JSON 스캔 시작{Style.RESET_ALL}")
        print(f"📁 대상 폴더: {Fore.BLUE}{folder_path}{Style.RESET_ALL}")
        
        json_files = glob.glob(os.path.join(folder_path, "*.json"))
        print(f"📊 JSON 파일: {Fore.GREEN}{len(json_files)}개{Style.RESET_ALL} 발견\n")
        
        if not json_files:
            print(f"{Fore.RED}❌ JSON 파일을 찾을 수 없습니다!{Style.RESET_ALL}")
            return
        
        for i, json_file in enumerate(json_files, 1):
            file_name = os.path.basename(json_file)
            print(f"   {i:2d}. {file_name:<25}", end=" ")
            self.check_json_file(json_file)
            if not any(match['json_file'] == file_name for match in self.matches[-1:]):
                print(f"✅ 깨끗함")
        
        self.print_results()
    
    def print_results(self):
        """결과 출력 (방법 2: 상세 통계 추가)"""
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📋 최종 스캔 결과{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        
        if not self.matches:
            print(f"\n{Fore.GREEN}✅ 모든 파일이 안전합니다!{Style.RESET_ALL}")
            print(f"   위협이 탐지되지 않았습니다.")
            return
        
        # 통계 계산
        unique_files = set(match['json_file'] for match in self.matches)
        total_unique_files = len(unique_files)
        total_matches = len(self.matches)
        
        # 중복 매치 파일들 찾기
        file_match_count = {}
        for match in self.matches:
            file_name = match['json_file']
            file_match_count[file_name] = file_match_count.get(file_name, 0) + 1
        
        multiple_matches = {f: c for f, c in file_match_count.items() if c > 1}
        
        # 상세 통계 출력
        print(f"\n{Fore.RED}🚨 위험 탐지 결과{Style.RESET_ALL}")
        print(f"   ├── 감염된 파일: {Fore.RED}{total_unique_files}개{Style.RESET_ALL}")
        print(f"   ├── 총 탐지 건수: {Fore.YELLOW}{total_matches}개{Style.RESET_ALL}")
        print(f"   └── 중복 감염: {Fore.MAGENTA}{len(multiple_matches)}개{Style.RESET_ALL} 파일")
        
        # 고위험 파일들 (여러 룰에 매치) 표시
        if multiple_matches:
            print(f"\n{Fore.MAGENTA}⚠️  여러 룰에 매치된 고위험 파일들:{Style.RESET_ALL}")
            for file_name, count in sorted(multiple_matches.items(), key=lambda x: x[1], reverse=True):
                # 해당 파일이 매치된 룰들 찾기
                matched_rules = [match['rule_name'] for match in self.matches if match['json_file'] == file_name]
                print(f"   ├── {Fore.RED}{file_name}{Style.RESET_ALL}: {Fore.YELLOW}{count}개 룰{Style.RESET_ALL} ({', '.join(matched_rules)})")
        
        print()  # 구분을 위한 빈 줄
        
        # 룰별로 그룹화해서 상세 결과 출력
        rule_groups = {}
        for match in self.matches:
            rule_name = match['rule_name']
            if rule_name not in rule_groups:
                rule_groups[rule_name] = []
            rule_groups[rule_name].append(match)
        
        # 위험도별 정렬 (Critical > High > Medium > Low)
        risk_order = {
            'Known_Malware_Hash': 1,  # Critical
            'Suspicious_PE_Executable': 2,  # High
            'Malicious_LNK_File': 3,  # High
            'Malicious_PDF': 4,  # Medium
            'Obfuscated_JavaScript': 5,  # Medium
            'Suspicious_MSI_Installer': 6,  # Medium
            'Suspicious_Unicode_Script': 7,  # Medium
            'Encrypted_Archive': 8  # Low
        }
        
        sorted_rules = sorted(rule_groups.items(), key=lambda x: risk_order.get(x[0], 99))
        
        for rule_name, matches in sorted_rules:
            # 위험도 표시
            if rule_name == 'Known_Malware_Hash':
                risk_badge = f"{Fore.RED}[CRITICAL]{Style.RESET_ALL}"
            elif rule_name in ['Suspicious_PE_Executable', 'Malicious_LNK_File']:
                risk_badge = f"{Fore.YELLOW}[HIGH]{Style.RESET_ALL}"
            elif rule_name in ['Malicious_PDF', 'Obfuscated_JavaScript', 'Suspicious_MSI_Installer', 'Suspicious_Unicode_Script']:
                risk_badge = f"{Fore.CYAN}[MEDIUM]{Style.RESET_ALL}"
            else:
                risk_badge = f"{Fore.GREEN}[LOW]{Style.RESET_ALL}"
            
            print(f"{Fore.RED}🎯 룰: {rule_name}{Style.RESET_ALL} {risk_badge} ({len(matches)}개 파일)")
            
            for i, match in enumerate(matches, 1):
                print(f"   └── {i}. {match['json_file']}")
                print(f"       ├── 파일타입: {match['file_type'][:80]}{'...' if len(match['file_type']) > 80 else ''}")
                print(f"       ├── 해시: {match['file_hash'][:32]}...")
                print(f"       └── 매치:")
                
                for item in match['matched_items']:
                    print(f"           └── {item}")
                print()

if __name__ == "__main__":
    # 지정된 경로로 스캔
    folder_path = r"C:\Users\popo7\Desktop\Semi_02\cape_reports"
    
    print(f"{Fore.CYAN}╭─────────────────────────────────────────────╮")
    print(f"│{Style.BRIGHT}         🎯 CAPE Malware Scanner           {Style.RESET_ALL}{Fore.CYAN}│")
    print(f"╰─────────────────────────────────────────────╯{Style.RESET_ALL}")
    
    scanner = CapeScanner("yara_rules2.yar")
    scanner.scan_folder(folder_path)
    
    print(f"\n{Fore.BLUE}스캔 완료! {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")