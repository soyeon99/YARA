import json
import os
import glob
import time
from datetime import datetime
from colorama import init, Fore, Back, Style
import sys

# Windows에서 색상 지원
init()

class TerminalYaraGenerator:
    def __init__(self):
        self.rules = []
        self.stats = {
            'total_files': 0,
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'file_types': {},
            'start_time': None,
            'end_time': None
        }
    
    def print_header(self):
        """헤더 출력"""
        print(f"\n{Fore.CYAN}╭─────────────────────────────────────────────────────────╮")
        print(f"│{Style.BRIGHT}                🎯 CAPE YARA Rule Generator                {Style.RESET_ALL}{Fore.CYAN}│")
        print(f"╰─────────────────────────────────────────────────────────╯{Style.RESET_ALL}\n")
    
    def print_scanning_files(self, folder_path):
        """파일 스캔 단계"""
        print(f"{Fore.YELLOW}📁 JSON 파일 스캔 중...{Style.RESET_ALL}")
        
        json_files = glob.glob(f"{folder_path}/*.json")
        self.stats['total_files'] = len(json_files)
        
        print(f"   └── {Fore.GREEN}{folder_path}/{Style.RESET_ALL} 폴더에서 {Fore.CYAN}{len(json_files)}개{Style.RESET_ALL} 파일 발견")
        
        # 파일 목록 미리보기 (처음 5개)a
        print(f"\n{Fore.BLUE}📋 발견된 파일들:{Style.RESET_ALL}")
        for i, file_path in enumerate(json_files[:5]):
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path) // 1024
            print(f"   ├── {file_name:<25} ({file_size}KB)")
        
        if len(json_files) > 5:
            print(f"   └── ... 그 외 {len(json_files)-5}개 파일")
        
        return json_files

    def categorize_file_type(self, file_type, file_name=""):
        """더 세분화된 파일 타입 분류"""
        file_type_lower = file_type.lower()
        file_name_lower = file_name.lower()
        
        # PDF 계열
        if 'pdf' in file_type_lower:
            if 'zip deflate' in file_type_lower:
                return 'PDF_Compressed'
            else:
                return 'PDF_Standard'
        
        # PE 실행파일 계열  
        elif 'pe32' in file_type_lower:
            if 'dll' in file_type_lower:
                return 'PE32_DLL'
            elif 'gui' in file_type_lower:
                return 'PE32_GUI'
            elif 'console' in file_type_lower:
                return 'PE32_Console'
            else:
                return 'PE32_Unknown'
        
        # 스크립트 계열
        elif any(x in file_type_lower for x in ['javascript', 'ascii text']):
            if 'very long lines' in file_type_lower:
                return 'Script_Obfuscated'
            elif '.js' in file_name_lower:
                return 'Script_JavaScript'
            elif 'crlf' in file_type_lower:
                return 'Script_Windows'
            else:
                return 'Script_Generic'
        
        # 문서 계열
        elif 'composite document' in file_type_lower:
            if 'msi installer' in file_type_lower:
                return 'MSI_Installer'
            else:
                return 'Document_Composite'
        
        # 아카이브 계열
        elif 'zip' in file_type_lower:
            if 'aes encrypted' in file_type_lower:
                return 'Archive_Encrypted'
            else:
                return 'Archive_Standard'
        
        # 쇼트컷 계열
        elif 'shortcut' in file_type_lower:
            if 'mshta.exe' in file_type:
                return 'LNK_MSHTA'
            elif 'powershell' in file_type:
                return 'LNK_PowerShell'
            else:
                return 'LNK_Generic'
        
        # 텍스트 계열
        elif 'unicode text' in file_type_lower:
            if 'utf-16' in file_type_lower:
                return 'Text_Unicode_UTF16'
            else:
                return 'Text_Unicode'
        
        # 바이너리/알 수 없는 것들
        elif 'data' in file_type_lower:
            return 'Binary_Data'
        elif file_type_lower == 'unknown':
            return 'Unknown_Type'
        else:
            # 긴 타입명은 줄임
            short_type = file_type_lower.replace(' ', '_')[:15]
            return f'Other_{short_type}'

    def analyze_file_types(self, json_files):
        """파일 타입 분석 (향상된 버전)"""
        print(f"\n{Fore.YELLOW}🔍 파일 타입 분석 중...{Style.RESET_ALL}")
        
        file_types = {}
        detailed_info = []
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                file_name = os.path.basename(json_file)
                file_type = data.get('target', {}).get('file', {}).get('type', 'Unknown')
                file_size = data.get('target', {}).get('file', {}).get('size', 0)
                
                # 세분화된 카테고리화
                category = self.categorize_file_type(file_type, file_name)
                
                file_types[category] = file_types.get(category, 0) + 1
                detailed_info.append((file_name, category, file_size))
                
            except Exception as e:
                file_types['Error_Parse'] = file_types.get('Error_Parse', 0) + 1
                detailed_info.append((os.path.basename(json_file), 'Error_Parse', 0))
        
        self.stats['file_types'] = file_types
        self.stats['detailed_info'] = detailed_info
        
        # 결과 출력 (더 자세하게)
        print(f"{Fore.BLUE}📊 세부 파일 분석 결과:{Style.RESET_ALL}")
        
        # 카테고리별 정렬해서 출력
        for category, count in sorted(file_types.items()):
            color = Fore.GREEN if count > 0 else Fore.RED
            print(f"   ├── {category:<20}: {color}{count}개{Style.RESET_ALL}")
        
        # 상세 정보 (처음 10개만)
        print(f"\n{Fore.BLUE}📋 파일별 상세 정보:{Style.RESET_ALL}")
        for file_name, category, size in detailed_info[:10]:
            size_str = f"{size//1024}KB" if size > 0 else "0KB"
            print(f"   ├── {file_name:<25} → {category:<15} ({size_str})")
        
        if len(detailed_info) > 10:
            print(f"   └── ... 그 외 {len(detailed_info)-10}개 파일")
    
    def print_progress_bar(self, current, total, file_name="", status=""):
        """진행률 표시"""
        percentage = int((current / total) * 100) if total > 0 else 0
        filled_length = int(32 * current // total) if total > 0 else 0
        bar = '█' * filled_length + '░' * (32 - filled_length)
        
        print(f"\r   [{Fore.GREEN}{bar}{Style.RESET_ALL}] {percentage:3d}% ({current}/{total}) {file_name:<20} {status}", end="", flush=True)
    
    def extract_meaningful_strings(self, strings_list, limit=5):
        """의미있는 문자열 추출"""
        meaningful = []
        
        for s in strings_list:
            if 4 <= len(s) <= 80:
                if any(pattern in s.lower() for pattern in [
                    'http', 'www.', '.exe', '.dll', '.bat', '.js', '.zip',
                    'temp', 'system', 'windows', 'program', 'user',
                    'hkey', 'software', 'registry', 'appdata'
                ]) or len([c for c in s if c.isalnum()]) / len(s) > 0.6:
                    meaningful.append(s)
        
        return meaningful[:limit]
    
    def generate_single_rule(self, json_data, file_name):
        """개별 JSON에서 YARA 룰 생성"""
        target_file = json_data.get('target', {}).get('file', {})
        
        file_hash = target_file.get('sha256', 'unknown')
        file_type = target_file.get('type', 'unknown')
        strings_list = target_file.get('strings', [])
        file_size = target_file.get('size', 0)
        
        meaningful_strings = self.extract_meaningful_strings(strings_list)
        
        rule_name = f"CAPE_{file_name.replace('.json', '').replace('-', '_').replace('(', '_').replace(')', '_')}"
        
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
        
        for i, string in enumerate(meaningful_strings):
            escaped_string = string.replace('\\', '\\\\').replace('"', '\\"')
            yara_rule += f'        $s{i} = "{escaped_string}" nocase\n'
        
        yara_rule += '''        
    condition:
        $hash or 2 of ($s*)
}'''
        
        return yara_rule
    
    def process_single_file(self, json_file, file_index):
        """개별 파일 처리"""
        file_name = os.path.basename(json_file)
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                cape_data = json.load(f)
            
            self.print_progress_bar(file_index, self.stats['total_files'], file_name, "🔄")
            
            rule = self.generate_single_rule(cape_data, file_name)
            self.rules.append(rule)
            
            self.stats['successful'] += 1
            
            time.sleep(0.1)
            self.print_progress_bar(file_index, self.stats['total_files'], file_name, "✅")
            
            return True, None
            
        except Exception as e:
            self.stats['failed'] += 1
            self.print_progress_bar(file_index, self.stats['total_files'], file_name, "❌")
            return False, str(e)
    
    def process_all_files(self, json_files):
        """모든 파일 처리"""
        print(f"\n{Fore.YELLOW}⚡ YARA 룰 생성 중...{Style.RESET_ALL}")
        self.stats['start_time'] = time.time()
        
        failed_files = []
        
        for i, json_file in enumerate(json_files, 1):
            success, error = self.process_single_file(json_file, i)
            self.stats['processed'] += 1
            
            if not success:
                failed_files.append((os.path.basename(json_file), error))
        
        print()
        self.stats['end_time'] = time.time()
        
        if failed_files:
            print(f"\n{Fore.RED}⚠️  처리 실패 파일들:{Style.RESET_ALL}")
            for file_name, error in failed_files:
                print(f"   ├── {file_name}: {error[:50]}...")
    
    def print_completion_stats(self):
        """완료 통계"""
        duration = self.stats['end_time'] - self.stats['start_time']
        avg_time = duration / self.stats['total_files'] if self.stats['total_files'] > 0 else 0
        
        print(f"\n{Fore.GREEN}🎉 완료!{Style.RESET_ALL}")
        print(f"   ├── 총 {Fore.CYAN}{len(self.rules)}개{Style.RESET_ALL} YARA 룰 생성")
        print(f"   ├── 처리 시간: {Fore.YELLOW}{duration:.1f}초{Style.RESET_ALL}")
        print(f"   ├── 평균 처리 시간: {Fore.YELLOW}{avg_time:.2f}초/파일{Style.RESET_ALL}")
        print(f"   ├── 성공률: {Fore.GREEN}{(self.stats['successful']/self.stats['total_files']*100):.1f}%{Style.RESET_ALL}")
        print(f"   └── 저장 위치: {Fore.BLUE}./cape_malware_rules.yar{Style.RESET_ALL}")
    
    def save_rules_with_progress(self, output_file):
        """룰 저장"""
        print(f"\n{Fore.YELLOW}💾 YARA 룰 저장 중...{Style.RESET_ALL}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"// Auto-generated YARA rules from CAPE analysis\n")
            f.write(f"// Generated on: {datetime.now()}\n")
            f.write(f"// Total rules: {len(self.rules)}\n\n")
            
            for i, rule in enumerate(self.rules):
                f.write(rule + "\n\n")
                
                if (i + 1) % 5 == 0 or i == len(self.rules) - 1:
                    percentage = int(((i + 1) / len(self.rules)) * 100)
                    print(f"\r   💾 저장 중... {percentage:3d}% ({i+1}/{len(self.rules)})", end="", flush=True)
        
        print(f"\n   ✅ {Fore.GREEN}{output_file}{Style.RESET_ALL} 저장 완료!")
    
    def print_next_steps(self):
        """다음 작업 안내"""
        print(f"\n{Fore.BLUE}📋 다음 작업:{Style.RESET_ALL}")
        print(f"   1. {Fore.YELLOW}yara cape_malware_rules.yar target_file{Style.RESET_ALL} - 룰 테스트")
        print(f"   2. {Fore.YELLOW}cat cape_malware_rules.yar | head -50{Style.RESET_ALL} - 룰 내용 확인")
        print(f"   3. False Positive 체크 및 룰 최적화")
        print(f"   4. 시그니처 데이터베이스 업데이트\n")
    
    def run(self, folder_path="./cape_reports"):
        """메인 실행 함수"""
        self.print_header()
        
        json_files = self.print_scanning_files(folder_path)
        if not json_files:
            print(f"{Fore.RED}❌ JSON 파일을 찾을 수 없습니다!{Style.RESET_ALL}")
            return
        
        self.analyze_file_types(json_files)
        self.process_all_files(json_files)
        
        if self.rules:
            self.save_rules_with_progress("cape_malware_rules.yar")
            
        self.print_completion_stats()
        self.print_next_steps()

if __name__ == "__main__":
    generator = TerminalYaraGenerator()
    generator.run("./cape_reports")