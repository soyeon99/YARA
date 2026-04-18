from flask import Flask, render_template, jsonify, request
import json
import os
import glob
import re
from datetime import datetime
from threading import Thread
import time

app = Flask(__name__)

class WebCapeScanner:
    def __init__(self, rules_file="yara_rules2.yar"):
        self.rules = []
        self.matches = []
        self.scan_progress = {
            'current': 0,
            'total': 0,
            'status': 'ready',
            'current_file': '',
            'scanning': False
        }
        self.load_rules(rules_file)
    
    def load_rules(self, rules_file):
        """YARA 룰 로드"""
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            rule_blocks = re.findall(r'rule\s+(\w+)\s*\{(.*?)\}', content, re.DOTALL)
            
            for rule_name, rule_content in rule_blocks:
                strings_match = re.search(r'strings:(.*?)condition:', rule_content, re.DOTALL)
                strings = []
                
                if strings_match:
                    for line in strings_match.group(1).split('\n'):
                        if '$' in line and '=' in line:
                            var_name = line.strip().split('=')[0].strip()
                            string_value = re.findall(r'"([^"]*)"', line)
                            if string_value:
                                strings.append((var_name, string_value[0]))
                
                condition_match = re.search(r'condition:\s*(.*)', rule_content, re.DOTALL)
                condition = condition_match.group(1).strip() if condition_match else ""
                
                self.rules.append({
                    'name': rule_name,
                    'strings': strings,
                    'condition': condition
                })
        except Exception as e:
            print(f"룰 로딩 오류: {e}")
    
    def get_matches(self, rule, file_type, file_hash, strings_list):
        """매치된 패턴들 찾기"""
        matches = []
        
        for var_name, pattern in rule['strings']:
            if pattern.lower() in file_type.lower():
                matches.append(f"{var_name}: '{pattern}' (filetype)")
                continue
            
            if pattern.lower() in file_hash.lower():
                matches.append(f"{var_name}: '{pattern}' (hash)")
                continue
            
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
            required_vars = len([s for s in rule['strings']])
            return match_count >= min(2, required_vars)
        else:
            return match_count > 0
    
    def check_json_file(self, json_file):
        """JSON 파일 검사"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            target = data.get('target', {}).get('file', {})
            file_type = target.get('type', '')
            file_hash = target.get('sha256', '')
            strings_list = target.get('strings', [])
            
            for rule in self.rules:
                matched_items = self.get_matches(rule, file_type, file_hash, strings_list)
                if self.evaluate_condition(rule, matched_items):
                    self.matches.append({
                        'json_file': os.path.basename(json_file),
                        'rule_name': rule['name'],
                        'file_type': file_type,
                        'file_hash': file_hash,
                        'matched_items': matched_items,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
        except Exception as e:
            print(f"파일 검사 오류 {json_file}: {e}")
    
    def scan_folder_async(self, folder_path):
        """비동기 폴더 스캔"""
        self.matches = []
        self.scan_progress['scanning'] = True
        self.scan_progress['status'] = 'scanning'
        
        json_files = glob.glob(os.path.join(folder_path, "*.json"))
        self.scan_progress['total'] = len(json_files)
        
        for i, json_file in enumerate(json_files, 1):
            self.scan_progress['current'] = i
            self.scan_progress['current_file'] = os.path.basename(json_file)
            
            self.check_json_file(json_file)
            time.sleep(0.1)  # 진행률 시각화를 위한 딜레이
        
        self.scan_progress['scanning'] = False
        self.scan_progress['status'] = 'completed'

# 전역 스캐너 인스턴스
scanner = WebCapeScanner()

@app.route('/')
def index():
    return render_template('index2.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    folder_path = r"C:\Users\popo7\Desktop\Semi_02\cape_reports"
    
    if scanner.scan_progress['scanning']:
        return jsonify({'status': 'already_scanning'})
    
    # 백그라운드에서 스캔 시작
    thread = Thread(target=scanner.scan_folder_async, args=(folder_path,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'scan_started'})

@app.route('/scan_progress')
def scan_progress():
    return jsonify(scanner.scan_progress)

@app.route('/scan_results')
def scan_results():
    # 룰별로 그룹화
    rule_groups = {}
    for match in scanner.matches:
        rule_name = match['rule_name']
        if rule_name not in rule_groups:
            rule_groups[rule_name] = []
        rule_groups[rule_name].append(match)
    
    return jsonify({
        'total_matches': len(scanner.matches),
        'total_rules': len(scanner.rules),
        'rule_groups': rule_groups
    })

@app.route('/rules_info')
def rules_info():
    rules_info = []
    for rule in scanner.rules:
        rules_info.append({
            'name': rule['name'],
            'strings_count': len(rule['strings']),
            'condition': rule['condition']
        })
    
    return jsonify({
        'total_rules': len(scanner.rules),
        'rules': rules_info
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)