from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
import os
import json
import glob
from datetime import datetime
from terminal_yara_gen import TerminalYaraGenerator  # 기존 로직 재사용

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './cape_reports'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_files():
    """JSON 파일 스캔"""
    json_files = glob.glob('./cape_reports/*.json')
    
    file_info = []
    for json_file in json_files:
        try:
            file_name = os.path.basename(json_file)
            file_size = os.path.getsize(json_file) // 1024
            
            # 파일 타입 미리 확인
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            file_type = data.get('target', {}).get('file', {}).get('type', 'Unknown')
            
            file_info.append({
                'name': file_name,
                'size': f"{file_size}KB",
                'type': file_type[:50] + "..." if len(file_type) > 50 else file_type
            })
        except:
            file_info.append({
                'name': os.path.basename(json_file),
                'size': 'Error',
                'type': 'Parse Error'
            })
    
    return jsonify({
        'total_files': len(json_files),
        'files': file_info[:10],  # 처음 10개만
        'more': len(json_files) - 10 if len(json_files) > 10 else 0
    })

@app.route('/generate')
def generate_yara():
    """YARA 룰 생성"""
    try:
        # 기존 터미널 버전 로직 재사용
        generator = TerminalYaraGenerator()
        
        # JSON 파일 스캔
        json_files = glob.glob('./cape_reports/*.json')
        if not json_files:
            return jsonify({'error': 'JSON 파일을 찾을 수 없습니다'})
        
        # 파일 처리 (조용히)
        generator.stats['total_files'] = len(json_files)
        
        for i, json_file in enumerate(json_files):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    cape_data = json.load(f)
                
                rule = generator.generate_single_rule(cape_data, os.path.basename(json_file))
                generator.rules.append(rule)
                generator.stats['successful'] += 1
            except:
                generator.stats['failed'] += 1
        
        # 결과 저장
        output_file = 'cape_malware_rules.yar'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"// Auto-generated YARA rules from CAPE analysis (Web Version)\n")
            f.write(f"// Generated on: {datetime.now()}\n")
            f.write(f"// Total rules: {len(generator.rules)}\n\n")
            
            for rule in generator.rules:
                f.write(rule + "\n\n")
        
        return jsonify({
            'success': True,
            'total_rules': len(generator.rules),
            'successful': generator.stats['successful'],
            'failed': generator.stats['failed'],
            'file_size': os.path.getsize(output_file) // 1024,
            'preview': generator.rules[0] if generator.rules else "No rules generated"
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/download')
def download():
    """생성된 YARA 파일 다운로드"""
    try:
        return send_file('cape_malware_rules.yar', 
                        as_attachment=True, 
                        download_name=f'cape_rules_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yar')
    except:
        return "파일을 찾을 수 없습니다", 404

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)