import os
import zipfile
import io
import xml.etree.ElementTree as ET
import zlib
from flask import Flask, request, jsonify
import requests

# --- Configuration ---
app = Flask(__name__)
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

def clean_xml_data(xml_bytes):
    """
    XML 데이터에서 파싱 오류를 유발할 수 있는 유효하지 않은 제어 문자를 제거합니다.
    (Tab, Newline, Carriage Return 제외)
    """
    if not xml_bytes:
        return xml_bytes
    
    # NULL 바이트(0x00) 제거
    cleaned_data = xml_bytes.replace(b'\x00', b'')
    
    # 기타 제어 문자(0x01-0x1F) 제거 (0x09, 0x0A, 0x0D는 제외)
    invalid_chars = [i for i in range(0x01, 0x20) if i not in [0x09, 0x0A, 0x0D]]
    for char_code in invalid_chars:
        cleaned_data = cleaned_data.replace(bytes([char_code]), b'')
        
    return cleaned_data

@app.route('/api/crashes', methods=['POST'])
def handle_crash_report():
    """언리얼 엔진 크래시 리포트를 수신하여 슬랙으로 전송합니다."""
    try:
        # --- 1. 데이터 추출 ---
        xml_data_bytes = None
        report_type = "Log"

        if 'CrashReport.zip' in request.files:
            report_type = "Crash"
            zip_file = request.files['CrashReport.zip']
            with zipfile.ZipFile(io.BytesIO(zip_file.read())) as thezip:
                for filename in thezip.namelist():
                    if 'CrashContext.runtime-xml' in filename:
                        xml_data_bytes = thezip.read(filename)
                        break
        elif request.data:
            decompressed_data = zlib.decompress(request.data)
            if decompressed_data.startswith(b'CR1'):
                xml_start_index = decompressed_data.find(b'<?xml')
                if xml_start_index != -1:
                    xml_data_bytes = decompressed_data[xml_start_index:]
            else:
                xml_data_bytes = decompressed_data
        
        if not xml_data_bytes:
            return "Bad Request: No valid crash data found.", 400

        # --- 2. 데이터 정제 ---
        cleaned_xml = clean_xml_data(xml_data_bytes)

        # --- 3. XML 파싱 및 정보 추출 ---
        root = ET.fromstring(cleaned_xml)
        
        error_message = getattr(root.find('.//ErrorMessage'), 'text', 'N/A')
        call_stack_nodes = root.findall('.//CallStack/Source')
        call_stack = "\n".join([node.text[:200] for node in call_stack_nodes[:10]]) if call_stack_nodes else "N/A"
        engine_version = getattr(root.find('.//BuildVersion'), 'text', 'N/A')
        user_name = getattr(root.find('.//UserName'), 'text', 'N/A')
        platform = getattr(root.find('.//PlatformFullName'), 'text', 'N/A')
        build_config = getattr(root.find('.//BuildConfiguration'), 'text', 'N/A')
        
        # --- 4. 슬랙 메시지 생성 및 전송 ---
        icon = ":boom:" if report_type == "Crash" else ":warning:"
        slack_message = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"{icon} Unreal Engine {report_type} Report! ({build_config})", "emoji": True}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Message:*\n```{error_message}```"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Platform:*\n{platform}"},
                    {"type": "mrkdwn", "text": f"*User:*\n{user_name}"},
                    {"type": "mrkdwn", "text": f"*Engine Version:*\n{engine_version}"}
                ]},
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Call Stack (Top 10):*\n```{call_stack}```"}}
            ]
        }

        requests.post(SLACK_WEBHOOK_URL, json=slack_message, timeout=10).raise_for_status()
        
        print(f"Successfully processed and sent a {report_type} report to Slack.")
        return jsonify({"status": "success"}), 200

    except Exception as e:
        # 오류 발생 시 Render 로그에 기록
        print(f"[ERROR] An unexpected error occurred: {e}")
        return "Internal Server Error", 500
