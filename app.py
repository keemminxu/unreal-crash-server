import os
import zipfile
import io
import xml.etree.ElementTree as ET
import zlib
import re
from flask import Flask, request, jsonify
import requests

# --- Configuration ---
app = Flask(__name__)
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

def clean_xml_data(xml_bytes):
    """
    XML 1.0 표준에 맞지 않는 모든 유효하지 않은 문자를 정규식을 사용하여 제거합니다.
    이는 언리얼 엔진 로그에 포함될 수 있는 깨진 문자나 제어 문자를 처리하는
    가장 확실한 방법입니다.
    """
    if not xml_bytes:
        return b''

    try:
        # UTF-8로 디코딩을 시도합니다. 깨진 문자는 무시합니다.
        xml_string = xml_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return b'' # 디코딩 실패 시 빈 바이트 반환

    # XML 1.0 명세에서 허용하는 문자 범위:
    # #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    # 이 범위를 벗어나는 모든 문자를 찾는 정규식입니다.
    invalid_xml_chars_re = re.compile(u'[^\u0009\u000a\u000d\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]')
    
    # 유효하지 않은 문자를 빈 문자열로 치환합니다.
    cleaned_string = invalid_xml_chars_re.sub('', xml_string)
    
    # XML 파서가 처리할 수 있도록 다시 UTF-8 바이트로 인코딩합니다.
    return cleaned_string.encode('utf-8')

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

        # --- 2. 데이터 정제 (가장 강력한 버전) ---
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
        # 오류 발생 시 Render 로그에 기록하여 최소한의 디버깅 정보를 남깁니다.
        print(f"[ERROR] An unexpected error occurred: {e}")
        return "Internal Server Error", 500
