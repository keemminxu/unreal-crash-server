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

def clean_xml_string(xml_string):
    """
    XML 1.0 표준에 맞지 않는 모든 유효하지 않은 문자를 정규식을 사용하여 제거합니다.
    """
    if not xml_string:
        return ""
    # XML 1.0 명세에서 허용하는 문자 범위를 벗어나는 모든 문자를 찾는 정규식
    invalid_xml_chars_re = re.compile(u'[^\u0009\u000a\u000d\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]')
    return invalid_xml_chars_re.sub('', xml_string)

@app.route('/api/crashes', methods=['POST'])
def handle_crash_report():
    """
    크래시 리포트를 받아, 파싱 성공 여부와 관계없이 최대한의 정보를 슬랙으로 전송합니다.
    """
    # --- 1. URL과 헤더에서 기본 정보 추출 ---
    app_version = request.args.get('AppVersion', 'N/A')
    build_environment = request.args.get('AppEnvironment', 'N/A')
    # URL의 UserID는 EpicAccountID|MachineId|SessionId 형식이므로 첫 부분을 사용
    user_id_from_url = request.args.get('UserID', 'N/A').split('|')[0]
    country = request.headers.get('Cf-Ipcountry', 'N/A')

    # 슬랙 메시지에 사용할 변수들 기본값 설정
    final_user_id = user_id_from_url
    error_message = "XML 데이터 없음"
    call_stack = "XML 데이터 없음"
    report_type = "Log"

    try:
        # --- 2. 본문에서 데이터 추출 및 압축 해제 ---
        raw_data = None
        if 'CrashReport.zip' in request.files:
            report_type = "Crash"
            zip_file = request.files['CrashReport.zip']
            with zipfile.ZipFile(io.BytesIO(zip_file.read())) as thezip:
                for filename in thezip.namelist():
                    if 'CrashContext.runtime-xml' in filename:
                        raw_data = thezip.read(filename)
                        break
        elif request.data:
            raw_data = zlib.decompress(request.data)
        
        if raw_data:
            # --- 3. XML 문서만 정확히 잘라내기 ---
            xml_content = None
            search_start_index = raw_data.find(b'CR1') if raw_data.startswith(b'CR1') else 0
            xml_start_index = raw_data.find(b'<?xml', search_start_index)
            if xml_start_index != -1:
                closing_tag = b'</FGenericCrashContext>'
                xml_end_index = raw_data.find(closing_tag, xml_start_index)
                if xml_end_index != -1:
                    end_of_slice = xml_end_index + len(closing_tag)
                    xml_content = raw_data[xml_start_index:end_of_slice]

            if xml_content:
                cleaned_xml_string = clean_xml_string(xml_content.decode('utf-8', errors='ignore'))
                
                # --- 4. XML 파싱 및 상세 정보 추출 ---
                root = ET.fromstring(cleaned_xml_string)
                
                # XML에서 더 정확한 정보가 있으면 덮어쓰기
                app_version = getattr(root.find('.//EngineVersion'), 'text', app_version)
                build_environment = getattr(root.find('.//BuildConfiguration'), 'text', build_environment)
                final_user_id = getattr(root.find('.//EpicAccountId'), 'text', user_id_from_url) # XML의 EpicAccountId 우선
                
                error_message = getattr(root.find('.//ErrorMessage'), 'text', '태그 없음')
                
                # CallStack 추출 방식 수정: find로 단일 노드를 찾고, text를 가져옵니다.
                call_stack_node = root.find('.//CallStack')
                if call_stack_node is not None and call_stack_node.text:
                    # 콜스택을 줄바꿈으로 나누고 상위 10개만 선택
                    call_stack_lines = call_stack_node.text.strip().split('\n')
                    call_stack = "\n".join(call_stack_lines[:10])
                else:
                    call_stack = "콜스택 없음"

    except Exception as e:
        # 어떤 단계에서든 오류가 발생하면, 오류 정보를 기록
        error_message = "서버 처리 중 오류 발생"
        call_stack = str(e)
        print(f"[ERROR] An unexpected error occurred during data processing: {e}")

    # --- 5. 최종 정보 취합 및 슬랙 전송 ---
    icon = ":boom:" if report_type == "Crash" else ":warning:"
    
    slack_message = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"{icon} Unreal Engine Report Received!", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*App Version:*\n{app_version}"},
                {"type": "mrkdwn", "text": f"*Build Env:*\n{build_environment}"},
                {"type": "mrkdwn", "text": f"*User ID:*\n{final_user_id}"},
                {"type": "mrkdwn", "text": f"*Country:*\n{country}"}
            ]},
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Error Message:*\n```{error_message}```"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Call Stack:*\n```{call_stack}```"}
            }
        ]
    }

    try:
        requests.post(SLACK_WEBHOOK_URL, json=slack_message, timeout=10).raise_for_status()
        print("Successfully sent a report to Slack.")
    except Exception as e:
        print(f"[ERROR] Failed to send final report to Slack: {e}")

    return jsonify({"status": "processed"}), 200
