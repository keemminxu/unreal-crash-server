import os
import zipfile
import io
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

@app.route('/api/crashes', methods=['POST'])
def handle_crash_report():
    """언리얼 엔진 크래시 리포터로부터 POST 요청을 받아 처리합니다."""
    if not SLACK_WEBHOOK_URL:
        print("Error: SLACK_WEBHOOK_URL is not set.")
        return "Internal server configuration error", 500

    xml_data = None
    
    # --- 수정된 부분 시작 ---
    # 1. Zip 파일이 있는지 먼저 확인 (하드 크래시의 경우)
    if 'CrashReport.zip' in request.files:
        print("Log: 'CrashReport.zip' found. Processing as a full crash report.")
        zip_file_storage = request.files['CrashReport.zip']
        try:
            with zipfile.ZipFile(io.BytesIO(zip_file_storage.read())) as thezip:
                for filename in thezip.namelist():
                    if 'CrashContext.runtime-xml' in filename:
                        xml_data = thezip.read(filename)
                        print(f"Log: Found and read '{filename}' from zip.")
                        break
        except zipfile.BadZipFile:
            print("Error: The uploaded file is not a valid zip file.")
            return "Bad Request: Invalid zip file format.", 400

    # 2. Zip 파일이 없다면, 요청의 본문에 데이터가 있는지 확인 (로그 전송의 경우)
    elif request.data:
        print("Log: No zip file found. Processing raw request body as a log report.")
        xml_data = request.data
        
    # 3. 두 경우 모두 해당하지 않으면 오류
    else:
        print("Error: Neither 'CrashReport.zip' nor raw body data found.")
        return "Bad Request: No crash data provided.", 400
    # --- 수정된 부분 끝 ---

    if not xml_data:
        print("Error: Could not extract XML data from the report.")
        return "Bad Request: XML context file not found in the report.", 400

    try:
        # 이후 로직은 동일합니다.
        root = ET.fromstring(xml_data)
        error_message = getattr(root.find('.//ErrorMessage'), 'text', 'N/A')
        call_stack_nodes = root.findall('.//CallStack/Source')
        call_stack = "\n".join([node.text[:200] for node in call_stack_nodes[:10]])
        engine_version = getattr(root.find('.//BuildVersion'), 'text', 'N/A')
        user_name = getattr(root.find('.//UserName'), 'text', 'N/A')
        platform = getattr(root.find('.//PlatformFullName'), 'text', 'N/A')
        build_config = getattr(root.find('.//BuildConfiguration'), 'text', 'N/A')
        
        report_type = "Crash" if "CrashReport.zip" in request.files else "Log"

        slack_message = {
            "blocks": [
                {
                    "type": "header",
                    "text": { "type": "plain_text", "text": f":warning: Unreal Engine {report_type} Report! ({build_config})", "emoji": True }
                },
                {
                    "type": "section",
                    "text": { "type": "mrkdwn", "text": f"*Message:*\n```{error_message}```" }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Platform:*\n{platform}"},
                        {"type": "mrkdwn", "text": f"*User:*\n{user_name}"},
                        {"type": "mrkdwn", "text": f"*Engine Version:*\n{engine_version}"}
                    ]
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": { "type": "mrkdwn", "text": f"*Call Stack (Top 10):*\n```{call_stack}```" }
                }
            ]
        }

        requests.post(SLACK_WEBHOOK_URL, json=slack_message).raise_for_status()
        print("Log: Successfully sent the report to Slack.")
        return jsonify({"status": "success"}), 200

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "Internal Server Error", 500