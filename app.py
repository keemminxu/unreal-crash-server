import os
import zipfile
import io
import xml.etree.ElementTree as ET
import zlib  # gzip 대신 zlib 라이브러리를 사용합니다.
from flask import Flask, request, jsonify
import requests

# Flask 애플리케이션 생성
app = Flask(__name__)

# Render 환경 변수에서 슬랙 웹훅 URL을 가져옵니다.
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

@app.route('/api/crashes', methods=['POST'])
def handle_crash_report():
    """언리얼 엔진 크래시 리포터로부터 POST 요청을 받아 처리합니다."""
    if not SLACK_WEBHOOK_URL:
        print("Error: SLACK_WEBHOOK_URL is not set in environment variables.")
        return "Internal server configuration error", 500

    xml_data = None
    report_type = "Log" # 기본값은 로그

    # 1. Zip 파일이 있는지 먼저 확인 (하드 크래시의 경우)
    if 'CrashReport.zip' in request.files:
        print("Log: 'CrashReport.zip' found. Processing as a full crash report.")
        report_type = "Crash"
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
        print(f"Log: No zip file. Processing raw request body. Headers: {request.headers}")
        
        decompressed_data = None
        try:
            # 먼저 zlib 압축 해제를 시도합니다.
            decompressed_data = zlib.decompress(request.data)
            print("Log: Successfully decompressed zlib-encoded body.")
        except zlib.error:
            # 만약 zlib 오류가 발생하면, 압축되지 않은 데이터로 간주하고 원본을 그대로 사용합니다.
            print("Log: Data is not zlib-compressed. Using raw body.")
            decompressed_data = request.data
        
        # --- 최종 수정: Unreal의 CR1 바이너리 래퍼 처리 ---
        # 데이터가 'CR1' 시그니처로 시작하는지 확인합니다.
        if decompressed_data.startswith(b'CR1'):
            print("Log: 'CR1' header detected. Searching for XML payload.")
            # '<?xml' 문자열을 찾아 실제 XML 데이터의 시작 위치를 찾습니다.
            xml_start_index = decompressed_data.find(b'<?xml')
            if xml_start_index != -1:
                # XML 시작 위치부터 끝까지를 실제 데이터로 사용합니다.
                xml_data = decompressed_data[xml_start_index:]
                print("Log: Successfully extracted XML payload from CR1 wrapper.")
            else:
                print("Error: 'CR1' header found, but no XML payload could be located.")
                xml_data = None
        else:
            # 'CR1' 헤더가 없으면, 전체 데이터가 XML이라고 가정합니다.
            print("Log: No 'CR1' header. Assuming data is pure XML.")
            xml_data = decompressed_data
        # --- 로직 끝 ---
        
    else:
        print("Error: Neither 'CrashReport.zip' nor raw body data found.")
        return "Bad Request: No crash data provided.", 400

    if not xml_data:
        print("Error: Could not extract XML data from the report.")
        return "Bad Request: XML context file not found in the report.", 400

    try:
        root = ET.fromstring(xml_data)
        error_message = getattr(root.find('.//ErrorMessage'), 'text', 'N/A')
        call_stack_nodes = root.findall('.//CallStack/Source')
        call_stack = "\n".join([node.text[:200] for node in call_stack_nodes[:10]]) if call_stack_nodes else "N/A"
        engine_version = getattr(root.find('.//BuildVersion'), 'text', 'N/A')
        user_name = getattr(root.find('.//UserName'), 'text', 'N/A')
        platform = getattr(root.find('.//PlatformFullName'), 'text', 'N/A')
        build_config = getattr(root.find('.//BuildConfiguration'), 'text', 'N/A')
        
        icon = ":boom:" if report_type == "Crash" else ":warning:"

        slack_message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{icon} Unreal Engine {report_type} Report! ({build_config})", "emoji": True}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Message:*\n```{error_message}```"}
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
                    "text": {"type": "mrkdwn", "text": f"*Call Stack (Top 10):*\n```{call_stack}```"}
                }
            ]
        }

        requests.post(SLACK_WEBHOOK_URL, json=slack_message).raise_for_status()
        print("Log: Successfully sent the report to Slack.")
        return jsonify({"status": "success"}), 200

    except ET.ParseError as e:
        print(f"Error: XML Parse Error - {e}. Data received might not be valid XML.")
        print(f"Received data (first 200 bytes): {xml_data[:200]}")
        return "Bad Request: Invalid XML format.", 400
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "Internal Server Error", 500
