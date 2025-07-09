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

def send_slack_error_report(error_title, error_details, raw_data=""):
    """파싱 실패 등 내부 오류 발생 시 슬랙으로 알림을 보냅니다."""
    if not SLACK_WEBHOOK_URL:
        return

    slack_message = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f":x: Crash Reporter Server Error!", "emoji": True}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Error Type:*\n{error_title}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Details:*\n```{error_details}```"}
            }
        ]
    }
    if raw_data:
        # 수신된 데이터의 일부를 추가로 보여줍니다.
        slack_message["blocks"].append({"type": "divider"})
        slack_message["blocks"].append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Received Data (first 500 bytes):*\n```{raw_data[:500]}```"}
        })
    
    try:
        requests.post(SLACK_WEBHOOK_URL, json=slack_message)
    except Exception as e:
        print(f"Failed to send error report to slack: {e}")


@app.route('/api/crashes', methods=['POST'])
def handle_crash_report():
    """언리얼 엔진 크래시 리포터로부터 POST 요청을 받아 처리합니다."""
    if not SLACK_WEBHOOK_URL:
        print("Error: SLACK_WEBHOOK_URL is not set in environment variables.")
        return "Internal server configuration error", 500

    xml_data_bytes = None
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
                        xml_data_bytes = thezip.read(filename)
                        print(f"Log: Found and read '{filename}' from zip.")
                        break
        except zipfile.BadZipFile as e:
            print(f"Error: {e}")
            return "Bad Request: Invalid zip file format.", 400

    # 2. Zip 파일이 없다면, 요청의 본문에 데이터가 있는지 확인 (로그 전송의 경우)
    elif request.data:
        print(f"Log: No zip file. Processing raw request body. Headers: {request.headers}")
        
        decompressed_data = None
        try:
            decompressed_data = zlib.decompress(request.data)
            print("Log: Successfully decompressed zlib-encoded body.")
        except zlib.error:
            print("Log: Data is not zlib-compressed. Using raw body.")
            decompressed_data = request.data
        
        if decompressed_data.startswith(b'CR1'):
            print("Log: 'CR1' header detected. Searching for XML payload.")
            xml_start_index = decompressed_data.find(b'<?xml')
            if xml_start_index != -1:
                xml_data_bytes = decompressed_data[xml_start_index:]
                print("Log: Successfully extracted XML payload from CR1 wrapper.")
            else:
                print("Error: 'CR1' header found, but no XML payload could be located.")
                xml_data_bytes = None
        else:
            print("Log: No 'CR1' header. Assuming data is pure XML.")
            xml_data_bytes = decompressed_data
        
    else:
        print("Error: Neither 'CrashReport.zip' nor raw body data found.")
        return "Bad Request: No crash data provided.", 400

    if not xml_data_bytes:
        print("Error: Could not extract XML data from the report.")
        return "Bad Request: XML context file not found in the report.", 400

    try:
        # XML 파싱 시도
        root = ET.fromstring(xml_data_bytes)
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
        # --- 최종 수정: XML 파싱 실패 시, 오류 내용을 슬랙으로 보냄 ---
        error_str = str(e)
        print(f"Error: XML Parse Error - {error_str}. Sending raw data to Slack for inspection.")
        
        # 수신된 데이터를 문자열로 변환 (오류 무시)
        raw_data_str = xml_data_bytes.decode('utf-8', errors='ignore')
        
        send_slack_error_report("XML Parse Error", error_str, raw_data_str)
        
        # 클라이언트에는 Bad Request 응답
        return "Bad Request: Invalid XML format.", 400
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        send_slack_error_report("An unexpected server error occurred", str(e))
        return "Internal Server Error", 500
