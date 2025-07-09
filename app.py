import os
import zipfile
import io
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify
import requests

# Flask 애플리케이션 생성
app = Flask(__name__)

# Render 환경 변수에서 슬랙 웹훅 URL을 가져옵니다.
# 배포 시 Render 대시보드에서 이 값을 설정해야 합니다.
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')

# 언리얼 엔진 설정 파일(DefaultEngine.ini)에 지정할 경로입니다.
@app.route('/api/crashes', methods=['POST'])
def handle_crash_report():
    """언리얼 엔진 크래시 리포터로부터 POST 요청을 받아 처리합니다."""

    # 1. 슬랙 웹훅 URL이 설정되었는지 확인
    if not SLACK_WEBHOOK_URL:
        print("Error: SLACK_WEBHOOK_URL is not set in environment variables.")
        # 서버 내부 오류이므로 500 에러를 반환합니다.
        return "Internal server configuration error", 500

    # 2. 크래시 리포트 파일 수신 확인
    # 언리얼 4.25+ 버전은 'CrashReport.zip' 파일을 보냅니다.
    if 'CrashReport.zip' not in request.files:
        print("Log: 'CrashReport.zip' not found in the request files.")
        return "Bad Request: Expected 'CrashReport.zip' file.", 400

    zip_file_storage = request.files['CrashReport.zip']
    print("Log: 'CrashReport.zip' received successfully.")

    # 3. ZIP 파일에서 XML 데이터 추출
    xml_data = None
    try:
        # 파일을 메모리 상에서 직접 열어서 처리합니다.
        with zipfile.ZipFile(io.BytesIO(zip_file_storage.read())) as thezip:
            # zip 파일 내에서 CrashContext.runtime-xml 파일을 찾습니다.
            for filename in thezip.namelist():
                if 'CrashContext.runtime-xml' in filename:
                    with thezip.open(filename) as xmlfile:
                        xml_data = xmlfile.read()
                        print(f"Log: Found and read '{filename}' from zip.")
                    break
    except zipfile.BadZipFile:
        print("Error: The uploaded file is not a valid zip file.")
        return "Bad Request: Invalid zip file format.", 400

    if not xml_data:
        print("Error: 'CrashContext.runtime-xml' not found inside the zip.")
        return "Bad Request: XML context file not found in zip.", 400

    # 4. XML 파싱 및 슬랙 메시지 생성
    try:
        root = ET.fromstring(xml_data)

        # 필요한 정보 추출 (값이 없을 경우를 대비해 .get() 사용)
        error_message = getattr(root.find('.//ErrorMessage'), 'text', 'N/A')
        call_stack_nodes = root.findall('.//CallStack/Source')
        # 콜스택은 상위 10개만, 그리고 너무 길지 않게 자릅니다.
        call_stack = "\n".join([node.text[:200] for node in call_stack_nodes[:10]])
        engine_version = getattr(root.find('.//BuildVersion'), 'text', 'N/A')
        user_name = getattr(root.find('.//UserName'), 'text', 'N/A')
        platform = getattr(root.find('.//PlatformFullName'), 'text', 'N/A')
        build_config = getattr(root.find('.//BuildConfiguration'), 'text', 'N/A')

        # Slack Block Kit을 사용해 보기 좋은 메시지 만들기
        slack_message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f":boom: Unreal Engine Crash! ({build_config})",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Error Message:*\n```{error_message}```"
                    }
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
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Call Stack (Top 10):*\n```{call_stack}```"
                    }
                }
            ]
        }

        # 5. 슬랙으로 알림 전송
        response = requests.post(SLACK_WEBHOOK_URL, json=slack_message)
        response.raise_for_status()  # 요청이 실패하면 예외를 발생시킴
        print("Log: Successfully sent the crash report to Slack.")

        # 언리얼 크래시 리포터에 성공 응답 전송
        return jsonify({"status": "success", "message": "Report sent to Slack."}), 200

    except ET.ParseError:
        print("Error: Failed to parse XML.")
        return "Bad Request: Invalid XML format.", 400
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to send message to Slack. {e}")
        return "Internal Server Error: Could not send to Slack.", 502
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "Internal Server Error", 500

# 서버를 직접 실행할 때 (로컬 테스트용)
if __name__ == '__main__':
    # Render 같은 프로덕션 환경에서는 이 부분이 실행되지 않습니다.
    # 대신 gunicorn이 app 객체를 직접 사용합니다.
    app.run(host='0.0.0.0', port=5000, debug=True)
