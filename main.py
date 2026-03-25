import os
import stat
import subprocess
import json
import threading
import tkinter as tk
import urllib.request
import urllib.error
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

class SecurityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Norton Security Auditor")

        width, height = 1000, 700
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e1e")

        self.findings = []
        self.is_scanning = False
        self.risky_ports = {'21': 'FTP', '23': 'Telnet', '80': 'HTTP', '22': 'SSH', '445': 'SMB', '3389': 'RDP'}

        self.apply_styles()
        self.setup_ui()

    def apply_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#2d2d2d", foreground="white", fieldbackground="#2d2d2d", rowheight=25)
        style.configure("Treeview.Heading", background="#333333", foreground="white", font=('Segoe UI', 10, 'bold'))
        style.configure("TProgressbar", thickness=10, background="#2ecc71")
        style.configure("TCombobox", fieldbackground="#333333", background="#333333", foreground="white")

    def setup_ui(self):
        self.header = tk.Frame(self.root, bg="#252526", height=60)
        self.header.pack(side="top", fill="x")
        tk.Label(self.header, text="🛡️   SECURITY AUDITOR", bg="#252526", fg="#2ecc71", font=("Segoe UI", 14, "bold")).pack(side="left", padx=20, pady=15)

        ctrl = tk.Frame(self.header, bg="#252526")
        ctrl.pack(side="right", padx=10)

        self.scan_mode = ttk.Combobox(ctrl, values=["Полная проверка", "Файловая проверка", "Сетевая проверка", "Проверка CVE (ПО)"], state="readonly", width=18)
        self.scan_mode.set("Полная проверка")
        self.scan_mode.pack(side="left", padx=5)

        self.btn_start = tk.Button(ctrl, text="ЗАПУСК", command=self.start_scan, bg="#2ecc71", fg="white", relief="flat", padx=15, font=("Segoe UI", 9, "bold"))
        self.btn_start.pack(side="left", padx=5)

        self.btn_stop = tk.Button(ctrl, text="ОТМЕНА", command=self.stop_scan, bg="#e74c3c", fg="white", relief="flat", padx=15, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        self.btn_save = tk.Button(ctrl, text="ЭКСПОРТ", command=self.save_to_json, bg="#3498db", fg="white", relief="flat", padx=15)
        self.btn_save.pack(side="left", padx=5)

        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate", style="TProgressbar")
        self.progress.pack(fill="x")

        self.tree_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.tree_frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.tree = ttk.Treeview(self.tree_frame, columns=("cat", "tgt", "thr", "fix"), show="headings")
        for col, head in zip(("cat", "tgt", "thr", "fix"), ("КАТЕГОРИЯ", "ОБЪЕКТ", "УГРОЗА", "РЕКОМЕНДАЦИЯ")):
            self.tree.heading(col, text=head)
            self.tree.column(col, width=150)
        self.tree.pack(side="left", fill="both", expand=True)

        self.log_text = tk.Text(self.root, height=10, bg="#000000", fg="#00ff00", font=("Consolas", 10), borderwidth=0, padx=10, pady=10)
        self.log_text.pack(fill="x", side="bottom", padx=20, pady=(0, 20))

    def log(self, msg):
        self.log_text.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see("end")

    def start_scan(self):
        if self.is_scanning: return
        self.tree.delete(*self.tree.get_children())
        self.log_text.delete("1.0", "end")
        self.findings = []
        self.is_scanning = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        threading.Thread(target=self.scan_logic_router, daemon=True).start()

    def stop_scan(self):
        self.is_scanning = False
        self.log(">> Остановка...")

    def scan_logic_router(self):
        try:
            mode = self.scan_mode.get()
            self.log(f"СТАРТ: {mode.upper()}")

            if self.is_scanning and mode in ["Полная проверка", "Проверка CVE (ПО)"]:
                self.check_cve(30 if mode == "Полная проверка" else 100)

            if self.is_scanning and mode in ["Полная проверка", "Файловая проверка"]:
                # Определяем смещение прогресса (30-80% если полная, 0-100% если файловая)
                start = 30 if mode == "Полная проверка" else 0
                limit = 50 if mode == "Полная проверка" else 100
                self.check_permissions(start, limit)

            if self.is_scanning and mode in ["Полная проверка", "Сетевая проверка"]:
                self.scan_network()

            if self.is_scanning:
                self.progress['value'] = 100
                self.log("АУДИТ ЗАВЕРШЕН.")
                messagebox.showinfo("Готово", f"Найдено проблем: {len(self.findings)}")
        except Exception as e:
            self.log(f"ОШИБКА: {e}")
        finally:
            self.is_scanning = False
            self.btn_start.config(state="normal")
            self.btn_stop.config(state="disabled")

    def check_cve(self, limit):
        self.log("Анализ CVE...")
        try:
            packages = list(importlib.metadata.distributions())
            total = len(packages)
            for i, pkg in enumerate(packages):
                if not self.is_scanning: break
                self.progress['value'] = (i / total) * limit
                name, ver = pkg.metadata['Name'], pkg.version
                try:
                    url = "https://api.osv.dev"
                    data = json.dumps({"version": ver, "package": {"name": name, "ecosystem": "PyPI"}}).encode()
                    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        res = json.loads(resp.read().decode())
                        if 'vulns' in res:
                            for v in res['vulns']:
                                self.log_issue("CVE", f"{name} {ver}", v.get('id'), f"pip install --upgrade {name}")
                except: continue
        except Exception as e: self.log(f"CVE Error: {e}")

    def check_permissions(self, start_val, limit_val):
        self.log("Глубокое сканирование директорий...")
        paths = ['/etc', '/var/www', '/home'] if os.name != 'nt' else [os.environ.get('USERPROFILE'), 'C:\\Windows\\Temp']
        sensitive_keywords = ['ssh', 'config', 'ssl', 'key', 'auth', 'db', 'backup']
        target_dirs = []
        for p in paths:
            if os.path.exists(p): target_dirs.append(p)

        processed = 0
        for base_path in target_dirs:
            if not self.is_scanning: break
            self.log(f"Проверка: {base_path}")

            for root, dirs, files in os.walk(base_path):
                if not self.is_scanning: break


                processed += 1
                if processed % 50 == 0:
                    self.progress['value'] = start_val + (min(processed / 1000, 1) * limit_val)

                for name in dirs:
                    path = os.path.join(root, name)
                    try:
                        info = os.lstat(path)
                        mode = info.st_mode


                        if (mode & stat.S_IWOTH) and "/tmp" not in path:

                            self.log_issue("Права", path, "Запись разрешена всем", "chmod 755")


                        if any(k in name.lower() for k in sensitive_keywords):
                            if (mode & stat.S_IROTH) or (mode & stat.S_IXOTH):
                                self.log_issue("Приватность", path, "Публичный доступ к конфигам", "chmod 700")
                    except (PermissionError, OSError):
                        continue

    def scan_network(self):
        self.log("Сканирование сети...")
        cmd = ['netstat', '-ano'] if os.name == 'nt' else ['ss', '-tulpn']
        try:
            raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            for port, desc in self.risky_ports.items():
                if f":{port}" in raw:
                    self.log_issue("Сеть", f"Порт {port}", f"Активен ({desc})", "Закрыть порт")
        except: self.log("Ошибка сетевой утилиты.")

    def log_issue(self, category, target, threat, fix):
        self.findings.append({"category": category, "target": target, "threat": threat, "fix": fix})
        self.tree.insert("", "end", values=(category, target, threat, fix))

    def save_to_json(self):
        if not self.findings:
            messagebox.showwarning("Внимание", "Нет данных для сохранения.")
            return


        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name = f"report_{timestamp}.json"

        try:
            with open(file_name, 'w', encoding='utf-8') as f:
                json.dump({
                    "scan_info": {
                        "timestamp": datetime.now().isoformat(),
                        "total_issues": len(self.findings)
                    },
                    "audit_report": self.findings
                }, f, indent=4, ensure_ascii=False)

            self.log(f"ОТЧЕТ СОЗДАН: {file_name}")
            messagebox.showinfo("Успех", f"Файл сохранен как:\n{file_name}")
        except Exception as e:
            self.log(f"ОШИБКА СОХРАНЕНИЯ: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityScannerGUI(root)
    root.mainloop()
