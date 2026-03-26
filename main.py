import os
import stat
import subprocess
import json
import threading
import tkinter as tk
import urllib.request
import urllib.error
import importlib.metadata
import concurrent.futures
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

class SecurityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Progers Security Auditor")
        width, height = 1000, 700
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e1e")

        self.findings = []
        self.is_scanning = False
        self.risky_ports = {'21': 'FTP', '23': 'Telnet', '80': 'HTTP', '22': 'SSH', '445': 'SMB', '3389': 'RDP'}

        self.critical_software = {
            'nginx': '1.26.0', 'openssh-server': '9.0', 'openssl': '3.0.0',
            'apache2': '2.4.50', 'docker-ce': '24.0.0', 'python3': '3.10.0',
            'postgresql': '15.0', 'redis-server': '7.0.0', 'sudo': '1.9.0'
        }

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
        tk.Label(self.header, text="🛡️    SECURITY AUDITOR", bg="#252526", fg="#2ecc71", font=("Segoe UI", 14, "bold")).pack(side="left", padx=20, pady=15)

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

    def log_issue(self, category, target, threat, fix):
        self.findings.append({"category": category, "target": target, "threat": threat, "fix": fix})
        self.root.after(0, lambda: self.tree.insert("", "end", values=(category, target, threat, fix)))

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
        self.log(">> Остановка процесса...")

    def scan_logic_router(self):
        try:
            mode = self.scan_mode.get()
            self.log(f"СТАРТ: {mode.upper()}")

            if self.is_scanning and mode in ["Полная проверка", "Проверка CVE (ПО)"]:
                self.check_packages()
                self.check_cve(30 if mode == "Полная проверка" else 100)

            if self.is_scanning and mode in ["Полная проверка", "Файловая проверка"]:
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
            self.root.after(0, lambda: self.btn_start.config(state="normal"))
            self.root.after(0, lambda: self.btn_stop.config(state="disabled"))

    def check_packages(self):
        self.log("Анализ системных версий ПО...")
        start_time = datetime.now()
        try:
            pkgs = subprocess.check_output(['dpkg-query', '-W', '-f=${Package} ${Version}\n'], text=True)
            lines = pkgs.splitlines()

            for i, line in enumerate(lines):
                if not self.is_scanning or (datetime.now() - start_time).total_seconds() > 5:
                    self.log(f"(!) Анализ системного ПО прерван по тайм-ауту")
                    break

                parts = line.split()
                if len(parts) < 2: continue
                name, version = parts[0], parts[1]

                clean_ver = version.split('-')[0].split('+')[0]

                if name in self.critical_software:
                    if clean_ver < self.critical_software[name]:
                        self.log_issue("Software", name, f"Версия {version} устарела", f"apt upgrade {name}")
        except Exception as e:
            self.log(f"[!] Ошибка dpkg: {e}")

    def check_cve(self, limit):
        self.log("Запрос к OSV API (Python packages)")
        start_time = datetime.now()
        try:
            packages = list(importlib.metadata.distributions())
            total = len(packages)

            for i, pkg in enumerate(packages):
                if not self.is_scanning or (datetime.now() - start_time).total_seconds() > 5:
                    self.log(f"(!) Анализ CVE прерван по тайм-ауту")
                    break

                self.progress['value'] = (i / total) * limit
                name, ver = pkg.metadata['Name'], pkg.version
                try:
                    url = "https://api.osv.dev"
                    data = json.dumps({"version": ver, "package": {"name": name, "ecosystem": "PyPI"}}).encode()
                    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        res = json.loads(resp.read().decode())
                        if 'vulns' in res:
                            for v in res['vulns']:
                                self.log_issue("CVE", f"{name} {ver}", v.get('id'), f"pip install --upgrade {name}")
                except: continue
        except Exception as e:
            self.log(f"CVE Error: {e}")

    def check_permissions(self, start_val, limit_val):
        self.log("Глубокое сканирование директорий...")
        paths = ['/etc', '/home', '/var', '/root', '/tmp'] if os.name != 'nt' else [os.environ.get('USERPROFILE'), 'C:\\Windows\\Temp']
        sensitive_keywords = [
            'ssh', 'config', 'ssl', 'key', 'auth', 'db', 'backup',
            'password', '.env', 'id_rsa', 'shadow', 'history', 'mysql'
        ]

        target_dirs = [p for p in paths if os.path.exists(p)]
        processed_files = 0

        for base_path in target_dirs:
            if not self.is_scanning: break
            self.log(f"Вход в директорию: {base_path}")

            for root, dirs, files in os.walk(base_path):
                if not self.is_scanning: break

                if root.count(os.sep) > 6: continue

                for name in dirs + files:
                    processed_files += 1
                    path = os.path.join(root, name)

                    if processed_files % 100 == 0:
                        self.progress['value'] = start_val + (min(processed_files / 5000, 1) * limit_val)

                    try:
                        info = os.lstat(path)
                        mode = info.st_mode
                        if (mode & stat.S_IWOTH) and "/tmp" not in path:
                            self.log_issue("Уязвимость", path, "Файл доступен для записи всем", "chmod o-w")

                        if (mode & stat.S_ISUID) or (mode & stat.S_ISGID):
                            self.log_issue("Права", path, "Установлен SUID/SGID бит", "Проверить легитимность")

                        if any(k in name.lower() for k in sensitive_keywords):
                            if (mode & stat.S_IROTH) or (mode & stat.S_IXOTH) or (mode & stat.S_IWGRP):
                                self.log_issue("Приватность", path, "Конфиденциальный файл открыт для других", "chmod 600")

                    except (PermissionError, OSError):
                        continue

        self.log(f"Проверка файлов завершена. Обработано объектов: {processed_files}")
        self.root.after(0, lambda: self.progress.configure(value=start_val + limit_val))

    def scan_network(self):
        self.log("Сканирование сети...")
        cmd = ['netstat', '-ano'] if os.name == 'nt' else ['ss', '-tulpn']
        try:
            raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            for port, desc in self.risky_ports.items():
                if f":{port}" in raw or f" {port} " in raw:
                    self.log_issue("Сеть", f"Порт {port}", f"Активен ({desc})", "Закрыть порт или Firewall")
        except: self.log("Ошибка сетевой утилиты.")

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

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityScannerGUI(root)
    root.mainloop()
