import os
import stat
import subprocess
import json
from datetime import datetime

class SecurityScanner:
    def __init__(self):
        self.findings = []
        
        self.risky_ports = {
            '21': 'FTP (Insecure)', '23': 'Telnet (Insecure)', '25': 'SMTP', 
            '80': 'HTTP', '110': 'POP3', '135': 'RPC', '139': 'NetBIOS', 
            '445': 'SMB (EternalBlue Risk)', '1433': 'MSSQL', '3306': 'MySQL', 
            '3389': 'RDP', '5432': 'PostgreSQL', '6379': 'Redis', 
            '9200': 'ElasticSearch', '27017': 'MongoDB',
            '22': 'SSH'
        }
        
        self.critical_software = {
            'nginx': '1.26.0', 'openssh-server': '9.0', 'openssl': '3.0.0',
            'apache2': '2.4.50', 'docker-ce': '24.0.0', 'python3': '3.10.0',
            'postgresql': '15.0', 'redis-server': '7.0.0', 'sudo': '1.9.0'
        }

    def log_issue(self, category, target, threat, fix):
        self.findings.append({
            "category": category,
            "target": target,
            "threat": threat,
            "fix": fix,
            "timestamp": datetime.now().strftime('%H:%M:%S')
        })

    def check_permissions(self):
        print("[*] Сканирование прав доступа...")
        paths = ['/etc', '/var/www', '/home', '/opt', '/root', '/usr/local/bin']
        sensitive = ['.ssh', 'config', 'ssl', 'keys', 'auth', '.env', 'database', 'backup']

        for base in paths:
            if not os.path.exists(base): continue
            for root, dirs, _ in os.walk(base):
                for name in dirs:
                    path = os.path.join(root, name)
                    try:
                        info = os.stat(path)
                        mode = oct(info.st_mode)[-3:]
                        if mode == '777' and '/tmp' not in path:
                            self.log_issue("Permissions", path, "World-writable (777)", f"chmod 755 {path}")
                        if any(k in name.lower() for k in sensitive) and (info.st_mode & stat.S_IROTH):
                            self.log_issue("Privacy", path, "Sensitive data world-readable", f"chmod 700 {path}")
                    except (PermissionError, OSError):
                        continue

    def scan_network(self):
        print("[*] Анализ сетевой активности...")
        try:
            raw = subprocess.check_output(['ss', '-tulpn'], text=True)
            for port, desc in self.risky_ports.items():
                if f":{port} " in raw:
                    self.log_issue("Network", f"Port {port}", f"Potential risk: {desc}", f"ufw deny {port}")
        except Exception:
            print("[!] Ошибка доступа к сетевым утилитам.")

    def check_packages(self):
        print("[*] Анализ версий ПО и запросы к CVE API...")
        try:
            pkgs = subprocess.check_output(['dpkg-query', '-W', '-f=${Package} ${Version}\n'], text=True)
            for line in pkgs.splitlines():
                parts = line.split(' ')
                if len(parts) < 2: continue
                name, version = parts[0], parts[1]
                clean_ver = version.split('-')[0].split('+')[0]
                
                if name in self.critical_software:
                    if clean_ver < self.critical_software[name]:
                        self.log_issue("Software", name, f"Version {version} outdated", f"apt upgrade {name}")
                    self.fetch_cve_online(name)
        except Exception:
            print("[!] Система управления пакетами не поддерживается.")

    def fetch_cve_online(self, package_name):
        try:
            url = f"https://cve.circl.lu/api/search/{package_name}"
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                data = res.json()
                if isinstance(data, list) and len(data) > 0:
                    cve_id = data[0].get('id', 'N/A')
                    self.log_issue("CVE-API", package_name, f"Known vulnerability {cve_id}", "Update package immediately")
        except:
            pass

    def save_json_log(self):
        if not self.findings: return
        
        filename = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report = {
            "metadata": {
                "system": os.uname().nodename,
                "date": datetime.now().isoformat(),
                "total_issues": len(self.findings)
            },
            "issues": self.findings
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"[+] Подробный лог сохранен: {filename}")

    def generate_report(self):
        print("\n" + "="*115)
        print(f" SECURITY REPORT | HOST: {os.uname().nodename} | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("="*115 + "\n")

        if not self.findings:
            print("Система чиста. Критических уязвимостей не обнаружено.")
            return

        fmt = "{:<15} | {:<35} | {:<35} | {:<20}"
        print(fmt.format("CATEGORY", "TARGET", "THREAT", "RECOMMENDATION"))
        print("-" * 115)

        for item in self.findings:
            target = (item['target'][:32] + '..') if len(item['target']) > 34 else item['target']
            threat = (item['threat'][:32] + '..') if len(item['threat']) > 34 else item['threat']
            print(fmt.format(item['category'], target, threat, item['fix']))

        print(f"\n[!] Итого найдено проблем: {len(self.findings)}")
        self.save_json_log()

def show_menu():
    scanner = SecurityScanner()
    while True:
        print("\n--- Система Аудита Безопасности ---")
        print("1. Полный аудит")
        print("2. Проверка файлов")
        print("3. Проверка сети")
        print("4. Проверка ПО")
        print("0. Выход")
        
        choice = input("\nВыбор: ")

        if choice == '1':
            scanner.check_permissions()
            scanner.scan_network()
            scanner.check_packages()
            scanner.generate_report()
            break
        elif choice == '2':
            scanner.check_permissions()
            scanner.generate_report()
            break
        elif choice == '3':
            scanner.scan_network()
            scanner.generate_report()
            break
        elif choice == '4':
            scanner.check_packages()
            scanner.generate_report()
            break
        elif choice == '0':
            break
        else:
            print("Ошибка ввода.")

if __name__ == "__main__":
    show_menu()
