
# 🎻⚔️ Ama-slay

Lightweight custom python SQLi tester for Amadey C2 customized based off leak webapp infra from https://github.com/3rkut/AmadeyPanel/tree/main

## Features

- Tests tuned to specific Amadey .sql and .php webapp infrastructure
- Tor integration with new identity requests before each test block
- Output includes basic vulnerability status and response metadata


## Current Test Blocks

- `IncreaseCount()` SQLi
- `GetTaskContent()` SQLi
- Login bypass attempts
- Config file poisoning
- Destructive operations (e.g., table clearing)

## 🧰 Requirements

- Python 3.6+
- Tor service running locally with `ControlPort` enabled (default: `9051`)
- Python packages:
  - `requests`
  - `PySocks`

Install dependencies:

```bash
pip install requests pysocks
```

Ensure Tor is running with `ControlPort 9051` and the `HashedControlPassword` or `CookieAuthentication` configured.

## 🔧 Usage

```bash
python amaslay.py --url http://target-site.com --proxy 127.0.0.1:9050
```

The script will:
- Connect via the specified SOCKS5 proxy (Tor)
- Request a new identity between each test
- Print the external IP to confirm rotation
- Perform and print results for each vulnerability test
