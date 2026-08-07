# Contributing to vulnlocal

Thanks for your interest in improving **vulnlocal**.

By participating, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md)
and use this project only for **authorized** research.

## What we welcome

- Bug fixes and reliability improvements
- Documentation / wiki / README clarity
- UI/UX fixes for the local Flask app
- Safer ingest/export edge cases
- Tests and accuracy improvements for version/CPE matching
- NSE script fixes (online API + offline `vulnlocal.pack`)

## What we do not accept

- Exploit runners, weaponized payloads, or PoCs aimed at unauthorized targets
- Credentials, API keys, or personal `settings.json` / database dumps
- Commits of `data/vulnlocal.db`, `downloads/`, or generated `vulnlocal.pack`
- HTML scraping of third-party UIs (feeds must stay official bulk/JSON APIs)

## Before you start

1. Search existing [Issues](https://github.com/sumitvibecoder/vulnlocal/issues)
2. Open an issue for larger changes so we can align on design
3. Read [SECURITY.md](SECURITY.md) for safe local deployment notes

## Development setup

```bash
git clone https://github.com/sumitvibecoder/vulnlocal.git
cd vulnlocal
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS:        source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py init-db
python run.py --dev --host 127.0.0.1 --port 8088
