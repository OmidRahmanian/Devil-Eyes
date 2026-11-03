"""Configure this machine's private WSL installation without printing secrets."""
import hashlib
import io
import os
from pathlib import Path
import secrets
import subprocess
import sys
import urllib.request
import json
import zipfile

APP = Path('/home/omid/.local/share/watchtower/app')

def main():
    os.umask(0o077)
    env_path = APP / '.env'
    if '--database' in sys.argv:
        values = dict(line.split('=', 1) for line in env_path.read_text().splitlines() if '=' in line)
        password = values['WATCHTOWER__DATABASE__URL'].split(':', 2)[2].split('@')[0]
        # Passwords are generated as hexadecimal; never interpolate arbitrary input into SQL.
        if len(password) != 64 or any(c not in '0123456789abcdef' for c in password):
            raise RuntimeError('Unexpected local database password format')
        def sql(statement, database='postgres'):
            return subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', database], input=statement, text=True, capture_output=True, check=True).stdout.strip()
        if sql("SELECT 1 FROM pg_roles WHERE rolname='watchtower_local';") != '1':
            sql(f"CREATE ROLE watchtower_local LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '{password}';")
        if sql("SELECT 1 FROM pg_database WHERE datname='watchtower_local';") != '1':
            sql('CREATE DATABASE watchtower_local OWNER watchtower_local;')
        sql('REVOKE ALL ON DATABASE watchtower_local FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE watchtower_local TO watchtower_local;')
        sql('REVOKE CREATE ON SCHEMA public FROM PUBLIC; ALTER SCHEMA public OWNER TO watchtower_local;', 'watchtower_local')
        print('Private application role and database ready.')
        return
    if not env_path.exists():
        password = secrets.token_hex(32)
        env_path.write_text(f'WATCHTOWER__DATABASE__URL=postgresql+psycopg://watchtower_local:{password}@127.0.0.1:5432/watchtower_local\nWATCHTOWER_PROJECT=local\nWATCHTOWER_PROFILE=development\n')
        env_path.chmod(0o600)
    binary = APP / '.venv/bin/subfinder'
    if not binary.exists():
        def download(url):
            req = urllib.request.Request(url, headers={'User-Agent': 'WatchTower-local-installer'})
            with urllib.request.urlopen(req, timeout=90) as response:
                return response.read()
        release = json.loads(download('https://api.github.com/repos/projectdiscovery/subfinder/releases/latest'))
        archive = next(a for a in release['assets'] if a['name'].endswith('_linux_amd64.zip'))
        checksums = next(a for a in release['assets'] if a['name'].endswith('checksums.txt'))
        payload = download(archive['browser_download_url'])
        expected = next(line.split()[0] for line in download(checksums['browser_download_url']).decode().splitlines() if line.split()[-1] == archive['name'])
        if hashlib.sha256(payload).hexdigest() != expected:
            raise RuntimeError('Subfinder checksum verification failed')
        with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
            binary.write_bytes(bundle.read('subfinder'))
        binary.chmod(0o700)
        print(f"Installed Subfinder {release['tag_name']} (checksum verified).")

if __name__ == '__main__':
    main()
