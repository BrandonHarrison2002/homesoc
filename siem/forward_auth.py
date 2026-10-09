#!/usr/bin/env python3
"""Send complete auth.log lines to Splunk HEC, with a durable read position."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import time
import urllib.request
from urllib.parse import urlsplit

READ_LIMIT = 128 * 1024


def identity(stat):
    return [stat.st_dev, stat.st_ino]


def read_events(path, checkpoint, from_start=False):
    """Read one bounded block. Finish a renamed .1 file before the current log."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Symlink log is not supported')
    with path.open('rb') as current:
        stat = os.fstat(current.fileno())
        if checkpoint is None:
            checkpoint = {'identity': identity(stat),
                          'offset': 0 if from_start else stat.st_size}
        stream = current
        rotated = None
        try:
            if checkpoint['identity'] != identity(stat):
                old = Path(str(path) + '.1')
                if old.is_symlink():
                    raise ValueError('Symlink rotation is not supported')
                rotated = old.open('rb')
                if identity(os.fstat(rotated.fileno())) != checkpoint['identity']:
                    raise ValueError('Checkpoint log no longer retained; manual review required')
                stream = rotated
            offset = checkpoint['offset']
            if os.fstat(stream.fileno()).st_size < offset:
                raise ValueError('Log was truncated; manual review required')
            stream.seek(offset)
            block = stream.read(READ_LIMIT)
            if len(block) == READ_LIMIT and b'\n' not in block:
                raise ValueError('Log line exceeds read limit')
            result = []
            for raw in block.splitlines(keepends=True):
                if not raw.endswith(b'\n'):
                    break
                start = offset
                offset += len(raw)
                event_id = hashlib.sha256(
                    json.dumps([checkpoint['identity'], start]).encode() + raw
                ).hexdigest()
                result.append({
                    'host': socket.gethostname(), 'source': str(path),
                    'sourcetype': '_json', 'time': time.time(),
                    'event': {'event_type': 'ssh_auth_log', 'event_id': event_id,
                              'raw': raw.decode('utf-8', errors='replace').rstrip('\r\n'),
                              'timestamp_basis': 'forwarded_at', 'sample_data': False}
                })
            next_state = {'identity': checkpoint['identity'], 'offset': offset}
            if rotated is not None and offset == os.fstat(stream.fileno()).st_size:
                next_state = {'identity': identity(stat), 'offset': 0}
            return result, next_state
        finally:
            if rotated is not None:
                rotated.close()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('HEC redirects are rejected')


def send(events, endpoint, token, ca_file):
    url = urlsplit(endpoint)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path != '/services/collector/event'):
        raise ValueError('Expected direct HTTPS HEC event URL')
    if not token or '\n' in token or '\r' in token:
        raise ValueError('Invalid token file')
    context = ssl.create_default_context(cafile=ca_file)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=context))
    for start in range(0, len(events), 100):
        batch = [dict(event, index='homesoc') for event in events[start:start + 100]]
        request = urllib.request.Request(endpoint,
            data='\n'.join(json.dumps(e) for e in batch).encode(),
            headers={'Authorization': 'Splunk ' + token,
                     'Content-Type': 'application/json'}, method='POST')
        with opener.open(request, timeout=15) as response:
            result = json.loads(response.read(4096))
        if result.get('code') != 0:
            raise ValueError('HEC did not accept batch')


def save_checkpoint(path, checkpoint):
    temp = path.with_suffix('.tmp')
    with temp.open('w') as output:
        json.dump(checkpoint, output)
        output.flush()
        os.fsync(output.fileno())
    temp.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--from-start', action='store_true',
                        help='On first run only, include the existing current log')
    args = parser.parse_args()
    os.umask(0o077)
    config = Path.home() / '.config/homesoc'
    state_dir = Path.home() / '.local/state/homesoc-siem'
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_dir.chmod(0o700)
    state_path = state_dir / 'auth-checkpoint.json'
    with (state_dir / 'auth.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        checkpoint = json.loads(state_path.read_text()) if state_path.exists() else None
        events, next_state = read_events('/var/log/auth.log', checkpoint, args.from_start)
        if args.dry_run:
            print(f'Dry run: {len(events)} auth log events; nothing sent or saved')
            return
        if events:
            token_path = config / 'splunk-hec.token'
            if token_path.stat().st_mode & 0o077:
                raise ValueError('Token must be readable only by its owner (chmod 600)')
            send(events, 'https://192.168.8.239:8088/services/collector/event',
                 token_path.read_text().strip(), str(config / 'splunk-hec.crt'))
        save_checkpoint(state_path, next_state)
        print(f'HEC accepted {len(events)} events; read position saved')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Do not print token, event bodies, or server response text to the journal.
        print(f'Auth sender stopped ({type(exc).__name__}); read position retained. '
              'Check connectivity, certificate, token and retained log rotation.', file=sys.stderr)
        sys.exit(1)
