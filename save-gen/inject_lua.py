#!/usr/bin/env python3
"""
DST Save Lua Injector

Injects Lua code into Don't Starve Together PS4/PS5 save files.

Injection targets (in order of preference):
1. World save files (0000000003, 0000000002) - These are loaded via loadstring()
   as "return {ents={...}}". We prepend our code before the "return" statement.
   This is the most reliable vector since the game MUST load this to restore the world.

2. .meta files (0000000003.meta) - Plaintext Lua loaded by the game engine.
   Smaller, but loaded every time the save is accessed.

3. modoverrides.lua / leveldataoverride.lua - Plaintext Lua, loaded early.
   Good for simpler payloads.

Usage:
  python3 inject_lua.py <savedata.dat> <payload.lua> <output.dat> [--target world|meta|modoverrides]

The payload Lua code runs inside the game's Lua VM with access to the full
game API (TheSim, TheFrontEnd, etc.).
"""

import sys
import os
import struct
import zlib

# Add parent dir for kleipack import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'prosperous'))

import dst_save


def inject_into_world_save(file_entry, lua_payload):
    """Inject Lua code into a world save file (0000000003 etc).

    The world save is: 16-byte header + zlib(lua_code)
    where lua_code is: return {ents={...}, ...}

    We modify it to:
        <payload_code>
        return {ents={...}, ...}

    So the payload executes before the return statement.
    The return value is preserved so the game still loads the world data.

    IMPORTANT: The file content is padded to preserve the original size.
    The container format appears sensitive to file size changes.
    The game reads compressed_len from the binary header, so trailing
    padding bytes after the compressed data are ignored.
    """
    orig_content_size = len(file_entry.content)
    header_tuple, original_lua = dst_save.decompress_world_save(file_entry.content)

    if isinstance(lua_payload, str):
        lua_payload = lua_payload.encode('utf-8')

    modified_lua = lua_payload + b'\n' + original_lua

    # Compress at level 9 to minimize size, then pad to original file size
    compressed = zlib.compress(modified_lua, 9)
    new_header = struct.pack('<4I', header_tuple[0], header_tuple[1],
                             len(modified_lua), len(compressed))
    new_content = new_header + compressed

    if len(new_content) > orig_content_size:
        # Pad to next 4KB boundary beyond what we need
        padded_size = (len(new_content) + 0xFFF) & ~0xFFF
        new_content += b'\x00' * (padded_size - len(new_content))
        print(f'  Expanded file: {orig_content_size} -> {padded_size} (+{padded_size - orig_content_size})')
    else:
        # Pad to exact original size
        new_content += b'\x00' * (orig_content_size - len(new_content))

    file_entry.content = new_content
    return len(modified_lua)


def inject_into_meta(file_entry, lua_payload):
    """Inject Lua code into a .meta file.

    Original: return {world_network={...}}
    Modified: pcall(function() <payload> end) return {world_network={...}}

    Padded to original size to preserve container layout.
    """
    orig_size = len(file_entry.content)
    original = file_entry.content

    if isinstance(lua_payload, str):
        lua_payload = lua_payload.encode('utf-8')

    wrapped = (
        b'pcall(function()\n'
        + lua_payload + b'\n'
        b'end)\n'
    )

    new_content = wrapped + original
    if len(new_content) < orig_size:
        new_content += b' ' * (orig_size - len(new_content))
    elif len(new_content) > orig_size:
        print(f'  WARNING: meta content {len(new_content)} > original {orig_size}')

    file_entry.content = new_content
    return len(file_entry.content)


def inject_into_lua_file(file_entry, lua_payload):
    """Inject into modoverrides.lua or leveldataoverride.lua.

    Padded to original size to preserve container layout.
    """
    return inject_into_meta(file_entry, lua_payload)


def find_session_dir(save_dir):
    """Find the session directory inside a save dir."""
    session = save_dir.find('session')
    if session and isinstance(session, dst_save.SaveDir) and session.children:
        return session.children[0]  # First (usually only) session
    return None


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Inject Lua into DST save files')
    parser.add_argument('save_file', help='Input savedata.dat')
    parser.add_argument('payload', help='Lua payload file to inject')
    parser.add_argument('output', help='Output save file')
    parser.add_argument('--target', choices=['world', 'meta', 'modoverrides', 'leveldata', 'all-world'],
                        default='world',
                        help='Injection target (default: world)')
    parser.add_argument('--shard', choices=['master', 'caves', 'both'], default='master',
                        help='Which shard to inject into (default: master)')
    parser.add_argument('--no-wrap', action='store_true',
                        help='Do not wrap payload in pcall (for debugging)')
    args = parser.parse_args()

    data = open(args.save_file, 'rb').read()
    root = dst_save.parse_save(data)

    lua_payload = open(args.payload, 'rb').read()
    print(f'Payload: {len(lua_payload)} bytes')

    dst_dir = root.find('DoNotStarveTogether')
    cluster = dst_dir.find('Cluster_1')

    shards = []
    if args.shard in ('master', 'both'):
        master = cluster.find('Master')
        if master:
            shards.append(('Master', master))
    if args.shard in ('caves', 'both'):
        caves = cluster.find('Caves')
        if caves:
            shards.append(('Caves', caves))

    if not shards:
        print('ERROR: No shards found')
        sys.exit(1)

    injected = 0

    for shard_name, shard in shards:
        if args.target == 'world' or args.target == 'all-world':
            save = shard.find('save')
            session = find_session_dir(save)
            if session:
                for child in session.children:
                    if isinstance(child, dst_save.SaveFile) and child.name.startswith('000000') and not child.name.endswith('.meta'):
                        size = inject_into_world_save(child, lua_payload)
                        print(f'  Injected into {shard_name}/save/session/{session.name}/{child.name} ({size} bytes)')
                        injected += 1
                        if args.target == 'world':
                            break  # Only inject into first world save

        elif args.target == 'meta':
            save = shard.find('save')
            session = find_session_dir(save)
            if session:
                for child in session.children:
                    if isinstance(child, dst_save.SaveFile) and child.name.endswith('.meta'):
                        size = inject_into_meta(child, lua_payload)
                        print(f'  Injected into {shard_name}/save/session/{session.name}/{child.name} ({size} bytes)')
                        injected += 1

        elif args.target == 'modoverrides':
            target = shard.find('modoverrides.lua')
            if target:
                size = inject_into_lua_file(target, lua_payload)
                print(f'  Injected into {shard_name}/modoverrides.lua ({size} bytes)')
                injected += 1

        elif args.target == 'leveldata':
            target = shard.find('leveldataoverride.lua')
            if target:
                size = inject_into_lua_file(target, lua_payload)
                print(f'  Injected into {shard_name}/leveldataoverride.lua ({size} bytes)')
                injected += 1

    if injected == 0:
        print('ERROR: No injection targets found')
        sys.exit(1)

    output = dst_save.serialize_save(root)
    open(args.output, 'wb').write(output)
    print(f'\nWritten: {args.output} ({len(output)} bytes, {injected} file(s) modified)')


if __name__ == '__main__':
    main()
