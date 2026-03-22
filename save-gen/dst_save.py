#!/usr/bin/env python3
"""
DST (Don't Starve Together) PS4/PS5 Save Container Parser/Repacker

The save container is a simple filesystem with this structure:
  root/
    /DoNotStarveTogether/      (empty dir, path reference)
    DoNotStarveTogether/
      Cluster_1/
        cluster_token.txt
        cluster.ini
        Caves/
          save/
            saveindex          (KLEI format - Lua table)
            profile            (KLEI compressed - JSON)
            session/<id>/
              0000000003       (binary: 16-byte hdr + zlib compressed Lua world data)
              0000000003.meta  (plaintext Lua table)
              0000000002       (binary: same format)
          client_temp/
          server_temp/
          mod_config_data/
          server.ini
          modoverrides.lua     (plaintext Lua)
          leveldataoverride.lua (plaintext Lua)
        Master/
          (same structure as Caves)
      client_save/
        saveindex
        profile
        session/<id>/<user_id>/
          0000000001           (player data with 3-byte prefix)
        ...

File entry format (after the name):
  6 bytes: unknown/padding
  8 bytes: timestamp (u64)
  4 bytes: unknown flags (0 for text files, 4 for binary world saves)
  4 bytes: file size
  N bytes: file content

Dir entry format (after the name):
  2 bytes: padding
  4 bytes: child count
  8 bytes: timestamp
  4 bytes: unknown

All names are: u32 length, char[length] name, \0 null terminator, u8 type (0x40=dir, 0x80=file)
"""

import struct
import sys
import os
import zlib
import copy


class SaveEntry:
    """Base class for directory/file entries."""
    pass


class SaveDir(SaveEntry):
    def __init__(self, name, children=None, padding=b'\x00\x00',
                 child_count_raw=None, timestamp=0, unk=0):
        self.name = name
        self.children = children or []
        self.padding = padding
        self.timestamp = timestamp
        self.unk = unk

    def find(self, path):
        """Find entry by path like 'Cluster_1/Master/save/session'."""
        parts = path.strip('/').split('/', 1)
        for child in self.children:
            if child.name == parts[0]:
                if len(parts) == 1:
                    return child
                if isinstance(child, SaveDir):
                    return child.find(parts[1])
        return None

    def __repr__(self):
        return f'SaveDir({self.name}/, {len(self.children)} children)'


class SaveFile(SaveEntry):
    def __init__(self, name, content=b'', unk_prefix=b'\x00' * 6,
                 timestamp=0, unk_flags=0):
        self.name = name
        self.content = content
        self.unk_prefix = unk_prefix
        self.timestamp = timestamp
        self.unk_flags = unk_flags

    def __repr__(self):
        return f'SaveFile({self.name}, {len(self.content)} bytes)'


def parse_entry(data, pos):
    """Parse one entry (file or directory) from the container."""
    namelen = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    name = data[pos:pos + namelen].rstrip(b'\x00').decode('ascii')
    pos += namelen

    # null terminator + type byte
    pos += 1  # \0
    typebyte = data[pos]
    pos += 1

    if typebyte == 0x40:
        # Directory
        padding = data[pos:pos + 2]
        pos += 2
        child_count = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        timestamp = struct.unpack_from('<Q', data, pos)[0]
        pos += 8
        unk = struct.unpack_from('<I', data, pos)[0]
        pos += 4

        entry = SaveDir(name, padding=padding, timestamp=timestamp, unk=unk)
        for _ in range(child_count):
            child, pos = parse_entry(data, pos)
            entry.children.append(child)
        return entry, pos

    elif typebyte == 0x80:
        # File
        unk_prefix = data[pos:pos + 6]
        pos += 6
        timestamp = struct.unpack_from('<Q', data, pos)[0]
        pos += 8
        unk_flags = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        file_size = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        content = data[pos:pos + file_size]
        pos += file_size

        entry = SaveFile(name, content, unk_prefix, timestamp, unk_flags)
        return entry, pos

    else:
        raise ValueError(f'Unknown type byte 0x{typebyte:02x} at pos 0x{pos - 1:X}')


def serialize_entry(entry):
    """Serialize an entry back to bytes."""
    name_bytes = entry.name.encode('ascii')
    header = struct.pack('<I', len(name_bytes)) + name_bytes + b'\x00'

    if isinstance(entry, SaveDir):
        header += b'\x40'
        header += entry.padding
        header += struct.pack('<I', len(entry.children))
        header += struct.pack('<Q', entry.timestamp)
        header += struct.pack('<I', entry.unk)
        result = header
        for child in entry.children:
            result += serialize_entry(child)
        return result

    elif isinstance(entry, SaveFile):
        header += b'\x80'
        header += entry.unk_prefix
        header += struct.pack('<Q', entry.timestamp)
        header += struct.pack('<I', entry.unk_flags)
        header += struct.pack('<I', len(entry.content))
        header += entry.content
        return header


def parse_save(data):
    """Parse a complete save container."""
    root, end = parse_entry(data, 0)
    if end != len(data):
        print(f'Warning: parsed {end} of {len(data)} bytes')
    return root


def serialize_save(root):
    """Serialize the full save container back to bytes."""
    return serialize_entry(root)


def print_tree(entry, depth=0):
    """Print the directory tree."""
    indent = '  ' * depth
    if isinstance(entry, SaveDir):
        print(f'{indent}[DIR] {entry.name}/ ({len(entry.children)} children)')
        for child in entry.children:
            print_tree(child, depth + 1)
    elif isinstance(entry, SaveFile):
        preview = ''
        if entry.content:
            safe = ''.join(chr(b) if 32 <= b < 127 else '.' for b in entry.content[:60])
            preview = f' | {safe}'
        print(f'{indent}[FILE] {entry.name} ({len(entry.content)} bytes){preview}')


def decompress_world_save(content):
    """Decompress a numbered world save file (16-byte header + zlib)."""
    if len(content) < 16:
        return None
    header = struct.unpack_from('<4I', content, 0)
    decompressed = zlib.decompress(content[16:])
    return header, decompressed


def compress_world_save(header_tuple, lua_data):
    """Compress Lua data back into world save format."""
    if isinstance(lua_data, str):
        lua_data = lua_data.encode('ascii')
    compressed = zlib.compress(lua_data)
    version, flags = header_tuple[0], header_tuple[1]
    header = struct.pack('<4I', version, flags, len(lua_data), len(compressed))
    return header + compressed


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage:')
        print('  dst_save.py tree <save.dat>           - Print directory tree')
        print('  dst_save.py extract <save.dat> <dir>   - Extract all files')
        print('  dst_save.py roundtrip <save.dat> <out> - Parse and reserialize (test)')
        print('  dst_save.py inject <save.dat> <path> <lua_file> <out> - Inject Lua into a file')
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'tree':
        data = open(sys.argv[2], 'rb').read()
        root = parse_save(data)
        print_tree(root)

    elif cmd == 'extract':
        data = open(sys.argv[2], 'rb').read()
        outdir = sys.argv[3]
        root = parse_save(data)

        def extract_recursive(entry, path):
            if isinstance(entry, SaveDir):
                dirpath = os.path.join(path, entry.name)
                os.makedirs(dirpath, exist_ok=True)
                for child in entry.children:
                    extract_recursive(child, dirpath)
            elif isinstance(entry, SaveFile):
                filepath = os.path.join(path, entry.name)
                with open(filepath, 'wb') as f:
                    f.write(entry.content)
                # Also decompress world saves
                if entry.name.startswith('000000') and not entry.name.endswith('.meta'):
                    try:
                        hdr, decompressed = decompress_world_save(entry.content)
                        with open(filepath + '.lua', 'wb') as f:
                            f.write(decompressed)
                    except:
                        pass

        extract_recursive(root, outdir)
        print(f'Extracted to {outdir}/')

    elif cmd == 'roundtrip':
        data = open(sys.argv[2], 'rb').read()
        root = parse_save(data)
        reser = serialize_save(root)
        out = sys.argv[3]
        open(out, 'wb').write(reser)
        if data == reser:
            print('Round-trip OK - output matches input exactly')
        else:
            print(f'MISMATCH: input={len(data)} output={len(reser)}')
            # Find first difference
            for i in range(min(len(data), len(reser))):
                if data[i] != reser[i]:
                    print(f'First diff at 0x{i:X}: orig=0x{data[i]:02x} new=0x{reser[i]:02x}')
                    break

    elif cmd == 'inject':
        if len(sys.argv) < 6:
            print('Usage: dst_save.py inject <save.dat> <internal_path> <lua_file> <output.dat>')
            print()
            print('Internal paths (examples):')
            print('  Cluster_1/Caves/save/session/SESSION_ID/0000000003.meta')
            print('  Cluster_1/Master/save/session/SESSION_ID/0000000003.meta')
            print('  Cluster_1/Master/leveldataoverride.lua')
            print('  Cluster_1/Master/modoverrides.lua')
            sys.exit(1)

        save_path = sys.argv[2]
        internal_path = sys.argv[3]
        lua_file = sys.argv[4]
        output_path = sys.argv[5]

        data = open(save_path, 'rb').read()
        root = parse_save(data)

        # Navigate to the target file
        # The internal_path is relative to the DoNotStarveTogether dir
        dst_dir = root.find('DoNotStarveTogether')
        if dst_dir is None:
            print('ERROR: Could not find DoNotStarveTogether directory')
            sys.exit(1)

        target = dst_dir.find(internal_path)
        if target is None:
            print(f'ERROR: Could not find {internal_path}')
            print('Available paths:')
            print_tree(dst_dir, 1)
            sys.exit(1)

        if not isinstance(target, SaveFile):
            print(f'ERROR: {internal_path} is a directory, not a file')
            sys.exit(1)

        lua_content = open(lua_file, 'rb').read()

        # Determine how to inject based on file type
        if target.name.endswith('.meta') or target.name.endswith('.lua'):
            # Plaintext Lua - just replace content directly
            print(f'Injecting {len(lua_content)} bytes of Lua into {target.name} (plaintext)')
            target.content = lua_content
        elif target.name.startswith('000000'):
            # Binary world save - need to compress
            print(f'Injecting {len(lua_content)} bytes of Lua into {target.name} (compressed)')
            old_hdr, _ = decompress_world_save(target.content)
            target.content = compress_world_save(old_hdr, lua_content)
        elif target.name == 'saveindex':
            # KLEI format
            import kleipack
            print(f'Injecting {len(lua_content)} bytes into {target.name} (KLEI format)')
            target.content = kleipack.pack(lua_content)
        else:
            print(f'Injecting {len(lua_content)} bytes into {target.name} (raw)')
            target.content = lua_content

        output = serialize_save(root)
        open(output_path, 'wb').write(output)
        print(f'Written to {output_path} ({len(output)} bytes)')

    else:
        print(f'Unknown command: {cmd}')
        sys.exit(1)
