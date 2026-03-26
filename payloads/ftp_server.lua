-- FTP Server for PS5 DST Exploit
-- Send via: cat ftp_server.lua | nc -q 0 <ps5_ip> 9066
--
-- Uses payload_us_eu.lua primitives (syscall, call, etc.)
-- Supports: USER, PASS, SYST, FEAT, PWD, CWD, CDUP, TYPE, PASV, PORT,
--           LIST, RETR, STOR, SIZE, DELE, MKD, RMD, RNFR, RNTO, REST,
--           SITE CHMOD, QUIT

local sc  = rawget(_G, "syscall")
local gsa = rawget(_G, "get_str_addr")
local rba = rawget(_G, "read_bytes_abs")
local r32 = rawget(_G, "read_u32_abs")
local r64 = rawget(_G, "read_u64_abs")
local plog = rawget(_G, "prosper_log") or function() end
local my_ip = rawget(_G, "my_ip") or "0.0.0.0"

if not sc then error("syscall not available") end

-- ============================================================
-- SYSCALL NUMBERS (FreeBSD / PS5)
-- ============================================================
local SYS_read       = 3
local SYS_write      = 4
local SYS_open       = 5
local SYS_close      = 6
local SYS_unlink     = 10
local SYS_chmod      = 15
local SYS_accept     = 30
local SYS_getsockname = 32
local SYS_socket     = 97
local SYS_connect    = 98
local SYS_bind       = 104
local SYS_setsockopt = 105
local SYS_listen     = 106
local SYS_rename     = 128
local SYS_mkdir      = 136
local SYS_rmdir      = 137
local SYS_stat       = 188
local SYS_getdents   = 272
local SYS_lseek      = 478

local AF_INET       = 2
local SOCK_STREAM   = 1
local SOL_SOCKET    = 0xFFFF
local SO_REUSEADDR  = 4
local FTP_PORT      = 1337

-- ============================================================
-- MEMORY HELPERS
-- ============================================================
local _hold = {}
local _aid = 0

local function le32(v)
    return string.char(v % 256, math.floor(v / 256) % 256,
                       math.floor(v / 65536) % 256, math.floor(v / 16777216) % 256)
end

local function alloc(n)
    _aid = _aid + 1
    local s = le32(_aid) .. string.rep("\0", n)
    _hold[#_hold + 1] = s
    return gsa(s) + 24 + 4
end

local function str_ptr(s)
    _hold[#_hold + 1] = s
    return gsa(s) + 24
end

local function cstr(s)
    local z = s .. "\0"
    _hold[#_hold + 1] = z
    return gsa(z) + 24
end

local function int_ptr(val)
    local s = le32(val) .. "\0\0\0\0"
    _hold[#_hold + 1] = s
    return gsa(s) + 24
end

local function is_err(v)
    return not v or v >= 0x80000000
end

local function read_u8(addr)
    local b = rba(addr, 1)
    return b and b[1] or 0
end

local function read_u16_le(addr)
    local b = rba(addr, 2)
    if not b then return 0 end
    return b[1] + b[2] * 256
end

local function read_u16_be(addr)
    local b = rba(addr, 2)
    if not b then return 0 end
    return b[1] * 256 + b[2]
end

local function read_str(addr, maxlen)
    local b = rba(addr, maxlen or 256)
    if not b then return "" end
    local t = {}
    for i = 1, #b do
        if b[i] == 0 then break end
        t[#t + 1] = string.char(b[i])
    end
    return table.concat(t)
end

local function read_buf(addr, len)
    local b = rba(addr, len)
    if not b then return "" end
    local t = {}
    for i = 1, #b do t[i] = string.char(b[i]) end
    return table.concat(t)
end

-- ============================================================
-- SOCKADDR HELPERS
-- ============================================================
local function make_sockaddr_in(port, ip_bytes)
    ip_bytes = ip_bytes or {0, 0, 0, 0}
    local s = string.char(16, AF_INET,
        math.floor(port / 256), port % 256,
        ip_bytes[1], ip_bytes[2], ip_bytes[3], ip_bytes[4])
        .. string.rep("\0", 8)
    _hold[#_hold + 1] = s
    return gsa(s) + 24
end

local function parse_ip(ip_str)
    local a, b, c, d = ip_str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if not a then return {0, 0, 0, 0} end
    return {tonumber(a), tonumber(b), tonumber(c), tonumber(d)}
end

-- ============================================================
-- FTP STATE
-- ============================================================
local CONN_NONE, CONN_ACTIVE, CONN_PASSIVE = 0, 1, 2

local srv_fd = nil
local ctrl_fd = nil
local data_fd = nil
local pasv_fd = nil
local data_sockaddr = nil
local conn_type = CONN_NONE
local cur_path = "/"
local xfer_type = "I"
local restore_pt = 0
local ren_from = ""

-- ============================================================
-- SOCKET I/O (using read/write syscalls on TCP sockets)
-- ============================================================
local function sock_write_raw(fd, buf, len)
    local rem = len
    local off = 0
    while rem > 0 do
        local n = sc(SYS_write, fd, buf + off, rem)
        if is_err(n) or n == 0 then return off end
        off = off + n
        rem = rem - n
    end
    return off
end

local function sock_write_str(fd, str)
    local addr = str_ptr(str)
    sock_write_raw(fd, addr, #str)
end

local function ctrl_msg(msg)
    sock_write_str(ctrl_fd, msg)
end

local function data_fd_active()
    return conn_type == CONN_PASSIVE and pasv_fd or data_fd
end

local function data_msg(msg)
    sock_write_str(data_fd_active(), msg)
end

local function data_send_raw(buf, len)
    sock_write_raw(data_fd_active(), buf, len)
end

local function data_recv_raw(buf, len)
    return sc(SYS_read, data_fd_active(), buf, len)
end

-- ============================================================
-- DATA CONNECTION MANAGEMENT
-- ============================================================
local function open_data_conn()
    if conn_type == CONN_ACTIVE then
        sc(SYS_connect, data_fd, data_sockaddr, 16)
    elseif conn_type == CONN_PASSIVE then
        local pa = alloc(16)
        local pl = int_ptr(16)
        pasv_fd = sc(SYS_accept, data_fd, pa, pl)
    end
end

local function close_data_conn()
    if data_fd then sc(SYS_close, data_fd) end
    if conn_type == CONN_PASSIVE and pasv_fd then
        sc(SYS_close, pasv_fd)
    end
    data_fd = nil
    pasv_fd = nil
    conn_type = CONN_NONE
end

-- ============================================================
-- PATH HELPERS
-- ============================================================
local function sanitize_path(base, name)
    if name:sub(1, 1) == "/" then return name end
    if base == "/" then return "/" .. name end
    return base .. "/" .. name
end

local function dir_up(path)
    if path == "/" then return "/" end
    return path:match("^(.*)/") or "/"
end

-- ============================================================
-- STAT / PERMISSION HELPERS
-- ============================================================
-- stat struct offsets (FreeBSD PS5):
--   +8:  st_mode  (uint16)
--   +72: st_size  (int64)

local function do_stat(path_str)
    local st = alloc(128)
    local p = cstr(path_str)
    local ret = sc(SYS_stat, p, st)
    if is_err(ret) then return nil end
    return st
end

local function list_perms(mode)
    local ft = math.floor(mode / 4096) % 16
    local c = ({[4] = 'd', [8] = '-', [10] = 'l', [2] = 'c',
                [6] = 'b', [1] = 'p', [12] = 's'})[ft] or '?'
    local masks = {
        {256, 'r'}, {128, 'w'}, {64, 'x'},
        {32, 'r'},  {16, 'w'},  {8, 'x'},
        {4, 'r'},   {2, 'w'},   {1, 'x'}
    }
    for _, m in ipairs(masks) do
        c = c .. (math.floor(mode / m[1]) % 2 > 0 and m[2] or '-')
    end
    return c
end

-- ============================================================
-- FTP COMMAND HANDLERS
-- ============================================================
local function cmd_USER() ctrl_msg("331 Username ok, send password\r\n") end
local function cmd_PASS() ctrl_msg("230 User logged in\r\n") end
local function cmd_NOOP() ctrl_msg("200 OK\r\n") end
local function cmd_SYST() ctrl_msg("215 UNIX Type: L8\r\n") end

local function cmd_FEAT()
    ctrl_msg("211-Extensions\r\n REST STREAM\r\n SIZE\r\n UTF8\r\n211 End\r\n")
end

local function cmd_PWD()
    ctrl_msg(string.format('257 "%s" is the current directory\r\n', cur_path))
end

local function cmd_TYPE(arg)
    if arg == "I" or arg == "A" then
        xfer_type = arg
        ctrl_msg("200 Type set to " .. arg .. "\r\n")
    else
        ctrl_msg("504 Type not supported\r\n")
    end
end

local function cmd_CWD(arg)
    if not arg or arg == "" then ctrl_msg("500 Missing argument\r\n"); return end
    local new_path
    if arg == "/" then
        new_path = "/"
    elseif arg == ".." then
        new_path = dir_up(cur_path)
    elseif arg:sub(1, 1) == "/" then
        new_path = arg
    elseif cur_path == "/" then
        new_path = "/" .. arg
    else
        new_path = cur_path .. "/" .. arg
    end
    -- Allow root always; verify others via stat
    if new_path == "/" or do_stat(new_path) then
        cur_path = new_path
        ctrl_msg("250 Directory changed\r\n")
    else
        ctrl_msg("550 Directory not found\r\n")
    end
end

local function cmd_CDUP()
    if cur_path ~= "/" then
        cur_path = dir_up(cur_path)
    end
    ctrl_msg("200 Command okay\r\n")
end

local function cmd_PASV()
    local ip = parse_ip(my_ip)
    data_fd = sc(SYS_socket, AF_INET, SOCK_STREAM, 0)
    if is_err(data_fd) then
        ctrl_msg("425 Can't open data connection\r\n")
        return
    end
    -- Bind to port 0 (OS picks)
    local sa = make_sockaddr_in(0, ip)
    sc(SYS_bind, data_fd, sa, 16)
    sc(SYS_listen, data_fd, 1)

    -- Get assigned port
    local picked = alloc(16)
    local namelen = int_ptr(16)
    sc(SYS_getsockname, data_fd, picked, namelen)
    local port = read_u16_be(picked + 2)

    local p_hi = math.floor(port / 256)
    local p_lo = port % 256
    ctrl_msg(string.format("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
        ip[1], ip[2], ip[3], ip[4], p_hi, p_lo))
    conn_type = CONN_PASSIVE
end

local function cmd_PORT(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local ip1, ip2, ip3, ip4, ph, pl = arg:match("(%d+),(%d+),(%d+),(%d+),(%d+),(%d+)")
    if not ip1 then ctrl_msg("500 Bad PORT format\r\n"); return end
    local port = tonumber(ph) * 256 + tonumber(pl)

    data_fd = sc(SYS_socket, AF_INET, SOCK_STREAM, 0)
    if is_err(data_fd) then
        ctrl_msg("425 Can't open data connection\r\n")
        return
    end
    data_sockaddr = make_sockaddr_in(port,
        {tonumber(ip1), tonumber(ip2), tonumber(ip3), tonumber(ip4)})
    conn_type = CONN_ACTIVE
    ctrl_msg("200 PORT command ok\r\n")
end

local function cmd_LIST()
    local st_buf = alloc(128)
    local p = cstr(cur_path)
    if is_err(sc(SYS_stat, p, st_buf)) then
        ctrl_msg("550 Directory not found\r\n")
        return
    end

    local fd = sc(SYS_open, p, 0, 0)
    if is_err(fd) then
        ctrl_msg("550 Can't open directory\r\n")
        return
    end

    ctrl_msg("150 Opening data transfer for LIST\r\n")
    open_data_conn()

    local dents = alloc(4096)
    while true do
        local nread = sc(SYS_getdents, fd, dents, 4096)
        if is_err(nread) or nread == 0 then break end

        local off = 0
        while off < nread do
            local reclen = read_u16_le(dents + off + 4)
            if reclen == 0 then break end
            local name = read_str(dents + off + 8, reclen - 8)

            if name ~= "" and name ~= "." and name ~= ".." then
                local full = cur_path == "/" and ("/" .. name)
                    or (cur_path .. "/" .. name)
                local fst = do_stat(full)
                if fst then
                    local mode = read_u16_le(fst + 8)
                    local size_lo = r32(fst + 72) or 0
                    local perms = list_perms(mode)
                    local line = string.format(
                        "%s 1 root root %10d Jan  1  2025 %s\r\n",
                        perms, size_lo, name)
                    data_msg(line)
                end
            end
            off = off + reclen
        end
    end

    sc(SYS_close, fd)
    close_data_conn()
    ctrl_msg("226 Transfer complete\r\n")
end

local function cmd_SIZE(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local path = sanitize_path(cur_path, arg)
    local st = do_stat(path)
    if not st then
        ctrl_msg("550 File not found\r\n")
        return
    end
    local size = r32(st + 72) or 0
    ctrl_msg(string.format("213 %d\r\n", size))
end

local function cmd_RETR(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local path = sanitize_path(cur_path, arg)
    local st = do_stat(path)
    if not st then
        ctrl_msg("550 File not found\r\n")
        return
    end
    local file_size = r32(st + 72) or 0

    local fd = sc(SYS_open, cstr(path), 0, 0)
    if is_err(fd) then
        ctrl_msg("550 Can't open file\r\n")
        return
    end

    if restore_pt > 0 then
        sc(SYS_lseek, fd, restore_pt, 0)
    end

    open_data_conn()
    ctrl_msg("150 Opening data transfer\r\n")

    local chunk_sz = 8192
    local buf = alloc(chunk_sz)
    local sent = 0
    while sent < file_size do
        local to_read = math.min(chunk_sz, file_size - sent)
        local n = sc(SYS_read, fd, buf, to_read)
        if is_err(n) or n == 0 then break end
        data_send_raw(buf, n)
        sent = sent + n
    end

    sc(SYS_close, fd)
    close_data_conn()
    ctrl_msg("226 Transfer complete\r\n")
    restore_pt = 0
end

local function cmd_STOR(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local path = sanitize_path(cur_path, arg)

    -- O_CREAT=0x200, O_RDWR=0x2, O_TRUNC=0x400
    local flags = 0x202 -- O_CREAT | O_RDWR
    if restore_pt > 0 then
        flags = 0x20A -- O_CREAT | O_RDWR | O_APPEND
    else
        flags = 0x602 -- O_CREAT | O_RDWR | O_TRUNC
    end

    local fd = sc(SYS_open, cstr(path), flags, 0x1FF) -- mode 0777
    if is_err(fd) then
        ctrl_msg("550 Can't create file\r\n")
        return
    end

    open_data_conn()
    ctrl_msg("150 Opening data transfer\r\n")

    local chunk_sz = 8192
    local buf = alloc(chunk_sz)
    while true do
        local n = data_recv_raw(buf, chunk_sz)
        if is_err(n) or n == 0 then break end
        sc(SYS_write, fd, buf, n)
    end

    sc(SYS_close, fd)
    close_data_conn()
    ctrl_msg("226 Transfer complete\r\n")
    restore_pt = 0
end

local function cmd_DELE(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local path = sanitize_path(cur_path, arg)
    if is_err(sc(SYS_unlink, cstr(path))) then
        ctrl_msg("550 Could not delete file\r\n")
    else
        ctrl_msg("250 File deleted\r\n")
    end
end

local function cmd_MKD(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local path = sanitize_path(cur_path, arg)
    if is_err(sc(SYS_mkdir, cstr(path), 0x1ED)) then -- 0755
        ctrl_msg("550 Can't create directory\r\n")
    else
        ctrl_msg(string.format('257 "%s" created\r\n', arg))
    end
end

local function cmd_RMD(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local path = sanitize_path(cur_path, arg)
    if is_err(sc(SYS_rmdir, cstr(path))) then
        ctrl_msg("550 Can't remove directory\r\n")
    else
        ctrl_msg("250 Directory removed\r\n")
    end
end

local function cmd_RNFR(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local path = sanitize_path(cur_path, arg)
    if do_stat(path) then
        ren_from = path
        ctrl_msg("350 Ready for RNTO\r\n")
    else
        ctrl_msg("550 File not found\r\n")
    end
end

local function cmd_RNTO(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    if ren_from == "" then ctrl_msg("503 RNFR required first\r\n"); return end
    local path = sanitize_path(cur_path, arg)
    if is_err(sc(SYS_rename, cstr(ren_from), cstr(path))) then
        ctrl_msg("550 Rename failed\r\n")
    else
        ctrl_msg("250 Renamed\r\n")
    end
    ren_from = ""
end

local function cmd_REST(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    restore_pt = tonumber(arg) or 0
    ctrl_msg(string.format("350 Restarting at %d\r\n", restore_pt))
end

local function cmd_SITE(arg)
    if not arg then ctrl_msg("500 Missing argument\r\n"); return end
    local action, perm, path = arg:match("(%S+)%s+(%d+)%s+(.+)")
    if action and action:upper() == "CHMOD" and path then
        local full = sanitize_path(cur_path, path)
        local mode = tonumber(string.format("%04d", tonumber(perm) or 0), 8)
        if is_err(sc(SYS_chmod, cstr(full), mode)) then
            ctrl_msg("550 Permission denied\r\n")
        else
            ctrl_msg("200 OK\r\n")
        end
    else
        ctrl_msg("500 SITE command not supported\r\n")
    end
end

-- ============================================================
-- COMMAND DISPATCH
-- ============================================================
local handlers = {
    USER = function(a) cmd_USER() end,
    PASS = function(a) cmd_PASS() end,
    NOOP = function(a) cmd_NOOP() end,
    SYST = function(a) cmd_SYST() end,
    FEAT = function(a) cmd_FEAT() end,
    PWD  = function(a) cmd_PWD() end,
    XPWD = function(a) cmd_PWD() end,
    TYPE = function(a) cmd_TYPE(a) end,
    CWD  = function(a) cmd_CWD(a) end,
    XCWD = function(a) cmd_CWD(a) end,
    CDUP = function(a) cmd_CDUP() end,
    XCUP = function(a) cmd_CDUP() end,
    PASV = function(a) cmd_PASV() end,
    PORT = function(a) cmd_PORT(a) end,
    LIST = function(a) cmd_LIST() end,
    NLST = function(a) cmd_LIST() end,
    SIZE = function(a) cmd_SIZE(a) end,
    RETR = function(a) cmd_RETR(a) end,
    STOR = function(a) cmd_STOR(a) end,
    APPE = function(a) restore_pt = -1; cmd_STOR(a) end,
    DELE = function(a) cmd_DELE(a) end,
    MKD  = function(a) cmd_MKD(a) end,
    XMKD = function(a) cmd_MKD(a) end,
    RMD  = function(a) cmd_RMD(a) end,
    XRMD = function(a) cmd_RMD(a) end,
    RNFR = function(a) cmd_RNFR(a) end,
    RNTO = function(a) cmd_RNTO(a) end,
    REST = function(a) cmd_REST(a) end,
    SITE = function(a) cmd_SITE(a) end,
    QUIT = function(a)
        ctrl_msg("221 Goodbye\r\n")
        return true
    end,
}

-- ============================================================
-- CLIENT SESSION
-- ============================================================
local function run_client()
    ctrl_msg("220 PS5 FTP Server\r\n")
    local recv_buf = alloc(512)

    while true do
        local n = sc(SYS_read, ctrl_fd, recv_buf, 512)
        if is_err(n) or n == 0 then break end

        local raw = read_buf(recv_buf, n)
        local cmd_line = raw:gsub("\r\n", ""):gsub("\n", "")
        local cmd = cmd_line:match("^(%S+)")
        local arg = cmd_line:match("^%S+%s+(.*)")

        if cmd then
            cmd = cmd:upper()
            plog("FTP> " .. cmd .. (arg and (" " .. arg) or ""))
            local handler = handlers[cmd]
            if handler then
                local quit = handler(arg)
                if quit then break end
            else
                ctrl_msg("500 Command not recognized\r\n")
            end
        end
    end

    -- Cleanup
    if ctrl_fd then sc(SYS_close, ctrl_fd); ctrl_fd = nil end
    if data_fd then sc(SYS_close, data_fd); data_fd = nil end
    if pasv_fd then sc(SYS_close, pasv_fd); pasv_fd = nil end
    conn_type = CONN_NONE
    cur_path = "/"
    restore_pt = 0
end

-- ============================================================
-- SERVER INIT
-- ============================================================
plog("FTP: starting on port " .. FTP_PORT)

srv_fd = sc(SYS_socket, AF_INET, SOCK_STREAM, 0)
if is_err(srv_fd) then error("socket() failed") end

-- SO_REUSEADDR
sc(SYS_setsockopt, srv_fd, SOL_SOCKET, SO_REUSEADDR, int_ptr(1), 4)

local bind_addr = make_sockaddr_in(FTP_PORT)
if is_err(sc(SYS_bind, srv_fd, bind_addr, 16)) then
    sc(SYS_close, srv_fd)
    error("bind() failed - port " .. FTP_PORT .. " in use?")
end

if is_err(sc(SYS_listen, srv_fd, 5)) then
    sc(SYS_close, srv_fd)
    error("listen() failed")
end

plog("FTP: listening on " .. my_ip .. ":" .. FTP_PORT)
rawget(_G, "notify")("FTP on " .. my_ip .. ":" .. FTP_PORT)

-- Accept loop - re-accept after each client disconnects
while true do
    local ca = alloc(16)
    local cl = int_ptr(16)
    ctrl_fd = sc(SYS_accept, srv_fd, ca, cl)
    if not is_err(ctrl_fd) then
        plog("FTP: client connected")
        local ok, err = pcall(run_client)
        if not ok then plog("FTP: error: " .. tostring(err)) end
        plog("FTP: client disconnected")
    end
end
