-- test_call_ctx: call 0xDEADBEEF with marked registers
-- Will crash with SIGSEGV at 0xDEADBEEF - check crash dump for register values
--
-- Expected registers at crash:
--   rip = 0x00000000DEADBEEF
--   rdi = 0x00000000AAAA1111  (arg1)
--   rsi = 0x00000000BBBB2222  (arg2)
--   rdx = 0x00000000CCCC3333  (arg3)
--   rcx = 0x00000000DDDD4444  (arg4)
--   r8  = 0x00000000EEEE5555  (arg5)
--   r9  = 0x00000000FFFF6666  (arg6)
--
-- Send: cat payloads/test_call_ctx.lua | nc -q 0 <ps5_ip> 9066

local call_ctx = rawget(_G, "call_ctx")
local plog = rawget(_G, "prosper_log") or function() end

if not call_ctx then
    error("call_ctx not available - rebuild save with updated payload")
end

plog("test_call_ctx: calling 0xDEADBEEF")
plog("  rdi=0xAAAA1111 rsi=0xBBBB2222 rdx=0xCCCC3333")
plog("  rcx=0xDDDD4444 r8=0xEEEE5555  r9=0xFFFF6666")
plog("  THIS WILL CRASH - check crash dump registers")

call_ctx(
    0xDEADBEEF, 0,      -- func addr (will crash)
    0xAAAA1111,          -- rdi
    0xBBBB2222,          -- rsi
    0xCCCC3333,          -- rdx
    0xDDDD4444,          -- rcx
    0xEEEE5555,          -- r8
    0xFFFF6666            -- r9
)
