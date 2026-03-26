-- test_call_ctx: call 0xDEADBEEF with marked registers (full 64-bit)
-- Will crash with SIGSEGV - check crash dump for register values
--
-- Expected registers at crash:
--   rip = 0x0000DEAD_DEADBEEF
--   rdi = 0x1111AAAA_AAAA1111  (arg1)
--   rsi = 0x2222BBBB_BBBB2222  (arg2)
--   rdx = 0x3333CCCC_CCCC3333  (arg3)
--   rcx = 0x4444DDDD_DDDD4444  (arg4)
--   r8  = 0x5555EEEE_EEEE5555  (arg5)
--   r9  = 0x6666FFFF_FFFF6666  (arg6)
--
-- Send: cat payloads/test_call_ctx.lua | nc -q 0 <ps5_ip> 9066

local call_ctx = rawget(_G, "call_ctx")
local plog = rawget(_G, "prosper_log") or function() end

if not call_ctx then
    error("call_ctx not available - rebuild save with updated payload")
end

plog("test_call_ctx: calling 0x0000DEAD_DEADBEEF")
plog("  rdi=0x1111AAAA_AAAA1111  rsi=0x2222BBBB_BBBB2222")
plog("  rdx=0x3333CCCC_CCCC3333  rcx=0x4444DDDD_DDDD4444")
plog("  r8 =0x5555EEEE_EEEE5555  r9 =0x6666FFFF_FFFF6666")
plog("  THIS WILL CRASH - check crash dump registers")

call_ctx(
    0xDEADBEEF, 0x0000DEAD,          -- rip = 0x0000DEAD_DEADBEEF
    {0xAAAA1111, 0x1111AAAA},         -- rdi = 0x1111AAAA_AAAA1111
    {0xBBBB2222, 0x2222BBBB},         -- rsi = 0x2222BBBB_BBBB2222
    {0xCCCC3333, 0x3333CCCC},         -- rdx = 0x3333CCCC_CCCC3333
    {0xDDDD4444, 0x4444DDDD},         -- rcx = 0x4444DDDD_DDDD4444
    {0xEEEE5555, 0x5555EEEE},         -- r8  = 0x5555EEEE_EEEE5555
    {0xFFFF6666, 0x6666FFFF}          -- r9  = 0x6666FFFF_FFFF6666
)
