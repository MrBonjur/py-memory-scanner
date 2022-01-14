########################################################################
#                           Memory Scanner                             #
#                      14.01.2022 create Bonjur                        #
#                 Works only on Windows x64 systems                    #
#            https://github.com/MrBonjur/py-memory-scanner             #
#                           Used python 3.9                            #
########################################################################

from ctypes.wintypes import WORD, DWORD, LPVOID
import psutil
import ctypes
import enum
import re


class memory_state(enum.IntEnum):
    mem_commit = 0x1000
    mem_free = 0x10000
    mem_reserve = 0x2000
    mem_decommit = 0x4000
    mem_release = 0x8000


class memory_protection(enum.IntEnum):
    page_execute = 0x10
    page_execute_read = 0x20
    page_execute_readwrite = 0x40
    page_execute_writecopy = 0x80
    page_noaccess = 0x01
    page_readonly = 0x02
    page_readwrite = 0x04
    page_writecopy = 0x08
    page_guard = 0x100
    page_nocache = 0x200
    page_writecombine = 0x400


class memory_types(enum.IntEnum):
    mem_image = 0x1000000
    mem_mapped = 0x40000
    mem_private = 0x20000


class memory_basic_information64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("__alignment1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("__alignment2", ctypes.c_ulong),
    ]

    @property
    def type(self):
        enum_type = [e for e in memory_types if e.value == self.Type] or None
        enum_type = enum_type[0] if enum_type else None
        return enum_type

    @property
    def state(self):
        enum_type = [e for e in memory_state if e.value == self.State] or None
        enum_type = enum_type[0] if enum_type else None
        return enum_type

    @property
    def protect(self):
        enum_type = [e for e in memory_protection if e.value == self.Protect]
        enum_type = enum_type[0] if enum_type else None
        return enum_type


class system_info(ctypes.Structure):
    DWORD_PTR = ctypes.c_ulonglong
    PVOID = LPVOID
    SIZE_T = ctypes.c_size_t

    class _U(ctypes.Union):
        class _S(ctypes.Structure):
            _fields_ = (('wProcessorArchitecture', WORD), ('wReserved', WORD))

        _fields_ = (('dwOemId', DWORD), ('_s', _S))
        _anonymous_ = ('_s',)

    _fields_ = (('_u', _U),
                ('dwPageSize', DWORD),
                ('lpMinimumApplicationAddress', LPVOID),
                ('lpMaximumApplicationAddress', LPVOID),
                ('dwActiveProcessorMask', DWORD_PTR),
                ('dwNumberOfProcessors', DWORD),
                ('dwProcessorType', DWORD),
                ('dwAllocationGranularity', DWORD),
                ('wProcessorLevel', WORD),
                ('wProcessorRevision', WORD))
    _anonymous_ = ('_u',)


sysinfo = system_info()

kernel32 = ctypes.WinDLL('kernel32')
kernel32.GetSystemInfo(ctypes.byref(sysinfo))


def get_pid(process):
    pid = None
    for proc in psutil.process_iter():
        if process.lower() in proc.name().lower():
            pid = proc.pid
            return pid
    if pid is None:
        raise OSError(f'Process {process} not found.')


def get_handle(pid):
    # standard rights required && synchronize (Get proc handle with need access)
    process_access = (0x000F0000 | 0x00100000 | 0xFFFF)
    kernel32.OpenProcess.restype = ctypes.c_ulonglong
    process_handle = kernel32.OpenProcess(process_access, False, pid)
    return process_handle


def virtual_query(handle, address):
    mbi = memory_basic_information64()

    kernel32.VirtualQueryEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_ulong
    kernel32.VirtualQueryEx(handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi))
    return mbi


def read_bytes(handle, address, byte):
    buffer = ctypes.create_string_buffer(byte)
    bytes_read = ctypes.c_size_t()
    kernel32.ReadProcessMemory.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t)
    )
    kernel32.ReadProcessMemory.restype = ctypes.c_long
    kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), ctypes.byref(buffer), byte, ctypes.byref(bytes_read))
    raw = buffer.raw
    return raw


def scan_pattern_page(handle, address, pattern):
    mbi = virtual_query(handle, address)
    next_region = mbi.BaseAddress + mbi.RegionSize
    allowed_protections = [
        0x20,  # PAGE_EXECUTE_READ
        0x40,  # PAGE_EXECUTE_READWRITE
        0x04,  # PAGE_READWRITE
        0x02,  # PAGE_READONLY
    ]

    # 0x1000 - memory commit | 0x20000 - scan dll (more addresses)
    if mbi.state != 0x1000 or mbi.protect not in allowed_protections or mbi.type != 0x20000:
        return next_region, None

    page_bytes = read_bytes(handle, address, mbi.RegionSize)
    found = []

    for match in re.finditer(pattern, page_bytes):
        found_address = mbi.BaseAddress + match.span()[0]
        found.append(found_address)

    return next_region, found


class Scanner():
    def __init__(self, process):
        self.process = process
        self.pid = get_pid(self.process)
        self.handle = get_handle(self.pid)

    def convert_array_to_text(self, array):  # b"\xB1\x00" -> "B1 00"
        array = str(array).replace("\\x", " ").replace("b'", "").replace("'", "").replace(" ", "", 1).replace("<",
                                                                                                              "", ).upper()
        return array

    def convert_text_to_array(self, text):  # "B1 00" -> b"\xB1\x00"
        array = eval("b'\\x" + text.replace(" ", "\\x") + "'")
        return array

    def array_scanner(self, array: bytes):  # b"\xB1\x00"
        begin_address = sysinfo.lpMinimumApplicationAddress
        end_address = sysinfo.lpMaximumApplicationAddress
        founds_addresses = []
        while begin_address < end_address:
            begin_address, temp = scan_pattern_page(self.handle, begin_address, array)
            if temp:
                for j in temp:
                    founds_addresses.append(hex(j))  # add founds addresses
        return founds_addresses

    def get_hex_to_text(self, byte: str, encoding: str):  # 45 72 72 6F 72 49 6E 66 6F -> ErrorInfo
        try:
            text = bytes.fromhex(byte).decode(encoding)
            if not re.match("^[-\[\]()\\\<>|!@#$%{}_^\"',&*~.+A-Za-z0-9]", text):
                return "."
            return bytes.fromhex(byte).decode(encoding)
        except ValueError:
            return "."

    def get_array_of_bytes(self, address, len_bytes):

        open_process = kernel32.OpenProcess(0x1f0fff, False, self.pid)  # 0x1f0fff - PROCESS_ALL_ACCESS
        default_array = ""
        hexadecimal_array = ""
        text_array = ""
        for view_address in range(address, address + len_bytes):
            data = ctypes.c_int64()
            kernel32.ReadProcessMemory(open_process, ctypes.c_void_p(view_address), ctypes.byref(data), 1,
                                       None)  # 1 byte

            non_hexadecimal_value = str(data.value)
            hex_value = hex(data.value)

            if len(hex_value) == 3:  # 0x3 -> 03
                hex_value = hex_value.replace("0x", "0").upper()
            else:  # 0xB1 -> B1
                hex_value = hex_value.replace("0x", "").upper()

            default_array += non_hexadecimal_value + " "
            hexadecimal_array += hex_value + " "
            text_array += Scanner.get_hex_to_text(self, byte=hex_value, encoding="utf-8")

        return [hexadecimal_array, text_array, default_array]

    def memory_view(self, address: hex, size: int):
        result = ""
        for view_address in range(address, address + size * 16, 0xF + 0x1):
            out_address = hex(view_address).upper().replace('0X', '0x')
            types_array_of_bytes = Scanner.get_array_of_bytes(self, view_address, 16)
            result += out_address + " | " + types_array_of_bytes[0] + " | " + types_array_of_bytes[1] + "\n"

        return result  # 0x2343160216F | 00 00 00 00 00 00 00 00 00 78 21 60 31 34 02 00  | .........x!.14..
