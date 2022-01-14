# Python memory scanner 
###### python version 3.9 | Only Windows x64 ######

## Usage example:

    import MemoryScanner

    MemoryScanner = MemoryScanner.Scanner("notepad")

    dump = MemoryScanner.memory_view(address=0x7FF77422FC82, size=10)
    print(dump)

Output:

    0x7FF77422FC82 | 2D 63 6F 72 65 2D 77 69 6E 72 74 2D 73 74 72 69  | -core-winrt-stri
    0x7FF77422FC92 | 6E 67 2D 6C 31 2D 31 2D 30 2E 64 6C 6C 00 61 70  | ng-l1-1-0.dll.ap
    0x7FF77422FCA2 | 69 2D 6D 73 2D 77 69 6E 2D 63 6F 72 65 2D 77 69  | i-ms-win-core-wi
    0x7FF77422FCB2 | 6E 72 74 2D 6C 31 2D 31 2D 30 2E 64 6C 6C 00 00  | nrt-l1-1-0.dll..
    0x7FF77422FCC2 | 00 00 47 65 74 52 65 73 74 72 69 63 74 65 64 45  | ..GetRestrictedE
    0x7FF77422FCD2 | 72 72 6F 72 49 6E 66 6F 00 00 0B 00 52 6F 4F 72  | rrorInfo....RoOr
    0x7FF77422FCE2 | 69 67 69 6E 61 74 65 4C 61 6E 67 75 61 67 65 45  | iginateLanguageE
    0x7FF77422FCF2 | 78 63 65 70 74 69 6F 6E 00 00 C7 02 49 6E 74 65  | xception....Inte
    0x7FF77422FD02 | 72 6C 6F 63 6B 65 64 50 75 73 68 45 6E 74 72 79  | rlockedPushEntry
    0x7FF77422FD12 | 53 4C 69 73 74 00 56 00 43 6F 49 6E 63 72 65 6D  | SList.V.CoIncrem



-------------------------
    import MemoryScanner

    MemoryScanner = MemoryScanner.Scanner("notepad")

    find = MemoryScanner.array_scanner(b"\xB1\x00")
    print(find)

Output:

    ['0x26c3800206f', '0x26c38007f78', '0x26c38017c41']




## The full list of methods is in example.py

    import MemoryScanner

    MemoryScanner = MemoryScanner.Scanner("notepad")

    pid = MemoryScanner.pid
    handle = MemoryScanner.handle

    dump = MemoryScanner.memory_view(address=0x7FF77422FC82, size=10)
    print(dump)
    find = MemoryScanner.array_scanner(b"\xB1\x00")
    print(find)

    byte_array = MemoryScanner.get_array_of_bytes(address=0x7FF77422FC82, len_bytes=20)
    text = MemoryScanner.convert_array_to_text(b"\xB1\x00\x01")
    array = MemoryScanner.convert_text_to_array("B1 00 01")
    hex_to_text = MemoryScanner.get_hex_to_text("45 72 72 6F 72 49 6E 66 6F", "utf-8")


##### dicord -> Bonjur#2002
##### tg - @Mrbonjur
