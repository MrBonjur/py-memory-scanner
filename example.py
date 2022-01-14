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



