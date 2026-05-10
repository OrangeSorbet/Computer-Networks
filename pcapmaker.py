import struct, sys

# Take binary input
binary_data = input("Enter binary data:\n")

# Remove spaces/newlines
binary_data = binary_data.replace(" ", "").replace("\n", "")

# Validate binary
if not all(bit in '01' for bit in binary_data):
    print("Invalid binary input!")
    exit()

# Make length multiple of 8
extra_bits = len(binary_data) % 8
if extra_bits != 0:
    print(f"Removing last {extra_bits} extra bits")
    binary_data = binary_data[:-extra_bits]

# Convert binary -> bytes
raw_bytes = bytes(
    int(binary_data[i:i+8], 2)
    for i in range(0, len(binary_data), 8)
)

print(f"\nTotal bytes before stripping: {len(raw_bytes)}")

# Detect and strip preamble+SFD
# Preamble is 7x 0xAA followed by 0xAB
preamble = bytes([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAB])
if raw_bytes[:8] == preamble:
    raw_bytes = raw_bytes[8:]
    print("Stripped 8-byte preamble+SFD")
elif raw_bytes[:5] == bytes([0xAA, 0xAA, 0xAA, 0xAA, 0xAB]):
    raw_bytes = raw_bytes[5:]
    print("Stripped 5-byte preamble+SFD")
else:
    print("No preamble detected — using raw bytes as-is")

print(f"Frame bytes after stripping: {len(raw_bytes)}")
print(f"Dst MAC : {':'.join(f'{b:02x}' for b in raw_bytes[0:6])}")
print(f"Src MAC : {':'.join(f'{b:02x}' for b in raw_bytes[6:12])}")
print(f"EtherType: 0x{raw_bytes[12]:02x}{raw_bytes[13]:02x}")

# Write valid pcap file manually — no scapy needed
PCAP_GLOBAL_HEADER = struct.pack('<IHHiIII',
    0xa1b2c3d4,  # magic number (little-endian, microsecond timestamps)
    2, 4,        # pcap version 2.4
    0,           # GMT timezone offset
    0,           # timestamp accuracy
    65535,       # snapshot length
    1,           # link-layer type: 1 = Ethernet (DLT_EN10MB)
)

PCAP_RECORD_HEADER = struct.pack('<IIII',
    0,              # timestamp seconds
    0,              # timestamp microseconds
    len(raw_bytes), # captured length
    len(raw_bytes), # original length
)

with open("packet.pcap", "wb") as f:
    f.write(PCAP_GLOBAL_HEADER)
    f.write(PCAP_RECORD_HEADER)
    f.write(raw_bytes)

print("\npacket.pcap created successfully!")
print("Open with: wireshark packet.pcap")