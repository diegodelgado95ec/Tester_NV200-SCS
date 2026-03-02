import serial, time

PORT = "COM7"
ADDR = 0x10  # SCS por defecto

def crc16_ssp(data: bytes) -> bytes:
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])

def build_packet(addr: int, seq: int, cmd: int, data: bytes = b"") -> bytes:
    seqid   = ((seq & 1) << 7) | (addr & 0x7F)
    payload = bytes([cmd]) + data
    body    = bytes([seqid, len(payload)]) + payload
    return bytes([0x7F]) + body + crc16_ssp(body)

# Verificaciones contra manual (addr=0x00)
assert build_packet(0x00, 1, 0x11) == bytes([0x7F,0x80,0x01,0x11,0x65,0x82])
assert build_packet(0x00, 1, 0x07) == bytes([0x7F,0x80,0x01,0x07,0x12,0x02])
assert build_packet(0x10, 1, 0x07) == bytes([0x7F,0x90,0x01,0x07,0x51,0x83])
print("✅ CRC verificado correctamente")

# Paquetes para addr=0x10
print(f"  SYNC:   {build_packet(0x10, 1, 0x11).hex(' ').upper()}")
print(f"  POLL:   {build_packet(0x10, 1, 0x07).hex(' ').upper()}")
print(f"  ENABLE: {build_packet(0x10, 1, 0x0A).hex(' ').upper()}")

try:
    s = serial.Serial(
        port=PORT, baudrate=9600,
        bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_TWO,
        xonxoff=False, rtscts=False, dsrdtr=False,
        timeout=2
    )
    s.reset_input_buffer()
    s.reset_output_buffer()

    seq = 1
    pkt = build_packet(ADDR, seq, 0x11)
    print(f"\nTX SYNC  → {pkt.hex(' ').upper()}")
    s.write(pkt)
    time.sleep(0.5)
    rx = s.read(s.in_waiting or 32)
    print(f"RX SYNC  ← {rx.hex(' ').upper() if rx else '(vacío)'}")

    if rx and rx[3] == 0xF0:
        print("✅ SCS respondió OK al SYNC")

        # POLL
        seq ^= 1
        pkt = build_packet(ADDR, seq, 0x07)
        print(f"\nTX POLL  → {pkt.hex(' ').upper()}")
        s.write(pkt)
        time.sleep(0.3)
        rx = s.read(s.in_waiting or 32)
        print(f"RX POLL  ← {rx.hex(' ').upper() if rx else '(vacío)'}")

    s.close()

except serial.SerialException as e:
    print(f"❌ Error puerto: {e}")
