"""
=============================================================
  eSSPCrypto  —  Diffie-Hellman key negotiation + AES-128
  FIX: GENERATOR y MODULUS deben ser primos de 64 bits.
  Valores pequeños causan neg_key < 3 bytes → 0xFA en routes.
=============================================================
"""

from email import generator
from email import generator
import os
import secrets
import struct
import time
import sympy


try:
    from Crypto.Cipher import AES
    _AES_AVAILABLE = True
except ImportError:
    _AES_AVAILABLE = False


FIXED_KEY_DEFAULT = 0x0123456701234567

# ─── FIX CRÍTICO ────────────────────────────────────────────
# GENERATOR: primo pequeño estándar DH (igual que el spec ITL)
# ─── VALORES EXACTOS DEL SPEC ITL ───────────────────────
_GENERATOR = 982451653                    # Generator oficial ITL

_MODULUS   = 4611686018427387847  # spec itl
# ────────────────────────────────────────────────────────

# ────────────────────────────────────────────────────────────


def _crc16(data: bytes) -> int:
    """Forward CRC-16, polinomio x16+x15+x2+1 = 0x8005, seed 0xFFFF"""
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def _int_to_8le(n: int) -> bytes:
    return (n & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def _8le_to_int(b: bytes) -> int:
    return int.from_bytes(b[:8], "little")


class eSSPCrypto:
    def __init__(self, fixed_key: int = FIXED_KEY_DEFAULT):
        self._fixed_key    = fixed_key
        self.is_negotiated = False
        self._count_enc    = 0
        self._count_dec    = 0
        self._aes_key      = b"\x00" * 16

    def negotiate(self, drv) -> bool:
        if not _AES_AVAILABLE:
            print("❌ pycryptodome no disponible")
            return False
        try:
            # Primos frescos 32-bit con secrets (sin depender de random)
            gen_seed = secrets.randbelow(2**30 - 2**28) + 2**28
            mod_seed = secrets.randbelow(2**31 - 2**30) + 2**30

            generator = sympy.nextprime(gen_seed)
            modulus   = sympy.nextprime(mod_seed)
            while modulus == generator:
                modulus = sympy.nextprime(modulus + 1)

            print(f"  DH generator={generator}  modulus={modulus}")

            code, _, _ = drv.send(0x4A, _int_to_8le(generator))
            print(f"  SET GENERATOR → 0x{code:02X}")
            if code != 0xF0:
                return False
            
            time.sleep(0.05) 
            
            code, _, _ = drv.send(0x4B, _int_to_8le(modulus))
            print(f"  SET MODULUS   → 0x{code:02X}")
            if code != 0xF0:
                return False

            time.sleep(0.05)   

            host_rnd   = int.from_bytes(os.urandom(8), "little") % (modulus - 2) + 1
            host_inter = pow(generator, host_rnd, modulus)

                # DEBUG CRÍTICO
            inter_bytes = _int_to_8le(host_inter)
            print(f"  host_rnd    = {host_rnd}")
            print(f"  host_inter  = {host_inter}  ({host_inter.bit_length()} bits)")
            print(f"  inter_bytes = {inter_bytes.hex().upper()}")

            code, extra, _ = drv.send(0x4C, inter_bytes)
            print(f"  REQUEST KEY   → 0x{code:02X}  extra_len={len(extra) if extra else 0}  raw={extra.hex() if extra else 'NADA'}")
            if code != 0xF0 or len(extra) < 8:
                print(f"  → Fallo en REQUEST KEY: code=0x{code:02X}, extra={extra}")
                return False


            slave_inter = _8le_to_int(extra[:8])
            neg_key     = pow(slave_inter, host_rnd, modulus)

            fixed_bytes = _int_to_8le(self._fixed_key)
            neg_bytes   = _int_to_8le(neg_key)
            print(f"  FIXED BYTES → {fixed_bytes.hex().upper()}")
            print(f"  NEG BYTES   → {neg_bytes.hex().upper()}")
            print(f"  AES KEY     → {(fixed_bytes + neg_bytes).hex().upper()}")

            self._aes_key      = fixed_bytes + neg_bytes
            self._count_enc    = 0
            self._count_dec    = 1
            self.is_negotiated = True
            return True

        except Exception as e:
            print(f"  EXCEPTION: {e}")
            return False

    def encrypt_packet(self, cmd: int, params: bytes = b"") -> bytes:
        data    = bytes([cmd]) + params
        e_len   = len(data)
        e_count = struct.pack("<I", self._count_enc)

        # pre_crc = e_len(1) + e_count(4) + data(N)
        pre_pad = bytes([e_len]) + e_count + data

        # total con CRC = pre_pad + 2 bytes CRC
        # necesita ser múltiplo de 16
        total_before_pad = len(pre_pad) + 2   # +2 = CRC
        pad_len = (16 - (total_before_pad % 16)) % 16
        padding = os.urandom(pad_len)

        pre_crc   = pre_pad + padding
        crc       = _crc16(pre_crc)
        plaintext = pre_crc + bytes([crc & 0xFF, (crc >> 8) & 0xFF])

        # Verificar que sea múltiplo de 16
        assert len(plaintext) % 16 == 0, f"plaintext {len(plaintext)} no es múltiplo de 16"

        cipher     = AES.new(self._aes_key, AES.MODE_ECB)
        ciphertext = b""
        for i in range(0, len(plaintext), 16):
            ciphertext += cipher.encrypt(plaintext[i:i+16])

        self._count_enc += 1
        return bytes([0x7E]) + ciphertext


    def decrypt_response(self, raw_enc: bytes) -> tuple:
        if not raw_enc or raw_enc[0] != 0x7E:
            raise ValueError("No STEX byte")

        ciphertext = raw_enc[1:]
        if len(ciphertext) % 16 != 0:
            raise ValueError("Longitud no múltiplo de 16")

        cipher    = AES.new(self._aes_key, AES.MODE_ECB)
        plaintext = b""
        for i in range(0, len(ciphertext), 16):
            plaintext += cipher.decrypt(ciphertext[i:i+16])

        body     = plaintext[:-2]
        crc_recv = plaintext[-2] | (plaintext[-1] << 8)
        if _crc16(body) != crc_recv:
            raise ValueError("CRC interno incorrecto")

        e_len   = plaintext[0]
        e_count = struct.unpack_from("<I", plaintext, 1)[0]

        if e_count != self._count_dec:
            raise ValueError(f"eCOUNT mismatch: got {e_count}, expected {self._count_dec}")

        self._count_dec += 1
        e_data = plaintext[5:5 + e_len]
        return (e_data[0], e_data[1:]) if e_data else (0x00, b"")
