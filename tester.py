"""
=============================================================
  ITL SSP / eSSP Driver + GUI  — tester.py  v3.3
  SCS (0x10) + NV200 (0x00) en el mismo COM (IF17)
  Modo manual + Modo Transacción integrado
=============================================================
"""

from cmath import log
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from contextlib import contextmanager
import threading
import serial
import serial.tools.list_ports
import struct
import time
from eSSPCrypto import eSSPCrypto


# ══════════════════════════════════════════════════════════
#  CRC-16 SSP
# ══════════════════════════════════════════════════════════

def crc16_ssp(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def build_packet(address: int, seq_bit: int, data: bytes) -> bytes:
    seqid   = ((seq_bit & 1) << 7) | (address & 0x7F)
    length  = len(data)
    payload = bytes([seqid, length]) + data
    crc     = crc16_ssp(payload)
    raw     = bytes([0x7F]) + payload + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    stuffed = bytes([0x7F])
    for b in raw[1:]:
        stuffed += bytes([b])
        if b == 0x7F:
            stuffed += bytes([0x7F])
    return stuffed


def parse_response(raw: bytes) -> tuple:
    if not raw or raw[0] != 0x7F:
        return 0, b""
    destuffed = bytearray()
    i = 1
    while i < len(raw):
        destuffed.append(raw[i])
        if raw[i] == 0x7F and i + 1 < len(raw) and raw[i + 1] == 0x7F:
            i += 2
        else:
            i += 1
    if len(destuffed) < 3:
        return 0, b""
    length = destuffed[1]
    data   = bytes(destuffed[2: 2 + length])
    if not data:
        return 0, b""
    return data[0], data[1:]


def parse_setup_request(data: bytes) -> dict:
    if len(data) < 9:
        return {}
    try:
        unit_type  = data[0]
        firmware   = data[1:5].decode("ascii", errors="ignore")
        country    = data[5:8].decode("ascii", errors="ignore")
        protocol   = data[8]
        num_denoms = data[9] if len(data) > 9 else 0
        denoms     = []
        for i in range(num_denoms):
            base = 10 + i * 2
            if base + 2 <= len(data):
                val = struct.unpack_from("<H", data, base)[0]
                denoms.append(val)
        return {
            "unit_type": unit_type,
            "firmware":  firmware,
            "country":   country,
            "protocol":  protocol,
            "denoms":    denoms,
        }
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════
#  DRIVER SSP — un driver por dispositivo, mismo serial
# ══════════════════════════════════════════════════════════

class SSPDriver:
    def __init__(self, ser: serial.Serial, address: int, bus_lock: threading.Lock):
        self.ser      = ser
        self.address  = address
        self.seq      = 1
        self.crypto   = eSSPCrypto()
        self._lock    = bus_lock
        self.info     = {}

    def close(self):
        pass

    @contextmanager
    def fast_timeout(self, t: float = 0.2):
        old = self.ser.timeout
        self.ser.timeout = t
        try:
            yield
        finally:
            self.ser.timeout = old

    def send(self, cmd: int, params: bytes = b"") -> tuple:
        with self._lock:
            pkt = build_packet(self.address, self.seq, bytes([cmd]) + params)
            self.ser.reset_input_buffer()
            self.ser.write(pkt)
            time.sleep(0.06)
            raw        = self.ser.read(256)
            self.seq  ^= 1
            code, extra = parse_response(raw)
            return code, extra, raw

    def send_encrypted(self, cmd: int, params: bytes = b"") -> tuple:
        if not self.crypto.is_negotiated:
            raise RuntimeError("eSSP: clave no negociada")
        with self._lock:
            enc_payload = self.crypto.encrypt_packet(cmd, params)
            pkt = build_packet(self.address, self.seq, enc_payload)
            self.ser.reset_input_buffer()
            self.ser.write(pkt)
            time.sleep(0.08)
            raw = self.ser.read(256)
            self.seq ^= 1
            if not raw or raw[0] != 0x7F:
                return (0, b""), raw
            destuffed = bytearray()
            i = 1
            while i < len(raw):
                destuffed.append(raw[i])
                if raw[i] == 0x7F and i + 1 < len(raw) and raw[i + 1] == 0x7F:
                    i += 2
                else:
                    i += 1
            if len(destuffed) < 3:
                return (0, b""), raw
            resp_len  = destuffed[1]
            resp_data = bytes(destuffed[2: 2 + resp_len])
            if not resp_data:
                return (0, b""), raw
            if resp_data[0] == 0x7E:
                decrypted = self.crypto.decrypt_response(resp_data)
                if not decrypted:
                    return (0xFE, b""), raw
                return decrypted, raw
            return (resp_data[0], resp_data[1:]), raw

    def negotiatekeys(self) -> bool:
        self.seq = 0
        code, _, _ = self.send(0x11)
        if code != 0xF0:
            return False
        time.sleep(0.1)
        self.send(0x06, bytes([6]))
        time.sleep(0.05)
        return self.crypto.negotiate(self)

    def force_sync(self) -> bool:
        for _ in range(3):
            self.seq = 1
            code, _, _ = self.send(0x11)
            self.seq = 0
            if code == 0xF0:
                return True
            time.sleep(0.2)
        return False

    def set_protocol(self, v: int = 7) -> bool:
        code, _, _ = self.send(0x06, bytes([v]))
        return code == 0xF0

    def setup_request(self) -> bytes:
        code, data, _ = self.send(0x05)
        return data if code == 0xF0 else b""

    def enable(self) -> bool:
        code, _, _ = self.send(0x0A)
        return code == 0xF0

    def disable(self) -> bool:
        code, _, _ = self.send(0x09)
        return code == 0xF0

    def reset(self) -> bool:
        code, _, _ = self.send(0x01)
        return code == 0xF0

    def poll(self) -> tuple:
        return self.send(0x07)

    def reject_note(self) -> bool:
        code, _, _ = self.send(0x08)
        return code == 0xF0

    def hold_note(self) -> bool:
        code, _, _ = self.send(0x18)
        return code == 0xF0

    def get_serial(self) -> int:
        code, data, _ = self.send(0x0C)
        if code == 0xF0 and len(data) >= 4:
            return struct.unpack(">I", data[:4])[0]
        return 0

    def get_fw(self) -> str:
        code, data, _ = self.send(0x20)
        return data.decode("ascii", errors="ignore") if code == 0xF0 else "N/A"

    def get_all_levels(self) -> list:
        code, data, _ = self.send(0x22)
        if code != 0xF0 or not data:
            return []
        num    = data[0]
        result = []
        for i in range(num):
            base = 1 + i * 9
            if base + 9 > len(data):
                break
            level   = struct.unpack_from("<H", data, base)[0]
            value   = struct.unpack_from("<I", data, base + 2)[0]
            country = data[base + 6: base + 9].decode("ascii", errors="ignore")
            result.append({"level": level, "value": value, "country": country})
        return result

    def payout_amount(self, cents: int, country: str, test: bool = False) -> tuple:
        option = 0x19 if test else 0x58
        params = struct.pack("<I", cents) + country.encode("ascii") + bytes([option])
        if self.crypto.is_negotiated:
            (code, extra), _ = self.send_encrypted(0x33, params)
        else:
            code, extra, _ = self.send(0x33, params)
        return code, extra

    def smart_empty(self) -> bool:
        if self.crypto.is_negotiated:
            (code, _), _ = self.send_encrypted(0x52)
        else:
            code, _, _ = self.send(0x52)
        return code == 0xF0

    def set_denomination_route(self, cents: int, country: str,
                               route: int = 0x00) -> tuple:
        params = (bytes([route])
                  + struct.pack("<I", cents)
                  + country.encode("ascii"))
        if self.crypto.is_negotiated:
            (code, extra), _ = self.send_encrypted(0x3B, params)
        else:
            code, extra, _ = self.send(0x3B, params)
        return code, extra

    def enable_payout_device(self) -> bool:
        if self.crypto.is_negotiated:
            (code, _), _ = self.send_encrypted(0x5C, bytes([0x00]))
        else:
            code, _, _ = self.send(0x5C, bytes([0x00]))
        return code == 0xF0

    def set_inhibits(self, b1: int = 0xFF, b2: int = 0xFF) -> bool:
        code, _, _ = self.send(0x02, bytes([b1, b2]))
        return code == 0xF0

    def enable_coin_mech(self, denoms: list, country: str) -> bool:
        with self.fast_timeout(0.2):
            for cents in denoms:
                params = bytes([0x01]) + struct.pack("<H", cents) + country.encode()
                self.send(0x40, params)
                time.sleep(0.02)
            self.send(0x49, bytes([0x01]))
            time.sleep(0.02)
        return self.enable()

    def reactivate_coin_mech(self) -> bool:
        """Reactiva el coin mech fisico sin reenviar denomination routes (0x40).
        Usar en segunda transaccion en adelante: solo 0x49 + 0x0A."""
        code49, _, _ = self.send(0x49, bytes([0x01]))
        time.sleep(0.05)
        return self.enable()


# ══════════════════════════════════════════════════════════
#  CONSTANTES DE EVENTOS
# ══════════════════════════════════════════════════════════

EVENTS = {
    0xC1: "PAY-IN ACTIVE",
    0xBF: "VALUE ADDED",
    0xDA: "DISPENSING",
    0xD2: "DISPENSED",
    0xD7: "FLOATING",
    0xD8: "FLOATED",
    0xD5: "JAMMED",
    0xB3: "SMART EMPTYING",
    0xB4: "SMART EMPTIED",
    0xDC: "INCOMPLETE PAYOUT",
    0xDD: "INCOMPLETE FLOAT",
    0xCF: "DEVICE FULL",
    0xE8: "DISABLED",
    0xE6: "FRAUD ATTEMPT",
    0xEF: "READ",
    0xEE: "NOTE CREDIT",
    0xED: "REJECTING",
    0xEC: "REJECTED",
    0xCC: "STACKING",
    0xEB: "STACKED",
    0xDB: "NOTE STORED IN PAYOUT",
    0xF1: "SLAVE RESET",
    0xDE: "CASHBOX PAID",
    0xDF: "COIN CREDIT",
    0xD9: "TIMEOUT",
    0xD6: "PAYOUT HALTED",
    0xC0: "MAINTENANCE REQUIRED",
    0xB6: "INITIALISING",
    0xB0: "JAM RECOVERY",
    0xB1: "ERROR DURING PAYOUT",
    0xE9: "UNSAFE JAM",
    0xE7: "STACKER FULL",
    0xE3: "CASHBOX REMOVED",
    0xE4: "CASHBOX REPLACED",
    0xCA: "NOTE INTO STACKER AT RESET",
    0xCB: "NOTE INTO STORE AT RESET",
    0xCD: "NOTE DISPENSED AT RESET",
    0xCE: "NOTE HELD IN BEZEL",
    0xC9: "NOTE TRANSFERRED TO STACKER",
}

ROUTE_ERRORS  = {1: "Sin payout conectado", 2: "Moneda inválida", 3: "Fallo payout"}
PAYOUT_ERRORS = {1: "Sin suficiente valor", 2: "No puede pagar exacto",
                 3: "Dispositivo ocupado",  4: "Dispositivo deshabilitado"}


# ══════════════════════════════════════════════════════════
#  PARSER DE EVENTOS
# ══════════════════════════════════════════════════════════

MULTI_COUNTRY_EVENTS = {
    0xBF, 0xDA, 0xD2, 0xD7, 0xD8, 0xD5,
    0xB3, 0xB4, 0xDC, 0xDD, 0xE6, 0xD9, 0xD6, 0xB1,
}


def parse_poll_events(extra: bytes, proto: int = 7) -> list:
    result = []
    i = 0
    while i < len(extra):
        code = extra[i]
        i   += 1
        name    = EVENTS.get(code, f"0x{code:02X}")
        ev_data = b""

        if proto >= 6 and code in MULTI_COUNTRY_EVENTS:
            if i < len(extra):
                n  = extra[i]
                sz = 1 + n * 7
                ev_data = extra[i: i + sz]
                i += sz

        elif code == 0xEF:
            if i < len(extra):
                ev_data = extra[i:i+1]
                i += 1

        elif code == 0xEE:
            if i < len(extra):
                ev_data = extra[i:i+1]
                i += 1

        elif code == 0xDB:
            if i < len(extra):
                ev_data = extra[i:i+1]
                i += 1

        elif code == 0xCF:
            pass

        elif code == 0xE6:
            if proto < 6 and i < len(extra):
                ev_data = extra[i:i+1]
                i += 1

        result.append({"code": code, "name": name, "data": ev_data})
    return result


def extract_value_country(ev_data: bytes) -> tuple:
    if not ev_data or len(ev_data) < 8:
        return 0, ""
    n = ev_data[0]
    if n > 0 and len(ev_data) >= 8:
        val     = struct.unpack_from("<I", ev_data, 1)[0]
        country = ev_data[5:8].decode("ascii", errors="ignore")
        return val, country
    return 0, ""


# ══════════════════════════════════════════════════════════
#  LÓGICA DE VUELTO
# ══════════════════════════════════════════════════════════

NV200_CHANGE_DENOMS = [1000, 500]
SCS_CHANGE_DENOMS   = [100, 25, 10, 5, 1]


def calculate_change_strategy(change_cents: int,
                               nv200_levels: dict,
                               scs_levels: dict) -> dict:
    if change_cents == 0:
        return {"nv200": 0, "scs": 0, "feasible": True, "message": "Pago exacto"}

    nv200_pay = 0
    remaining  = change_cents

    for denom in NV200_CHANGE_DENOMS:
        available = nv200_levels.get(denom, 0)
        while remaining >= denom and available > 0:
            nv200_pay += denom
            remaining -= denom
            available -= 1

    scs_pay = 0
    for denom in SCS_CHANGE_DENOMS:
        available = scs_levels.get(denom, 0)
        while remaining >= denom and available > 0:
            scs_pay  += denom
            remaining -= denom
            available -= 1

    if remaining > 0:
        msg = (f"⚠ Sin cambio suficiente (faltan ${remaining/100:.2f}). "
               f"Ingrese monto exacto o use POS / DeUna.")
        return {"nv200": nv200_pay, "scs": scs_pay,
                "feasible": False, "message": msg}

    return {"nv200": nv200_pay, "scs": scs_pay,
            "feasible": True,
            "message": f"Vuelto: NV200 ${nv200_pay/100:.2f} + SCS ${scs_pay/100:.2f}"}


# ══════════════════════════════════════════════════════════
#  ESTADO DE TRANSACCIÓN
# ══════════════════════════════════════════════════════════

class TransactionState:
    IDLE        = "idle"
    COLLECTING  = "collecting"
    CONFIRMING  = "confirming"
    DISPENSING  = "dispensing"
    COMPLETE    = "complete"
    CANCELLED   = "cancelled"

    def __init__(self):
        self.reset()

    def reset(self):
        self.status          = self.IDLE
        self.price_cents     = 0
        self.total_cents     = 0
        self.coin_breakdown  = {}
        self.note_breakdown  = {}
        self.escrow_value    = 0
        self.escrow_country  = ""
        self.change_strategy = {}
        self.start_time      = None
        self.timeout_secs    = 180

    def add_coin(self, cents: int):
        self.coin_breakdown[cents] = self.coin_breakdown.get(cents, 0) + 1
        self.total_cents += cents

    def add_note_credit(self, cents: int):
        self.note_breakdown[cents] = self.note_breakdown.get(cents, 0) + 1
        self.total_cents += cents
        self.escrow_value   = 0
        self.escrow_country = ""

    def set_escrow(self, cents: int, country: str):
        self.escrow_value   = cents
        self.escrow_country = country

    def clear_escrow(self):
        self.escrow_value   = 0
        self.escrow_country = ""

    @property
    def remaining_cents(self):
        return max(0, self.price_cents - self.total_cents)

    @property
    def elapsed(self):
        if self.start_time:
            return time.time() - self.start_time
        return 0

    @property
    def timed_out(self):
        return self.elapsed > self.timeout_secs


# ══════════════════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ITL SSP Monitor v3.3 — SCS + NV200")
        self.geometry("1100x800")
        self.resizable(True, True)
        self.configure(bg="#1e1e2e")

        self._ser        = None
        self._bus_lock   = threading.Lock()
        self.scs         = None
        self.nv200       = None
        self.polling     = False
        self.poll_thread = None
        self.txn         = TransactionState()
        self._last_dispensing_msg = None
        self._dispensed_handled   = False

        self._build_ui()
        self._refresh_ports()

    # ──────────────────────────────────────────────────────
    #  UI BUILD
    # ──────────────────────────────────────────────────────

    def _build_ui(self):
        top = tk.Frame(self, bg="#1e1e2e", pady=6)
        top.pack(fill="x", padx=12)

        tk.Label(top, text="Puerto:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left")
        self.port_var = tk.StringVar()
        self.port_cb  = ttk.Combobox(top, textvariable=self.port_var,
                                     width=10, state="readonly")
        self.port_cb.pack(side="left", padx=(4, 12))

        tk.Label(top, text="País:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left")
        self.country_var = tk.StringVar(value="USD")
        ttk.Combobox(top, textvariable=self.country_var, width=6,
                     state="readonly", values=["USD", "EUR", "GBP"]).pack(
                     side="left", padx=(4, 16))

        self.btn_connect = tk.Button(
            top, text="Conectar ambos", width=14, command=self._connect,
            bg="#89b4fa", fg="#1e1e2e", font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2")
        self.btn_connect.pack(side="left", padx=4)

        tk.Button(top, text="↻", width=3, command=self._refresh_ports,
                  bg="#313244", fg="#cdd6f4", font=("Consolas", 11),
                  relief="flat", cursor="hand2").pack(side="left")

        self.status_var = tk.StringVar(value="Desconectado")
        tk.Label(top, textvariable=self.status_var,
                 bg="#1e1e2e", fg="#a6e3a1",
                 font=("Consolas", 10)).pack(side="right", padx=8)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",        background="#1e1e2e", borderwidth=0)
        style.configure("TNotebook.Tab",    background="#313244", foreground="#cdd6f4",
                        font=("Consolas", 10, "bold"), padding=[12, 4])
        style.map("TNotebook.Tab",
                  background=[("selected", "#89b4fa")],
                  foreground=[("selected", "#1e1e2e")])

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=12, pady=4)

        self.tab_manual = tk.Frame(self.nb, bg="#1e1e2e")
        self.tab_txn    = tk.Frame(self.nb, bg="#1e1e2e")
        self.nb.add(self.tab_manual, text=" 🔧 Manual ")
        self.nb.add(self.tab_txn,    text=" 💳 Transacción ")

        self._build_manual_tab()
        self._build_txn_tab()

    def _build_manual_tab(self):
        p = self.tab_manual

        scs_f = tk.LabelFrame(p, text=" SCS (monedas 0x10) ",
            bg="#1e1e2e", fg="#89dceb", font=("Consolas", 10, "bold"),
            bd=1, relief="solid")
        scs_f.pack(fill="x", padx=8, pady=(8, 4))

        for label, cmd in [
            ("SYNC",       lambda: self._m_sync(self.scs, "SCS")),
            ("INIT",       lambda: self._m_init_scs()),
            ("ENABLE",     lambda: self._m_enable_scs()),
            ("DISABLE",    lambda: self._m_cmd(self.scs, "SCS", "DISABLE", 0x09)),
            ("RESET",      lambda: self._m_cmd(self.scs, "SCS", "RESET",   0x01)),
            ("GET LEVELS", lambda: self._m_levels(self.scs, "SCS")),
            ("GET SERIAL", lambda: self._m_serial(self.scs, "SCS")),
            ("POLL ▶/■",   lambda: self._toggle_poll_manual("SCS")),
        ]:
            tk.Button(scs_f, text=label, command=cmd,
                      bg="#313244", fg="#cdd6f4", font=("Consolas", 9),
                      relief="flat", cursor="hand2", padx=6, pady=4).pack(
                      side="left", padx=3, pady=6)

        nv_f = tk.LabelFrame(p, text=" NV200 (billetes 0x00) ",
            bg="#1e1e2e", fg="#89dceb", font=("Consolas", 10, "bold"),
            bd=1, relief="solid")
        nv_f.pack(fill="x", padx=8, pady=4)

        for label, cmd in [
            ("SYNC",       lambda: self._m_sync(self.nv200, "NV200")),
            ("INIT",       lambda: self._m_init_nv200()),
            ("ENABLE",     lambda: self._m_cmd(self.nv200, "NV200", "ENABLE",  0x0A)),
            ("DISABLE",    lambda: self._m_cmd(self.nv200, "NV200", "DISABLE", 0x09)),
            ("RESET",      lambda: self._m_cmd(self.nv200, "NV200", "RESET",   0x01)),
            ("GET LEVELS", lambda: self._m_levels(self.nv200, "NV200")),
            ("GET SERIAL", lambda: self._m_serial(self.nv200, "NV200")),
            ("SMART EMPTY",lambda: self._m_empty()),
            ("POLL ▶/■",   lambda: self._toggle_poll_manual("NV200")),
        ]:
            tk.Button(nv_f, text=label, command=cmd,
                      bg="#313244", fg="#cdd6f4", font=("Consolas", 9),
                      relief="flat", cursor="hand2", padx=6, pady=4).pack(
                      side="left", padx=3, pady=6)

        pay_f = tk.LabelFrame(p, text=" Payout manual ",
            bg="#1e1e2e", fg="#89dceb", font=("Consolas", 10, "bold"),
            bd=1, relief="solid")
        pay_f.pack(fill="x", padx=8, pady=4)

        tk.Label(pay_f, text="Dispositivo:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left", padx=(8, 4))
        self.payout_dev_var = tk.StringVar(value="NV200")
        ttk.Combobox(pay_f, textvariable=self.payout_dev_var, width=8,
                     state="readonly", values=["NV200", "SCS"]).pack(
                     side="left", padx=4)

        tk.Label(pay_f, text="Monto ($):", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left", padx=(8, 4))
        self.amount_var = tk.StringVar(value="1.00")
        tk.Entry(pay_f, textvariable=self.amount_var, width=8,
                 bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                 font=("Consolas", 11), relief="flat").pack(side="left", padx=4)

        tk.Button(pay_f, text="TEST PAYOUT",
                  command=lambda: self._m_payout(test=True),
                  bg="#f9e2af", fg="#1e1e2e", font=("Consolas", 9, "bold"),
                  relief="flat", cursor="hand2", padx=8, pady=4).pack(
                  side="left", padx=4)
        tk.Button(pay_f, text="PAYOUT",
                  command=lambda: self._m_payout(test=False),
                  bg="#a6e3a1", fg="#1e1e2e", font=("Consolas", 9, "bold"),
                  relief="flat", cursor="hand2", padx=8, pady=4).pack(
                  side="left", padx=4)

        self._build_log(p)

    def _build_txn_tab(self):
        p = self.tab_txn

        ctrl = tk.Frame(p, bg="#1e1e2e")
        ctrl.pack(fill="x", padx=8, pady=8)

        price_f = tk.LabelFrame(ctrl, text=" Precio del producto ",
            bg="#1e1e2e", fg="#89dceb", font=("Consolas", 10, "bold"),
            bd=1, relief="solid")
        price_f.pack(side="left", padx=(0, 12), pady=4, fill="y")

        tk.Label(price_f, text="$", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 20, "bold")).pack(side="left", padx=(8, 0))
        self.price_var = tk.StringVar(value="0.00")
        tk.Entry(price_f, textvariable=self.price_var, width=8,
                 bg="#313244", fg="#a6e3a1", insertbackground="#cdd6f4",
                 font=("Consolas", 20, "bold"), relief="flat",
                 justify="right").pack(side="left", padx=(0, 8), pady=8)

        btn_f = tk.Frame(ctrl, bg="#1e1e2e")
        btn_f.pack(side="left", padx=8)

        self.btn_cobrar = tk.Button(
            btn_f, text="💰 COBRAR", command=self._txn_start,
            bg="#a6e3a1", fg="#1e1e2e", font=("Consolas", 13, "bold"),
            relief="flat", cursor="hand2", padx=16, pady=8, width=12)
        self.btn_cobrar.pack(pady=(0, 4))

        self.btn_cancelar = tk.Button(
            btn_f, text="✖ CANCELAR", command=self._txn_cancel,
            bg="#f38ba8", fg="#1e1e2e", font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2", padx=12, pady=6, width=12,
            state="disabled")
        self.btn_cancelar.pack()

        state_f = tk.LabelFrame(ctrl, text=" Estado ",
            bg="#1e1e2e", fg="#89dceb", font=("Consolas", 10, "bold"),
            bd=1, relief="solid")
        state_f.pack(side="left", padx=8, pady=4, fill="both", expand=True)

        self.txn_status_var = tk.StringVar(value="Esperando selección...")
        tk.Label(state_f, textvariable=self.txn_status_var,
                 bg="#1e1e2e", fg="#f9e2af",
                 font=("Consolas", 11, "bold"),
                 wraplength=300, justify="left").pack(padx=8, pady=4, anchor="w")

        prog_f = tk.Frame(p, bg="#1e1e2e")
        prog_f.pack(fill="x", padx=8)

        tk.Label(prog_f, text="Insertado:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=4)
        self.inserted_var = tk.StringVar(value="$0.00")
        tk.Label(prog_f, textvariable=self.inserted_var,
                 bg="#1e1e2e", fg="#a6e3a1",
                 font=("Consolas", 14, "bold")).grid(row=0, column=1, sticky="w", padx=4)

        tk.Label(prog_f, text="Precio:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).grid(row=0, column=2, sticky="w", padx=(20, 4))
        self.price_disp_var = tk.StringVar(value="$0.00")
        tk.Label(prog_f, textvariable=self.price_disp_var,
                 bg="#1e1e2e", fg="#89b4fa",
                 font=("Consolas", 14, "bold")).grid(row=0, column=3, sticky="w", padx=4)

        tk.Label(prog_f, text="Falta:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).grid(row=0, column=4, sticky="w", padx=(20, 4))
        self.remaining_var = tk.StringVar(value="$0.00")
        tk.Label(prog_f, textvariable=self.remaining_var,
                 bg="#1e1e2e", fg="#f38ba8",
                 font=("Consolas", 14, "bold")).grid(row=0, column=5, sticky="w", padx=4)

        tk.Label(prog_f, text="Vuelto:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).grid(row=0, column=6, sticky="w", padx=(20, 4))
        self.change_var = tk.StringVar(value="$0.00")
        tk.Label(prog_f, textvariable=self.change_var,
                 bg="#1e1e2e", fg="#cba6f7",
                 font=("Consolas", 14, "bold")).grid(row=0, column=7, sticky="w", padx=4)

        self.timer_var = tk.StringVar(value="")
        tk.Label(prog_f, textvariable=self.timer_var,
                 bg="#1e1e2e", fg="#f9e2af",
                 font=("Consolas", 10)).grid(row=0, column=8, sticky="e", padx=(20, 4))

        self.txn_log = scrolledtext.ScrolledText(
            p, height=18, bg="#181825", fg="#cdd6f4",
            font=("Consolas", 9), insertbackground="#cdd6f4",
            relief="flat", state="disabled")
        self.txn_log.pack(fill="both", expand=True, padx=8, pady=8)

        for tag, color in [
            ("ok",      "#a6e3a1"), ("error",   "#f38ba8"),
            ("event",   "#89dceb"), ("warning", "#f9e2af"),
            ("info",    "#b4befe"), ("credit",  "#a6e3a1"),
            ("crypto",  "#cba6f7"), ("payout",  "#cba6f7"),
        ]:
            self.txn_log.tag_config(tag, foreground=color)

    def _build_log(self, parent):
        poll_f = tk.Frame(parent, bg="#1e1e2e")
        poll_f.pack(fill="x", padx=8, pady=(4, 0))

        self.btn_poll_m = tk.Button(poll_f, text="▶ POLL AMBOS",
            command=self._toggle_poll_both,
            bg="#a6e3a1", fg="#1e1e2e",
            font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
            padx=10, pady=4)
        self.btn_poll_m.pack(side="left", padx=4, pady=4)

        tk.Label(poll_f, text="Intervalo (ms):", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left")
        self.interval_var = tk.StringVar(value="200")
        tk.Entry(poll_f, textvariable=self.interval_var, width=6,
                 bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                 font=("Consolas", 11), relief="flat").pack(side="left", padx=4)

        self.enc_var = tk.StringVar(value="🔓 Sin cifrado")
        tk.Label(poll_f, textvariable=self.enc_var,
                 bg="#1e1e2e", fg="#f9e2af",
                 font=("Consolas", 10)).pack(side="right", padx=8)

        tk.Button(poll_f, text="Limpiar", command=self._clear_log,
                  bg="#313244", fg="#cdd6f4", font=("Consolas", 9),
                  relief="flat", cursor="hand2", padx=6, pady=4).pack(
                  side="right", padx=4)

        self.log = scrolledtext.ScrolledText(
            parent, height=14, bg="#181825", fg="#cdd6f4",
            font=("Consolas", 9), insertbackground="#cdd6f4",
            relief="flat", state="disabled")
        self.log.pack(fill="both", expand=True, padx=8, pady=8)

        for tag, color in [
            ("ok", "#a6e3a1"), ("error", "#f38ba8"), ("event", "#89dceb"),
            ("warning", "#f9e2af"), ("info", "#b4befe"), ("crypto", "#cba6f7"),
            ("credit", "#a6e3a1"), ("payout", "#cba6f7"),
        ]:
            self.log.tag_config(tag, foreground=color)

    # ──────────────────────────────────────────────────────
    #  CONEXIÓN
    # ──────────────────────────────────────────────────────

    def _refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_cb["values"] = ports
        if ports:
            self.port_cb.current(0)

    def _connect(self):
        if self._ser:
            self.polling = False
            time.sleep(0.3)
            self._ser.close()
            self._ser    = None
            self.scs     = None
            self.nv200   = None
            self.btn_connect.config(text="Conectar ambos", bg="#89b4fa")
            self.status_var.set("Desconectado")
            self.btn_poll_m.config(text="▶ POLL AMBOS", bg="#a6e3a1")
            self._log("Desconectado.", "warning")
            return

        port = self.port_var.get()
        if not port:
            messagebox.showerror("Error", "Selecciona un puerto COM.")
            return
        try:
            self._bus_lock = threading.Lock()
            self._ser = serial.Serial(
                port=port, baudrate=9600,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_TWO,
                timeout=1)
            self.scs   = SSPDriver(self._ser, 0x10, self._bus_lock)
            self.nv200 = SSPDriver(self._ser, 0x00, self._bus_lock)
            self.btn_connect.config(text="Desconectar", bg="#f38ba8")
            self.status_var.set(f"Conectado → {port}  |  SCS(0x10) + NV200(0x00)")
            self._log(f"Conectado a {port} — SCS(0x10) + NV200(0x00) en bus IF17", "ok")
            self._log("Iniciando configuración de dispositivos...", "info")
            threading.Thread(target=self._startup_init_thread, daemon=True).start()

        except Exception as e:
            self._log(f"Error al conectar: {e}", "error")
            messagebox.showerror("Error", str(e))

    # ──────────────────────────────────────────────────────
    #  LOGGING
    # ──────────────────────────────────────────────────────

    def _log(self, msg: str, tag: str = "", widget=None):
        if widget is None:
            widget = self.log
        ts = time.strftime("%H:%M:%S")
        widget.configure(state="normal")
        widget.insert("end", f"[{ts}] {msg}\n", tag)
        widget.see("end")
        widget.configure(state="disabled")

    def _tlog(self, msg: str, tag: str = ""):
        self._log(msg, tag, self.txn_log)

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _require(self) -> bool:
        if not self._ser or not self.scs or not self.nv200:
            messagebox.showwarning("Sin conexión", "Conecta primero.")
            return False
        return True

    def _update_enc_label(self):
        scs_ok = self.scs  and self.scs.crypto.is_negotiated
        nv_ok  = self.nv200 and self.nv200.crypto.is_negotiated
        if scs_ok and nv_ok:
            self.enc_var.set("🔒 eSSP ACTIVO (ambos)")
        elif scs_ok or nv_ok:
            self.enc_var.set("🔒 eSSP parcial")
        else:
            self.enc_var.set("🔓 Sin cifrado")

    # ──────────────────────────────────────────────────────
    #  COMANDOS MANUALES
    # ──────────────────────────────────────────────────────

    def _m_sync(self, drv, name):
        if not self._require(): return
        ok = drv.force_sync()
        self._log(f"{name} SYNC → {'OK ✓' if ok else 'FAIL ✗'}",
                  "ok" if ok else "error")

    def _m_cmd(self, drv, name, label, cmd_byte):
        if not self._require(): return
        code, _, _ = drv.send(cmd_byte)
        self._log(f"{name} {label} → {'OK ✓' if code == 0xF0 else f'0x{code:02X}'}",
                  "ok" if code == 0xF0 else "warning")

    def _m_levels(self, drv, name):
        if not self._require(): return
        levels = drv.get_all_levels()
        if not levels:
            self._log(f"{name} GET LEVELS → sin datos", "warning")
            return
        for d in levels:
            self._log(
                f"  {name} {d['country']} ${d['value']/100:>8.2f} → {d['level']} unidades",
                "info")

    def _m_serial(self, drv, name):
        if not self._require(): return
        self._log(f"{name} SERIAL → {drv.get_serial()}", "info")

    def _m_empty(self):
        if not self._require(): return
        if messagebox.askyesno("Confirmar", "¿Ejecutar Smart Empty en NV200?"):
            ok = self.nv200.smart_empty()
            self._log(f"NV200 SMART EMPTY → {'OK ✓' if ok else 'FAIL ✗'}",
                      "ok" if ok else "error")

    def _m_payout(self, test: bool):
        if not self._require(): return
        try:
            cents = round(float(self.amount_var.get()) * 100)
            country = self.country_var.get()
            drv     = self.nv200 if self.payout_dev_var.get() == "NV200" else self.scs
            name    = self.payout_dev_var.get()
        except ValueError:
            messagebox.showerror("Error", "Monto inválido.")
            return
        code, extra = drv.payout_amount(cents, country, test=test)
        label = "TEST PAYOUT" if test else "PAYOUT"
        if code == 0xF0:
            self._log(f"{name} {label} {cents/100:.2f} {country} → OK ✓", "ok")
        elif code == 0xF5 and extra:
            err = PAYOUT_ERRORS.get(extra[0], f"0x{extra[0]:02X}")
            self._log(f"{name} {label} → FAIL: {err}", "error")
        else:
            self._log(f"{name} {label} → 0x{code:02X}", "warning")

    def _m_enable_scs(self):
        if not self._require(): return
        def run():
            info    = self.scs.info
            country = info.get("country", self.country_var.get())
            denoms  = info.get("denoms", [1, 5, 10, 25, 100])
            ok = self.scs.enable_coin_mech(denoms, country)
            self.after(0, self._log,
                       f"SCS ENABLE (coin mech) → {'OK ✓' if ok else 'FAIL ✗'}",
                       "ok" if ok else "error")
        threading.Thread(target=run, daemon=True).start()

    def _m_init_scs(self):
        if not self._require(): return
        threading.Thread(target=self._init_scs_thread, kwargs={"enable_after": False}, daemon=True).start()

    def _m_init_nv200(self):
        if not self._require(): return
        threading.Thread(target=self._init_nv200_thread, kwargs={"enable_after": False}, daemon=True).start()


    # ──────────────────────────────────────────────────────
    #  INIT THREADS
    # ──────────────────────────────────────────────────────

    def _init_scs_thread(self, log_widget=None, enable_after: bool = True):
        drv     = self.scs
        country = self.country_var.get()
        log     = lambda m, t="": self.after(0, self._log, m, t, log_widget or self.log)

        log("═══ INIT SCS (0x10) ═══", "info")
        ok = drv.force_sync()
        log(f"  SCS SYNC → {'OK ✓' if ok else 'FAIL ✗'}", "ok" if ok else "error")
        if not ok:
            return False

        raw  = drv.setup_request()
        info = parse_setup_request(raw) if raw else {}
        drv.info = info
        country  = info.get("country", country)
        denoms   = info.get("denoms", [1, 5, 10, 25, 100])
        proto    = info.get("protocol", 7)
        log(f"  SCS SETUP → FW:{info.get('firmware','?')} PROTO:{proto} DENOMS:{denoms}", "info")

        drv.set_protocol(proto)

        log("  SCS negociando clave eSSP...", "crypto")
        enc_ok = drv.negotiatekeys()
        log(f"  SCS KEY EXCHANGE → {'OK ✓' if enc_ok else 'FAIL ✗'}",
            "crypto" if enc_ok else "warning")
        self.after(0, self._update_enc_label)

        for cents in denoms:
            code, extra = drv.set_denomination_route(cents, country, route=0x00)
            tag = "ok" if code == 0xF0 else "warning"
            msg = "OK ✓" if code == 0xF0 else \
                (ROUTE_ERRORS.get(extra[0], f"0x{extra[0]:02X}") if extra else f"0x{code:02X}")
            log(f"    ROUTE {cents/100:.2f} {country} → {msg}", tag)
            time.sleep(0.06)

        # Comandos coin mech (configuración) — solo en startup
        for cents in denoms:
            params = bytes([0x01]) + struct.pack("<H", cents) + country.encode()
            drv.send(0x40, params)
            time.sleep(0.05)
        drv.send(0x49, bytes([0x01]))
        time.sleep(0.05)

        if enable_after:
            ok = drv.enable()
            log(f"  SCS ENABLE → {'OK ✓  ← esperando monedas' if ok else 'FAIL ✗'}",
                "ok" if ok else "error")
            return ok
        else:
            log("  SCS lista (DISABLED — esperando transacción)", "info")
            return True

    def _init_nv200_thread(self, log_widget=None, enable_after: bool = True):
        drv     = self.nv200
        country = self.country_var.get()
        log     = lambda m, t="": self.after(0, self._log, m, t,
                                            log_widget or self.log)
        NV200_DENOMS = [100, 200, 500, 1000, 2000]

        log("═══ INIT NV200 (0x00) ═══", "info")
        ok = drv.force_sync()
        log(f"  NV200 SYNC → {'OK ✓' if ok else 'FAIL ✗'}", "ok" if ok else "error")
        if not ok:
            return False

        raw  = drv.setup_request()
        info = parse_setup_request(raw) if raw else {}
        drv.info = info
        country  = info.get("country", country)
        proto    = info.get("protocol", 7)
        log(f"  NV200 SETUP → FW:{info.get('firmware','?')} PROTO:{proto}", "info")

        proto_to_set = max(proto, 6)
        ok_proto = drv.set_protocol(proto_to_set)
        drv.info["protocol"] = proto_to_set
        log(f"  NV200 PROTOCOL {proto_to_set} → {'OK ✓' if ok_proto else 'FAIL ✗'}",
            "ok" if ok_proto else "warning")

        drv.set_inhibits(0xFF, 0xFF)

        log("  NV200 negociando clave eSSP...", "crypto")
        enc_ok = drv.negotiatekeys()
        log(f"  NV200 KEY EXCHANGE → {'OK ✓' if enc_ok else 'FAIL ✗'}",
            "crypto" if enc_ok else "error")
        self.after(0, self._update_enc_label)

        if not enc_ok:
            log("  KEY EXCHANGE FAIL — abortando init NV200", "error")
            return False

        for cents in NV200_DENOMS:
            code, extra = drv.set_denomination_route(cents, country, route=0x00)
            tag = "ok" if code == 0xF0 else "warning"
            msg = "OK ✓" if code == 0xF0 else \
                  (ROUTE_ERRORS.get(extra[0], f"0x{extra[0]:02X}") if extra else f"0x{code:02X}")
            log(f"    ROUTE ${cents/100:.2f} {country} → {msg}", tag)
            time.sleep(0.06)

        if enable_after:
            ok  = drv.enable()
            ok2 = drv.enable_payout_device()
            log(f"  NV200 ENABLE VALIDATOR → {'OK ✓' if ok else 'FAIL ✗'}",
                "ok" if ok else "error")
            log(f"  NV200 ENABLE PAYOUT → {'OK ✓  — NV200 listo' if ok2 else 'FAIL ✗'}",
                "ok" if ok2 else "error")
            return ok and ok2
        else:
            log("  NV200 lista (DISABLED — esperando transacción)", "info")
            return True

    def _init_both_thread(self, log_widget=None):
        results = {}
        t1 = threading.Thread(
            target=lambda: results.__setitem__(
                "scs", self._init_scs_thread(log_widget)), daemon=True)
        t2 = threading.Thread(
            target=lambda: results.__setitem__(
                "nv200", self._init_nv200_thread(log_widget)), daemon=True)
        t1.start()
        time.sleep(0.5)
        t2.start()
        t1.join()
        t2.join()
        return results.get("scs", False) and results.get("nv200", False)

    def _startup_init_thread(self):
        """Init completo UNA SOLA VEZ al conectar. Deja dispositivos en DISABLED."""
        log = lambda m, t="": self.after(0, self._log, m, t)

        log("══════ STARTUP INIT ══════", "info")
        scs_done   = threading.Event()
        nv200_done = threading.Event()

        def init_scs():
            self._init_scs_thread(enable_after=False)
            scs_done.set()

        def init_nv200():
            self._init_nv200_thread(enable_after=False)
            nv200_done.set()

        t1 = threading.Thread(target=init_scs,   daemon=True)
        t2 = threading.Thread(target=init_nv200, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.after(0, log, "══ Dispositivos listos (DISABLED) — sistema en espera ══", "ok")
        self.after(0, self.status_var.set,
                f"Listo  |  SCS ✓  NV200 ✓  |  esperando cobro")


    # ──────────────────────────────────────────────────────
    #  POLL
    # ──────────────────────────────────────────────────────

    def _toggle_poll_both(self):
        if not self._require(): return
        if self.polling:
            self.polling = False
            self.btn_poll_m.config(text="▶ POLL AMBOS", bg="#a6e3a1")
            self._log("Poll detenido.", "warning")
        else:
            self.polling = True
            self.btn_poll_m.config(text="■ DETENER POLL", bg="#f38ba8")
            self.poll_thread = threading.Thread(
                target=self._poll_loop_manual, daemon=True)
            self.poll_thread.start()

    def _toggle_poll_manual(self, which: str):
        if not self._require(): return
        if self.polling:
            self.polling = False
            self._log(f"Poll {which} detenido.", "warning")
        else:
            self.polling = True
            drv  = self.scs if which == "SCS" else self.nv200
            name = which
            self.poll_thread = threading.Thread(
                target=lambda: self._poll_single(drv, name), daemon=True)
            self.poll_thread.start()

    def _poll_single(self, drv, name):
        while self.polling:
            try:
                interval = int(self.interval_var.get()) / 1000.0
            except ValueError:
                interval = 0.2
            code, extra, raw = drv.poll()
            if code == 0xF0 and extra:
                proto  = drv.info.get("protocol", 7)
                events = parse_poll_events(extra, proto)
                for ev in events:
                    self._handle_poll_event(ev, raw, name, drv)
            elif code == 0xF1:
                self.after(0, self._log,
                           f"⚠ {name} SLAVE RESET → re-enabling...", "warning")
                self._auto_reenable(drv, name)
            time.sleep(interval)

    def _poll_loop_manual(self):
        while self.polling:
            try:
                interval = int(self.interval_var.get()) / 1000.0
            except ValueError:
                interval = 0.2
            for drv, name in [(self.scs, "SCS"), (self.nv200, "NV200")]:
                if not self.polling:
                    break
                code, extra, raw = drv.poll()
                if code == 0xF0 and extra:
                    proto  = drv.info.get("protocol", 7)
                    events = parse_poll_events(extra, proto)
                    for ev in events:
                        self._handle_poll_event(ev, raw, name, drv)
                elif code == 0xF1:
                    self.after(0, self._log,
                               f"⚠ {name} SLAVE RESET → re-enabling...", "warning")
                    self._auto_reenable(drv, name)
                time.sleep(interval / 2)

    def _handle_poll_event(self, ev: dict, raw: bytes, name: str, drv):
        code    = ev["code"]
        ev_name = ev["name"]
        data    = ev["data"]
        raw_hex = raw.hex().upper()

        if code == 0xBE:
            return

        tag = "event"
        msg = f"[{name}] POLL EVENT → {ev_name}"

        if code == 0xBF:
            val, country = extract_value_country(data)
            if val:
                msg = f"[{name}] POLL EVENT → VALUE ADDED  ${val/100:.2f} {country}"
                tag = "credit"

        elif code == 0xDA:
            val, country = extract_value_country(data)
            new_msg = (f"[{name}] POLL EVENT → DISPENSING  ${val/100:.2f} {country}..."
                       if val else f"[{name}] POLL EVENT → DISPENSING  (iniciando...)")
            if self._last_dispensing_msg != new_msg:
                self._last_dispensing_msg = new_msg
                self.after(0, self._log, f"{new_msg}  (raw: {raw_hex})", "payout")
            return

        elif code == 0xD2:
            if self._dispensed_handled:
                return
            self._dispensed_handled = True
            val, country = extract_value_country(data)
            amount = f"${val/100:.2f} {country}" if val else ""
            self._last_dispensing_msg = None
            msg = f"[{name}] POLL EVENT → DISPENSED  {amount}  ✓ COMPLETADO"
            tag = "ok"
            self.after(0, self._log, f"{msg}  (raw: {raw_hex})", tag)
            self.nv200.disable()
            if self.txn.status == TransactionState.DISPENSING:
                self.txn.status = TransactionState.COMPLETE
                self.after(0, self._txn_on_dispense_complete)
            else:
                self.polling = False
                self.after(0, self._log, "  NV200 deshabilitado — poll detenido", "info")
            return

        elif code == 0xEF:
            channel = data[0] if data else 0
            msg = f"[{name}] POLL EVENT → READ  canal={channel}"

        elif code == 0xEE:
            channel = data[0] if data else 0
            msg = f"[{name}] POLL EVENT → NOTE CREDIT  canal={channel}"
            tag = "credit"

        elif code == 0xDB:
            channel = data[0] if data else 0
            msg = f"[{name}] POLL EVENT → NOTE STORED IN PAYOUT  canal={channel}"
            tag = "info"

        elif code in (0xB3, 0xB4):
            label = "SMART EMPTYING" if code == 0xB3 else "SMART EMPTIED"
            val, country = extract_value_country(data)
            msg = (f"[{name}] POLL EVENT → {label}  ${val/100:.2f} {country}"
                   if val else f"[{name}] POLL EVENT → {label}  (iniciando...)")
            tag = "payout"
            if code == 0xB4:
                self.polling = False

        elif code == 0xE8:
            tag = "warning"

        self.after(0, self._log, f"{msg}  (raw: {raw_hex})", tag)

    def _auto_reenable(self, drv, name):
        def run():
            time.sleep(0.5)
            if name == "SCS":
                ok = drv.reactivate_coin_mech()
            else:
                ok = drv.enable()
                if ok:
                    drv.enable_payout_device()
            self.after(0, self._log,
                       f"  ✓ {name} Re-ENABLE → {'OK' if ok else 'FAIL'}", "ok")
        threading.Thread(target=run, daemon=True).start()

    # ──────────────────────────────────────────────────────
    #  TRANSACCIÓN AUTOMÁTICA
    # ──────────────────────────────────────────────────────

    def _txn_start(self):
        if not self._require(): return
        try:
            price_cents = round(float(self.price_var.get()) * 100)
        except ValueError:
            messagebox.showerror("Error", "Precio inválido.")
            return
        if price_cents < 25:
            messagebox.showerror("Error", "Precio mínimo: $0.25")
            return

        if not self.nv200.crypto.is_negotiated or not self.scs.crypto.is_negotiated:
            messagebox.showwarning("No listo",
                "Los dispositivos aún no han completado la inicialización.\n"
                "Espera unos segundos e intenta nuevamente.")
            return

        self.txn.reset()
        self.txn.price_cents = price_cents
        self.txn.status      = TransactionState.COLLECTING
        self.txn.start_time  = time.time()

        self.btn_cobrar.config(state="disabled")
        self.btn_cancelar.config(state="normal")
        self.after(0, self._txn_set_status, f"Cobrando ${price_cents/100:.2f}...")
        self.after(0, self._tlog,
                f"═══ TRANSACCIÓN INICIADA — Precio: ${price_cents/100:.2f} ═══", "info")

        def quick_enable():
            country = self.nv200.info.get("country", self.country_var.get())

            ok  = self.nv200.enable()
            ok2 = self.nv200.enable_payout_device()
            self.after(0, self._tlog,
                    f"  NV200 ENABLE → {'OK ✓' if ok and ok2 else 'FAIL ✗'}",
                    "ok" if ok else "error")

            # FIX (Opcion A): 0x49 reactiva el coin mech fisico + 0x0A enable
            # Sin reenviar 0x40 (denomination routes) — persisten desde startup
            ok_scs = self.scs.reactivate_coin_mech()
            self.after(0, self._tlog,
                    f"  SCS ENABLE (0x49+0x0A) → {'OK ✓' if ok_scs else 'FAIL ✗'}",
                    "ok" if ok_scs else "error")

            if self.txn.status != TransactionState.COLLECTING:
                return  # cancelado durante quick_enable

            self.after(0, self._tlog, "Dispositivos listos — insertando dinero...", "info")
            threading.Thread(target=self._txn_poll_loop, args=(country,), daemon=True).start()

        threading.Thread(target=quick_enable, daemon=True).start()

    def _txn_init_and_collect(self):
        country = self.country_var.get()
        self.after(0, self._txn_set_status, "Inicializando dispositivos...")

        ok = self._init_both_thread(self.txn_log)
        if not ok:
            self.after(0, self._txn_set_status, "⚠ Error en INIT — verifica conexión")
            self.after(0, self._txn_reset_buttons)
            return

        self.after(0, self._txn_set_status,
                   f"✓ Listo — Inserte dinero  (${self.txn.price_cents/100:.2f})")
        self.after(0, self._tlog, "Dispositivos listos — insertando dinero...", "ok")
        self._txn_poll_loop(country)

    def _txn_poll_loop(self, country: str):
        if self.txn.status != TransactionState.COLLECTING:
            return

        while self.txn.status == TransactionState.COLLECTING:
            if self.txn.timed_out:
                self.after(0, self._tlog,
                           f"⏱ Timeout ({self.txn.timeout_secs}s) — cancelando...",
                           "warning")
                self._txn_do_cancel(country)
                return

            rem = self.txn.timeout_secs - int(self.txn.elapsed)
            self.after(0, self.timer_var.set, f"⏱ {rem}s")

            code_s, extra_s, raw_s = self.scs.poll()
            if code_s == 0xF0 and extra_s:
                proto  = self.scs.info.get("protocol", 7)
                events = parse_poll_events(extra_s, proto)
                for ev in events:
                    self._txn_handle_scs_event(ev, raw_s, country)

            code_n, extra_n, raw_n = self.nv200.poll()
            if code_n == 0xF0 and extra_n:
                proto  = self.nv200.info.get("protocol", 7)
                events = parse_poll_events(extra_n, proto)
                for ev in events:
                    self._txn_handle_nv200_event(ev, raw_n, country)
            elif code_n == 0xF1:
                time.sleep(0.3)
                self.nv200.enable()
                self.nv200.enable_payout_device()
                if self.txn.elapsed > 10:
                    self.after(0, self._tlog, "⚠ NV200 RESET inesperado — re-habilitado", "warning")

            if (self.txn.escrow_value > 0 and
                    int(self.txn.elapsed * 2) % 8 == 0):
                self.nv200.hold_note()

            if self.txn.total_cents >= self.txn.price_cents:
                    time.sleep(0.6)
                    try:
                        c, ex, _ = self.scs.poll()
                        if c == 0xF0 and ex:
                            proto = self.scs.info.get("protocol", 7)
                            for ev in parse_poll_events(ex, proto):
                                if ev["code"] == 0xBF:
                                    val, ctry = extract_value_country(ev["data"])
                                    if val:
                                        self.txn.add_coin(val)
                                        self.after(0, self._tlog,
                                                f"  SCS MONEDA TARDÍA +${val/100:.2f} "
                                                f"| Total: ${self.txn.total_cents/100:.2f}",
                                                "warning")
                                        self.after(0, self._update_txn_display)
                    except Exception:
                        pass
                    self._txn_process_payment(country)
                    return

            time.sleep(0.15)

    def _txn_handle_scs_event(self, ev: dict, raw: bytes, country: str):
        code = ev["code"]
        data = ev["data"]

        if code == 0xBF:
            val, ctry = extract_value_country(data)
            if val:
                self.txn.add_coin(val)
                self.after(0, self._tlog,
                           f"  SCS MONEDA +${val/100:.2f} {ctry}  "
                           f"| Total: ${self.txn.total_cents/100:.2f}  "
                           f"| Falta: ${self.txn.remaining_cents/100:.2f}", "credit")
                self.after(0, self._update_txn_display)

        elif code == 0xF1:
            self.after(0, self._tlog, "⚠ SCS RESET en transacción — re-enabling", "warning")
            self.scs.reactivate_coin_mech()

    def _txn_handle_nv200_event(self, ev: dict, raw: bytes, country: str):
        code = ev["code"]
        data = ev["data"]

        if code == 0xEF:
            channel = data[0] if data else 0
            if channel > 0:
                self.after(0, self._tlog,
                           f"  NV200 BILLETE EN ESCROW canal={channel} — esperando...",
                           "warning")
                NV200_CHAN = {1: 100, 2: 200, 3: 500, 4: 1000, 5: 2000}
                val = NV200_CHAN.get(channel, 0)
                if val:
                    self.txn.set_escrow(val, country)
                    if self.txn.total_cents + val >= self.txn.price_cents:
                        self.after(0, self._tlog,
                                   f"  NV200 Aceptando billete ${val/100:.2f} "
                                   f"(cubre el precio)", "credit")
                    else:
                        self.nv200.hold_note()
            else:
                self.after(0, self._tlog, "  NV200 leyendo billete...", "event")

        elif code == 0xEE:
            val  = self.txn.escrow_value
            ctry = self.txn.escrow_country or country
            if val == 0:
                channel = data[0] if data else 0
                NV200_CHAN = {1: 100, 2: 200, 3: 500, 4: 1000, 5: 2000}
                val  = NV200_CHAN.get(channel, 0)
                ctry = country
            if val:
                self.txn.add_note_credit(val)
                self.after(0, self._tlog,
                           f"  NV200 BILLETE ACREDITADO +${val/100:.2f} {ctry}  "
                           f"| Total: ${self.txn.total_cents/100:.2f}  "
                           f"| Falta: ${self.txn.remaining_cents/100:.2f}", "credit")
                self.after(0, self._update_txn_display)

        elif code == 0xEC:
            self.after(0, self._tlog,
                       "  NV200 Billete rechazado (devuelto al cliente)", "warning")
            self.txn.clear_escrow()

        elif code == 0xF1:
            self.after(0, self._tlog, "⚠ NV200 RESET en transacción", "warning")
            self.nv200.enable()
            self.nv200.enable_payout_device()

    def _txn_process_payment(self, country: str):
        self.txn.status = TransactionState.CONFIRMING
        change = self.txn.total_cents - self.txn.price_cents

        self.after(0, self._txn_set_status,
                   f"✓ Pago completo — Calculando vuelto ${change/100:.2f}...")
        self.after(0, self._tlog,
                   f"✓ PAGO COMPLETO: recibido ${self.txn.total_cents/100:.2f} "
                   f"precio ${self.txn.price_cents/100:.2f} "
                   f"vuelto ${change/100:.2f}", "ok")

        self.scs.disable()
        self.nv200.disable()

        if change == 0:
            self.after(0, self._txn_set_status, "✅ PAGO EXACTO — Transacción completa")
            self.after(0, self._tlog, "✅ Pago exacto. Sin vuelto.", "ok")
            self.after(0, self._txn_reset_buttons)
            self.txn.status = TransactionState.COMPLETE
            return

        nv200_levels = {d["value"]: d["level"] for d in self.nv200.get_all_levels()}
        scs_levels   = {d["value"]: d["level"] for d in self.scs.get_all_levels()}
        strategy     = calculate_change_strategy(change, nv200_levels, scs_levels)
        self.txn.change_strategy = strategy

        self.after(0, self._tlog, f"  Estrategia: {strategy['message']}", "info")

        if not strategy["feasible"]:
            self.after(0, self._txn_set_status, strategy["message"])
            self.after(0, self._tlog, strategy["message"], "error")
            if strategy["nv200"] == 0 and strategy["scs"] == 0:
                self.after(0, self._txn_reset_buttons)
                return

        self.txn.status = TransactionState.DISPENSING
        self._dispensed_handled = False
        threading.Thread(
            target=self._txn_dispense_change,
            args=(strategy, country),
            daemon=True).start()

    def _txn_on_dispense_complete(self):
        self.after(0, self._txn_set_status, "✅ TRANSACCIÓN COMPLETA")
        self.after(0, self._tlog, "═══ ✅ TRANSACCIÓN COMPLETA ═══", "ok")
        self.after(0, self._txn_reset_buttons)

    def _txn_dispense_change(self, strategy: dict, country: str):
        self.nv200.disable()
        self.scs.disable()
        time.sleep(0.5)

        dispensed_ok = True

        if strategy["nv200"] > 0:
            self.after(0, self._tlog,
                    f"  → NV200 dispensando ${strategy['nv200']/100:.2f}...", "payout")
            self.nv200.enable()
            self.nv200.enable_payout_device()
            time.sleep(0.2)
            code, extra = self.nv200.payout_amount(
                strategy["nv200"], country, test=False)
            if code == 0xF0:
                proto = self.nv200.info.get("protocol", 7)
                # FIX v3.3: salir tan pronto llega DISPENSED — evita espera de ~60s
                nv200_done = False
                for _ in range(60):
                    c, ex, _ = self.nv200.poll()
                    if c == 0xF0 and ex:
                        evts = parse_poll_events(ex, proto)
                        for ev in evts:
                            if ev["code"] == 0xD2:
                                val, ctry = extract_value_country(ev["data"])
                                self.after(0, self._tlog,
                                        f"  ✓ NV200 DISPENSED ${val/100:.2f}", "ok")
                                nv200_done = True
                            elif ev["code"] in (0xD5, 0xB1):
                                self.after(0, self._tlog,
                                        f"  ⚠ NV200 error: {ev['name']}", "error")
                                dispensed_ok = False
                                nv200_done = True
                    if nv200_done:
                        break
                    time.sleep(0.2)
            else:
                err = PAYOUT_ERRORS.get(extra[0] if extra else 0, "")
                self.after(0, self._tlog, f"  ⚠ NV200 PAYOUT FAIL: {err}", "error")
                dispensed_ok = False
            self.nv200.disable()

        if strategy["scs"] > 0:
            self.after(0, self._tlog,
                    f"  → SCS dispensando ${strategy['scs']/100:.2f} en monedas...", "payout")
            self.scs.enable()
            time.sleep(0.4)

            test_code, test_extra = self.scs.payout_amount(strategy["scs"], country, test=True)
            if test_code != 0xF0:
                err = PAYOUT_ERRORS.get(test_extra[0] if test_extra else 0, "sin fondos")
                self.after(0, self._tlog, f"  ⚠ SCS sin fondos suficientes: {err}", "error")
                dispensed_ok = False
            else:
                code, extra = self.scs.payout_amount(strategy["scs"], country, test=False)
                if code == 0xF0:
                    proto = self.scs.info.get("protocol", 7)
                    scs_done = False
                    for _ in range(60):
                        c, ex, _ = self.scs.poll()
                        if c == 0xF0 and ex:
                            evts = parse_poll_events(ex, proto)
                            for ev in evts:
                                if ev["code"] == 0xD2:
                                    val, _ = extract_value_country(ev["data"])
                                    self.after(0, self._tlog,
                                            f"  ✓ SCS DISPENSED ${val/100:.2f}", "ok")
                                    scs_done = True
                                elif ev["code"] in (0xDC, 0xB1):
                                    self.after(0, self._tlog,
                                            f"  ⚠ SCS error: {ev['name']}", "error")
                                    dispensed_ok = False
                                    scs_done = True
                        if scs_done:
                            break
                        time.sleep(0.2)
                else:
                    err = PAYOUT_ERRORS.get(extra[0] if extra else 0, "")
                    self.after(0, self._tlog, f"  ⚠ SCS PAYOUT FAIL: {err}", "error")
                    dispensed_ok = False
            self.scs.disable()

        status = ("✅ TRANSACCIÓN COMPLETA" if dispensed_ok
                else "⚠ TRANSACCIÓN CON ERRORES — verificar vuelto")
        tag    = "ok" if dispensed_ok else "error"
        self.after(0, self._txn_set_status, status)
        self.after(0, self._tlog, f"═══ {status} ═══", tag)
        self.txn.status = TransactionState.COMPLETE
        self.after(0, self._txn_reset_buttons)

    def _txn_cancel(self):
        if self.txn.status not in (
                TransactionState.COLLECTING, TransactionState.CONFIRMING):
            return
        country = self.txn.escrow_country or self.country_var.get()
        self.txn.status = TransactionState.CANCELLED
        self._tlog("✖ CANCELACIÓN solicitada por operador", "warning")
        threading.Thread(
            target=self._txn_do_cancel, args=(country,), daemon=True).start()

    def _txn_do_cancel(self, country: str):
        self.after(0, self._txn_set_status, "Devolviendo dinero al cliente...")

        if self.txn.escrow_value > 0:
            self.after(0, self._tlog,
                    f"  NV200 REJECT billete ${self.txn.escrow_value/100:.2f}...", "warning")
            self.nv200.reject_note()
            time.sleep(1.5)

        total_coins = sum(v * c for v, c in self.txn.coin_breakdown.items())
        if total_coins > 0:
            self.after(0, self._tlog,
                    f"  SCS devolviendo ${total_coins/100:.2f} en monedas...", "payout")
            self.scs.disable()
            time.sleep(0.3)
            self.scs.enable()
            time.sleep(0.4)
            code, extra = self.scs.payout_amount(total_coins, country, test=False)
            if code == 0xF0:
                proto = self.scs.info.get("protocol", 7)
                for _ in range(30):
                    c, ex, _ = self.scs.poll()
                    if c == 0xF0 and ex:
                        evts = parse_poll_events(ex, proto)
                        for ev in evts:
                            if ev["code"] == 0xD2:
                                val, _ = extract_value_country(ev["data"])
                                self.after(0, self._tlog,
                                        f"  ✓ SCS DEVUELTO ${val/100:.2f}", "ok")
                    time.sleep(0.2)
            else:
                err = PAYOUT_ERRORS.get(extra[0] if extra else 0, "error desconocido")
                self.after(0, self._tlog, f"  ⚠ SCS no pudo devolver: {err}", "error")
            self.scs.disable()

        total_notes = sum(v * c for v, c in self.txn.note_breakdown.items())
        if total_notes > 0:
            self.after(0, self._tlog,
                    f"  NV200 devolviendo ${total_notes/100:.2f} en billetes...", "payout")
            self.nv200.enable()
            self.nv200.enable_payout_device()
            time.sleep(0.2)
            code, extra = self.nv200.payout_amount(total_notes, country, test=False)
            if code == 0xF0:
                proto = self.nv200.info.get("protocol", 7)
                for _ in range(60):
                    c, ex, _ = self.nv200.poll()
                    if c == 0xF0 and ex:
                        evts = parse_poll_events(ex, proto)
                        for ev in evts:
                            if ev["code"] == 0xD2:
                                val, _ = extract_value_country(ev["data"])
                                self.after(0, self._tlog,
                                        f"  ✓ NV200 DEVUELTO ${val/100:.2f}", "ok")
                            elif ev["code"] in (0xD5, 0xB1):
                                self.after(0, self._tlog,
                                        f"  ⚠ NV200 error: {ev['name']}", "error")
                    time.sleep(0.2)
            else:
                err = PAYOUT_ERRORS.get(extra[0] if extra else 0, "error desconocido")
                self.after(0, self._tlog, f"  ⚠ NV200 no pudo devolver: {err}", "error")
            self.nv200.disable()

        self.after(0, self._txn_set_status, "Transacción cancelada — dinero devuelto")
        self.after(0, self._tlog, "✖ Transacción cancelada.", "warning")
        self.after(0, self._txn_reset_buttons)


    # ──────────────────────────────────────────────────────
    #  UI UPDATE HELPERS
    # ──────────────────────────────────────────────────────

    def _update_txn_display(self):
        self.inserted_var.set(f"${self.txn.total_cents/100:.2f}")
        self.price_disp_var.set(f"${self.txn.price_cents/100:.2f}")
        self.remaining_var.set(f"${self.txn.remaining_cents/100:.2f}")
        change = max(0, self.txn.total_cents - self.txn.price_cents)
        self.change_var.set(f"${change/100:.2f}")

    def _txn_set_status(self, msg: str):
        self.txn_status_var.set(msg)

    def _txn_reset_buttons(self):
        if self.scs:  self.scs.disable()
        if self.nv200: self.nv200.disable()

        self.btn_cobrar.config(state="normal")
        self.btn_cancelar.config(state="disabled")
        self.timer_var.set("")
        self._update_txn_display()


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = App()
    app.mainloop()
