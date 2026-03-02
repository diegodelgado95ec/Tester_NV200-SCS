"""
=============================================================
  ITL SSP / eSSP Driver + GUI  — tester.py
  SCS (monedas 0x10) | NV200 (billetes 0x00)
=============================================================
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from contextlib import contextmanager
import threading
import serial
import serial.tools.list_ports
import struct
import time
import os
import random
from Crypto.Cipher import AES
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
#  DRIVER SSP
# ══════════════════════════════════════════════════════════

class SSPDriver:
    def __init__(self, port: str, address: int, baudrate: int = 9600):
        self.address = address
        self.seq     = 1
        self.crypto  = eSSPCrypto()
        self._lock   = threading.Lock()
        self.ser     = serial.Serial(
            port=port, baudrate=baudrate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_TWO,
            timeout=1
        )

    def close(self):
        if self.ser.is_open:
            self.ser.close()

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
            print(f"  PKT COMPLETO → {pkt.hex().upper()}")
            print(f"  ENC PAYLOAD  → {enc_payload.hex().upper()}")
            self.ser.write(pkt)
            time.sleep(0.08)
            raw = self.ser.read(256)
            self.seq ^= 1
            print(f"  ENC RECV raw={raw.hex().upper()}")
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

    def negotiate_keys(self) -> bool:
        self.send(0x01)
        time.sleep(1.5)
        self.send(0x11)
        time.sleep(0.1)
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

    def set_protocol(self, v: int = 6) -> bool:
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
        code, extra, raw = self.send(0x07)
        return code, extra, raw

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

    def payout_amount(self, cents: int, country: str, test: bool = False) -> bool:
        option = 0x19 if test else 0x58
        params = struct.pack("<I", cents) + country.encode("ascii") + bytes([option])
        if self.crypto.is_negotiated:
            (code, _), _ = self.send_encrypted(0x33, params)
        else:
            code, _, _ = self.send(0x33, params)
        return code == 0xF0

    def smart_empty(self) -> bool:
        if self.crypto.is_negotiated:
            (code, _), _ = self.send_encrypted(0x52)
        else:
            code, _, _ = self.send(0x52)
        return code == 0xF0

    def set_denomination_route_encrypted(self, cents: int, country: str,
                                          route: int = 0x00) -> tuple:
        params = (bytes([route])
                  + struct.pack("<I", cents)
                  + country.encode("ascii"))
        (code, extra), _ = self.send_encrypted(0x3B, params)
        return code, extra

    def enable_coin_mech(self, denoms: list, country: str) -> bool:
        """Envía inhibits + coin mech + enable. Usa fast_timeout para ser rápido."""
        with self.fast_timeout(0.2):
            for cents in denoms:
                params = bytes([0x01]) + struct.pack("<H", cents) + country.encode()
                self.send(0x40, params)
                time.sleep(0.02)
            self.send(0x49, bytes([0x01]))
            time.sleep(0.02)
        return self.enable()


# ══════════════════════════════════════════════════════════
#  CONSTANTES DE EVENTOS
# ══════════════════════════════════════════════════════════

GENERIC_RESPONSES = {
    0xF0: "OK",
    0xF1: "SLAVE RESET",
    0xF2: "CMD NOT KNOWN",
    0xF3: "WRONG PARAMS",
    0xF4: "PARAM OUT OF RANGE",
    0xF5: "CANNOT PROCESS",
    0xF6: "SOFTWARE ERROR",
    0xF8: "FAIL",
    0xFA: "KEY NOT SET",
    0xFE: "DECRYPT ERROR",
}

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
    0xEF: "NOTE READ",
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
}

ROUTE_ERRORS = {1: "Sin payout conectado", 2: "Moneda inválida", 3: "Fallo payout"}


# ══════════════════════════════════════════════════════════
#  Parser de eventos SSP con tamaños variables
# ══════════════════════════════════════════════════════════

def parse_poll_events(extra: bytes, proto: int = 7) -> list:
    MULTI_COUNTRY_EVENTS = {
        0xBF, 0xDA, 0xD2, 0xD7, 0xD8, 0xD5,
        0xB3, 0xB4, 0xDC, 0xDD, 0xE6, 0xD9, 0xD6,
    }
    result = []
    i = 0
    while i < len(extra):
        code = extra[i]
        i += 1
        name    = EVENTS.get(code, f"0x{code:02X}")
        ev_data = b""
        if proto >= 6 and code in MULTI_COUNTRY_EVENTS:
            if i < len(extra):
                n_countries = extra[i]
                block_size  = 1 + n_countries * 7
                ev_data     = extra[i: i + block_size]
                i          += block_size
        result.append({"code": code, "name": name, "data": ev_data})
    return result


def format_value_added(ev_data: bytes) -> str:
    if not ev_data or len(ev_data) < 1:
        return ""
    n = ev_data[0]
    parts = []
    for k in range(n):
        base = 1 + k * 7
        if base + 7 > len(ev_data):
            break
        val     = struct.unpack_from("<I", ev_data, base)[0]
        country = ev_data[base + 4: base + 7].decode("ascii", errors="ignore")
        parts.append(f"{val/100:.2f} {country}")
    return "  ".join(parts)


# ══════════════════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ITL SSP Monitor (eSSP)")
        self.resizable(True, True)
        self.geometry("980x720")
        self.configure(bg="#1e1e2e")

        self.driver       = None
        self.polling      = False
        self.poll_thread  = None
        self.device_proto = 7
        self.device_info  = {}
        self.is_emptying  = False
        self._reenabling  = False
        self._negotiating = False

        self._build_ui()
        self._refresh_ports()

    def _build_ui(self):
        top = tk.Frame(self, bg="#1e1e2e", pady=8)
        top.pack(fill="x", padx=12)

        tk.Label(top, text="Puerto:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left")
        self.port_var = tk.StringVar()
        self.port_cb  = ttk.Combobox(top, textvariable=self.port_var,
                                     width=10, state="readonly")
        self.port_cb.pack(side="left", padx=(4, 12))

        tk.Label(top, text="Dispositivo:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left")
        self.dev_var = tk.StringVar(value="SCS (0x10)")
        ttk.Combobox(top, textvariable=self.dev_var, width=16, state="readonly",
                     values=["SCS (0x10)", "NV200 (0x00)"]).pack(
                     side="left", padx=(4, 12))

        tk.Label(top, text="País:", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left")
        self.country_var = tk.StringVar(value="USD")
        ttk.Combobox(top, textvariable=self.country_var, width=6,
                     state="readonly", values=["USD", "EUR", "GBP"]).pack(
                     side="left", padx=(4, 12))

        self.btn_connect = tk.Button(
            top, text="Conectar", width=10, command=self._connect,
            bg="#89b4fa", fg="#1e1e2e", font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2")
        self.btn_connect.pack(side="left", padx=4)

        tk.Button(top, text="↻", width=3, command=self._refresh_ports,
                  bg="#313244", fg="#cdd6f4", font=("Consolas", 11),
                  relief="flat", cursor="hand2").pack(side="left")

        status_row = tk.Frame(self, bg="#1e1e2e")
        status_row.pack(fill="x", padx=12)
        self.status_var = tk.StringVar(value="Desconectado")
        tk.Label(status_row, textvariable=self.status_var,
                 bg="#1e1e2e", fg="#a6e3a1",
                 font=("Consolas", 10)).pack(side="left")
        self.enc_var = tk.StringVar(value="🔓 Sin cifrado")
        self.enc_lbl = tk.Label(status_row, textvariable=self.enc_var,
                                bg="#1e1e2e", fg="#f9e2af",
                                font=("Consolas", 10))
        self.enc_lbl.pack(side="right", padx=8)

        cmd_frame = tk.LabelFrame(self, text=" Comandos ",
            bg="#1e1e2e", fg="#89dceb", font=("Consolas", 10, "bold"),
            bd=1, relief="solid")
        cmd_frame.pack(fill="x", padx=12, pady=(4, 0))

        btns = [
            ("SYNC",          self._cmd_sync),
            ("INIT COMPLETO", self._cmd_full_init),
            ("SETUP REQUEST", self._cmd_setup),
            ("NEGOTIATE KEY", self._cmd_negotiate),
            ("ENABLE",        self._cmd_enable),
            ("DISABLE",       self._cmd_disable),
            ("RESET",         self._cmd_reset),
            ("GET LEVELS",    self._cmd_levels),
            ("GET SERIAL",    self._cmd_serial),
            ("GET FW",        self._cmd_fw),
            ("SMART EMPTY",   self._cmd_empty),
        ]
        for i, (label, cmd) in enumerate(btns):
            tk.Button(cmd_frame, text=label, command=cmd,
                      bg="#313244", fg="#cdd6f4", font=("Consolas", 9),
                      relief="flat", cursor="hand2", padx=6, pady=4,
                      activebackground="#45475a",
                      activeforeground="#cdd6f4").grid(
                row=0, column=i, padx=3, pady=6, sticky="ew")

        pay_frame = tk.LabelFrame(self, text=" Pago ",
            bg="#1e1e2e", fg="#89dceb", font=("Consolas", 10, "bold"),
            bd=1, relief="solid")
        pay_frame.pack(fill="x", padx=12, pady=(4, 0))

        tk.Label(pay_frame, text="Monto ($):", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left", padx=(8, 4))
        self.amount_var = tk.StringVar(value="1.00")
        tk.Entry(pay_frame, textvariable=self.amount_var, width=8,
                 bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                 font=("Consolas", 11), relief="flat").pack(side="left", padx=4)

        tk.Button(pay_frame, text="TEST PAYOUT",
                  command=lambda: self._cmd_payout(test=True),
                  bg="#f9e2af", fg="#1e1e2e", font=("Consolas", 9, "bold"),
                  relief="flat", cursor="hand2", padx=8, pady=4).pack(
                  side="left", padx=4)
        tk.Button(pay_frame, text="PAYOUT",
                  command=lambda: self._cmd_payout(test=False),
                  bg="#a6e3a1", fg="#1e1e2e", font=("Consolas", 9, "bold"),
                  relief="flat", cursor="hand2", padx=8, pady=4).pack(
                  side="left", padx=4)

        poll_frame = tk.LabelFrame(self, text=" Poll ",
            bg="#1e1e2e", fg="#89dceb", font=("Consolas", 10, "bold"),
            bd=1, relief="solid")
        poll_frame.pack(fill="x", padx=12, pady=(4, 0))

        self.btn_poll = tk.Button(poll_frame, text="▶ INICIAR POLL",
            command=self._toggle_poll, bg="#a6e3a1", fg="#1e1e2e",
            font=("Consolas", 10, "bold"), relief="flat", cursor="hand2",
            padx=10, pady=4)
        self.btn_poll.pack(side="left", padx=8, pady=6)

        tk.Label(poll_frame, text="Intervalo (ms):", bg="#1e1e2e", fg="#cdd6f4",
                 font=("Consolas", 10)).pack(side="left")
        self.interval_var = tk.StringVar(value="200")
        tk.Entry(poll_frame, textvariable=self.interval_var, width=6,
                 bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                 font=("Consolas", 11), relief="flat").pack(side="left", padx=4)

        tk.Button(poll_frame, text="Limpiar log", command=self._clear_log,
                  bg="#313244", fg="#cdd6f4", font=("Consolas", 9),
                  relief="flat", cursor="hand2", padx=8, pady=4).pack(
                  side="right", padx=8)

        self.log = scrolledtext.ScrolledText(
            self, height=14, bg="#181825", fg="#cdd6f4",
            font=("Consolas", 9), insertbackground="#cdd6f4",
            relief="flat", state="disabled")
        self.log.pack(fill="both", expand=True, padx=12, pady=8)

        self.log.tag_config("ok",      foreground="#a6e3a1")
        self.log.tag_config("error",   foreground="#f38ba8")
        self.log.tag_config("event",   foreground="#89dceb")
        self.log.tag_config("warning", foreground="#f9e2af")
        self.log.tag_config("info",    foreground="#b4befe")
        self.log.tag_config("crypto",  foreground="#cba6f7")
        self.log.tag_config("credit",  foreground="#a6e3a1")

    def _refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_cb["values"] = ports
        if ports:
            self.port_cb.current(0)

    def _log(self, msg: str, tag: str = ""):
        ts = time.strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{ts}] {msg}\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _get_address(self) -> int:
        return 0x10 if "SCS" in self.dev_var.get() else 0x00

    def _require_driver(self) -> bool:
        if not self.driver:
            messagebox.showwarning("Sin conexión", "Conecta primero el dispositivo.")
            return False
        return True

    def _update_enc_label(self):
        if self.driver and self.driver.crypto.is_negotiated:
            self.enc_var.set("🔒 eSSP ACTIVO")
            self.enc_lbl.config(fg="#a6e3a1")
        else:
            self.enc_var.set("🔓 Sin cifrado")
            self.enc_lbl.config(fg="#f9e2af")

    def _connect(self):
        if self.driver:
            self.polling = False
            time.sleep(0.3)
            self.driver.close()
            self.driver       = None
            self.device_info  = {}
            self._reenabling  = False
            self._negotiating = False
            self.btn_connect.config(text="Conectar", bg="#89b4fa")
            self.status_var.set("Desconectado")
            self.btn_poll.config(text="▶ INICIAR POLL", bg="#a6e3a1")
            self._update_enc_label()
            self._log("Desconectado.", "warning")
            return
        port = self.port_var.get()
        if not port:
            messagebox.showerror("Error", "Selecciona un puerto COM.")
            return
        try:
            self.driver = SSPDriver(port, self._get_address())
            self.btn_connect.config(text="Desconectar", bg="#f38ba8")
            self.status_var.set(f"Conectado → {port}  |  {self.dev_var.get()}")
            self._log(f"Conectado a {port} ({self.dev_var.get()})", "ok")
            self._update_enc_label()
        except Exception as e:
            self._log(f"Error al conectar: {e}", "error")
            messagebox.showerror("Error", str(e))

    def _cmd_sync(self):
        if not self._require_driver(): return
        ok = self.driver.force_sync()
        self._log("SYNC → " + ("OK ✓" if ok else "FAIL ✗"), "ok" if ok else "error")

    def _cmd_setup(self):
        if not self._require_driver(): return
        data = self.driver.setup_request()
        if data:
            info = parse_setup_request(data)
            self.device_info  = info
            self.device_proto = info.get("protocol", 7)
            self._log(
                f"SETUP REQUEST → FW:{info.get('firmware','')} "
                f"PROTO:{info.get('protocol','')} "
                f"PAÍS:{info.get('country','')} "
                f"DENOMS:{info.get('denoms',[])}",
                "ok")
        else:
            self._log("SETUP REQUEST → FAIL", "error")

    def _cmd_negotiate(self):
        if not self._require_driver(): return
        self._log("── Negociando clave eSSP (Diffie-Hellman)...", "crypto")
        def run():
            self._negotiating = True
            try:
                ok = self.driver.negotiate_keys()
                if ok:
                    key_hex = self.driver.crypto._aes_key.hex().upper()
                    self.after(0, self._log,
                               f"  KEY EXCHANGE → OK ✓  KEY:{key_hex}", "crypto")
                else:
                    self.after(0, self._log,
                               "  KEY EXCHANGE → FAIL ✗", "error")
                self.after(0, self._update_enc_label)
            finally:
                self._negotiating = False
        threading.Thread(target=run, daemon=True).start()

    def _cmd_enable(self):
        if not self._require_driver(): return
        def run():
            info    = self.device_info
            country = info.get("country", self.country_var.get())
            denoms  = info.get("denoms", [])
            ok = self.driver.enable_coin_mech(denoms, country)
            self.after(0, self._log,
                    "ENABLE → " + ("OK ✓" if ok else "FAIL ✗"),
                    "ok" if ok else "error")
        threading.Thread(target=run, daemon=True).start()

    def _cmd_disable(self):
        if not self._require_driver(): return
        ok = self.driver.disable()
        self._log("DISABLE → " + ("OK ✓" if ok else "FAIL ✗"), "ok" if ok else "error")

    def _cmd_reset(self):
        if not self._require_driver(): return
        ok = self.driver.reset()
        if ok:
            self.driver.crypto.is_negotiated = False
            self._update_enc_label()
        self._log("RESET → " + ("OK ✓" if ok else "FAIL ✗"), "ok" if ok else "error")

    def _cmd_serial(self):
        if not self._require_driver(): return
        self._log(f"SERIAL NUMBER → {self.driver.get_serial()}", "info")

    def _cmd_fw(self):
        if not self._require_driver(): return
        self._log(f"FIRMWARE → {self.driver.get_fw()}", "info")

    def _cmd_levels(self):
        if not self._require_driver(): return
        levels = self.driver.get_all_levels()
        if not levels:
            self._log("GET ALL LEVELS → sin datos", "warning")
            return
        for d in levels:
            self._log(
                f"  {d['country']}  {d['value']/100:>8.2f}  →  {d['level']} unidades",
                "info")

    def _cmd_empty(self):
        if not self._require_driver(): return
        if messagebox.askyesno("Confirmar", "¿Ejecutar Smart Empty?"):
            ok = self.driver.smart_empty()
            self._log("SMART EMPTY → " + ("OK ✓" if ok else "FAIL ✗"),
                      "ok" if ok else "error")

    def _cmd_payout(self, test: bool = False):
        if not self._require_driver(): return
        try:
            cents   = int(float(self.amount_var.get()) * 100)
            country = self.country_var.get()
        except ValueError:
            messagebox.showerror("Error", "Monto inválido.")
            return
        ok    = self.driver.payout_amount(cents, country, test=test)
        label = "TEST PAYOUT" if test else "PAYOUT"
        self._log(f"{label} {cents/100:.2f} {country} → "
                  + ("OK ✓" if ok else "FAIL ✗"),
                  "ok" if ok else "error")

    def _cmd_full_init(self):
        if not self._require_driver(): return
        country = self.country_var.get()
        is_scs  = "SCS" in self.dev_var.get()
        def run():
            self._negotiating = True
            try:
                self.after(0, self._log, "═══ INIT COMPLETO ═══", "info")
                ok = self.driver.force_sync()
                self.after(0, self._log,
                           f"  SYNC → {'OK ✓' if ok else 'FAIL ✗'}",
                           "ok" if ok else "error")
                if not ok:
                    self.after(0, self._log,
                               "  ⚠ Sin respuesta — verifica cables y dirección",
                               "error")
                    return
                raw_data    = self.driver.setup_request()
                info        = parse_setup_request(raw_data) if raw_data else {}
                proto       = info.get("protocol", 7)
                denoms      = info.get("denoms", [])
                fw          = info.get("firmware", "?")
                country_dev = info.get("country", country)
                self.device_info  = info
                self.device_proto = proto
                self.after(0, self._log,
                           f"  SETUP → FW:{fw}  PROTO:{proto}  "
                           f"PAÍS:{country_dev}  DENOMS:{denoms}", "info")
                ok = self.driver.set_protocol(proto)
                self.after(0, self._log,
                           f"  PROTOCOL VER {proto} → {'OK ✓' if ok else 'FAIL ✗'}",
                           "ok" if ok else "warning")
                self.after(0, self._log,
                           "  Negociando clave eSSP (Diffie-Hellman)...", "crypto")
                enc_ok = self.driver.negotiate_keys()
                if enc_ok:
                    key_hex = self.driver.crypto._aes_key.hex().upper()
                    self.after(0, self._log,
                               f"  KEY EXCHANGE → OK ✓  KEY:{key_hex[:16]}...",
                               "crypto")
                else:
                    self.after(0, self._log,
                               "  KEY EXCHANGE → FAIL ✗  (rutas sin cifrar)",
                               "warning")
                self.after(0, self._update_enc_label)
                if is_scs:
                    self._full_init_scs(country_dev, denoms, proto)
                else:
                    self._full_init_nv200(country_dev, denoms, proto)
            finally:
                self._negotiating = False
        threading.Thread(target=run, daemon=True).start()

    def _full_init_scs(self, country: str, denoms: list, proto: int):
        if not denoms:
            denoms = {
                "USD": [1, 5, 10, 25, 100],
                "EUR": [5, 10, 20, 50, 100, 200],
                "GBP": [1, 2, 5, 10, 20, 50, 100, 200],
            }.get(country, [1, 5, 10, 25, 100])

        self.after(0, self._log, f"  Denominaciones: {denoms}", "info")
        enc    = self.driver.crypto.is_negotiated
        method = "🔒 CIFRADO" if enc else "⚠ SIN CIFRAR"
        self.after(0, self._log,
                   f"  [1/4] Set Denomination Route ({method})...", "info")
        for cents in denoms:
            if enc:
                code, extra = self.driver.set_denomination_route_encrypted(
                    cents, country, route=0x00)
            else:
                params = bytes([0x00]) + struct.pack("<I", cents) + country.encode()
                code, extra, _ = self.driver.send(0x3B, params)
            tag = "ok" if code == 0xF0 else "warning"
            if code == 0xF0:
                msg = "OK ✓"
            elif code == 0xF5 and extra:
                msg = f"CANNOT PROCESS ({ROUTE_ERRORS.get(extra[0], extra[0])})"
                tag = "error"
            else:
                msg = f"0x{code:02X}"
            self.after(0, self._log,
                       f"    ROUTE {cents/100:.2f} {country} → {msg}", tag)
            time.sleep(0.06)

        self.after(0, self._log, "  [2/4] Set Coin Inhibits...", "info")
        for cents in denoms:
            params = bytes([0x01]) + struct.pack("<H", cents) + country.encode()
            code, _, _ = self.driver.send(0x40, params)
            tag = "ok" if code == 0xF0 else "warning"
            self.after(0, self._log,
                       f"    INHIBIT {cents/100:.2f} {country} → "
                       f"{'OK' if code == 0xF0 else f'0x{code:02X}'}",
                       tag)
            time.sleep(0.06)

        self.after(0, self._log, "  [3/4] Enable Coin Mech...", "info")
        code, _, _ = self.driver.send(0x49, bytes([0x01]))
        self.after(0, self._log,
                   f"    ENABLE COIN MECH → "
                   f"{'OK ✓' if code == 0xF0 else f'0x{code:02X}'}",
                   "ok" if code == 0xF0 else "warning")
        time.sleep(0.06)

        self.after(0, self._log, "  [4/4] Enable...", "info")
        ok = self.driver.enable()
        self.after(0, self._log,
                   f"  ENABLE → {'OK ✓  ← insertar monedas ahora' if ok else 'FAIL ✗'}",
                   "ok" if ok else "error")
        if ok:
            self.after(0, self._log,
                       "  ✓ SCS listo — LED verde fijo esperado", "ok")

    def _full_init_nv200(self, country: str, denoms: list, proto: int):
        if not denoms:
            denoms = {
                "USD": [100, 200, 500, 1000, 2000, 5000, 10000],
                "EUR": [500, 1000, 2000, 5000, 10000, 20000, 50000],
                "GBP": [500, 1000, 2000, 5000, 10000, 20000, 50000],
            }.get(country, [100, 200, 500, 1000, 2000, 5000, 10000])

        code, _, _ = self.driver.send(0x02, bytes([0x7F, 0x00]))
        self.after(0, self._log,
                   f"  SET INHIBITS → {'OK ✓' if code == 0xF0 else f'0x{code:02X}'}",
                   "ok" if code == 0xF0 else "warning")
        time.sleep(0.06)

        enc    = self.driver.crypto.is_negotiated
        method = "🔒 CIFRADO" if enc else "⚠ SIN CIFRAR"
        self.after(0, self._log,
                   f"  Set Denomination Routes ({method})...", "info")
        for cents in denoms:
            if enc:
                code, extra = self.driver.set_denomination_route_encrypted(
                    cents, country, route=0x00)
            else:
                params = bytes([0x00]) + struct.pack("<I", cents) + country.encode()
                code, extra, _ = self.driver.send(0x3B, params)
            tag = "ok" if code == 0xF0 else "warning"
            msg = "OK ✓" if code == 0xF0 else f"0x{code:02X}"
            self.after(0, self._log,
                       f"    ROUTE ${cents/100:.2f} {country} → {msg}", tag)
            time.sleep(0.06)

        ok = self.driver.enable()
        self.after(0, self._log,
                   f"  ENABLE (validator) → {'OK ✓' if ok else 'FAIL ✗'}",
                   "ok" if ok else "error")
        time.sleep(0.1)

        if self.driver.crypto.is_negotiated:
            (code, extra), _ = self.driver.send_encrypted(0x5C, bytes([0x00]))
        else:
            code, extra, _ = self.driver.send(0x5C, bytes([0x00]))

        payout_errors = {1: "Sin payout", 2: "Moneda inválida", 3: "Ocupado",
                         4: "Vacío",      5: "Error dispositivo"}
        if code == 0xF0:
            self.after(0, self._log,
                       "  ENABLE PAYOUT DEVICE → OK ✓  — NV200 listo", "ok")
        else:
            err = payout_errors.get(extra[0] if extra else 0, f"0x{code:02X}")
            self.after(0, self._log,
                       f"  ENABLE PAYOUT DEVICE → FAIL ({err})", "error")

    def _toggle_poll(self):
        if self.polling:
            self.polling = False
            self.btn_poll.config(text="▶ INICIAR POLL", bg="#a6e3a1")
        else:
            if not self._require_driver(): return
            self.polling = True
            self.btn_poll.config(text="⏹ DETENER POLL", bg="#f38ba8")
            self.poll_thread = threading.Thread(
                target=self._poll_loop, daemon=True)
            self.poll_thread.start()

    def _auto_enable_after_reset(self):
        time.sleep(0.3)
        try:
            info    = self.device_info
            country = info.get("country", self.country_var.get())
            denoms  = info.get("denoms", [])
            ok = self.driver.enable_coin_mech(denoms, country)
            if ok:
                self.after(0, self._log, "  ✓ Re-ENABLE + COIN MECH → OK", "ok")
            else:
                self.after(0, self._log, "  ✗ Re-ENABLE → FAIL", "error")
        except Exception as e:
            self.after(0, self._log, f"  ✗ Re-ENABLE error: {e}", "error")
        finally:
            self._reenabling = False

    def _poll_loop(self):
        empty_timeout = 0

        while self.polling:
            try:
                interval = int(self.interval_var.get()) / 1000
            except ValueError:
                interval = 0.2

            try:
                code, extra, raw = self.driver.poll()
            except Exception as e:
                self.after(0, self._log, f"POLL ERROR: {e}", "error")
                self.polling = False
                break

            if not raw:
                if self.is_emptying:
                    empty_timeout += 1
                    if empty_timeout > 10:
                        self.after(0, self._log,
                                "⚠ EMPTY timeout — re-sync...", "warning")
                        self.is_emptying = False
                        empty_timeout = 0
                        self.driver.force_sync()
                time.sleep(interval)
                continue

            empty_timeout = 0

            if extra:
                events = parse_poll_events(extra, proto=self.device_proto)
                for ev in events:
                    name    = ev["name"]
                    ev_data = ev["data"]
                    code_ev = ev["code"]

                    if code_ev not in EVENTS:
                        self.after(0, self._log,
                                f"POLL EVENT → 0x{code_ev:02X} (ignorado)"
                                f"  (raw: {raw.hex().upper()})",
                                "warning")
                        continue

                    if code_ev in (0xF1, 0xE8) and not self._negotiating:
                        if not self._reenabling:
                            self._reenabling = True
                            label = "SLAVE RESET" if code_ev == 0xF1 else "DISABLED"
                            self.after(0, self._log,
                                    f"⚠ SCS {label} detectado — re-enabling...",
                                    "warning")
                            threading.Thread(
                                target=self._auto_enable_after_reset,
                                daemon=True
                            ).start()

                    if code_ev == 0xB3:
                        self.is_emptying = True
                    elif code_ev == 0xB4:
                        self.is_emptying = False
                        self.after(0, self._log, "  ✓ EMPTY COMPLETADO", "ok")
                        threading.Thread(
                            target=lambda: (
                                time.sleep(0.5),
                                self.driver.force_sync()
                            ),
                            daemon=True
                        ).start()

                    if ev_data and code_ev in {
                        0xBF, 0xDA, 0xD2, 0xD7, 0xD8,
                        0xB3, 0xB4, 0xDC, 0xDD, 0xD9,
                    }:
                        val_str = format_value_added(ev_data)
                        tag     = "credit" if code_ev == 0xBF else "event"
                        self.after(0, self._log,
                                f"POLL EVENT → {name}  {val_str}"
                                f"  (raw: {raw.hex().upper()})",
                                tag)
                    else:
                        self.after(0, self._log,
                                f"POLL EVENT → {name}"
                                f"  (raw: {raw.hex().upper()})",
                                "event")

            elif code != 0xF0:
                resp_name = GENERIC_RESPONSES.get(code, f"0x{code:02X}")
                self.after(0, self._log,
                        f"POLL → {resp_name}"
                        f"  (raw: {raw.hex().upper()})",
                        "warning")

            time.sleep(interval)

        self.after(0, self._log, "Poll detenido.", "warning")
        self.after(0, self.btn_poll.config,
                {"text": "▶ INICIAR POLL", "bg": "#a6e3a1"})


if __name__ == "__main__":
    app = App()
    app.mainloop()
