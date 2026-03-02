#!/usr/bin/env python3
"""
Tester SSP - NV200 (Billetes) + SCS (Monedas)
Programa de prueba simple para validar funcionamiento de máquinas ITL
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import serial
import serial.tools.list_ports
import threading
import time
import struct

# ─────────────── CRC-16 SSP ───────────────
def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0x8005
            else:
                crc >>= 1
    return crc

def build_packet(address: int, command: int, data: bytes = b"", seq_flag: bool = False) -> bytes:
    seq_id = (0x80 if seq_flag else 0x00) | (address & 0x7F)
    payload = bytes([command]) + data
    length  = len(payload)
    raw     = bytes([seq_id, length]) + payload
    crc     = crc16(raw)
    packet  = bytes([0x7F, seq_id, length]) + payload + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    # byte stuffing
    stuffed = bytearray([0x7F])
    for b in packet[1:]:
        stuffed.append(b)
        if b == 0x7F:
            stuffed.append(0x7F)
    return bytes(stuffed)

# ─────────────── Clase genérica SSP ───────────────
class SSPDevice:
    def __init__(self, port: str, address: int, baudrate: int = 9600):
        self.port     = port
        self.address  = address
        self.baudrate = baudrate
        self.ser      = None
        self.seq      = False

    def connect(self):
        self.ser = serial.Serial(self.port, self.baudrate,
                                 bytesize=8, parity="N", stopbits=2,
                                 timeout=1)

    def disconnect(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def send(self, command: int, data: bytes = b"") -> bytes:
        if not self.ser or not self.ser.is_open:
            return b""
        pkt = build_packet(self.address, command, data, self.seq)
        self.seq = not self.seq
        self.ser.reset_input_buffer()
        self.ser.write(pkt)
        time.sleep(0.1)
        raw = self.ser.read(64)
        return raw

    def sync(self):           return self.send(0x11)
    def reset(self):          return self.send(0x01)
    def enable(self):         return self.send(0x0A)
    def disable(self):        return self.send(0x09)
    def poll(self):           return self.send(0x07)
    def get_all_levels(self): return self.send(0x22)

    def payout(self, amount_pennies: int, currency: str = "USD") -> bytes:
        """Payout Amount 0x33"""
        val  = struct.pack("<I", amount_pennies)
        cur  = currency.encode("ascii")[:3].ljust(3, b"\x00")
        opt  = bytes([0x58])   # ejecutar pago
        return self.send(0x33, val + cur + opt)

    def set_inhibits(self, mask_lo=0xFF, mask_hi=0xFF) -> bytes:
        return self.send(0x02, bytes([mask_lo, mask_hi]))

    def host_protocol_version(self, version=8) -> bytes:
        return self.send(0x06, bytes([version]))

    def setup_request(self) -> bytes:
        return self.send(0x05)

# ─────────────── Dirección SCS (default 0x10) ───────────────
class SCS(SSPDevice):
    def __init__(self, port, baudrate=9600):
        super().__init__(port, address=0x10, baudrate=baudrate)

# ─────────────── Dirección NV200 (default 0x00) ───────────────
class NV200(SSPDevice):
    def __init__(self, port, baudrate=9600):
        super().__init__(port, address=0x00, baudrate=baudrate)
    def enable_payout(self):
        return self.send(0x5C, bytes([0x00]))

# ─────────────── GUI ───────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SSP Tester — NV200 + SCS")
        self.resizable(False, False)

        self.nv200: NV200 = None
        self.scs:   SCS   = None
        self._poll_active = False

        self._build_ui()
        self._refresh_ports()

    # ── Construcción de la interfaz ──────────────────────────────────────
    def _build_ui(self):
        pad = dict(padx=6, pady=4)

        # ── Fila 0: Puertos y conexión ──
        frm_ports = ttk.LabelFrame(self, text="Puertos COM")
        frm_ports.grid(row=0, column=0, columnspan=2, sticky="ew", **pad)

        ttk.Label(frm_ports, text="NV200 Puerto:").grid(row=0, column=0, **pad)
        self.cb_nv200 = ttk.Combobox(frm_ports, width=10, state="readonly")
        self.cb_nv200.grid(row=0, column=1, **pad)

        ttk.Label(frm_ports, text="SCS Puerto:").grid(row=0, column=2, **pad)
        self.cb_scs = ttk.Combobox(frm_ports, width=10, state="readonly")
        self.cb_scs.grid(row=0, column=3, **pad)

        ttk.Button(frm_ports, text="Refrescar", command=self._refresh_ports).grid(row=0, column=4, **pad)
        ttk.Button(frm_ports, text="Conectar", command=self._connect).grid(row=0, column=5, **pad)
        ttk.Button(frm_ports, text="Desconectar", command=self._disconnect).grid(row=0, column=6, **pad)

        self.lbl_status = ttk.Label(frm_ports, text="● Desconectado", foreground="red")
        self.lbl_status.grid(row=0, column=7, **pad)

        # ── Fila 1: Cuanto se debe cobrar ──
        frm_cobro = ttk.LabelFrame(self, text="Cobro de la Transacción")
        frm_cobro.grid(row=1, column=0, columnspan=2, sticky="ew", **pad)

        ttk.Label(frm_cobro, text="Monto a cobrar ($):").grid(row=0, column=0, **pad)
        self.ent_cobro = ttk.Entry(frm_cobro, width=12)
        self.ent_cobro.insert(0, "1.00")
        self.ent_cobro.grid(row=0, column=1, **pad)

        ttk.Label(frm_cobro, text="Moneda:").grid(row=0, column=2, **pad)
        self.ent_currency = ttk.Entry(frm_cobro, width=6)
        self.ent_currency.insert(0, "USD")
        self.ent_currency.grid(row=0, column=3, **pad)

        # ── Fila 2: Ingresos registrados ──
        frm_ingresos = ttk.LabelFrame(self, text="Ingresos Registrados (última sesión)")
        frm_ingresos.grid(row=2, column=0, columnspan=2, sticky="ew", **pad)

        ttk.Label(frm_ingresos, text="NV200 (billetes):").grid(row=0, column=0, **pad)
        self.lbl_nv200_in = ttk.Label(frm_ingresos, text="$ 0.00", font=("Consolas", 13, "bold"))
        self.lbl_nv200_in.grid(row=0, column=1, **pad)

        ttk.Label(frm_ingresos, text="SCS (monedas):").grid(row=0, column=2, **pad)
        self.lbl_scs_in = ttk.Label(frm_ingresos, text="$ 0.00", font=("Consolas", 13, "bold"))
        self.lbl_scs_in.grid(row=0, column=3, **pad)

        ttk.Label(frm_ingresos, text="TOTAL:").grid(row=0, column=4, **pad)
        self.lbl_total = ttk.Label(frm_ingresos, text="$ 0.00", font=("Consolas", 14, "bold"), foreground="blue")
        self.lbl_total.grid(row=0, column=5, **pad)

        ttk.Button(frm_ingresos, text="Limpiar contadores",
                   command=self._clear_counters).grid(row=0, column=6, **pad)

        # acumuladores internos (en centavos)
        self._nv200_cents = 0
        self._scs_cents   = 0

        # ── Fila 3: Acciones de devolución ──
        frm_dev = ttk.LabelFrame(self, text="Devolución / Pago de Cambio")
        frm_dev.grid(row=3, column=0, columnspan=2, sticky="ew", **pad)

        ttk.Label(frm_dev, text="Devolver con:").grid(row=0, column=0, **pad)
        self.dev_var = tk.StringVar(value="NV200")
        ttk.Radiobutton(frm_dev, text="NV200 (billetes)", variable=self.dev_var,
                        value="NV200").grid(row=0, column=1, **pad)
        ttk.Radiobutton(frm_dev, text="SCS (monedas)", variable=self.dev_var,
                        value="SCS").grid(row=0, column=2, **pad)

        ttk.Label(frm_dev, text="Monto a devolver ($):").grid(row=0, column=3, **pad)
        self.ent_dev = ttk.Entry(frm_dev, width=10)
        self.ent_dev.insert(0, "0.50")
        self.ent_dev.grid(row=0, column=4, **pad)

        ttk.Button(frm_dev, text="Devolver dinero",
                   command=self._devolver).grid(row=0, column=5, **pad)

        # Botón calcular cambio automático
        ttk.Button(frm_dev, text="Auto cambio (cobrado - ingresado)",
                   command=self._auto_change).grid(row=1, column=0, columnspan=6, **pad)

        # ── Fila 4: Controles de dispositivo ──
        frm_ctrl = ttk.LabelFrame(self, text="Control de Dispositivos")
        frm_ctrl.grid(row=4, column=0, columnspan=2, sticky="ew", **pad)

        for i, (lbl, cmd) in enumerate([
            ("SYNC NV200",     lambda: self._cmd_nv200("sync")),
            ("ENABLE NV200",   lambda: self._cmd_nv200("enable")),
            ("DISABLE NV200",  lambda: self._cmd_nv200("disable")),
            ("POLL NV200",     lambda: self._cmd_nv200("poll")),
            ("SYNC SCS",       lambda: self._cmd_scs("sync")),
            ("ENABLE SCS",     lambda: self._cmd_scs("enable")),
            ("DISABLE SCS",    lambda: self._cmd_scs("disable")),
            ("POLL SCS",       lambda: self._cmd_scs("poll")),
        ]):
            ttk.Button(frm_ctrl, text=lbl, command=cmd, width=14).grid(
                row=i // 4, column=i % 4, **pad)

        # Poll automático
        frm_auto = ttk.Frame(frm_ctrl)
        frm_auto.grid(row=2, column=0, columnspan=4, **pad)
        ttk.Button(frm_auto, text="▶ Iniciar Poll Auto (200ms)",
                   command=self._start_poll).pack(side="left", **pad)
        ttk.Button(frm_auto, text="■ Detener Poll Auto",
                   command=self._stop_poll).pack(side="left", **pad)
        self.lbl_poll = ttk.Label(frm_auto, text="Poll: inactivo")
        self.lbl_poll.pack(side="left", **pad)

        # ── Fila 5: Log ──
        frm_log = ttk.LabelFrame(self, text="Log de Comunicación")
        frm_log.grid(row=5, column=0, columnspan=2, sticky="nsew", **pad)

        self.log = scrolledtext.ScrolledText(frm_log, width=90, height=16,
                                             font=("Consolas", 9), state="disabled")
        self.log.pack(fill="both", expand=True)

        ttk.Button(frm_log, text="Limpiar Log", command=self._clear_log).pack(anchor="e")

    # ── Utilidades ──────────────────────────────────────────────────────
    def _refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.cb_nv200["values"] = ports
        self.cb_scs["values"]   = ports
        if ports:
            self.cb_nv200.set(ports[0])
            self.cb_scs.set(ports[-1] if len(ports) > 1 else ports[0])

    def _log(self, msg: str):
        self.log.config(state="normal")
        self.log.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def _clear_log(self):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    def _clear_counters(self):
        self._nv200_cents = 0
        self._scs_cents   = 0
        self._update_labels()
        self._log("Contadores reiniciados.")

    def _update_labels(self):
        total = self._nv200_cents + self._scs_cents
        self.lbl_nv200_in.config(text=f"$ {self._nv200_cents/100:.2f}")
        self.lbl_scs_in.config(  text=f"$ {self._scs_cents/100:.2f}")
        self.lbl_total.config(   text=f"$ {total/100:.2f}")

    def _parse_resp(self, raw: bytes, device_name: str) -> str:
        if not raw:
            return f"{device_name}: sin respuesta"
        hex_str = " ".join(f"{b:02X}" for b in raw)
        first_data = raw[3] if len(raw) > 3 else 0
        codes = {0xF0: "OK", 0xF1: "RESET", 0xF2: "CMD_DESCONOCIDO",
                 0xF3: "PARAMS_INCORRECTOS", 0xF4: "PARAM_FUERA_RANGO",
                 0xF5: "NO_PROCESADO", 0xF8: "FALLO", 0xFA: "KEY_NO_SET"}
        status = codes.get(first_data, f"0x{first_data:02X}")
        return f"{device_name}: [{status}] {hex_str}"

    # ── Conexión ────────────────────────────────────────────────────────
    def _connect(self):
        try:
            p_nv = self.cb_nv200.get()
            p_sc = self.cb_scs.get()
            if not p_nv or not p_sc:
                messagebox.showerror("Error", "Selecciona puertos COM")
                return
            self.nv200 = NV200(p_nv)
            self.nv200.connect()
            self.scs   = SCS(p_sc)
            self.scs.connect()
            self.lbl_status.config(text="● Conectado", foreground="green")
            self._log(f"Conectado: NV200={p_nv}  SCS={p_sc}")
        except Exception as e:
            self._log(f"ERROR conexión: {e}")
            messagebox.showerror("Error de conexión", str(e))

    def _disconnect(self):
        self._stop_poll()
        if self.nv200: self.nv200.disconnect()
        if self.scs:   self.scs.disconnect()
        self.lbl_status.config(text="● Desconectado", foreground="red")
        self._log("Desconectado.")

    # ── Comandos ────────────────────────────────────────────────────────
    def _cmd_nv200(self, cmd: str):
        if not self.nv200:
            self._log("NV200 no conectado"); return
        funcs = {"sync": self.nv200.sync, "enable": self.nv200.enable,
                 "disable": self.nv200.disable, "poll": self.nv200.poll}
        resp = funcs[cmd]()
        self._log(self._parse_resp(resp, f"NV200.{cmd}"))

    def _cmd_scs(self, cmd: str):
        if not self.scs:
            self._log("SCS no conectado"); return
        funcs = {"sync": self.scs.sync, "enable": self.scs.enable,
                 "disable": self.scs.disable, "poll": self.scs.poll}
        resp = funcs[cmd]()
        self._log(self._parse_resp(resp, f"SCS.{cmd}"))

    # ── Poll automático ─────────────────────────────────────────────────
    def _start_poll(self):
        if self._poll_active: return
        self._poll_active = True
        self.lbl_poll.config(text="Poll: activo ●")
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def _stop_poll(self):
        self._poll_active = False
        self.lbl_poll.config(text="Poll: inactivo")

    def _poll_loop(self):
        while self._poll_active:
            if self.nv200:
                r = self.nv200.poll()
                self._handle_poll_nv200(r)
            if self.scs:
                r = self.scs.poll()
                self._handle_poll_scs(r)
            time.sleep(0.2)

    def _handle_poll_nv200(self, raw: bytes):
        if not raw or len(raw) < 4: return
        event = raw[3]
        if event == 0xEE:   # Credit
            # leer canal del siguiente byte si existe
            ch = raw[4] if len(raw) > 4 else 0
            # valor aproximado (sin dataset real, usamos placeholder)
            self._log(f"NV200: BILLETE ACEPTADO canal={ch}")
        elif event == 0xED:
            self._log("NV200: Rechazando billete...")
        elif event == 0xE9:
            self._log("NV200: ⚠ ATASCO INSEGURO")
        elif event == 0xE7:
            self._log("NV200: ⚠ CASETA LLENA")

    def _handle_poll_scs(self, raw: bytes):
        if not raw or len(raw) < 4: return
        event = raw[3]
        if event == 0xBF:   # Value Added
            if len(raw) >= 9:
                val_cents = struct.unpack_from("<I", raw, 4)[0]
                self._scs_cents += val_cents
                self.after(0, self._update_labels)
                self._log(f"SCS: MONEDA valor acumulado += {val_cents/100:.2f}")
        elif event == 0xCF:
            self._log("SCS: ⚠ DISPOSITIVO LLENO")
        elif event == 0xD5:
            self._log("SCS: ⚠ ATASCO")

    # ── Devolución ──────────────────────────────────────────────────────
    def _devolver(self):
        try:
            amount = float(self.ent_dev.get())
            cents  = int(round(amount * 100))
            cur    = self.ent_currency.get().strip() or "USD"
        except ValueError:
            messagebox.showerror("Error", "Ingresa un monto válido"); return

        if cents <= 0:
            messagebox.showerror("Error", "El monto debe ser mayor a 0"); return

        device = self.dev_var.get()
        if device == "NV200":
            if not self.nv200:
                self._log("NV200 no conectado"); return
            resp = self.nv200.payout(cents, cur)
            self._log(self._parse_resp(resp, f"NV200.payout({amount:.2f} {cur})"))
        else:
            if not self.scs:
                self._log("SCS no conectado"); return
            resp = self.scs.payout(cents, cur)
            self._log(self._parse_resp(resp, f"SCS.payout({amount:.2f} {cur})"))

    def _auto_change(self):
        try:
            cobro = float(self.ent_cobro.get())
            cobro_cents = int(round(cobro * 100))
        except ValueError:
            messagebox.showerror("Error", "Ingresa un monto de cobro válido"); return

        total_in = self._nv200_cents + self._scs_cents
        cambio   = total_in - cobro_cents

        if cambio < 0:
            self._log(f"Falta por cobrar: $ {abs(cambio)/100:.2f}")
            messagebox.showwarning("Pendiente",
                f"Aún faltan $ {abs(cambio)/100:.2f} por ingresar.")
            return
        if cambio == 0:
            self._log("Cobro exacto. Sin cambio.")
            messagebox.showinfo("OK", "Cobro exacto. Sin cambio.")
            return

        # Proponer cambio con SCS primero (monedas), resto con NV200
        self.ent_dev.delete(0, "end")
        self.ent_dev.insert(0, f"{cambio/100:.2f}")
        self._log(f"Cambio calculado: $ {cambio/100:.2f} — usa el botón Devolver dinero")
        messagebox.showinfo("Cambio", f"Monto a devolver: $ {cambio/100:.2f}\nSelecciona el dispositivo y pulsa Devolver.")

    def on_close(self):
        self._disconnect()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
