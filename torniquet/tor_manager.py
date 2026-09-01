"""Tor process lifecycle and control-port operations."""
import os
import signal as sig
import subprocess
import time
from pathlib import Path

from stem import Signal
from stem.control import Controller
from stem.connection import IncorrectPassword, MissingPassword

TORNIQUET_HOME = Path.home() / ".torniquet"
PID_FILE = TORNIQUET_HOME / "tor.pid"
TORRC = TORNIQUET_HOME / "torrc"
DATA_DIR = TORNIQUET_HOME / "tor-data"

DEFAULT_TORRC = """\
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory {data_dir}
"""


class TorManager:
    def __init__(self, control_port: int = 9051, socks_port: int = 9050):
        self.control_port = control_port
        self.socks_port = socks_port
        TORNIQUET_HOME.mkdir(exist_ok=True)
        DATA_DIR.mkdir(exist_ok=True)
        if not TORRC.exists():
            TORRC.write_text(DEFAULT_TORRC.format(data_dir=DATA_DIR))

    # -- lifecycle -----------------------------------------------------

    def is_running(self) -> bool:
        if not PID_FILE.exists():
            return False
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, ValueError, OSError):
            return False

    def start(self, on_progress=None):
        """Start tor and block until bootstrap hits 100%. Calls on_progress(pct) as it advances."""
        if self.is_running():
            return

        proc = subprocess.Popen(
            ["tor", "-f", str(TORRC)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        PID_FILE.write_text(str(proc.pid))

        deadline = time.time() + 60
        controller = None
        last_pct = -1
        try:
            while time.time() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError("tor exited before bootstrapping finished")

                if controller is None:
                    try:
                        controller = self._controller()
                    except Exception:
                        time.sleep(0.3)
                        continue

                try:
                    phase = controller.get_info("status/bootstrap-phase", "")
                except Exception:
                    time.sleep(0.3)
                    continue

                pct = self._extract_pct(phase)
                if pct != last_pct:
                    last_pct = pct
                    if on_progress:
                        on_progress(pct)
                if pct >= 100:
                    return
                time.sleep(0.3)
        finally:
            if controller is not None:
                controller.close()

        raise TimeoutError("tor did not finish bootstrapping in time")

    @staticmethod
    def _extract_pct(phase_line: str) -> int:
        try:
            for token in phase_line.split():
                if token.startswith("PROGRESS="):
                    return int(token.split("=", 1)[1])
        except (IndexError, ValueError):
            pass
        return 0

    def stop(self):
        if not PID_FILE.exists():
            return
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, sig.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass
        finally:
            PID_FILE.unlink(missing_ok=True)

    # -- control port ----------------------------------------------------

    def _controller(self) -> Controller:
        controller = Controller.from_port(port=self.control_port)
        try:
            controller.authenticate()
        except (IncorrectPassword, MissingPassword) as e:
            raise RuntimeError(f"could not authenticate to tor control port: {e}")
        return controller

    def get_status(self) -> dict:
        running = self.is_running()
        if not running:
            return {"running": False}

        info = {"running": True, "pid": PID_FILE.read_text().strip()}
        try:
            with self._controller() as controller:
                info["circuits"] = len(controller.get_circuits())
                info["bootstrap"] = controller.get_info("status/bootstrap-phase", "")
        except Exception as e:
            info["control_error"] = str(e)
        info["socks_port"] = self.socks_port
        info["control_port"] = self.control_port
        return info

    def new_circuit(self):
        with self._controller() as controller:
            controller.signal(Signal.NEWNYM)
            time.sleep(1)
