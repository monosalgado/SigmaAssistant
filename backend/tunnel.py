"""
SSH Tunnel Manager for remote Ollama access.

Automatically opens an SSH tunnel to the NVIDIA Spark server when the app
starts, and closes it cleanly when the app stops.

Only activates when ECONOMY_PROVIDER=ollama is set in .env.
If the tunnel fails (not on network, VPN down, server off), the app
continues normally — economy calls fall back to Gemini automatically.
"""

from __future__ import annotations
import os
import socket
import subprocess
import time


class SSHTunnelManager:
    """Manages a persistent SSH port-forward tunnel as a subprocess."""

    def __init__(self):
        self._process = None
        self._enabled = False
        self._host = None
        self._user = None
        self._key_path = None
        self._local_port = 11434

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Open the tunnel. Called on FastAPI startup.

        Returns True if tunnel is ready, False if not needed or failed.
        """
        if not self._load_config():
            return False

        # Port already reachable — tunnel from a previous run, or Ollama
        # is running locally. Either way, nothing to do.
        if self._is_port_open():
            print(f"[tunnel] Port {self._local_port} already reachable — skipping new tunnel")
            return True

        print(f"[tunnel] Opening SSH tunnel → {self._user}@{self._host}:{self._local_port} ...")

        cmd = [
            "ssh",
            "-N",                                        # no remote command
            "-o", "BatchMode=yes",                       # fail fast, no interactive prompts
            "-o", "StrictHostKeyChecking=accept-new",    # auto-accept new host keys
            "-o", "ConnectTimeout=10",                   # don't hang forever
            "-o", "ServerAliveInterval=30",              # send keepalives
            "-o", "ServerAliveCountMax=3",               # drop after 3 missed keepalives
            "-i", self._key_path,
            "-L", f"{self._local_port}:localhost:{self._local_port}",
            f"{self._user}@{self._host}",
        ]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            print("[tunnel] ✗ 'ssh' command not found — skipping tunnel")
            return False
        except Exception as e:
            print(f"[tunnel] ✗ Could not start SSH process: {e}")
            return False

        # Wait up to 10 seconds for the port to open
        for _ in range(10):
            time.sleep(1)
            if self._is_port_open():
                print(f"[tunnel] ✓ Tunnel ready — Ollama reachable at localhost:{self._local_port}")
                return True
            # SSH process died before the port opened
            if self._process.poll() is not None:
                stderr = self._process.stderr.read().decode(errors="replace").strip()
                print(f"[tunnel] ✗ SSH exited early: {stderr or '(no output)'}")
                self._process = None
                print("[tunnel]   Economy tier will fall back to Gemini this session.")
                return False

        # Timed out — tunnel process may still be alive but port never opened
        print("[tunnel] ✗ Timed out waiting for port — killing SSH process")
        self._cleanup()
        print("[tunnel]   Economy tier will fall back to Gemini this session.")
        return False

    def stop(self) -> None:
        """Close the tunnel. Called on FastAPI shutdown."""
        if not self._process:
            return
        print("[tunnel] Closing SSH tunnel...")
        self._cleanup()
        print("[tunnel] Tunnel closed.")

    def is_alive(self) -> bool:
        """True if port is currently reachable (tunnel or local Ollama)."""
        if not self._enabled:
            return False
        # Check if our process silently died
        if self._process and self._process.poll() is not None:
            print("[tunnel] SSH process died unexpectedly")
            self._process = None
        return self._is_port_open()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_config(self) -> bool:
        """Read SSH connection config from environment variables.

        Returns False (and prints nothing) if the tunnel is not needed.
        """
        from dotenv import load_dotenv
        load_dotenv()

        economy_provider = os.getenv("ECONOMY_PROVIDER", "").lower().strip()
        if economy_provider != "ollama":
            return False  # not using Ollama for economy — nothing to do

        ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        # Only tunnel if Ollama URL is localhost (remote URL = no tunnel needed)
        if "localhost" not in ollama_url and "127.0.0.1" not in ollama_url:
            return False

        self._host = os.getenv("SPARK_SSH_HOST", "").strip()
        self._user = os.getenv("SPARK_SSH_USER", "").strip()
        self._key_path = os.path.expanduser(
            os.getenv("SPARK_SSH_KEY", "~/.ssh/id_ed25519")
        )

        if not self._host or not self._user:
            print("[tunnel] SPARK_SSH_HOST / SPARK_SSH_USER not set — skipping tunnel")
            return False

        self._enabled = True
        return True

    def _is_port_open(self) -> bool:
        """Return True if localhost:<port> accepts a TCP connection."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex(("localhost", self._local_port)) == 0
        except Exception:
            return False

    def _cleanup(self) -> None:
        """Terminate the SSH subprocess."""
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None


# Module-level singleton — imported by main.py and llm_client.py
tunnel_manager = SSHTunnelManager()
