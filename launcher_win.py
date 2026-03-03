"""
launcher_win.py — CyberWar Sandbox Windows Launcher
=====================================================
Entry point for the Windows .exe (no console window).

- Starts Flask on localhost:5000 in a background thread
- Opens the default browser automatically
- Puts a system-tray icon in the notification area
  Right-click → Open Browser  /  Quit
- Closing the tray icon stops the server cleanly

Requires:  pystray  pillow  (both installed by build_win.bat)
Fallback:  if pystray is unavailable, shows a plain tkinter window instead.
"""

import os
import sys
import threading
import time
import webbrowser
import socket

# ── Ensure project root is on path inside the PyInstaller bundle ─────────────
BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

HOST = "127.0.0.1"


def find_free_port(start=5000):
    for p in range(start, start + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, p))
                return p
            except OSError:
                continue
    return start


def start_server(port):
    from app import app as flask_app
    flask_app.run(host=HOST, port=port, debug=False, use_reloader=False)


def wait_for_server(port, timeout=8):
    for _ in range(int(timeout / 0.15)):
        time.sleep(0.15)
        try:
            with socket.create_connection((HOST, port), timeout=0.3):
                return True
        except OSError:
            continue
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  System-tray icon (pystray + Pillow)
# ─────────────────────────────────────────────────────────────────────────────

def _make_icon_image():
    """Generate a simple amber-on-dark icon image programmatically."""
    from PIL import Image, ImageDraw
    size = 64
    img  = Image.new('RGBA', (size, size), (5, 10, 14, 255))
    draw = ImageDraw.Draw(img)
    # Amber circle
    draw.ellipse([8, 8, 56, 56], outline=(245, 166, 35, 255), width=4)
    # Inner cross-hair
    mid = size // 2
    draw.line([(mid, 14), (mid, 50)], fill=(245, 166, 35, 200), width=2)
    draw.line([(14, mid), (50, mid)], fill=(245, 166, 35, 200), width=2)
    return img


def run_tray(port, stop_event):
    try:
        import pystray
        from PIL import Image
    except ImportError:
        # pystray / Pillow not available — fall back to tkinter
        _run_tkinter_fallback(port, stop_event)
        return

    url = f"http://{HOST}:{port}"

    def on_open(icon, item):
        webbrowser.open(url)

    def on_quit(icon, item):
        icon.stop()
        stop_event.set()

    icon_image = _make_icon_image()
    menu = pystray.Menu(
        pystray.MenuItem("Open CyberWar Sandbox", on_open, default=True),
        pystray.MenuItem(f"Running on {url}", lambda *_: None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", on_quit),
    )
    icon = pystray.Icon("CyberWar Sandbox", icon_image, "CyberWar Sandbox", menu)
    icon.run()


def _run_tkinter_fallback(port, stop_event):
    """Minimal tkinter window — shown when pystray is unavailable."""
    url = f"http://{HOST}:{port}"
    try:
        import tkinter as tk
        from tkinter import font as tkfont

        root = tk.Tk()
        root.title("CyberWar Sandbox")
        root.resizable(False, False)
        root.configure(bg="#050a0e")

        w, h = 320, 160
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        AMBER = "#f5a623"; DIM = "#4a6a7a"; BG = "#050a0e"; BG2 = "#081218"; TEXT = "#c8dfe8"

        tk.Label(root, text="CYBERWAR SANDBOX",
                 fg=AMBER, bg=BG,
                 font=tkfont.Font(family="Arial", size=14, weight="bold")).pack(pady=(18,4))
        tk.Label(root, text="● Server running",
                 fg="#00ff88", bg=BG,
                 font=tkfont.Font(family="Arial", size=9)).pack()
        lbl = tk.Label(root, text=url, fg=TEXT, bg=BG2,
                       font=tkfont.Font(family="Courier", size=10),
                       padx=8, pady=4, cursor="hand2")
        lbl.pack(pady=(8,0), padx=20, fill="x")
        lbl.bind("<Button-1>", lambda e: webbrowser.open(url))

        def quit_app():
            root.destroy()
            stop_event.set()

        tk.Button(root, text="Open in Browser",
                  command=lambda: webbrowser.open(url),
                  bg=BG2, fg=AMBER, relief="flat",
                  font=tkfont.Font(family="Arial", size=9),
                  padx=12, pady=5).pack(pady=(8,2), padx=20, fill="x")
        tk.Button(root, text="Quit CyberWar",
                  command=quit_app,
                  bg=BG2, fg=DIM, relief="flat",
                  font=tkfont.Font(family="Arial", size=9),
                  padx=12, pady=5).pack(pady=(0,14), padx=20, fill="x")

        root.protocol("WM_DELETE_WINDOW", quit_app)
        root.mainloop()
    except Exception:
        print(f"CyberWar Sandbox running at {url}")
        print("Press Ctrl+C to quit.")
        try:
            stop_event.wait()
        except KeyboardInterrupt:
            stop_event.set()


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    port = find_free_port(5000)
    url  = f"http://{HOST}:{port}"

    # Start Flask
    server_thread = threading.Thread(target=start_server, args=(port,), daemon=True)
    server_thread.start()

    # Wait for server to be ready
    wait_for_server(port)

    # Open browser
    webbrowser.open(url)

    # Show tray icon / GUI — blocks until user quits
    stop_event = threading.Event()
    run_tray(port, stop_event)


if __name__ == "__main__":
    main()
