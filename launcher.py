#!/usr/bin/env python3
"""
launcher.py — CyberWar Sandbox Mac Launcher
============================================
Entry point for the double-click macOS .app bundle.

- Starts the Flask server on localhost:5000 in a background thread
- Opens the browser automatically
- Shows a minimal Tkinter "server running" window with a Quit button
  (keeps the process alive while the server is running)
- Clicking Quit (or closing the window) stops the server cleanly
"""

import os
import sys
import threading
import time
import webbrowser
import socket

# Ensure our package root is on sys.path (needed inside PyInstaller bundle)
BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

PORT = 5000
HOST = "127.0.0.1"
URL  = f"http://{HOST}:{PORT}"


def find_free_port(start=5000):
    """Return the first free port >= start."""
    for p in range(start, start + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, p))
                return p
            except OSError:
                continue
    return start


def start_server(port):
    """Run Flask in a daemon thread so it dies when the main process exits."""
    from app import app as flask_app
    flask_app.run(host=HOST, port=port, debug=False, use_reloader=False)


def show_gui(port):
    """
    Display a small Tkinter window so the user can see the server URL
    and quit cleanly.  Falls back to a blocking wait if Tkinter is absent.
    """
    url = f"http://{HOST}:{port}"
    try:
        import tkinter as tk
        from tkinter import font as tkfont

        root = tk.Tk()
        root.title("CyberWar Sandbox")
        root.resizable(False, False)
        root.configure(bg="#050a0e")

        # Centre on screen
        root.update_idletasks()
        w, h = 320, 160
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        # ── Styles ──────────────────────────────────────────────────────
        AMBER  = "#f5a623"
        DIM    = "#4a6a7a"
        BG     = "#050a0e"
        BG2    = "#081218"
        TEXT   = "#c8dfe8"
        BORDER = "#1a3a50"

        heading_font = tkfont.Font(family="Helvetica", size=14, weight="bold")
        mono_font    = tkfont.Font(family="Courier",   size=10)
        small_font   = tkfont.Font(family="Helvetica", size=9)

        # ── Widgets ──────────────────────────────────────────────────────
        title_lbl = tk.Label(root, text="CYBERWAR SANDBOX",
                             fg=AMBER, bg=BG, font=heading_font)
        title_lbl.pack(pady=(18, 4))

        status_lbl = tk.Label(root, text="● Server running",
                              fg="#00ff88", bg=BG, font=small_font)
        status_lbl.pack()

        url_lbl = tk.Label(root, text=url,
                           fg=TEXT, bg=BG2, font=mono_font,
                           relief="flat", padx=8, pady=4, cursor="hand2")
        url_lbl.pack(pady=(8, 0), padx=20, fill="x")
        url_lbl.bind("<Button-1>", lambda e: webbrowser.open(url))

        open_btn = tk.Button(root,
                             text="Open in Browser",
                             command=lambda: webbrowser.open(url),
                             bg=BG2, fg=AMBER,
                             relief="flat", bd=1,
                             font=small_font, padx=12, pady=5,
                             cursor="hand2",
                             highlightbackground=BORDER)
        open_btn.pack(pady=(8, 2), padx=20, fill="x")

        quit_btn = tk.Button(root,
                             text="Quit CyberWar",
                             command=root.destroy,
                             bg=BG2, fg=DIM,
                             relief="flat", bd=1,
                             font=small_font, padx=12, pady=5,
                             cursor="hand2",
                             highlightbackground=BORDER)
        quit_btn.pack(pady=(0, 14), padx=20, fill="x")

        root.mainloop()

    except Exception:
        # Tkinter unavailable or failed — just block until Ctrl-C
        print(f"\n  CyberWar Sandbox is running at {url}")
        print("  Press Ctrl+C to quit.\n")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


def main():
    global PORT
    PORT = find_free_port(5000)
    url  = f"http://{HOST}:{PORT}"

    # ── Start Flask in the background ────────────────────────────────────
    server_thread = threading.Thread(target=start_server, args=(PORT,), daemon=True)
    server_thread.start()

    # ── Wait until the server accepts connections ─────────────────────────
    for _ in range(30):
        time.sleep(0.15)
        try:
            with socket.create_connection((HOST, PORT), timeout=0.3):
                break
        except OSError:
            continue

    # ── Open browser ──────────────────────────────────────────────────────
    webbrowser.open(url)

    # ── Show GUI (blocking until user quits) ─────────────────────────────
    show_gui(PORT)


if __name__ == "__main__":
    main()
