import threading
import queue
import tkinter as tk
from tkinter import ttk
from url_scanner import crawl, format_report


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("URL Security Scanner")
        root.geometry("800x600")

        main = ttk.Frame(root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # Input row
        input_row = ttk.Frame(main)
        input_row.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(input_row, text="Start URL:").pack(side=tk.LEFT)
        self.url_var = tk.StringVar(value="https://example.com")
        self.url_entry = ttk.Entry(input_row, textvariable=self.url_var, width=60)
        self.url_entry.pack(side=tk.LEFT, padx=(6, 12))

        ttk.Label(input_row, text="Depth:").pack(side=tk.LEFT)
        self.depth_var = tk.IntVar(value=2)
        self.depth_spin = ttk.Spinbox(input_row, from_=1, to=3, textvariable=self.depth_var, width=4)
        self.depth_spin.pack(side=tk.LEFT, padx=(6, 12))

        self.start_btn = ttk.Button(input_row, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT)

        # Paned area for logs/results
        paned = ttk.Panedwindow(main, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Logs
        logs_frame = ttk.Labelframe(paned, text="Progress / Logs")
        self.logs_text = tk.Text(logs_frame, height=12, wrap=tk.NONE)
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        self.logs_text.configure(state=tk.DISABLED)
        paned.add(logs_frame, weight=1)

        # Results
        results_frame = ttk.Labelframe(paned, text="Scan Report")
        self.results_text = tk.Text(results_frame, wrap=tk.NONE)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.configure(state=tk.DISABLED)
        paned.add(results_frame, weight=2)

        # Queue for thread-safe messages
        self.q = queue.Queue()
        self.scanning_thread = None

    def start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            return
        depth = int(self.depth_var.get())

        # prepare UI
        self.start_btn.configure(state=tk.DISABLED)
        self.clear_text(self.logs_text)
        self.clear_text(self.results_text)
        self.append_log(f"Starting scan for {url} (depth={depth})\n")

        # start background scan
        self.scanning_thread = threading.Thread(target=self._run_scan, args=(url, depth), daemon=True)
        self.scanning_thread.start()

        # start polling queue
        self.root.after(100, self._drain_queue)

    def _run_scan(self, url, depth):
        # log_callback will be called from this background thread; push messages to queue
        def log_cb(msg):
            self.q.put(("LOG", str(msg)))

        try:
            results = crawl(url, max_depth=depth, max_pages=200, log_callback=log_cb)
            self.q.put(("RESULT", results))
        except Exception as e:
            self.q.put(("LOG", f"Scan error: {type(e).__name__}: {e}"))
            self.q.put(("DONE", None))

    def _drain_queue(self):
        while not self.q.empty():
            typ, payload = self.q.get()
            if typ == "LOG":
                self.append_log(payload + "\n")
            elif typ == "RESULT":
                report = format_report(payload)
                self.append_result(report)
                self.append_log("\nScan complete.\n")
                self.start_btn.configure(state=tk.NORMAL)
            elif typ == "DONE":
                self.append_log("\nScan finished with errors.\n")
                self.start_btn.configure(state=tk.NORMAL)

        # If thread still running, keep polling; otherwise final update done
        if self.scanning_thread and self.scanning_thread.is_alive():
            self.root.after(100, self._drain_queue)

    def append_log(self, text: str):
        self.logs_text.configure(state=tk.NORMAL)
        self.logs_text.insert(tk.END, text)
        self.logs_text.see(tk.END)
        self.logs_text.configure(state=tk.DISABLED)

    def append_result(self, text: str):
        self.results_text.configure(state=tk.NORMAL)
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.results_text.configure(state=tk.DISABLED)

    def clear_text(self, widget):
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.configure(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
