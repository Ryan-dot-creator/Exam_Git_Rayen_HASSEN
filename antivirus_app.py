import hashlib
import json
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib import parse
from urllib import request

API_BASE_URL = "https://www.virustotal.com/api/v3"


def calculate_md5(file_path, chunk_size=8192):
    md5 = hashlib.md5()
    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
    return md5.hexdigest()


class VirusTotalClient:
    def __init__(self, api_key):
        self.api_key = api_key

    def _request(self, endpoint):
        url = f"{API_BASE_URL}{endpoint}"
        req = request.Request(url)
        req.add_header("x-apikey", self.api_key)
        with request.urlopen(req, timeout=30) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)

    def lookup_hash(self, file_hash):
        return self._request(f"/files/{file_hash}")

    def search_filename(self, filename):
        query = parse.quote(f"name:{filename}")
        return self._request(f"/search?query={query}")


class AntivirusGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VirusTotal File Checker")
        self.geometry("700x500")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        padding = {"padx": 12, "pady": 8}

        api_frame = ttk.LabelFrame(self, text="VirusTotal API")
        api_frame.pack(fill="x", **padding)

        ttk.Label(api_frame, text="API Key:").grid(row=0, column=0, sticky="w", **padding)
        self.api_entry = ttk.Entry(api_frame, width=60, show="*")
        self.api_entry.grid(row=0, column=1, sticky="w", **padding)

        file_frame = ttk.LabelFrame(self, text="File Scan")
        file_frame.pack(fill="x", **padding)

        ttk.Label(file_frame, text="File Path:").grid(row=0, column=0, sticky="w", **padding)
        self.file_entry = ttk.Entry(file_frame, width=60)
        self.file_entry.grid(row=0, column=1, sticky="w", **padding)
        ttk.Button(file_frame, text="Browse", command=self._browse_file).grid(
            row=0, column=2, sticky="w", **padding
        )

        ttk.Label(file_frame, text="Or file name:").grid(row=1, column=0, sticky="w", **padding)
        self.name_entry = ttk.Entry(file_frame, width=60)
        self.name_entry.grid(row=1, column=1, sticky="w", **padding)

        action_frame = ttk.Frame(self)
        action_frame.pack(fill="x", **padding)
        ttk.Button(action_frame, text="Scan", command=self._start_scan).pack(side="left")
        ttk.Button(action_frame, text="Clear", command=self._clear).pack(side="left", padx=8)

        result_frame = ttk.LabelFrame(self, text="Results")
        result_frame.pack(fill="both", expand=True, **padding)

        self.result_text = tk.Text(result_frame, height=16, wrap="word")
        self.result_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.result_text.configure(state="disabled")

    def _browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def _clear(self):
        self.file_entry.delete(0, tk.END)
        self.name_entry.delete(0, tk.END)
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.configure(state="disabled")

    def _start_scan(self):
        api_key = self.api_entry.get().strip()
        file_path = self.file_entry.get().strip()
        filename = self.name_entry.get().strip()

        if not api_key:
            messagebox.showerror("Missing API Key", "Please enter your VirusTotal API key.")
            return

        if not file_path and not filename:
            messagebox.showerror("Missing Input", "Select a file or enter a file name to search.")
            return

        self._write_result("Scanning...\n")
        thread = threading.Thread(
            target=self._scan, args=(api_key, file_path, filename), daemon=True
        )
        thread.start()

    def _scan(self, api_key, file_path, filename):
        try:
            client = VirusTotalClient(api_key)
            if file_path:
                file_hash = calculate_md5(file_path)
                response = client.lookup_hash(file_hash)
                self._display_file_report(file_hash, response)
            else:
                response = client.search_filename(filename)
                self._display_search_results(filename, response)
        except Exception as exc:
            self._write_result(f"Error: {exc}\n")

    def _display_file_report(self, file_hash, response):
        data = response.get("data")
        if not data:
            self._write_result(f"No data returned for hash {file_hash}.\n")
            return

        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = [
            f"MD5: {file_hash}",
            f"Malicious: {stats.get('malicious', 0)}",
            f"Suspicious: {stats.get('suspicious', 0)}",
            f"Harmless: {stats.get('harmless', 0)}",
            f"Undetected: {stats.get('undetected', 0)}",
            f"Last analysis date: {attributes.get('last_analysis_date')}",
        ]
        self._write_result("\n".join(results) + "\n")

    def _display_search_results(self, filename, response):
        data = response.get("data", [])
        if not data:
            self._write_result(f"No matches found for name '{filename}'.\n")
            return

        self._write_result(f"Found {len(data)} matches for '{filename}':\n")
        for entry in data:
            attributes = entry.get("attributes", {})
            md5 = attributes.get("md5", "unknown")
            stats = attributes.get("last_analysis_stats", {})
            self._write_result(
                f"- {attributes.get('meaningful_name', 'unknown')} (MD5: {md5}) "
                f"Malicious: {stats.get('malicious', 0)}\n"
            )

    def _write_result(self, text):
        self.result_text.configure(state="normal")
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.configure(state="disabled")


if __name__ == "__main__":
    app = AntivirusGUI()
    app.mainloop()
