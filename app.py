import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List
import os

from ocsp_tester.runner import TestRunner, TestInputs
from ocsp_tester.exporters import export_results_json, export_results_csv


class OCSPTesterGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("OCSP Server Test Suite")
        self.geometry("1200x800")

        self.var_ocsp_url = tk.StringVar()
        self.var_issuer_path = tk.StringVar()
        self.var_good_cert = tk.StringVar()
        self.var_revoked_cert = tk.StringVar()
        self.var_unknown_ca_cert = tk.StringVar()

        # Optional client signing for sigRequired/auth tests
        self.var_client_cert = tk.StringVar()
        self.var_client_key = tk.StringVar()

        self.var_latency_samples = tk.IntVar(value=5)
        self.var_enable_load = tk.BooleanVar(value=False)
        self.var_load_concurrency = tk.IntVar(value=5)
        self.var_load_requests = tk.IntVar(value=50)

        self.runner = TestRunner()
        self.results = []

        self._build_ui()

    def _build_ui(self) -> None:
        pad = {"padx": 6, "pady": 4}

        frm = ttk.Frame(self)
        frm.pack(fill=tk.X, **pad)

        ttk.Label(frm, text="OCSP URL").grid(row=0, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_ocsp_url, width=80).grid(row=0, column=1, sticky=tk.W)

        ttk.Label(frm, text="Issuer CA").grid(row=1, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_issuer_path, width=80).grid(row=1, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_issuer_path)).grid(row=1, column=2)

        ttk.Label(frm, text="Known GOOD cert").grid(row=2, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_good_cert, width=80).grid(row=2, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_good_cert)).grid(row=2, column=2)

        ttk.Label(frm, text="Known REVOKED cert").grid(row=3, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_revoked_cert, width=80).grid(row=3, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_revoked_cert)).grid(row=3, column=2)

        ttk.Label(frm, text="Unknown-CA cert (optional)").grid(row=4, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_unknown_ca_cert, width=80).grid(row=4, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_unknown_ca_cert)).grid(row=4, column=2)

        ttk.Label(frm, text="Client cert (optional)").grid(row=5, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_client_cert, width=80).grid(row=5, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_client_cert)).grid(row=5, column=2)

        ttk.Label(frm, text="Client key (optional)").grid(row=6, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_client_key, width=80).grid(row=6, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_client_key)).grid(row=6, column=2)

        sep = ttk.Separator(self)
        sep.pack(fill=tk.X, **pad)

        perf = ttk.Frame(self)
        perf.pack(fill=tk.X, **pad)
        ttk.Label(perf, text="Latency samples").grid(row=0, column=0, sticky=tk.E)
        ttk.Entry(perf, textvariable=self.var_latency_samples, width=8).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(perf, text="Enable load test", variable=self.var_enable_load).grid(row=0, column=2, sticky=tk.W)
        ttk.Label(perf, text="Concurrency").grid(row=0, column=3, sticky=tk.E)
        ttk.Entry(perf, textvariable=self.var_load_concurrency, width=8).grid(row=0, column=4, sticky=tk.W)
        ttk.Label(perf, text="Total requests").grid(row=0, column=5, sticky=tk.E)
        ttk.Entry(perf, textvariable=self.var_load_requests, width=8).grid(row=0, column=6, sticky=tk.W)

        actions = ttk.Frame(self)
        actions.pack(fill=tk.X, **pad)
        ttk.Button(actions, text="Run Tests", command=self._run_tests).pack(side=tk.LEFT)
        ttk.Button(actions, text="Export JSON", command=self._export_json).pack(side=tk.LEFT, padx=6)
        ttk.Button(actions, text="Export CSV", command=self._export_csv).pack(side=tk.LEFT)

        self.tree = ttk.Treeview(self, columns=("category", "name", "status", "message"), show="headings")
        self.tree.heading("category", text="Category")
        self.tree.heading("name", text="Test")
        self.tree.heading("status", text="Status")
        self.tree.heading("message", text="Message")
        self.tree.pack(fill=tk.BOTH, expand=True, **pad)

        self.details = tk.Text(self, height=10)
        self.details.pack(fill=tk.BOTH, expand=False, **pad)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _browse(self, var: tk.StringVar) -> None:
        path = filedialog.askopenfilename(filetypes=[("Certificates", "*.pem *.cer *.crt *.der"), ("All files", "*.*")])
        if path:
            var.set(path)

    def _collect_inputs(self) -> TestInputs:
        return TestInputs(
            ocsp_url=self.var_ocsp_url.get().strip(),
            issuer_path=self.var_issuer_path.get().strip(),
            known_good_cert_path=self.var_good_cert.get().strip() or None,
            known_revoked_cert_path=self.var_revoked_cert.get().strip() or None,
            unknown_ca_cert_path=self.var_unknown_ca_cert.get().strip() or None,
            client_sign_cert_path=self.var_client_cert.get().strip() or None,
            client_sign_key_path=self.var_client_key.get().strip() or None,
            latency_samples=max(1, int(self.var_latency_samples.get() or 1)),
            enable_load_test=bool(self.var_enable_load.get()),
            load_concurrency=max(1, int(self.var_load_concurrency.get() or 1)),
            load_requests=max(1, int(self.var_load_requests.get() or 1)),
        )

    def _run_tests(self) -> None:
        inputs = self._collect_inputs()
        if not inputs.ocsp_url or not inputs.issuer_path:
            messagebox.showerror("Input error", "OCSP URL and Issuer CA are required.")
            return

        self.tree.delete(*self.tree.get_children())
        self.details.delete("1.0", tk.END)
        threading.Thread(target=self._run_tests_thread, args=(inputs,), daemon=True).start()

    def _run_tests_thread(self, inputs: TestInputs) -> None:
        try:
            self.results = self.runner.run_all(inputs)
            for r in self.results:
                self.tree.insert("", tk.END, iid=r.id, values=(r.category, r.name, r.status.value, r.message))
        except Exception as exc:
            messagebox.showerror("Execution error", str(exc))

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        rid = sel[0]
        match = next((r for r in self.results if r.id == rid), None)
        self.details.delete("1.0", tk.END)
        if match:
            self.details.insert(tk.END, f"ID: {match.id}\n")
            self.details.insert(tk.END, f"Category: {match.category}\n")
            self.details.insert(tk.END, f"Name: {match.name}\n")
            self.details.insert(tk.END, f"Status: {match.status.value}\n")
            self.details.insert(tk.END, f"Message: {match.message}\n\n")
            for k, v in match.details.items():
                self.details.insert(tk.END, f"{k}: {v}\n")

    def _export_json(self) -> None:
        if not self.results:
            messagebox.showinfo("Export", "No results to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        export_results_json(self.results, path)
        messagebox.showinfo("Export", f"Saved to {path}")

    def _export_csv(self) -> None:
        if not self.results:
            messagebox.showinfo("Export", "No results to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        export_results_csv(self.results, path)
        messagebox.showinfo("Export", f"Saved to {path}")


if __name__ == "__main__":
    os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")
    app = OCSPTesterGUI()
    app.mainloop()
