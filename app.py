import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from typing import List
import os
import sys
import io
from datetime import datetime

from ocsp_tester.runner import TestRunner, TestInputs
from ocsp_tester.exporters import export_results_json, export_results_csv
from ocsp_tester.config import ConfigManager, OCSPConfig
from ocsp_tester.monitor import OCSPMonitor


class ConsoleRedirector:
    """Redirect stdout/stderr to a text widget"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        
    def write(self, text):
        try:
            # Insert text into the widget
            self.text_widget.insert(tk.END, text)
            self.text_widget.see(tk.END)
            # Also write to original stdout for debugging
            self.original_stdout.write(text)
        except Exception:
            # If GUI is not available, just write to original stdout
            self.original_stdout.write(text)
        
    def flush(self):
        try:
            self.original_stdout.flush()
        except Exception:
            pass
            
    def restore(self):
        """Restore original stdout/stderr"""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr


class OCSPTesterGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("OCSP Server Test Suite")
        self.geometry("1200x800")

        # Create menu bar
        self._create_menu_bar()

        # Initialize configuration manager
        self.config_manager = ConfigManager()
        self.config = self.config_manager.load_config()

        self.var_ocsp_url = tk.StringVar(value=self.config.ocsp_url)
        self.var_issuer_path = tk.StringVar(value=self.config.issuer_path)
        self.var_good_cert = tk.StringVar(value=self.config.good_cert)
        self.var_revoked_cert = tk.StringVar(value=self.config.revoked_cert)
        self.var_unknown_ca_cert = tk.StringVar(value=self.config.unknown_ca_cert)

        # Optional client signing for sigRequired/auth tests
        self.var_client_cert = tk.StringVar(value=self.config.client_cert)
        self.var_client_key = tk.StringVar(value=self.config.client_key)

        self.var_latency_samples = tk.IntVar(value=self.config.latency_samples)
        self.var_enable_load = tk.BooleanVar(value=self.config.enable_load_test)
        self.var_load_concurrency = tk.IntVar(value=self.config.load_concurrency)
        self.var_load_requests = tk.IntVar(value=self.config.load_requests)

        # Monitoring variables
        self.var_crl_override_url = tk.StringVar(value=self.config.crl_override_url)
        self.var_check_validity = tk.BooleanVar(value=self.config.check_validity)
        self.var_follow_log = tk.BooleanVar(value=self.config.follow_log)
        self.var_show_info = tk.BooleanVar(value=self.config.show_info)
        self.var_show_warn = tk.BooleanVar(value=self.config.show_warn)
        self.var_show_cmd = tk.BooleanVar(value=self.config.show_cmd)
        self.var_show_stderr = tk.BooleanVar(value=self.config.show_stderr)
        self.var_show_status = tk.BooleanVar(value=self.config.show_status)
        self.var_show_debug = tk.BooleanVar(value=self.config.show_debug)
        
        
        # Trust anchor configuration variables
        self.var_trust_anchor = tk.StringVar(value=self.config.trust_anchor_path)
        self.var_trust_anchor_type = tk.StringVar(value=self.config.trust_anchor_type)
        self.var_require_explicit_policy = tk.BooleanVar(value=self.config.require_explicit_policy)
        self.var_inhibit_policy_mapping = tk.BooleanVar(value=self.config.inhibit_policy_mapping)
        
        # Advanced testing options
        self.var_test_cryptographic_preferences = tk.BooleanVar(value=self.config.test_cryptographic_preferences)
        self.var_test_non_issued_certificates = tk.BooleanVar(value=self.config.test_non_issued_certificates)
        
        # OCSP response validation settings
        self.var_max_age_hours = tk.IntVar(value=self.config.max_age_hours)

        self.runner = TestRunner()
        self.results = []
        self.monitor = None  # Will be initialized after UI is built

        self._build_ui()
        
        # Initialize monitor after UI is built
        self.monitor = OCSPMonitor(log_callback=self._log_monitor, config=self.config)
        
        # Configure advanced testing options from config
        self.monitor.test_cryptographic_preferences = self.config.test_cryptographic_preferences
        self.monitor.test_non_issued_certificates = self.config.test_non_issued_certificates
        
        # Ensure debug logging is enabled by default
        self.var_show_debug.set(True)
        self._log_monitor("[DEBUG] Debug logging enabled by default\n")
        
        # Add some initial console output to demonstrate terminal capture
        # This will be captured by the Console Log tab
        print("=" * 60)
        print("OCSP Server Test Suite - Console Log")
        print("=" * 60)
        print(f"Application started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Python version: {sys.version}")
        print(f"Working directory: {os.getcwd()}")
        print("=" * 60)
        print("This console log captures all stdout/stderr output")
        print("including print statements, error messages, and")
        print("any other terminal output from the application.")
        print("=" * 60)
        
        # Set up cleanup when window is closed
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _on_closing(self):
        """Handle window closing"""
        if hasattr(self, 'console_redirector'):
            self.console_redirector.restore()
        self.destroy()

    def __del__(self):
        """Cleanup when GUI is destroyed"""
        if hasattr(self, 'console_redirector'):
            self.console_redirector.restore()

    def _build_ui(self) -> None:
        pad = {"padx": 6, "pady": 4}

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, **pad)

        # Monitoring tab (now first)
        self.monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_frame, text="OCSP/CRL Monitor")
        
        # Testing tab (now second)
        self.test_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.test_frame, text="Conformance Testing")
        
        # Console Log tab
        self.console_log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.console_log_frame, text="Console Log")

        self._build_monitoring_ui()
        self._build_testing_ui()
        self._build_console_log_ui()

    def _create_menu_bar(self) -> None:
        """Create the menu bar with File and Help menus"""
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Config submenu
        config_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Config", menu=config_menu)
        config_menu.add_command(label="Save Config", command=self._save_config)
        config_menu.add_command(label="Load Config", command=self._load_config)
        
        # Export submenu
        export_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Export", menu=export_menu)
        export_menu.add_command(label="Export as JSON", command=self._export_json)
        export_menu.add_command(label="Export as CSV", command=self._export_csv)
        
        # Separator
        file_menu.add_separator()
        
        # Exit
        file_menu.add_command(label="Exit", command=self.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

    def _build_testing_ui(self) -> None:
        pad = {"padx": 6, "pady": 4}

        frm = ttk.Frame(self.test_frame)
        frm.pack(fill=tk.X, **pad)

        ttk.Label(frm, text="OCSP URL").grid(row=0, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_ocsp_url, width=80).grid(row=0, column=1, sticky=tk.W)

        ttk.Label(frm, text="CRL Override URL").grid(row=1, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_crl_override_url, width=80).grid(row=1, column=1, sticky=tk.W)

        ttk.Label(frm, text="Issuer CA").grid(row=2, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_issuer_path, width=80).grid(row=2, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_issuer_path)).grid(row=2, column=2)

        ttk.Label(frm, text="Known GOOD cert").grid(row=3, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_good_cert, width=80).grid(row=3, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_good_cert)).grid(row=3, column=2)

        ttk.Label(frm, text="Known REVOKED cert").grid(row=4, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_revoked_cert, width=80).grid(row=4, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_revoked_cert)).grid(row=4, column=2)

        ttk.Label(frm, text="Unknown-CA cert (optional)").grid(row=5, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_unknown_ca_cert, width=80).grid(row=5, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_unknown_ca_cert)).grid(row=5, column=2)

        ttk.Label(frm, text="Client cert (optional)").grid(row=6, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_client_cert, width=80).grid(row=6, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_client_cert)).grid(row=6, column=2)

        ttk.Label(frm, text="Client key (optional)").grid(row=7, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_client_key, width=80).grid(row=7, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_client_key)).grid(row=7, column=2)
        
        # Trust anchor configuration
        ttk.Label(frm, text="Trust Anchor (optional)").grid(row=8, column=0, sticky=tk.E)
        ttk.Entry(frm, textvariable=self.var_trust_anchor, width=80).grid(row=8, column=1, sticky=tk.W)
        ttk.Button(frm, text="Browse", command=lambda: self._browse(self.var_trust_anchor)).grid(row=8, column=2)
        
        # Combined configuration and test categories frame
        combined_frame = ttk.Frame(self.test_frame)
        combined_frame.pack(fill=tk.X, **pad)
        
        # Trust anchor configuration (left side)
        trust_anchor_frame = ttk.LabelFrame(combined_frame, text="Trust Anchor Configuration", padding=5)
        trust_anchor_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Trust anchor type selection
        ttk.Label(trust_anchor_frame, text="Trust Anchor Type:").grid(row=0, column=0, sticky=tk.W, **pad)
        trust_anchor_type_frame = ttk.Frame(trust_anchor_frame)
        trust_anchor_type_frame.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Radiobutton(trust_anchor_type_frame, text="Root CA", variable=self.var_trust_anchor_type, value="root").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(trust_anchor_type_frame, text="Bridge CA", variable=self.var_trust_anchor_type, value="bridge").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(trust_anchor_type_frame, text="Intermediate CA", variable=self.var_trust_anchor_type, value="intermediate").pack(side=tk.LEFT, padx=5)
        
        # Trust anchor validation options
        ttk.Label(trust_anchor_frame, text="Validation Options:").grid(row=1, column=0, sticky=tk.W, **pad)
        options_frame = ttk.Frame(trust_anchor_frame)
        options_frame.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Checkbutton(options_frame, text="Require explicit policy", variable=self.var_require_explicit_policy).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(options_frame, text="Inhibit policy mapping", variable=self.var_inhibit_policy_mapping).pack(side=tk.LEFT, padx=5)
        
        # Advanced testing options
        ttk.Label(trust_anchor_frame, text="Advanced Testing:").grid(row=2, column=0, sticky=tk.W, **pad)
        advanced_frame = ttk.Frame(trust_anchor_frame)
        advanced_frame.grid(row=2, column=1, sticky=tk.W)
        
        ttk.Checkbutton(advanced_frame, text="Cryptographic Preferences", variable=self.var_test_cryptographic_preferences).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(advanced_frame, text="Non-Issued Certificates", variable=self.var_test_non_issued_certificates).pack(side=tk.LEFT, padx=5)
        
        # OCSP response validation settings
        ttk.Label(trust_anchor_frame, text="OCSP Response Validation:").grid(row=3, column=0, sticky=tk.W, **pad)
        validation_frame = ttk.Frame(trust_anchor_frame)
        validation_frame.grid(row=3, column=1, sticky=tk.W)
        
        ttk.Label(validation_frame, text="Max Age (hours):").pack(side=tk.LEFT, padx=5)
        max_age_spinbox = ttk.Spinbox(validation_frame, from_=1, to=168, width=5, textvariable=self.var_max_age_hours)
        max_age_spinbox.pack(side=tk.LEFT, padx=5)
        ttk.Label(validation_frame, text="(1-168 hours, default: 24)").pack(side=tk.LEFT, padx=5)

        # Test category selection checkboxes (right side)
        test_categories_frame = ttk.LabelFrame(combined_frame, text="Test Categories", padding=5)
        test_categories_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Create checkboxes for different test categories
        self.var_enable_ocsp_tests = tk.BooleanVar(value=True)
        self.var_enable_crl_tests = tk.BooleanVar(value=True)
        self.var_enable_path_validation_tests = tk.BooleanVar(value=True)
        self.var_enable_ikev2_tests = tk.BooleanVar(value=False)
        self.var_enable_federal_bridge_tests = tk.BooleanVar(value=False)
        self.var_enable_performance_tests = tk.BooleanVar(value=False)
        
        # First row of checkboxes
        ttk.Checkbutton(test_categories_frame, text="OCSP Tests", variable=self.var_enable_ocsp_tests).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Checkbutton(test_categories_frame, text="CRL Tests", variable=self.var_enable_crl_tests).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Checkbutton(test_categories_frame, text="Path Validation Tests", variable=self.var_enable_path_validation_tests).grid(row=0, column=2, sticky=tk.W, padx=5)
        
        # Second row of checkboxes
        ttk.Checkbutton(test_categories_frame, text="IKEv2 Tests", variable=self.var_enable_ikev2_tests).grid(row=1, column=0, sticky=tk.W, padx=5)
        ttk.Checkbutton(test_categories_frame, text="Federal Bridge Tests", variable=self.var_enable_federal_bridge_tests).grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Checkbutton(test_categories_frame, text="Performance Tests", variable=self.var_enable_performance_tests).grid(row=1, column=2, sticky=tk.W, padx=5)
        
        # Add a "Select All" and "Select None" button
        select_frame = ttk.Frame(test_categories_frame)
        select_frame.grid(row=2, column=0, columnspan=3, pady=5)
        ttk.Button(select_frame, text="Select All", command=self._select_all_test_categories).pack(side=tk.LEFT, padx=5)
        ttk.Button(select_frame, text="Select None", command=self._select_none_test_categories).pack(side=tk.LEFT, padx=5)
        ttk.Button(select_frame, text="Default Selection", command=self._select_default_test_categories).pack(side=tk.LEFT, padx=5)

        # Performance test configuration
        perf = ttk.Frame(self.test_frame)
        perf.pack(fill=tk.X, **pad)
        ttk.Label(perf, text="Latency samples").grid(row=0, column=0, sticky=tk.E)
        ttk.Entry(perf, textvariable=self.var_latency_samples, width=8).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(perf, text="Enable load test", variable=self.var_enable_load).grid(row=0, column=2, sticky=tk.W)
        ttk.Label(perf, text="Concurrency").grid(row=0, column=3, sticky=tk.E)
        ttk.Entry(perf, textvariable=self.var_load_concurrency, width=8).grid(row=0, column=4, sticky=tk.W)
        ttk.Label(perf, text="Total requests").grid(row=0, column=5, sticky=tk.E)
        ttk.Entry(perf, textvariable=self.var_load_requests, width=8).grid(row=0, column=6, sticky=tk.W)

        sep = ttk.Separator(self.test_frame)
        sep.pack(fill=tk.X, **pad)

        actions = ttk.Frame(self.test_frame)
        actions.pack(fill=tk.X, **pad)
        
        self.run_tests_btn = ttk.Button(actions, text="Run Tests", command=self._run_tests)
        self.run_tests_btn.pack(side=tk.LEFT)
        
        # Progress indicator
        self.progress_var = tk.StringVar(value="Ready")
        self.progress_label = ttk.Label(actions, textvariable=self.progress_var)
        self.progress_label.pack(side=tk.LEFT, padx=10)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(actions, mode='indeterminate')
        self.progress_bar.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        self.tree = ttk.Treeview(self.test_frame, columns=("category", "name", "status", "message"), show="headings")
        self.tree.heading("category", text="Category", command=lambda: self._sort_tree("category"))
        self.tree.heading("name", text="Test", command=lambda: self._sort_tree("name"))
        self.tree.heading("status", text="Status", command=lambda: self._sort_tree("status"))
        self.tree.heading("message", text="Message", command=lambda: self._sort_tree("message"))
        self.tree.pack(fill=tk.BOTH, expand=True, **pad)
        
        # Initialize sorting state
        self.tree_sort_column = None
        self.tree_sort_reverse = False

        self.details = tk.Text(self.test_frame, height=10)
        self.details.pack(fill=tk.BOTH, expand=False, **pad)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def _build_monitoring_ui(self) -> None:
        pad = {"padx": 6, "pady": 4}

        # Certificate and issuer selection
        cert_frame = ttk.Frame(self.monitor_frame)
        cert_frame.pack(fill=tk.X, **pad)
        
        ttk.Label(cert_frame, text="Issuer Certificate:").grid(row=0, column=0, sticky=tk.E)
        ttk.Entry(cert_frame, textvariable=self.var_issuer_path, width=80).grid(row=0, column=1, sticky=tk.W)
        ttk.Button(cert_frame, text="Browse", command=lambda: self._browse(self.var_issuer_path)).grid(row=0, column=2)

        ttk.Label(cert_frame, text="Certificate File:").grid(row=1, column=0, sticky=tk.E)
        ttk.Entry(cert_frame, textvariable=self.var_good_cert, width=80).grid(row=1, column=1, sticky=tk.W)
        ttk.Button(cert_frame, text="Browse", command=lambda: self._browse(self.var_good_cert)).grid(row=1, column=2)

        # URLs
        url_frame = ttk.Frame(self.monitor_frame)
        url_frame.pack(fill=tk.X, **pad)
        
        ttk.Label(url_frame, text="OCSP URL:").grid(row=0, column=0, sticky=tk.E)
        ttk.Entry(url_frame, textvariable=self.var_ocsp_url, width=80).grid(row=0, column=1, sticky=tk.W)

        ttk.Label(url_frame, text="CRL Override URL:").grid(row=1, column=0, sticky=tk.E)
        ttk.Entry(url_frame, textvariable=self.var_crl_override_url, width=80).grid(row=1, column=1, sticky=tk.W)

        # Options
        options_frame = ttk.Frame(self.monitor_frame)
        options_frame.pack(fill=tk.X, **pad)
        
        ttk.Checkbutton(options_frame, text="Check Certificate Validity Period", variable=self.var_check_validity).grid(row=0, column=0, sticky=tk.W)

        # Control buttons
        control_frame = ttk.Frame(self.monitor_frame)
        control_frame.pack(fill=tk.X, **pad)
        
        ttk.Button(control_frame, text="Run OCSP Check", command=self._run_ocsp_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Run CRL Check", command=self._run_crl_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Show Test Results", command=self._show_test_results_in_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Log", command=self._clear_monitor_log).pack(side=tk.LEFT, padx=5)
        
        # Log filter options
        filter_frame = ttk.Frame(self.monitor_frame)
        filter_frame.pack(fill=tk.X, **pad)
        
        ttk.Checkbutton(filter_frame, text="Follow Log", variable=self.var_follow_log).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(filter_frame, text="[INFO]", variable=self.var_show_info).pack(side=tk.LEFT)
        ttk.Checkbutton(filter_frame, text="[WARN]", variable=self.var_show_warn).pack(side=tk.LEFT)
        ttk.Checkbutton(filter_frame, text="[DEBUG]", variable=self.var_show_debug).pack(side=tk.LEFT)
        ttk.Checkbutton(filter_frame, text="[CMD]", variable=self.var_show_cmd).pack(side=tk.LEFT)
        ttk.Checkbutton(filter_frame, text="[STDERR]", variable=self.var_show_stderr).pack(side=tk.LEFT)
        ttk.Checkbutton(filter_frame, text="[STATUS]", variable=self.var_show_status).pack(side=tk.LEFT)
        
        # Debug control buttons
        debug_frame = ttk.Frame(self.monitor_frame)
        debug_frame.pack(fill=tk.X, **pad)
        
        ttk.Button(debug_frame, text="Enable All Debug", command=self._enable_all_debug).pack(side=tk.LEFT, padx=5)

        # Summary labels
        self.ocsp_summary = tk.StringVar(value="")
        self.crl_summary = tk.StringVar(value="")
        
        ttk.Label(self.monitor_frame, textvariable=self.ocsp_summary, justify='left', foreground='blue', font=("Courier", 10)).pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(self.monitor_frame, textvariable=self.crl_summary, justify='left', foreground='blue', font=("Courier", 10)).pack(fill=tk.X, padx=10, pady=5)

        # Output log
        self.monitor_output = scrolledtext.ScrolledText(self.monitor_frame, height=25)
        self.monitor_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_console_log_ui(self) -> None:
        """Build the console log UI"""
        pad = {"padx": 6, "pady": 4}
        
        # Console log output - captures actual terminal output
        self.console_log_output = scrolledtext.ScrolledText(self.console_log_frame, height=30)
        self.console_log_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add a note at the top
        info_label = ttk.Label(self.console_log_frame, text="Console Log - Captures actual terminal/console output (stdout/stderr)", 
                              font=("Arial", 10, "italic"), foreground="gray")
        info_label.pack(pady=5)
        
        # Set up stdout/stderr redirection after GUI is built
        self.console_redirector = ConsoleRedirector(self.console_log_output)
        # Store original stdout/stderr for restoration if needed
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        sys.stdout = self.console_redirector
        sys.stderr = self.console_redirector

    def _browse(self, var: tk.StringVar) -> None:
        path = filedialog.askopenfilename(filetypes=[("Certificates", "*.pem *.cer *.crt *.der"), ("All files", "*.*")])
        if path:
            var.set(path)

    def _collect_inputs(self) -> TestInputs:
        # Update config with current checkbox values before creating TestInputs
        self.config.test_cryptographic_preferences = bool(self.var_test_cryptographic_preferences.get())
        self.config.test_non_issued_certificates = bool(self.var_test_non_issued_certificates.get())
        self.config.max_age_hours = int(self.var_max_age_hours.get())
        
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
            crl_override_url=self.var_crl_override_url.get().strip() or None,
            trust_anchor_path=self.var_trust_anchor.get().strip() or None,
            trust_anchor_type=self.var_trust_anchor_type.get(),
            require_explicit_policy=bool(self.var_require_explicit_policy.get()),
            inhibit_policy_mapping=bool(self.var_inhibit_policy_mapping.get()),
            config=self.config
        )

    def _run_tests(self) -> None:
        inputs = self._collect_inputs()
        if not inputs.ocsp_url or not inputs.issuer_path:
            messagebox.showerror("Input error", "OCSP URL and Issuer CA are required.")
            return
        
        # Check if any test categories are selected
        if not any([
            self.var_enable_ocsp_tests.get(),
            self.var_enable_crl_tests.get(),
            self.var_enable_path_validation_tests.get(),
            self.var_enable_ikev2_tests.get(),
            self.var_enable_federal_bridge_tests.get(),
            self.var_enable_performance_tests.get()
        ]):
            messagebox.showerror("Input error", "Please select at least one test category to run.")
            return

        # Clear previous results and show progress
        self.tree.delete(*self.tree.get_children())
        self.details.delete("1.0", tk.END)
        
        # Update UI to show tests are running
        self.run_tests_btn.config(state='disabled', text='Running...')
        self.progress_var.set("Running tests...")
        self.progress_bar.start()
        
        # Start test execution in background thread
        threading.Thread(target=self._run_tests_thread, args=(inputs,), daemon=True).start()
        
        # Show debug reminder
        if not self.var_show_debug.get():
            messagebox.showinfo("Debug Logging", "Debug logging is currently disabled. Enable [DEBUG] checkbox in the OCSP/CRL Monitor tab to see detailed test execution information.")

    def _run_tests_thread(self, inputs: TestInputs) -> None:
        try:
            # Update progress with detailed steps
            self.progress_var.set("Initializing tests...")
            self._log_monitor(f"[INFO] Starting test execution at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self._log_monitor(f"[INFO] OCSP URL: {inputs.ocsp_url}\n")
            self._log_monitor(f"[INFO] Issuer path: {inputs.issuer_path}\n")
            
            # Enable debug logging for test execution
            self._log_monitor("[DEBUG] Debug logging enabled for test execution\n")
            self._log_monitor(f"[DEBUG] Test configuration: latency_samples={inputs.latency_samples}, load_test={inputs.enable_load_test}\n")
            self._log_monitor(f"[DEBUG] Certificate paths - Good: {inputs.known_good_cert_path}, Revoked: {inputs.known_revoked_cert_path}\n")
            
            # Test runner instantiation
            self.progress_var.set("Creating test runner...")
            self._log_monitor("[INFO] Creating TestRunner instance...\n")
            self._log_monitor("[DEBUG] TestRunner initialization starting...\n")
            runner = TestRunner(log_callback=self._log_monitor)
            self._log_monitor("[DEBUG] TestRunner initialization completed\n")
            self._log_monitor("[INFO] TestRunner created successfully\n")
            
            # Run the tests with timeout protection
            self.progress_var.set("Executing tests...")
            self._log_monitor("[INFO] Starting test execution...\n")
            self._log_monitor("[DEBUG] Test execution thread starting...\n")
            
            # Windows-compatible timeout mechanism
            import threading
            import time
            
            # Add timeout protection using threading
            timeout_occurred = threading.Event()
            test_results = None
            test_exception = None
            
            def run_tests_with_timeout():
                nonlocal test_results, test_exception
                try:
                    self._log_monitor("[DEBUG] TestRunner.run_all() called\n")
                    # Pass selected test categories to the runner
                    test_categories = {
                        'ocsp_tests': self.var_enable_ocsp_tests.get(),
                        'crl_tests': self.var_enable_crl_tests.get(),
                        'path_validation_tests': self.var_enable_path_validation_tests.get(),
                        'ikev2_tests': self.var_enable_ikev2_tests.get(),
                        'federal_bridge_tests': self.var_enable_federal_bridge_tests.get(),
                        'performance_tests': self.var_enable_performance_tests.get()
                    }
                    self._log_monitor(f"[DEBUG] Test categories enabled: {test_categories}\n")
                    test_results = runner.run_all(inputs, test_categories=test_categories)
                    self._log_monitor(f"[DEBUG] TestRunner.run_all() completed with {len(test_results)} results\n")
                except Exception as e:
                    test_exception = e
                    self._log_monitor(f"[DEBUG] TestRunner.run_all() failed with exception: {str(e)}\n")
            
            # Start test execution in a separate thread
            test_thread = threading.Thread(target=run_tests_with_timeout, daemon=True)
            test_thread.start()
            
            self._log_monitor("[DEBUG] Test execution thread started, waiting for completion...\n")
            
            # Wait for completion with timeout (5 minutes)
            test_thread.join(timeout=300)  # 5 minutes
            
            if test_thread.is_alive():
                self._log_monitor("[DEBUG] Test execution thread timed out after 5 minutes\n")
                # Test is still running, timeout occurred
                self._log_monitor("[ERROR] Test execution timed out after 5 minutes\n")
                raise Exception("Test execution timed out")
            else:
                self._log_monitor("[DEBUG] Test execution thread completed successfully\n")
            
            if test_exception:
                self._log_monitor(f"[DEBUG] Test execution failed with exception: {str(test_exception)}\n")
                raise test_exception
            
            self._log_monitor(f"[DEBUG] Results processing starting...\n")
            self._log_monitor(f"[DEBUG] Total test results received: {len(test_results)}\n")
            
            self.results = test_results
            self._log_monitor(f"[INFO] Test execution completed successfully - {len(self.results)} results\n")
            
            # Update progress
            self.progress_var.set("Processing results...")
            self._log_monitor("[INFO] Processing test results...\n")
            
            # Populate the tree with results
            for i, r in enumerate(self.results):
                self.tree.insert("", tk.END, iid=r.id, values=(r.category, r.name, r.status.value, r.message))
                if i % 5 == 0:  # Update progress every 5 tests
                    self.progress_var.set(f"Processing results... ({i+1}/{len(self.results)})")
            
            # Update progress
            self.progress_var.set("Updating monitoring window...")
            self._log_monitor("[INFO] Updating monitoring window...\n")
            
            # Automatically show test results in monitoring window
            self._show_test_results_in_monitor()
            
            # Also log to monitoring window that tests completed
            self._log_monitor(f"\n[INFO] Test execution completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self._log_monitor(f"[INFO] Total tests executed: {len(self.results)}\n")
            
            # Count results by status
            status_counts = {}
            for result in self.results:
                status = result.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
            
            self._log_monitor(f"[INFO] Test results summary: {status_counts}\n")
            self._log_monitor("="*80 + "\n")
            
            # Update progress to show completion
            self.progress_var.set(f"Completed - {len(self.results)} tests run")
            
        except Exception as exc:
            self.progress_var.set("Error occurred")
            self._log_monitor(f"[ERROR] Test execution failed: {str(exc)}\n")
            self._log_monitor(f"[ERROR] Error type: {type(exc).__name__}\n")
            import traceback
            self._log_monitor(f"[ERROR] Traceback: {traceback.format_exc()}\n")
            messagebox.showerror("Execution error", str(exc))
        finally:
            # Re-enable UI elements
            self.run_tests_btn.config(state='normal', text='Run Tests')
            self.progress_bar.stop()

    

   

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
            
            # Enhanced details display for Path Validation tests
            if "Path Validation" in match.category:
                self.details.insert(tk.END, "=== DETAILED TEST INFORMATION ===\n\n")
            
            def format_details(data, indent_level=0):
                """Recursively format nested details with proper indentation"""
                indent = "  " * indent_level
                for k, v in data.items():
                    if isinstance(v, dict):
                        self.details.insert(tk.END, f"{indent}{k}:\n")
                        format_details(v, indent_level + 1)
                    elif isinstance(v, list):
                        self.details.insert(tk.END, f"{indent}{k}:\n")
                        for item in v:
                            if isinstance(item, dict):
                                format_details(item, indent_level + 1)
                            else:
                                self.details.insert(tk.END, f"{indent}  - {item}\n")
                    else:
                        self.details.insert(tk.END, f"{indent}{k}: {v}\n")
                if indent_level == 0:
                    self.details.insert(tk.END, "\n")
            
            format_details(match.details)

    def _sort_tree(self, column: str) -> None:
        """Sort the tree by the specified column"""
        # Determine if we're sorting the same column (toggle reverse) or a new column
        if self.tree_sort_column == column:
            self.tree_sort_reverse = not self.tree_sort_reverse
        else:
            self.tree_sort_column = column
            self.tree_sort_reverse = False
        
        # Get all items from the tree
        items = []
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            items.append((item, values))
        
        # Define column mapping for sorting
        column_map = {
            "category": 0,
            "name": 1, 
            "status": 2,
            "message": 3
        }
        
        # Sort the items
        col_index = column_map.get(column, 0)
        
        # Custom sorting for status column (PASS, FAIL, WARN, SKIP, ERROR)
        if column == "status":
            status_order = {"PASS": 0, "FAIL": 1, "WARN": 2, "SKIP": 3, "ERROR": 4}
            items.sort(key=lambda x: status_order.get(x[1][col_index], 5), reverse=self.tree_sort_reverse)
        else:
            # Regular string sorting for other columns
            items.sort(key=lambda x: x[1][col_index].lower() if x[1][col_index] else "", reverse=self.tree_sort_reverse)
        
        # Clear the tree and re-insert sorted items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for item_id, values in items:
            self.tree.insert("", tk.END, iid=item_id, values=values)
        
        # Update column headers to show sort direction
        for col in ["category", "name", "status", "message"]:
            if col == column:
                arrow = " ↓" if self.tree_sort_reverse else " ↑"
                self.tree.heading(col, text=self.tree.heading(col)['text'].replace(" ↑", "").replace(" ↓", "") + arrow)
            else:
                # Remove arrows from other columns
                self.tree.heading(col, text=self.tree.heading(col)['text'].replace(" ↑", "").replace(" ↓", ""))

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

    def _show_about(self) -> None:
        """Show about dialog"""
        about_text = """OCSP Server Test Suite
        
A comprehensive testing application for OCSP (Online Certificate Status Protocol) servers with both GUI and monitoring capabilities.

Features:
• Comprehensive OCSP Testing
• CRL Monitoring  
• Certificate Validation
• Export Capabilities (JSON/CSV)
• Advanced Testing Options

Version: 2.1.0
License: MIT License

Copyright (c) 2025 OCSP Testing Tool"""
        
        messagebox.showinfo("About OCSP Server Test Suite", about_text)

    def _save_config(self) -> None:
        """Save current configuration to file"""
        try:
            # Update config with current values
            self.config.ocsp_url = self.var_ocsp_url.get().strip()
            self.config.issuer_path = self.var_issuer_path.get().strip()
            self.config.good_cert = self.var_good_cert.get().strip()
            self.config.revoked_cert = self.var_revoked_cert.get().strip()
            self.config.unknown_ca_cert = self.var_unknown_ca_cert.get().strip()
            self.config.client_cert = self.var_client_cert.get().strip()
            self.config.client_key = self.var_client_key.get().strip()
            self.config.latency_samples = max(1, int(self.var_latency_samples.get() or 1))
            self.config.enable_load_test = bool(self.var_enable_load.get())
            self.config.load_concurrency = max(1, int(self.var_load_concurrency.get() or 1))
            self.config.load_requests = max(1, int(self.var_load_requests.get() or 1))
            
            # Update monitoring settings
            self.config.crl_override_url = self.var_crl_override_url.get().strip()
            self.config.check_validity = bool(self.var_check_validity.get())
            self.config.follow_log = bool(self.var_follow_log.get())
            self.config.show_info = bool(self.var_show_info.get())
            self.config.show_warn = bool(self.var_show_warn.get())
            self.config.show_debug = bool(self.var_show_debug.get())
            self.config.show_cmd = bool(self.var_show_cmd.get())
            self.config.show_stderr = bool(self.var_show_stderr.get())
            self.config.show_status = bool(self.var_show_status.get())
            
            # Update trust anchor settings
            self.config.trust_anchor_path = self.var_trust_anchor.get().strip()
            self.config.trust_anchor_type = self.var_trust_anchor_type.get()
            self.config.require_explicit_policy = bool(self.var_require_explicit_policy.get())
            self.config.inhibit_policy_mapping = bool(self.var_inhibit_policy_mapping.get())
            
            # Update advanced testing settings
            self.config.test_cryptographic_preferences = bool(self.var_test_cryptographic_preferences.get())
            self.config.test_non_issued_certificates = bool(self.var_test_non_issued_certificates.get())
            
            # Update OCSP response validation settings
            self.config.max_age_hours = int(self.var_max_age_hours.get())
            
            if self.config_manager.save_config(self.config):
                messagebox.showinfo("Config", "Configuration saved successfully!")
            else:
                messagebox.showerror("Config", "Failed to save configuration.")
        except Exception as exc:
            messagebox.showerror("Config", f"Error saving configuration: {exc}")

    def _load_config(self) -> None:
        """Load configuration from file"""
        try:
            self.config = self.config_manager.load_config()
            
            # Update UI with loaded values
            self.var_ocsp_url.set(self.config.ocsp_url)
            self.var_issuer_path.set(self.config.issuer_path)
            self.var_good_cert.set(self.config.good_cert)
            self.var_revoked_cert.set(self.config.revoked_cert)
            self.var_unknown_ca_cert.set(self.config.unknown_ca_cert)
            self.var_client_cert.set(self.config.client_cert)
            self.var_client_key.set(self.config.client_key)
            self.var_latency_samples.set(self.config.latency_samples)
            self.var_enable_load.set(self.config.enable_load_test)
            self.var_load_concurrency.set(self.config.load_concurrency)
            self.var_load_requests.set(self.config.load_requests)
            
            # Update monitoring variables
            self.var_crl_override_url.set(self.config.crl_override_url)
            self.var_check_validity.set(self.config.check_validity)
            self.var_follow_log.set(self.config.follow_log)
            self.var_show_info.set(self.config.show_info)
            self.var_show_warn.set(self.config.show_warn)
            self.var_show_debug.set(self.config.show_debug)
            self.var_show_cmd.set(self.config.show_cmd)
            self.var_show_stderr.set(self.config.show_stderr)
            self.var_show_status.set(self.config.show_status)
            
            # Update trust anchor variables
            self.var_trust_anchor.set(self.config.trust_anchor_path)
            self.var_trust_anchor_type.set(self.config.trust_anchor_type)
            self.var_require_explicit_policy.set(self.config.require_explicit_policy)
            self.var_inhibit_policy_mapping.set(self.config.inhibit_policy_mapping)
            
            # Update advanced testing variables
            self.var_test_cryptographic_preferences.set(self.config.test_cryptographic_preferences)
            self.var_test_non_issued_certificates.set(self.config.test_non_issued_certificates)
            
            # Update OCSP response validation variables
            self.var_max_age_hours.set(self.config.max_age_hours)
            
            messagebox.showinfo("Config", "Configuration loaded successfully!")
        except Exception as exc:
            messagebox.showerror("Config", f"Error loading configuration: {exc}")

    def _log_monitor(self, text: str) -> None:
        """Log callback for monitoring"""
        if ("[INFO]" in text and not self.var_show_info.get()) or \
           ("[WARN]" in text and not self.var_show_warn.get()) or \
           ("[DEBUG]" in text and not self.var_show_debug.get()) or \
           ("[CMD]" in text and not self.var_show_cmd.get()) or \
           ("[STDERR]" in text and not self.var_show_stderr.get()) or \
           ("[STATUS]" in text and not self.var_show_status.get()):
            return
        
        # Write to monitoring output
        self.monitor_output.insert(tk.END, text)
        if self.var_follow_log.get():
            self.monitor_output.see(tk.END)
        
        # Also print to stdout so it appears in console log
        print(text, end='')

    def _clear_monitor_log(self) -> None:
        """Clear monitoring log"""
        self.monitor_output.delete(1.0, tk.END)
        self.console_log_output.delete(1.0, tk.END)

    def _enable_all_debug(self) -> None:
        """Enable all debug logging options"""
        self.var_show_debug.set(True)
        self.var_show_info.set(True)
        self.var_show_warn.set(True)
        self.var_show_cmd.set(True)
        self.var_show_stderr.set(True)
        self.var_show_status.set(True)
        self._log_monitor("[DEBUG] All debug logging options enabled\n")



    def _select_all_test_categories(self) -> None:
        """Select all test categories"""
        self.var_enable_ocsp_tests.set(True)
        self.var_enable_crl_tests.set(True)
        self.var_enable_path_validation_tests.set(True)
        self.var_enable_ikev2_tests.set(True)
        self.var_enable_federal_bridge_tests.set(True)
        self.var_enable_performance_tests.set(True)

    def _select_none_test_categories(self) -> None:
        """Select no test categories"""
        self.var_enable_ocsp_tests.set(False)
        self.var_enable_crl_tests.set(False)
        self.var_enable_path_validation_tests.set(False)
        self.var_enable_ikev2_tests.set(False)
        self.var_enable_federal_bridge_tests.set(False)
        self.var_enable_performance_tests.set(False)

    def _select_default_test_categories(self) -> None:
        """Select default test categories"""
        self.var_enable_ocsp_tests.set(True)
        self.var_enable_crl_tests.set(True)
        self.var_enable_path_validation_tests.set(True)
        self.var_enable_ikev2_tests.set(False)
        self.var_enable_federal_bridge_tests.set(False)
        self.var_enable_performance_tests.set(False)

    def _show_test_results_in_monitor(self) -> None:
        """Display latest test results in monitoring window"""
        if not hasattr(self, 'results') or not self.results:
            self._log_monitor("[INFO] No test results available. Run tests first.\n")
            return
        
        self._log_monitor("\n" + "="*80 + "\n")
        self._log_monitor("LATEST TEST RESULTS\n")
        self._log_monitor("="*80 + "\n\n")
        
        # Group results by category
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = []
            categories[result.category].append(result)
        
        # Display results by category
        for category, results in categories.items():
            self._log_monitor(f"[{category.upper()} TESTS]\n")
            self._log_monitor("-" * 40 + "\n")
            
            for result in results:
                status_icon = "✅" if result.status.value == "PASS" else "❌" if result.status.value == "FAIL" else "⚠️" if result.status.value == "WARN" else "⏭️" if result.status.value == "SKIP" else "🔍" if result.status.value == "INFO" else "❌"
                self._log_monitor(f"{status_icon} {result.name}\n")
                self._log_monitor(f"   Status: {result.status.value}\n")
                self._log_monitor(f"   Message: {result.message}\n")
                
                if result.details:
                    self._log_monitor("   Details:\n")
                    for key, value in result.details.items():
                        if isinstance(value, dict):
                            self._log_monitor(f"     {key}:\n")
                            for sub_key, sub_value in value.items():
                                if isinstance(sub_value, (list, dict)):
                                    self._log_monitor(f"       {sub_key}: {sub_value}\n")
                                else:
                                    self._log_monitor(f"       {sub_key}: {sub_value}\n")
                        elif isinstance(value, list):
                            self._log_monitor(f"     {key}:\n")
                            for item in value:
                                self._log_monitor(f"       - {item}\n")
                        else:
                            self._log_monitor(f"     {key}: {value}\n")
                
                self._log_monitor(f"   Duration: {result.duration_ms}ms\n")
                self._log_monitor("\n")
            
            self._log_monitor("\n")
        
        self._log_monitor("="*80 + "\n")
        self._log_monitor(f"Total Tests: {len(self.results)}\n")
        
        # Count by status
        status_counts = {}
        for result in self.results:
            status = result.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        self._log_monitor("Status Summary:\n")
        for status, count in status_counts.items():
            self._log_monitor(f"  {status}: {count}\n")
        
        self._log_monitor("="*80 + "\n\n")

    def _run_ocsp_monitor(self) -> None:
        """Run OCSP monitoring check"""
        cert = self.var_good_cert.get()
        issuer = self.var_issuer_path.get()
        url = self.var_ocsp_url.get()
        
        if not cert or not issuer:
            messagebox.showerror("Input Error", "Please select both a certificate and issuer file.")
            return
            
        # Update monitor settings
        self.monitor.check_validity = self.var_check_validity.get()
        
        threading.Thread(target=self._ocsp_monitor_thread, args=(cert, issuer, url), daemon=True).start()

    def _run_crl_monitor(self) -> None:
        """Run CRL monitoring check"""
        cert = self.var_good_cert.get()
        issuer = self.var_issuer_path.get()
        crl_url = self.var_crl_override_url.get()
        
        if not cert or not issuer:
            messagebox.showerror("Input Error", "Please select both a certificate and issuer file.")
            return
            
        # Update monitor settings
        self.monitor.check_validity = self.var_check_validity.get()
        
        threading.Thread(target=self._crl_monitor_thread, args=(cert, issuer, crl_url), daemon=True).start()

    def _ocsp_monitor_thread(self, cert: str, issuer: str, url: str) -> None:
        """OCSP monitoring thread"""
        try:
            results = self.monitor.run_ocsp_check(cert, issuer, url)
            if "summary" in results:
                self.ocsp_summary.set(results["summary"])
        except Exception as exc:
            self._log_monitor(f"[ERROR] OCSP Monitor Exception: {exc}\n")

    def _crl_monitor_thread(self, cert: str, issuer: str, crl_url: str) -> None:
        """CRL monitoring thread"""
        try:
            results = self.monitor.run_crl_check(cert, issuer, crl_url)
            if "summary" in results:
                self.crl_summary.set(results["summary"])
        except Exception as exc:
            self._log_monitor(f"[ERROR] CRL Monitor Exception: {exc}\n")


if __name__ == "__main__":
    os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")
    app = OCSPTesterGUI()
    app.mainloop()
