import json
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class OCSPConfig:
    """Configuration for OCSP Tester application"""
    ocsp_url: str = "http://ocsp.xca.xpki.com/ocsp"
    issuer_path: str = ""
    good_cert: str = ""
    revoked_cert: str = ""
    unknown_ca_cert: str = ""
    client_cert: str = ""
    client_key: str = ""
    latency_samples: int = 5
    enable_load_test: bool = False
    load_concurrency: int = 5
    load_requests: int = 50
    
    # Monitoring settings
    crl_override_url: str = "http://ocsp.xca.xpki.com"
    check_validity: bool = True
    follow_log: bool = True
    show_info: bool = True
    show_warn: bool = True
    show_cmd: bool = True
    show_stderr: bool = True
    show_status: bool = True
    show_debug: bool = True  # DEBUG logging toggle
    
    # Trust anchor settings
    trust_anchor_path: str = ""
    trust_anchor_type: str = "root"
    require_explicit_policy: bool = False
    inhibit_policy_mapping: bool = False


class ConfigManager:
    """Manages saving and loading of configuration"""
    
    def __init__(self, config_file: str = "ocsp_config.json"):
        self.config_file = config_file
        self.config = OCSPConfig()
    
    def load_config(self) -> OCSPConfig:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Update config with loaded data
                    for key, value in data.items():
                        if hasattr(self.config, key):
                            setattr(self.config, key, value)
            except Exception as e:
                print(f"Error loading config: {e}")
                # Keep default config
        return self.config
    
    def save_config(self, config: OCSPConfig) -> bool:
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(config), f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def update_from_dict(self, data: Dict[str, Any]) -> None:
        """Update config from dictionary"""
        for key, value in data.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
