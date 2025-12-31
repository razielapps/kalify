#!/usr/bin/env python3
"""
KALIFY ULTIMATE - Transform Ubuntu into a Kali-powered security workstation
The most complete script to bring Kali's power to Ubuntu without dual-booting
"""

import os
import sys
import subprocess
import shutil
import argparse
import tempfile
import json
import yaml
import requests
import hashlib
import tarfile
import zipfile
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
import getpass
import platform
import time
import random
import string
from datetime import datetime
import urllib.request
import urllib.error
import configparser
import xml.etree.ElementTree as ET
import html

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class KalifyUltimate:
    def __init__(self, args):
        self.dry_run = args.dry_run
        self.minimal = args.minimal
        self.web_focus = args.web_focus
        self.mobile_focus = args.mobile_focus
        self.cloud_focus = args.cloud_focus
        self.forensic_mode = args.forensic_mode
        self.skip_kernel = args.skip_kernel
        self.skip_tools = args.skip_tools
        self.user = getpass.getuser()
        self.home_dir = os.path.expanduser("~")
        self.config_dir = os.path.join(self.home_dir, ".kalify-ultimate")
        self.tool_configs = os.path.join(self.config_dir, "configs")
        self.log_file = os.path.join(self.config_dir, "installation.log")
        self.install_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Create config directory
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.tool_configs, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Ubuntu version check
        self.distro = self.get_distro()
        self.ubuntu_version = self.get_ubuntu_version()
        
        # Installation tracking
        self.installed_tools = set()
        self.failed_tools = []
        self.warnings = []
        
    def get_distro(self):
        """Get Ubuntu version"""
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read()
                for line in content.splitlines():
                    if line.startswith("PRETTY_NAME"):
                        return line.split("=")[1].strip().strip('"')
        except:
            pass
        return "Unknown"
    
    def get_ubuntu_version(self):
        """Get precise Ubuntu version"""
        try:
            result = subprocess.run(["lsb_release", "-rs"], capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return "unknown"
    
    def setup_logging(self):
        """Setup logging for installation"""
        with open(self.log_file, "w") as f:
            f.write(f"Kalify Ultimate Installation Log\n")
            f.write(f"Started: {self.install_time}\n")
            f.write(f"User: {self.user}\n")
            f.write(f"System: {platform.platform()}\n\n")
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        with open(self.log_file, "a") as f:
            f.write(log_entry + "\n")
        
        # Color code console output
        if level == "ERROR":
            print(f"{Colors.RED}{log_entry}{Colors.END}")
        elif level == "WARNING":
            print(f"{Colors.YELLOW}{log_entry}{Colors.END}")
        elif level == "SUCCESS":
            print(f"{Colors.GREEN}{log_entry}{Colors.END}")
        else:
            print(f"{Colors.CYAN}{log_entry}{Colors.END}")
    
    def run_cmd(self, cmd: List[str], sudo: bool = False, capture: bool = False, 
                check: bool = True, timeout: int = 300) -> Optional[str]:
        """Run a shell command with advanced error handling"""
        cmd_str = ' '.join(cmd)
        self.log(f"Running: {cmd_str}", "COMMAND")
        
        if self.dry_run:
            return "[DRY RUN]"
        
        if sudo and os.geteuid() != 0:
            cmd = ["sudo"] + cmd
        
        try:
            if capture:
                result = subprocess.run(cmd, check=check, capture_output=True, 
                                      text=True, timeout=timeout)
                return result.stdout.strip()
            else:
                subprocess.run(cmd, check=check, timeout=timeout)
                return None
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed (exit {e.returncode}): {cmd_str}"
            self.log(error_msg, "ERROR")
            if capture:
                self.log(f"STDOUT: {e.stdout}", "ERROR")
                self.log(f"STDERR: {e.stderr}", "ERROR")
            return None
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {timeout}s: {cmd_str}"
            self.log(error_msg, "ERROR")
            return None
    
    def check_dependencies(self):
        """Check for required dependencies"""
        self.log("Checking system dependencies...", "INFO")
        
        deps = ["python3", "git", "curl", "wget", "gnupg", "software-properties-common"]
        missing = []
        
        for dep in deps:
            try:
                subprocess.run(["which", dep], check=True, capture_output=True)
            except:
                missing.append(dep)
        
        if missing:
            self.log(f"Installing missing dependencies: {missing}", "INFO")
            self.run_cmd(["apt", "update"], sudo=True)
            self.run_cmd(["apt", "install", "-y"] + missing, sudo=True)
        
        # Check disk space (min 20GB free)
        try:
            result = subprocess.run(["df", "/", "--output=avail"], capture_output=True, text=True)
            free_gb = int(result.stdout.splitlines()[1]) / 1024 / 1024
            if free_gb < 20:
                self.log(f"Warning: Only {free_gb:.1f}GB free, recommend 20GB+", "WARNING")
        except:
            pass
    
    def add_kali_repositories(self):
        """Add Kali Linux repositories with proper configuration"""
        self.log("Adding Kali Linux repositories...", "INFO")
        
        # Remove any existing kali sources
        kali_list = "/etc/apt/sources.list.d/kali.list"
        if os.path.exists(kali_list):
            self.log("Backing up existing kali.list", "INFO")
            shutil.copy2(kali_list, f"{kali_list}.bak.{self.install_time}")
        
        # Create kali sources with correct architecture
        kali_sources = """# Kali Linux repositories
deb http://http.kali.org/kali kali-rolling main non-free contrib
# deb-src http://http.kali.org/kali kali-rolling main non-free contrib
"""
        
        if self.dry_run:
            self.log(f"[DRY] Would write to {kali_list}", "INFO")
            return
        
        with open(kali_list, "w") as f:
            f.write(kali_sources)
        
        # Add Kali GPG key with multiple fallbacks
        gpg_keys = [
            "https://archive.kali.org/archive-key.asc",
            "https://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2022.1_all.deb",
            "https://packages.kali.org/kali/pool/main/k/kali-archive-keyring/"
        ]
        
        key_added = False
        for key_url in gpg_keys:
            try:
                self.log(f"Trying to fetch GPG key from: {key_url}", "INFO")
                if key_url.endswith(".deb"):
                    # Download and install keyring package
                    key_file = "/tmp/kali-keyring.deb"
                    self.run_cmd(["wget", "-q", "-O", key_file, key_url])
                    self.run_cmd(["dpkg", "-i", key_file], sudo=True)
                else:
                    # Download and add asc key
                    key_data = requests.get(key_url, timeout=30).content
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
                        tmp.write(key_data)
                        tmp_name = tmp.name
                    
                    self.run_cmd(["apt-key", "add", tmp_name], sudo=True)
                    os.unlink(tmp_name)
                
                key_added = True
                self.log("Kali GPG key added successfully", "SUCCESS")
                break
                
            except Exception as e:
                self.log(f"Failed to add key from {key_url}: {e}", "WARNING")
                continue
        
        if not key_added:
            # Last resort: use Ubuntu keyserver
            self.log("Trying Ubuntu keyserver as fallback...", "WARNING")
            self.run_cmd(["apt-key", "adv", "--keyserver", "keyserver.ubuntu.com", 
                         "--recv-keys", "ED444FF07D8D0BF6"], sudo=True)
        
        # Set Kali repository priority (lower than Ubuntu)
        preferences = """# Prefer Ubuntu packages over Kali
Package: *
Pin: release a=kali-rolling
Pin-Priority: 50

# But allow kali-specific packages
Package: kali-* linux-image-kali* linux-headers-kali*
Pin: release a=kali-rolling
Pin-Priority: 1000
"""
        
        with open("/etc/apt/preferences.d/kali.pref", "w") as f:
            f.write(preferences)
        
        # Update package lists
        self.log("Updating package lists...", "INFO")
        self.run_cmd(["apt", "update"], sudo=True)
        
        self.log("Kali repositories configured successfully", "SUCCESS")
    
    def install_kali_kernel(self):
        """Install Kali's custom kernel with wireless patches"""
        if self.skip_kernel:
            self.log("Skipping Kali kernel installation", "INFO")
            return
        
        self.log("Installing Kali Linux custom kernel...", "INFO")
        
        # First, check if we're on a supported architecture
        arch = platform.machine()
        if arch not in ["x86_64", "amd64"]:
            self.log(f"Architecture {arch} may not have Kali kernel packages", "WARNING")
        
        # Backup current kernel config
        self.run_cmd(["cp", "/boot/config-$(uname -r)", "/tmp/kernel-config.backup"], sudo=True)
        
        # Install Kali kernel metapackage
        kernel_packages = [
            "kali-linux-headless",  # Minimal Kali with kernel
            "linux-image-kali",
            "linux-headers-kali",
            "kali-tools-headless",
        ]
        
        self.run_cmd(["apt", "install", "-y"] + kernel_packages, sudo=True)
        
        # Install wireless injection drivers
        self.log("Installing wireless injection drivers...", "INFO")
        wireless_packages = [
            "realtek-rtl88xxau-dkms",
            "realtek-rtl8188eus-dkms",
            "realtek-rtl8192eu-dkms",
            "rtl8812au-dkms",
            "rtl8814au-dkms",
            "ath9k-htc-firmware",
            "kismet-driver-rtl8812au",
            "kismet-driver-rtl8814au",
            "firmware-atheros",
            "firmware-realtek",
            "firmware-iwlwifi",
        ]
        
        self.run_cmd(["apt", "install", "-y"] + wireless_packages, sudo=True)
        
        # Blacklist conflicting drivers
        blacklist_content = """# Kali wireless driver blacklist
# Prevent conflict with injection drivers
blacklist rtl8xxxu
blacklist r8188eu
blacklist rtl8192cu
blacklist rtl8192du
blacklist rtl8192eu
blacklist rtl8723au
blacklist rtl8723bu
blacklist mt7601u
blacklist rt2800usb
blacklist rt2x00usb
"""
        
        with open("/etc/modprobe.d/kali-blacklist.conf", "w") as f:
            f.write(blacklist_content)
        
        # Load necessary modules
        modules = ["cfg80211", "mac80211", "ath9k_htc", "rtl8187", "rt2800usb"]
        for module in modules:
            self.run_cmd(["modprobe", module], sudo=True)
        
        # Update grub
        self.run_cmd(["update-grub"], sudo=True)
        
        self.log("Kali kernel installed. Reboot required for full effect.", "SUCCESS")
    
    def install_kali_metapackages(self):
        """Install Kali metapackages based on selected focus"""
        if self.skip_tools:
            self.log("Skipping tool installation", "INFO")
            return
        
        self.log("Installing Kali Linux metapackages...", "INFO")
        
        # Base metapackages everyone gets
        base_metapackages = [
            "kali-linux-core",
            "kali-tools-top10",
        ]
        
        # Focus-based metapackages
        focus_metapackages = []
        
        if self.minimal:
            focus_metapackages = ["kali-linux-default"]
        elif self.web_focus:
            focus_metapackages = [
                "kali-tools-information-gathering",
                "kali-tools-vulnerability",
                "kali-tools-web",
                "kali-tools-database",
                "kali-tools-passwords",
            ]
        elif self.mobile_focus:
            focus_metapackages = [
                "kali-tools-mobile",
                "kali-tools-reverse-engineering",
            ]
        elif self.cloud_focus:
            focus_metapackages = [
                "kali-tools-cloud",
                "kali-tools-database",
            ]
        elif self.forensic_mode:
            focus_metapackages = [
                "kali-tools-forensics",
                "kali-tools-response",
            ]
        else:
            # Install ALL Kali tools (warning: huge!)
            focus_metapackages = [
                "kali-linux-default",
                "kali-tools-information-gathering",
                "kali-tools-vulnerability",
                "kali-tools-web",
                "kali-tools-database",
                "kali-tools-passwords",
                "kali-tools-wireless",
                "kali-tools-reverse-engineering",
                "kali-tools-exploitation",
                "kali-tools-post-exploitation",
                "kali-tools-forensics",
                "kali-tools-reporting",
                "kali-tools-social-engineering",
            ]
        
        # Combine and install
        all_metapackages = base_metapackages + focus_metapackages
        
        self.log(f"Installing {len(all_metapackages)} metapackages", "INFO")
        
        for meta in all_metapackages:
            self.log(f"Installing {meta}...", "INFO")
            result = self.run_cmd(["apt", "install", "-y", meta], sudo=True)
            if result is None:
                self.log(f"Failed to install {meta}", "ERROR")
            else:
                self.installed_tools.add(meta)
        
        self.log("Kali metapackages installation complete", "SUCCESS")
    
    def install_individual_tools(self):
        """Install individual tools not in metapackages"""
        self.log("Installing additional individual tools...", "INFO")
        
        # Categorize tools for better installation management
        tool_categories = {
            "network": [
                "macchanger", "arp-scan", "netdiscover", "nbtscan", "onesixtyone",
                "ike-scan", "hping3", "packit", "nemesis", "tcpreplay", "netsniff-ng",
                "dsniff", "fragroute", "fragrouter", "yersinia", "thc-ipv6",
            ],
            "web": [
                "ffuf", "nuclei", "jaeles", "dalfox", "arjun", "xsstrike", "xspear",
                "byp4xx", "feroxbuster", "hakrawler", "katana", "gau", "waybackurls",
                "httprobe", "gospider", "subfinder", "amass", "assetfinder", "findomain",
                "naabu", "httpx", "notify", "dnsx", "interactsh-client",
            ],
            "exploitation": [
                "powershell-empire", "starkiller", "crackmapexec", "bloodhound",
                "bloodhound.py", "impacket-scripts", "evil-winrm", "kerbrute",
                "silentbridge", "patator", "ncrack", "medusa", "hydra", "john",
                "hashcat", "ophcrack", "rcracki_mt", "truecrack", "chntpw",
            ],
            "wireless": [
                "wifite2", "reaver", "bully", "pixiewps", "eapmd5pass", "asleap",
                "cowpatty", "pyrit", "genpmk", "airgeddon", "wifiphisher",
            ],
            "mobile": [
                "apktool", "dex2jar", "jd-gui", "androguard", "bytecode-viewer",
                "jeb-ce", "python-uncompyle6", "frida", "objection", "jadx",
                "mobsf", "quark-engine",
            ],
            "cloud": [
                "awscli", "azure-cli", "gcloud", "prowler", "scoutsuite",
                "cloudsplaining", "cloudmapper", "cartography", "terraformer",
                "checkov", "tfsec", "terrascan", "kubectl", "helm", "k9s",
                "kube-bench", "kube-hunter", "kubesec", "trivy", "grype", "syft",
            ],
            "forensic": [
                "volatility3", "autopsy", "guymager", "dc3dd", "testdisk",
                "photorec", "scalpel", "foremost", "bulk-extractor", "binwalk",
                "strings", "xxd", "hexedit", "bless", "peepdf", "pdf-parser",
                "pdfid", "oledump", "viper", "malwoverview",
            ],
            "reverse": [
                "ghidra", "radare2", "cutter", "angr", "binaryninja", "flare-floss",
                "x64dbg", "ollydbg", "ida-free", "peda", "pwndbg", "gef",
                "ropper", "shellnoob", "pwncat", "socat", "cryptcat",
            ],
            "osint": [
                "maltego", "recon-ng", "theharvester", "spiderfoot", "osrframework",
                "datasploit", "sn0int", "photon", "gitleaks", "trufflehog",
                "gitrob", "shhgit", "waymore", "emailharvester", "holehe",
            ],
        }
        
        # Install based on focus
        if self.minimal:
            categories_to_install = ["network", "web"]
        elif self.web_focus:
            categories_to_install = ["network", "web", "exploitation"]
        elif self.mobile_focus:
            categories_to_install = ["mobile", "reverse", "exploitation"]
        elif self.cloud_focus:
            categories_to_install = ["cloud", "web", "exploitation"]
        elif self.forensic_mode:
            categories_to_install = ["forensic", "reverse", "network"]
        else:
            categories_to_install = list(tool_categories.keys())
        
        # Install tools by category
        for category in categories_to_install:
            self.log(f"Installing {category} tools...", "INFO")
            tools = tool_categories.get(category, [])
            
            # Install in batches to avoid command line too long
            batch_size = 20
            for i in range(0, len(tools), batch_size):
                batch = tools[i:i + batch_size]
                self.log(f"  Batch {i//batch_size + 1}: {len(batch)} tools", "INFO")
                
                result = self.run_cmd(["apt", "install", "-y"] + batch, sudo=True)
                if result is None:
                    self.log(f"  Some tools in batch failed", "WARNING")
                else:
                    for tool in batch:
                        self.installed_tools.add(tool)
        
        self.log("Individual tools installation complete", "SUCCESS")
    
    def install_from_source(self):
        """Install tools only available via source/git"""
        self.log("Installing tools from source...", "INFO")
        
        # Create tools directory
        tools_dir = os.path.join(self.home_dir, "Tools")
        os.makedirs(tools_dir, exist_ok=True)
        
        # Git repositories to clone and install
        git_repos = {
            # Web tools
            "XSStrike": "https://github.com/s0md3v/XSStrike.git",
            "ParamSpider": "https://github.com/devanshbatham/ParamSpider.git",
            "SecretFinder": "https://github.com/m4ll0k/SecretFinder.git",
            "LinkFinder": "https://github.com/GerbenJavado/LinkFinder.git",
            "GooFuzz": "https://github.com/m3n0sd0n4ld/GooFuzz.git",
            
            # Network tools
            "NmapAutomator": "https://github.com/21y4d/nmapAutomator.git",
            "EyeWitness": "https://github.com/FortyNorthSecurity/EyeWitness.git",
            
            # OSINT
            "SocialScan": "https://github.com/iojw/socialscan.git",
            "EmailFinder": "https://github.com/Josue87/EmailFinder.git",
            
            # Post-exploitation
            "PEASS-ng": "https://github.com/carlospolop/PEASS-ng.git",
            "LinEnum": "https://github.com/rebootuser/LinEnum.git",
            "Linux-Smart-Enumeration": "https://github.com/diego-treitos/linux-smart-enumeration.git",
            
            # Mobile
            "Apktool": "https://github.com/iBotPeaches/Apktool.git",
            "Mobile-Security-Framework-MobSF": "https://github.com/MobSF/Mobile-Security-Framework-MobSF.git",
            
            # Payloads
            "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
            "ReverseShellCheatSheet": "https://github.com/swisskyrepo/ReverseShellCheatSheet.git",
        }
        
        # Install git tools
        for tool_name, repo_url in git_repos.items():
            tool_path = os.path.join(tools_dir, tool_name)
            
            if os.path.exists(tool_path):
                self.log(f"Updating {tool_name}...", "INFO")
                self.run_cmd(["git", "-C", tool_path, "pull"])
            else:
                self.log(f"Cloning {tool_name}...", "INFO")
                self.run_cmd(["git", "clone", "--depth", "1", repo_url, tool_path])
            
            # Run installation scripts if they exist
            install_script = os.path.join(tool_path, "setup.py")
            if os.path.exists(install_script):
                self.log(f"Installing {tool_name}...", "INFO")
                self.run_cmd(["python3", "setup.py", "install"], cwd=tool_path)
            
            install_script = os.path.join(tool_path, "install.sh")
            if os.path.exists(install_script):
                self.run_cmd(["chmod", "+x", install_script])
                self.run_cmd(["./install.sh"], cwd=tool_path, sudo=True)
        
        # Install Go tools
        self.install_go_tools()
        
        # Install Python tools via pip
        self.install_python_tools()
        
        self.log("Source installations complete", "SUCCESS")
    
    def install_go_tools(self):
        """Install Go-based security tools"""
        self.log("Installing Go tools...", "INFO")
        
        # First install Go if not present
        go_check = self.run_cmd(["which", "go"], capture=True)
        if not go_check:
            self.log("Installing Go...", "INFO")
            self.run_cmd(["apt", "install", "-y", "golang-go"], sudo=True)
        
        # Go tools to install
        go_tools = [
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "github.com/projectdiscovery/notify/cmd/notify@latest",
            "github.com/projectdiscovery/katana/cmd/katana@latest",
            "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
            "github.com/tomnomnom/waybackurls@latest",
            "github.com/tomnomnom/httprobe@latest",
            "github.com/tomnomnom/anew@latest",
            "github.com/tomnomnom/gf@latest",
            "github.com/tomnomnom/qsreplace@latest",
            "github.com/ffuf/ffuf@latest",
            "github.com/lc/gau/v2/cmd/gau@latest",
            "github.com/hakluke/hakrawler@latest",
            "github.com/hahwul/dalfox/v2@latest",
            "github.com/jaeles-project/jaeles@latest",
            "github.com/shenwei356/rush@latest",
        ]
        
        for tool in go_tools:
            self.log(f"Installing {tool.split('/')[-1]}...", "INFO")
            self.run_cmd(["go", "install", tool])
        
        # Add Go bin to PATH
        go_bin = os.path.join(self.home_dir, "go/bin")
        if os.path.exists(go_bin):
            with open(os.path.join(self.home_dir, ".bashrc"), "a") as f:
                f.write(f'\nexport PATH="$PATH:{go_bin}"\n')
    
    def install_python_tools(self):
        """Install Python-based security tools"""
        self.log("Installing Python tools...", "INFO")
        
        # Python packages to install
        python_packages = [
            "scapy", "pwntools", "ropgadget", "angr", "z3-solver",
            "unicorn", "capstone", "keystone-engine", "pefile",
            "pylnk3", "oletools", "androguard", "frida-tools",
            "objection", "mitmproxy", "requests", "beautifulsoup4",
            "lxml", "colorama", "tabulate", "pyfiglet", "tqdm",
            "python-nmap", "paramiko", "impacket", "pycryptodome",
            "cryptography", "passlib", "pypykatz", "minidump",
            "pysmb", "ldap3", "pyopenssl", "service_identity",
            "twisted", "scrapy", "selenium", "pillow", "pytesseract",
            "openai", "transformers", "torch", "torchvision",
        ]
        
        # Install with pip
        for package in python_packages:
            self.log(f"Installing {package}...", "INFO")
            self.run_cmd(["pip3", "install", "--upgrade", package])
    
    def setup_metasploit(self):
        """Configure Metasploit Framework"""
        self.log("Configuring Metasploit Framework...", "INFO")
        
        # Initialize database
        self.run_cmd(["msfdb", "init"])
        self.run_cmd(["msfdb", "start"])
        
        # Create custom config
        msf_dir = os.path.join(self.home_dir, ".msf4")
        os.makedirs(msf_dir, exist_ok=True)
        
        # Create database config
        db_config = f"""production:
  adapter: postgresql
  database: msf
  username: msf
  password: {''.join(random.choices(string.ascii_letters + string.digits, k=16))}
  host: localhost
  port: 5432
  pool: 200
  timeout: 5
"""
        
        with open(os.path.join(msf_dir, "database.yml"), "w") as f:
            f.write(db_config)
        
        # Create resource scripts
        resource_script = os.path.join(msf_dir, "startup.rc")
        with open(resource_script, "w") as f:
            f.write("""# Auto-start commands
use auxiliary/server/capture/http
use auxiliary/server/capture/http_ntlm
use auxiliary/server/capture/smb
setg LHOST 0.0.0.0
setg LPORT 8080
run
""")
        
        # Create alias
        with open(os.path.join(self.home_dir, ".bashrc"), "a") as f:
            f.write('\nalias msf="msfconsole -q -r ~/.msf4/startup.rc"\n')
            f.write('alias msfdb-start="sudo systemctl start postgresql && msfdb start"\n')
            f.write('alias msfdb-stop="msfdb stop && sudo systemctl stop postgresql"\n')
        
        self.log("Metasploit configured", "SUCCESS")
    
    def setup_burpsuite(self):
        """Configure Burp Suite Professional"""
        self.log("Configuring Burp Suite...", "INFO")
        
        # Check if Burp is installed
        burp_check = self.run_cmd(["which", "burpsuite"], capture=True)
        if not burp_check:
            self.log("Burp Suite not found, installing...", "INFO")
            self.run_cmd(["apt", "install", "-y", "burpsuite"], sudo=True)
        
        # Create config directory
        burp_dir = os.path.join(self.home_dir, ".BurpSuite")
        os.makedirs(burp_dir, exist_ok=True)
        
        # Create project file
        project_config = {
            "burp": {
                "project_options": {
                    "connections": {
                        "upstream_proxy": {
                            "use_user_options": False
                        },
                        "timeouts": {
                            "normal_timeout": 120000,
                            "open-ended_timeout": 0
                        }
                    },
                    "http": {
                        "redirections": "all",
                        "status_100_response": "automatically_respond",
                        "streaming_responses": "automatic"
                    },
                    "ssl": {
                        "client_certificates": [],
                        "server_certificates": {
                            "automatically_ignore_errors": True
                        }
                    },
                    "sessions": {
                        "cookie_jar": {
                            "enabled": True
                        }
                    },
                    "misc": {
                        "prompt_on_exit": False,
                        "use_proxy_history": True
                    }
                }
            }
        }
        
        config_file = os.path.join(burp_dir, "project_config.json")
        with open(config_file, "w") as f:
            json.dump(project_config, f, indent=2)
        
        # Create Burp macro for authentication
        macro_file = os.path.join(burp_dir, "macros.xml")
        with open(macro_file, "w") as f:
            f.write("""<?xml version="1.0" ?>
<burp>
  <macros/>
</burp>""")
        
        # Create alias with Java optimizations
        with open(os.path.join(self.home_dir, ".bashrc"), "a") as f:
            f.write('\nalias burp="java -jar -Xmx4g -XX:+UseG1GC /usr/share/burpsuite/burpsuite.jar &"\n')
        
        self.log("Burp Suite configured", "SUCCESS")
    
    def setup_wireshark(self):
        """Configure Wireshark for non-root usage"""
        self.log("Configuring Wireshark...", "INFO")
        
        # Allow non-root capture
        self.run_cmd(["dpkg-reconfigure", "-f", "noninteractive", "wireshark-common"], sudo=True)
        self.run_cmd(["usermod", "-a", "-G", "wireshark", self.user], sudo=True)
        
        # Create custom profiles
        wireshark_dir = os.path.join(self.home_dir, ".config/wireshark/profiles")
        os.makedirs(wireshark_dir, exist_ok=True)
        
        # Create security profile
        security_profile = os.path.join(wireshark_dir, "Security")
        os.makedirs(security_profile, exist_ok=True)
        
        # Copy default config
        default_prefs = "/usr/share/wireshark/preferences"
        if os.path.exists(default_prefs):
            shutil.copy2(default_prefs, os.path.join(security_profile, "preferences"))
        
        # Create custom color rules
        color_file = os.path.join(security_profile, "colorfilters")
        with open(color_file, "w") as f:
            f.write("""@http@[HTTP]
@dns@[DNS]
@tls@[TLS]
@ssh@[SSH]
@telnet@[Telnet]
@ftp@[FTP]
@smb@[SMB]
""")
        
        self.log("Wireshark configured for user capture", "SUCCESS")
    
    def setup_security_aliases(self):
        """Create comprehensive security aliases"""
        self.log("Creating security aliases...", "INFO")
        
        aliases = [
            "# ==================== KALIFY ULTIMATE ALIASES ====================",
            "# System",
            "alias kali-status='echo \"Kalify Ultimate System\" && uname -a && dpkg -l | grep -i kali | wc -l'",
            "alias sec-update='sudo apt update && sudo apt full-upgrade -y && msfupdate'",
            "alias sec-clean='sudo apt autoremove -y && sudo apt autoclean'",
            "alias show-ips=\"ip -c addr show | grep -E 'inet |inet6 '\"",
            "alias show-routes=\"ip -c route show\"",
            "",
            "# Network",
            "alias scan-local='sudo nmap -sS -sV -sC -O -T4 192.168.1.0/24'",
            "alias scan-quick='sudo nmap -sS -T4 -F'",
            "alias scan-full='sudo nmap -sS -sV -sC -O -p- -T4'",
            "alias scan-udp='sudo nmap -sU -T4 --top-ports 100'",
            "alias traffic-mon='sudo tcpdump -i any -n not port 22'",
            "alias mac-change='sudo macchanger -r eth0'",
            "alias arp-scan='sudo arp-scan --localnet'",
            "",
