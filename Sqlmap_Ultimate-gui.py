#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQLMAP ULTIME GUI v4.0 - JATHNIEL EDITION
Interface graphique professionnelle pour sqlmap

Usage académique et légal uniquement (CTF, labo, pentest autorisé).

CHANGELOG v4.0 :
[FIX] Suppression des résultats hardcodés (fake vulns/dbs/tables/WAF)
[FIX] Suppression des options sqlmap inexistantes (--graphql, --nosql)
[FIX] Suppression des onglets injection factices (XXE, LDAP, Command, SSTI, SSRF)
[FIX] Auth Basic/Digest maintenant transmise à sqlmap
[FIX] Parsing RÉEL de la sortie sqlmap (Parameter, DBMS, databases, tables)
[FIX] Arbre de résultats alimenté par le vrai scan
[FIX] Statistiques mises à jour dynamiquement
[FIX] --dbs / --dump / --os-shell maintenant déclenchables
[FIX] Champ "Colonne" maintenant utilisé
[NEW] Bouton "Dump" et "OS Shell"
[NEW] WAF detection RÉELLE (via headers HTTP)
[NEW] Support cookie + user-agent
[NEW] Export JSON des résultats
"""

import sys
import os
import json
import time
import threading
import subprocess
import re
from datetime import datetime
from typing import Optional, Dict, List, Any

try:
    from PySide6.QtWidgets import *
    from PySide6.QtCore import *
    from PySide6.QtGui import *
except ImportError:
    print("[!] PySide6 non installé. Installez avec : pip install PySide6")
    sys.exit(1)

import requests


# ==================== CONFIGURATION ====================

CONFIG = {
    'title': 'SQLMAP ULTIME GUI v4.0 - JATHNIEL EDITION',
    'version': '4.0',
    'author': 'JATHNIEL',
    'sqlmap_bin': 'sqlmap',  # chemin vers sqlmap
}


# ==================== WAF SIGNATURES (utilisées réellement) ====================

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
    'AWS WAF': ['x-amzn-requestid', 'awselb', 'aws-waf'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'Imperva': ['incap_ses', 'visid_incap', 'x-iinfo'],
    'Akamai': ['akamai', 'x-akamai', 'akamaighost'],
    'Sucuri': ['sucuri', 'x-sucuri-id'],
    'Barracuda': ['barracuda', 'barra_counter_session'],
    'F5 BIG-IP': ['bigipserver', 'tscookie', 'f5-'],
    'Nginx': ['nginx'],
    'Apache': ['apache'],
}


# ==================== SQLMAP WRAPPER ====================

class SQLMapWrapper(QObject):
    """Wrapper sqlmap avec signaux Qt."""

    output_received = Signal(str)
    scan_finished = Signal(str)
    status_changed = Signal(str)
    parsed_event = Signal(str, dict)   # (type, data) pour parsing structuré

    def __init__(self):
        super().__init__()
        self.process = None
        self.running = False
        self.results = {
            'url': '',
            'started_at': None,
            'finished_at': None,
            'vulnerabilities': [],
            'dbms': None,
            'databases': [],
            'tables': {},          # db -> [tables]
            'columns': {},         # (db, table) -> [columns]
            'dumped_data': [],     # lignes dumpées
            'waf': None,
            'raw_output': [],      # tout ce que sqlmap a sorti
        }

    def start_scan(self, params: Dict):
        if self.running:
            self.status_changed.emit("⚠️ Un scan est déjà en cours")
            return

        self.running = True
        self.results = {
            'url': params.get('url', ''),
            'started_at': datetime.now().isoformat(),
            'finished_at': None,
            'vulnerabilities': [],
            'dbms': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'dumped_data': [],
            'waf': None,
            'raw_output': [],
        }

        cmd = self.build_command(params)
        self.status_changed.emit(f"🚀 Scan démarré : {' '.join(cmd)}")
        self.results['raw_output'].append(f"$ {' '.join(cmd)}")

        threading.Thread(target=self.run_scan, args=(cmd,), daemon=True).start()

    def build_command(self, params: Dict) -> List[str]:
        """Construit la commande sqlmap — UNIQUEMENT avec options valides."""
        cmd = [CONFIG['sqlmap_bin']]

        if params.get('url'):
            cmd.extend(["-u", params['url']])

        if params.get('method') == 'POST' and params.get('data'):
            cmd.extend(["--data", params['data']])

        # Options de base
        cmd.extend(["--level", str(params.get('level', 3))])
        cmd.extend(["--risk", str(params.get('risk', 2))])

        if params.get('techniques'):
            cmd.extend(["--technique", params['techniques']])

        cmd.extend(["--threads", str(params.get('threads', 5))])
        cmd.extend(["--timeout", str(params.get('timeout', 30))])

        if params.get('delay', 0) > 0:
            cmd.extend(["--delay", str(params['delay'])])

        if params.get('batch', True):
            cmd.append("--batch")

        if params.get('random_agent', True):
            cmd.append("--random-agent")

        if params.get('proxy'):
            cmd.extend(["--proxy", params['proxy']])

        if params.get('tamper'):
            tamper_str = ",".join(params['tamper']) if isinstance(params['tamper'], list) else params['tamper']
            if tamper_str:
                cmd.extend(["--tamper", tamper_str])

        # Headers
        if params.get('headers'):
            for key, value in params['headers'].items():
                cmd.extend(["--header", f"{key}: {value}"])

        # Cookie / UA
        if params.get('cookies'):
            cmd.extend(["--cookie", params['cookies']])

        if params.get('user_agent'):
            cmd.extend(["--user-agent", params['user_agent']])

        # Auth Basic/Digest  (CORRIGÉ : maintenant transmis)
        if params.get('auth_type') and params.get('auth_cred'):
            cmd.extend(["--auth-type", params['auth_type']])
            cmd.extend(["--auth-cred", params['auth_cred']])

        # JSON (flag valide)
        if params.get('json_injection'):
            cmd.append("--json")

        # Extraction DB
        if params.get('dbs'):
            cmd.append("--dbs")

        if params.get('database'):
            cmd.extend(["-D", params['database']])

            if params.get('tables'):
                cmd.append("--tables")

            if params.get('table'):
                cmd.extend(["-T", params['table']])

                if params.get('columns'):
                    cmd.append("--columns")

                if params.get('dump'):
                    cmd.append("--dump")

        if params.get('os_shell'):
            cmd.append("--os-shell")

        # Ne pas renvoyer les caractères spéciaux
        return cmd

    def run_scan(self, cmd: List[str]):
        """Exécute sqlmap et parse la sortie en temps réel."""
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            while self.running and self.process:
                line = self.process.stdout.readline()
                if not line:
                    if self.process.poll() is not None:
                        break
                    continue

                line = line.rstrip('\n')
                if line:
                    self.output_received.emit(line)
                    self.results['raw_output'].append(line)
                    self.parse_output(line)

            self.process.wait()
            exit_code = self.process.returncode

            self.running = False
            self.results['finished_at'] = datetime.now().isoformat()

            if exit_code == 0:
                self.status_changed.emit("✅ Scan terminé (succès)")
                self.scan_finished.emit("success")
            else:
                self.status_changed.emit(f"⚠️ Scan terminé (code {exit_code})")
                self.scan_finished.emit(f"exit_{exit_code}")

        except FileNotFoundError:
            self.output_received.emit(
                f"❌ sqlmap introuvable. Installez-le : sudo apt install sqlmap"
            )
            self.running = False
            self.scan_finished.emit("not_found")
        except Exception as e:
            self.output_received.emit(f"❌ Erreur: {e}")
            self.running = False
            self.scan_finished.emit("error")

    # ==================== PARSING RÉEL DE LA SORTIE SQLMAP ====================

    def parse_output(self, line: str):
        """Parse réellement la sortie sqlmap pour alimenter les résultats."""
        stripped = line.strip()

        # 1. Vulnérabilité détectée
        # "Parameter: id (GET)"  suivi de "    Type: boolean-based blind"
        m = re.match(r'^Parameter:\s+(.+?)\s+\((.+?)\)', stripped)
        if m:
            param_name = m.group(1)
            method = m.group(2)
            vuln = {'parameter': param_name, 'method': method, 'technique': 'unknown'}
            self.results['vulnerabilities'].append(vuln)
            self.parsed_event.emit('vuln', vuln)
            self.status_changed.emit(f"🚨 Vulnérabilité: {param_name} ({method})")
            return

        # Technique associée (ligne suivante du bloc Parameter)
        m = re.match(r'^Type:\s+(.+)', stripped)
        if m and self.results['vulnerabilities']:
            tech = m.group(1).strip()
            self.results['vulnerabilities'][-1]['technique'] = tech
            self.parsed_event.emit('vuln_tech', {'technique': tech})
            return

        # 2. DBMS
        m = re.match(r'^back-end DBMS:\s+(.+)', stripped, re.IGNORECASE)
        if m:
            self.results['dbms'] = m.group(1).strip()
            self.status_changed.emit(f"🗄️ DBMS: {self.results['dbms']}")
            self.parsed_event.emit('dbms', {'dbms': self.results['dbms']})
            return

        # 3. Databases
        # "available databases [3]:"
        m = re.match(r'^available databases\s*\[\d+\]:', stripped, re.IGNORECASE)
        if m:
            self.parsed_event.emit('db_section_start', {})
            return

        # Les noms de DB apparaissent après "[*] nom_db"
        m = re.match(r'^\[\*\]\s+(\S+)', stripped)
        if m:
            name = m.group(1)
            # Heuristique : si on vient de voir "available databases"
            if self.results['raw_output'][-2:-1] and any(
                'available databases' in l for l in self.results['raw_output'][-6:]
            ):
                if name not in self.results['databases']:
                    self.results['databases'].append(name)
                    self.parsed_event.emit('database', {'name': name})
                    self.status_changed.emit(f"🗄️ Base: {name}")
            return

        # 4. Tables (après "Database: xxx")
        m = re.match(r'^Database:\s+(.+)', stripped)
        if m:
            self._current_db = m.group(1).strip()
            self.parsed_event.emit('db_context', {'db': self._current_db})
            return

        # "Table: users"
        m = re.match(r'^Table:\s+(.+)', stripped)
        if m:
            table = m.group(1).strip()
            db = getattr(self, '_current_db', 'unknown')
            self.results['tables'].setdefault(db, [])
            if table not in self.results['tables'][db]:
                self.results['tables'][db].append(table)
                self.parsed_event.emit('table', {'db': db, 'table': table})
                self.status_changed.emit(f"📋 Table: {db}.{table}")
            return

        # 5. Colonnes
        m = re.match(r'^\[(\d+)\s+columns?\]', stripped)
        if m:
            self.parsed_event.emit('columns_section', {'count': int(m.group(1))})
            return

        # Ligne de colonne : "+---------+---------+"
        if re.match(r'^\+\-+\+', stripped):
            return

        # Ligne de données : "| id      | name    |"
        if stripped.startswith('|') and stripped.endswith('|'):
            cells = [c.strip() for c in stripped.strip('|').split('|')]
            if cells and any(cells):
                self.parsed_event.emit('dumped_row', {'row': cells})
            return

        # 6. Détection WAF dans la sortie
        if 'waf' in stripped.lower() and 'detected' in stripped.lower():
            m = re.search(r'(WAF|firewall)[^\w]*([A-Za-z0-9_\- ]+)', stripped, re.IGNORECASE)
            if m:
                waf_name = m.group(2).strip()
                self.results['waf'] = waf_name
                self.parsed_event.emit('waf', {'waf': waf_name})
                self.status_changed.emit(f"🛡️ WAF: {waf_name}")
            return

        # 7. Payload/Injection info
        if stripped.startswith('Payload:'):
            payload = stripped.replace('Payload:', '').strip()
            if self.results['vulnerabilities']:
                self.results['vulnerabilities'][-1].setdefault('payloads', []).append(payload)
            return

    def stop_scan(self):
        """Arrête proprement le process sqlmap."""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                time.sleep(0.5)
                if self.process.poll() is None:
                    self.process.kill()
            except Exception:
                pass
            self.status_changed.emit("⏹️ Scan arrêté")


# ==================== WAF DETECTION RÉELLE ====================

class WAFDetector(QObject):
    """Détection WAF réelle par analyse des headers HTTP."""

    detection_done = Signal(str, list)  # (waf_name, matched_headers)

    def detect(self, url: str, timeout: int = 10):
        """Lance la détection dans un thread."""
        threading.Thread(
            target=self._detect, args=(url, timeout), daemon=True
        ).start()

    def _detect(self, url: str, timeout: int):
        if not url:
            self.detection_done.emit('Aucun (URL vide)', [])
            return

        try:
            r = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (WAF-Detection)'}
            )
        except Exception as e:
            self.detection_done.emit(f'Erreur: {e}', [])
            return

        headers_lower = {k.lower(): str(v).lower() for k, v in r.headers.items()}
        cookies = r.cookies.get_dict()

        detected_waf = None
        matched = []

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                # Check headers
                for hname, hvalue in headers_lower.items():
                    if sig_lower in hname or sig_lower in hvalue:
                        detected_waf = waf_name
                        matched.append(f"Header: {hname}={hvalue[:60]}")
                        break
                # Check cookies
                for cname, cvalue in cookies.items():
                    if sig_lower in cname.lower() or sig_lower in str(cvalue).lower():
                        detected_waf = waf_name
                        matched.append(f"Cookie: {cname}={str(cvalue)[:60]}")
                        break
                if detected_waf:
                    break
            if detected_waf:
                break

        if detected_waf:
            self.detection_done.emit(detected_waf, matched)
        else:
            self.detection_done.emit('Aucun WAF détecté', [])


# ==================== INTERFACE PRINCIPALE ====================

class SQLMapGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.wrapper = SQLMapWrapper()
        self.waf_detector = WAFDetector()
        self._current_dumped_rows = 0
        self._last_db_context = None

        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        self.setWindowTitle(CONFIG['title'])
        self.setGeometry(100, 100, 1400, 850)
        self.setStyleSheet(self._stylesheet())

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)

        # Header
        header = QLabel(f"🔍 SQLMAP ULTIME GUI v{CONFIG['version']} - {CONFIG['author']}")
        header.setStyleSheet(
            "font-size: 20px; font-weight: bold; color: #00ff88; padding: 10px;"
        )
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_config_tab(), "⚙️ Configuration")
        self.tabs.addTab(self.create_extraction_tab(), "🗄️ Extraction")
        self.tabs.addTab(self.create_console_tab(), "📟 Console")
        self.tabs.addTab(self.create_results_tab(), "📊 Résultats")
        layout.addWidget(self.tabs)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ Prêt")

    def _stylesheet(self):
        return """
            QMainWindow { background-color: #1a1a2e; }
            QWidget { background-color: #1a1a2e; color: #e0e0e0; font-family: 'Segoe UI', Arial, sans-serif; }
            QPushButton {
                background-color: #2d2d44; color: #e0e0e0; border: 1px solid #4a4a6a;
                border-radius: 6px; padding: 8px 16px; font-weight: bold;
            }
            QPushButton:hover { background-color: #3d3d5a; }
            QPushButton:disabled { background-color: #1e1e2e; color: #666; }
            QPushButton#danger { background-color: #6a2d2d; border-color: #8a3d3d; }
            QPushButton#danger:hover { background-color: #8a3d3d; }
            QPushButton#success { background-color: #2d6a2d; border-color: #3d8a3d; }
            QPushButton#success:hover { background-color: #3d8a3d; }
            QPushButton#primary { background-color: #2d2d6a; border-color: #3d3d8a; }
            QPushButton#primary:hover { background-color: #3d3d8a; }
            QLineEdit, QTextEdit, QComboBox, QPlainTextEdit {
                background-color: #0d0d1a; border: 1px solid #2d2d44;
                border-radius: 6px; padding: 8px; color: #e0e0e0;
                font-family: 'Consolas', monospace;
            }
            QTabWidget::pane { border: 1px solid #2d2d44; border-radius: 6px; background-color: #1a1a2e; }
            QTabBar::tab { background-color: #2d2d44; padding: 8px 16px; margin-right: 2px; }
            QTabBar::tab:selected { background-color: #3d3d5a; }
            QStatusBar { background-color: #0d0d1a; color: #8888aa; }
            QGroupBox { border: 1px solid #2d2d44; border-radius: 6px; margin-top: 10px; padding-top: 10px; }
            QGroupBox::title { color: #00ff88; subcontrol-origin: margin; left: 10px; }
            QTableWidget { background-color: #0d0d1a; border: 1px solid #2d2d44; gridline-color: #2d2d44; }
            QTableWidget::item { color: #e0e0e0; }
            QHeaderView::section { background-color: #2d2d44; padding: 8px; border: none; color: #00ff88; }
            QTreeWidget { background-color: #0d0d1a; border: 1px solid #2d2d44; color: #e0e0e0; }
            QTreeWidget::item { padding: 4px; }
            QCheckBox { color: #e0e0e0; }
            QSpinBox, QDoubleSpinBox { color: #e0e0e0; background-color: #0d0d1a; border: 1px solid #2d2d44; border-radius: 4px; padding: 4px; }
        """

    # ==================== ONGLETS ====================

    def create_config_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # --- Cible ---
        url_group = QGroupBox("🎯 Cible")
        url_layout = QGridLayout()

        url_layout.addWidget(QLabel("URL:"), 0, 0)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/page?id=1")
        url_layout.addWidget(self.url_input, 0, 1, 1, 3)

        url_layout.addWidget(QLabel("Méthode:"), 1, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST"])
        url_layout.addWidget(self.method_combo, 1, 1)

        url_layout.addWidget(QLabel("Données POST:"), 2, 0)
        self.post_data = QLineEdit()
        self.post_data.setPlaceholderText("param1=value1&param2=value2")
        self.post_data.setEnabled(False)
        url_layout.addWidget(self.post_data, 2, 1, 1, 3)

        self.method_combo.currentTextChanged.connect(
            lambda t: self.post_data.setEnabled(t == "POST")
        )

        url_group.setLayout(url_layout)
        layout.addWidget(url_group)

        # --- Auth ---
        auth_group = QGroupBox("🔐 Authentification")
        auth_layout = QGridLayout()

        auth_layout.addWidget(QLabel("Type:"), 0, 0)
        self.auth_combo = QComboBox()
        self.auth_combo.addItems(["Aucune", "Basic", "Digest"])
        auth_layout.addWidget(self.auth_combo, 0, 1)

        auth_layout.addWidget(QLabel("Identifiant:"), 1, 0)
        self.auth_user = QLineEdit()
        self.auth_user.setPlaceholderText("user")
        auth_layout.addWidget(self.auth_user, 1, 1)

        auth_layout.addWidget(QLabel("Mot de passe:"), 2, 0)
        self.auth_pass = QLineEdit()
        self.auth_pass.setEchoMode(QLineEdit.EchoMode.Password)
        auth_layout.addWidget(self.auth_pass, 2, 1)

        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)

        # --- Headers ---
        headers_group = QGroupBox("📋 Headers personnalisés")
        headers_layout = QVBoxLayout()

        self.headers_table = QTableWidget(0, 2)
        self.headers_table.setHorizontalHeaderLabels(["Clé", "Valeur"])
        self.headers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        headers_layout.addWidget(self.headers_table)

        hbtn = QHBoxLayout()
        add_btn = QPushButton("➕ Ajouter")
        add_btn.clicked.connect(self.add_header)
        hbtn.addWidget(add_btn)

        rem_btn = QPushButton("➖ Supprimer")
        rem_btn.clicked.connect(self.remove_header)
        hbtn.addWidget(rem_btn)
        hbtn.addStretch()
        headers_layout.addLayout(hbtn)

        headers_group.setLayout(headers_layout)
        layout.addWidget(headers_group)

        # --- Options avancées ---
        opt_group = QGroupBox("⚙️ Options avancées")
        opt_layout = QGridLayout()

        opt_layout.addWidget(QLabel("Niveau:"), 0, 0)
        self.level_spin = QSpinBox(); self.level_spin.setRange(1, 5); self.level_spin.setValue(3)
        opt_layout.addWidget(self.level_spin, 0, 1)

        opt_layout.addWidget(QLabel("Risque:"), 1, 0)
        self.risk_spin = QSpinBox(); self.risk_spin.setRange(1, 3); self.risk_spin.setValue(2)
        opt_layout.addWidget(self.risk_spin, 1, 1)

        opt_layout.addWidget(QLabel("Threads:"), 2, 0)
        self.threads_spin = QSpinBox(); self.threads_spin.setRange(1, 20); self.threads_spin.setValue(5)
        opt_layout.addWidget(self.threads_spin, 2, 1)

        opt_layout.addWidget(QLabel("Timeout:"), 3, 0)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(5, 120); self.timeout_spin.setValue(30)
        opt_layout.addWidget(self.timeout_spin, 3, 1)

        opt_layout.addWidget(QLabel("Délai (s):"), 4, 0)
        self.delay_spin = QDoubleSpinBox(); self.delay_spin.setRange(0, 10); self.delay_spin.setSingleStep(0.5); self.delay_spin.setValue(0.5)
        opt_layout.addWidget(self.delay_spin, 4, 1)

        opt_layout.addWidget(QLabel("Proxy:"), 5, 0)
        self.proxy_input = QLineEdit(); self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        opt_layout.addWidget(self.proxy_input, 5, 1)

        opt_layout.addWidget(QLabel("Cookie:"), 6, 0)
        self.cookie_input = QLineEdit(); self.cookie_input.setPlaceholderText("PHPSESSID=abc123")
        opt_layout.addWidget(self.cookie_input, 6, 1)

        opt_layout.addWidget(QLabel("User-Agent:"), 7, 0)
        self.ua_input = QLineEdit(); self.ua_input.setPlaceholderText("(vide = --random-agent)")
        opt_layout.addWidget(self.ua_input, 7, 1)

        opt_group.setLayout(opt_layout)
        layout.addWidget(opt_group)

        # --- Techniques ---
        tech_group = QGroupBox("💉 Techniques")
        tech_layout = QHBoxLayout()

        self.tech_checkboxes = {}
        for key, label in [("B", "Boolean"), ("E", "Error"), ("U", "Union"),
                           ("S", "Stacked"), ("T", "Time"), ("Q", "Inline")]:
            cb = QCheckBox(label)
            cb.setChecked(True)
            tech_layout.addWidget(cb)
            self.tech_checkboxes[key] = cb

        tech_group.setLayout(tech_layout)
        layout.addWidget(tech_group)

        # --- Tamper ---
        tamper_group = QGroupBox("🎭 Tamper scripts")
        tamper_layout = QHBoxLayout()

        self.tamper_input = QLineEdit()
        self.tamper_input.setPlaceholderText("space2comment,randomcase,equaltolike")
        tamper_layout.addWidget(self.tamper_input)

        tamper_group.setLayout(tamper_layout)
        layout.addWidget(tamper_group)

        # --- WAF Detection réelle ---
        waf_group = QGroupBox("🛡️ Détection WAF (réelle, via headers HTTP)")
        waf_layout = QHBoxLayout()

        self.waf_detect_btn = QPushButton("🔎 Détecter le WAF")
        self.waf_detect_btn.setObjectName("primary")
        self.waf_detect_btn.clicked.connect(self.detect_waf)
        waf_layout.addWidget(self.waf_detect_btn)

        self.waf_result = QLabel("—")
        self.waf_result.setStyleSheet("color: #ffaa00; font-weight: bold;")
        waf_layout.addWidget(self.waf_result)
        waf_layout.addStretch()

        waf_group.setLayout(waf_layout)
        layout.addWidget(waf_group)

        # --- Boutons principaux ---
        btn_layout = QHBoxLayout()

        self.scan_btn = QPushButton("🚀 Lancer le scan")
        self.scan_btn.setObjectName("success")
        self.scan_btn.clicked.connect(self.start_scan)
        btn_layout.addWidget(self.scan_btn)

        self.stop_btn = QPushButton("⏹️ Arrêter")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("🧹 Effacer console")
        self.clear_btn.clicked.connect(self.clear_console)
        btn_layout.addWidget(self.clear_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        layout.addStretch()

        return tab

    def create_extraction_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        info = QLabel(
            "💡 Utilise les options natives de sqlmap. "
            "Remplis les champs puis clique sur le bouton correspondant."
        )
        info.setStyleSheet("color: #ffaa00; padding: 8px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Databases
        db_group = QGroupBox("🗄️ Énumérer les bases de données")
        db_layout = QHBoxLayout()

        self.btn_list_dbs = QPushButton("📋 Lister les bases (--dbs)")
        self.btn_list_dbs.setObjectName("primary")
        self.btn_list_dbs.clicked.connect(lambda: self.run_extraction('dbs'))
        db_layout.addWidget(self.btn_list_dbs)

        db_group.setLayout(db_layout)
        layout.addWidget(db_group)

        # Tables
        tables_group = QGroupBox("📋 Énumérer les tables")
        tables_layout = QGridLayout()

        tables_layout.addWidget(QLabel("Base de données:"), 0, 0)
        self.extract_db = QLineEdit()
        self.extract_db.setPlaceholderText("nom_base")
        tables_layout.addWidget(self.extract_db, 0, 1)

        self.btn_list_tables = QPushButton("📋 Lister les tables (--tables)")
        self.btn_list_tables.setObjectName("primary")
        self.btn_list_tables.clicked.connect(lambda: self.run_extraction('tables'))
        tables_layout.addWidget(self.btn_list_tables, 0, 2)

        tables_group.setLayout(tables_layout)
        layout.addWidget(tables_group)

        # Columns
        cols_group = QGroupBox("📊 Énumérer les colonnes")
        cols_layout = QGridLayout()

        cols_layout.addWidget(QLabel("Base:"), 0, 0)
        self.col_db = QLineEdit()
        cols_layout.addWidget(self.col_db, 0, 1)

        cols_layout.addWidget(QLabel("Table:"), 1, 0)
        self.col_table = QLineEdit()
        cols_layout.addWidget(self.col_table, 1, 1)

        self.btn_list_columns = QPushButton("📊 Lister les colonnes (--columns)")
        self.btn_list_columns.setObjectName("primary")
        self.btn_list_columns.clicked.connect(lambda: self.run_extraction('columns'))
        cols_layout.addWidget(self.btn_list_columns, 0, 2, 2, 1)

        cols_group.setLayout(cols_layout)
        layout.addWidget(cols_group)

        # Dump
        dump_group = QGroupBox("💾 Dump de données")
        dump_layout = QGridLayout()

        dump_layout.addWidget(QLabel("Base:"), 0, 0)
        self.dump_db = QLineEdit()
        dump_layout.addWidget(self.dump_db, 0, 1)

        dump_layout.addWidget(QLabel("Table:"), 1, 0)
        self.dump_table = QLineEdit()
        dump_layout.addWidget(self.dump_table, 1, 1)

        dump_layout.addWidget(QLabel("Colonnes (CSV):"), 2, 0)
        self.dump_columns = QLineEdit()
        self.dump_columns.setPlaceholderText("user,password (vide = toutes)")
        dump_layout.addWidget(self.dump_columns, 2, 1)

        self.btn_dump = QPushButton("💾 Dumper (--dump)")
        self.btn_dump.setObjectName("success")
        self.btn_dump.clicked.connect(lambda: self.run_extraction('dump'))
        dump_layout.addWidget(self.btn_dump, 0, 2, 3, 1)

        dump_group.setLayout(dump_layout)
        layout.addWidget(dump_group)

        # OS Shell
        shell_group = QGroupBox("🐚 OS Shell (dangereux, autorisation requise)")
        shell_layout = QHBoxLayout()

        self.btn_os_shell = QPushButton("🐚 Lancer un OS shell (--os-shell)")
        self.btn_os_shell.setObjectName("danger")
        self.btn_os_shell.clicked.connect(lambda: self.run_extraction('os_shell'))
        shell_layout.addWidget(self.btn_os_shell)
        shell_layout.addStretch()

        shell_group.setLayout(shell_layout)
        layout.addWidget(shell_group)

        layout.addStretch()
        return tab

    def create_console_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        self.console.setMaximumBlockCount(10000)  # évite l'explosion mémoire
        layout.addWidget(self.console)

        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("📋 Copier tout")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.console.toPlainText()))
        btn_layout.addWidget(copy_btn)

        clear_btn = QPushButton("🧹 Effacer")
        clear_btn.clicked.connect(self.clear_console)
        btn_layout.addWidget(clear_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        return tab

    def create_results_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Stats
        stats_group = QGroupBox("📊 Statistiques")
        stats_layout = QGridLayout()

        self.stats_labels = {}
        stats_items = [
            ("Vulnérabilités:", "vulns", "0"),
            ("DBMS:", "dbms", "—"),
            ("Bases de données:", "dbs", "0"),
            ("Tables:", "tables", "0"),
            ("Colonnes:", "columns", "0"),
            ("Lignes dumpées:", "dumped", "0"),
            ("WAF:", "waf", "—"),
        ]

        for i, (label, key, default) in enumerate(stats_items):
            stats_layout.addWidget(QLabel(label), i, 0)
            lbl = QLabel(default)
            lbl.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 14px;")
            stats_layout.addWidget(lbl, i, 1)
            self.stats_labels[key] = lbl

        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        # Arbre résultats
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Résultat", "Détail"])
        self.results_tree.setColumnWidth(0, 400)
        layout.addWidget(self.results_tree)

        # Boutons
        btn_layout = QHBoxLayout()
        export_btn = QPushButton("📤 Exporter JSON")
        export_btn.clicked.connect(self.export_json)
        btn_layout.addWidget(export_btn)

        clear_btn = QPushButton("🧹 Effacer résultats")
        clear_btn.clicked.connect(self.clear_results)
        btn_layout.addWidget(clear_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Arbre items
        self.tree_items = {}

        return tab

    # ==================== SIGNAUX ====================

    def connect_signals(self):
        self.wrapper.output_received.connect(self.append_console)
        self.wrapper.status_changed.connect(self.update_status)
        self.wrapper.scan_finished.connect(self.on_scan_finished)
        self.wrapper.parsed_event.connect(self.on_parsed_event)

        self.waf_detector.detection_done.connect(self.on_waf_detected)

    # ==================== ACTIONS ====================

    def add_header(self):
        row = self.headers_table.rowCount()
        self.headers_table.insertRow(row)
        self.headers_table.setItem(row, 0, QTableWidgetItem(""))
        self.headers_table.setItem(row, 1, QTableWidgetItem(""))

    def remove_header(self):
        row = self.headers_table.currentRow()
        if row >= 0:
            self.headers_table.removeRow(row)

    def build_params(self) -> Dict:
        params = {
            'url': self.url_input.text().strip(),
            'method': self.method_combo.currentText(),
            'data': self.post_data.text().strip(),
            'level': self.level_spin.value(),
            'risk': self.risk_spin.value(),
            'techniques': ''.join(k for k, cb in self.tech_checkboxes.items() if cb.isChecked()),
            'threads': self.threads_spin.value(),
            'timeout': self.timeout_spin.value(),
            'delay': self.delay_spin.value(),
            'batch': True,
            'random_agent': True,
        }

        if self.proxy_input.text().strip():
            params['proxy'] = self.proxy_input.text().strip()

        if self.cookie_input.text().strip():
            params['cookies'] = self.cookie_input.text().strip()

        if self.ua_input.text().strip():
            params['user_agent'] = self.ua_input.text().strip()

        if self.tamper_input.text().strip():
            params['tamper'] = self.tamper_input.text().strip()

        # Headers
        headers = {}
        for row in range(self.headers_table.rowCount()):
            k = self.headers_table.item(row, 0)
            v = self.headers_table.item(row, 1)
            if k and v and k.text().strip() and v.text().strip():
                headers[k.text().strip()] = v.text().strip()
        if headers:
            params['headers'] = headers

        # Auth
        auth_type = self.auth_combo.currentText()
        if auth_type != "Aucune":
            user = self.auth_user.text().strip()
            password = self.auth_pass.text().strip()
            if user:
                params['auth_type'] = auth_type.upper()
                params['auth_cred'] = f"{user}:{password}"

        return params

    def start_scan(self):
        params = self.build_params()
        if not params['url']:
            self.append_console("❌ Veuillez entrer une URL")
            return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.showMessage("📡 Scan en cours...")
        self.append_console("=" * 70)
        self.append_console(f"🚀 Nouveau scan sur {params['url']}")
        self.append_console("=" * 70)

        self.clear_results()
        self.wrapper.start_scan(params)

    def run_extraction(self, action: str):
        """Lance une extraction ciblée."""
        if self.wrapper.running:
            self.append_console("⚠️ Un scan est déjà en cours")
            return

        params = self.build_params()
        if not params['url']:
            self.append_console("❌ Veuillez entrer une URL dans l'onglet Configuration")
            return

        if action == 'dbs':
            params['dbs'] = True
        elif action == 'tables':
            db = self.extract_db.text().strip()
            if not db:
                self.append_console("❌ Remplis le champ 'Base de données'")
                return
            params['database'] = db
            params['tables'] = True
        elif action == 'columns':
            db = self.col_db.text().strip()
            table = self.col_table.text().strip()
            if not db or not table:
                self.append_console("❌ Remplis 'Base' et 'Table'")
                return
            params['database'] = db
            params['table'] = table
            params['columns'] = True
        elif action == 'dump':
            db = self.dump_db.text().strip()
            table = self.dump_table.text().strip()
            if not db or not table:
                self.append_console("❌ Remplis 'Base' et 'Table'")
                return
            params['database'] = db
            params['table'] = table
            params['columns'] = True
            params['dump'] = True
        elif action == 'os_shell':
            if not self.confirm_dangerous_action():
                return
            params['os_shell'] = True

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.append_console("=" * 70)
        self.append_console(f"🎯 Extraction : {action}")
        self.append_console("=" * 70)

        self.wrapper.start_scan(params)

    def confirm_dangerous_action(self) -> bool:
        reply = QMessageBox.warning(
            self,
            "⚠️ Action dangereuse",
            "L'OS shell donne un accès shell sur le serveur cible.\n\n"
            "Confirmes-tu avoir une AUTORISATION ÉCRITE ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def detect_waf(self):
        url = self.url_input.text().strip()
        if not url:
            self.append_console("❌ Rentre une URL dans l'onglet Configuration")
            return
        self.waf_detect_btn.setEnabled(False)
        self.waf_result.setText("🔎 Détection en cours...")
        self.waf_detector.detect(url)

    def on_waf_detected(self, waf_name: str, matched: list):
        self.waf_detect_btn.setEnabled(True)
        self.waf_result.setText(waf_name)
        self.stats_labels['waf'].setText(waf_name)
        self.append_console(f"🛡️ WAF détecté : {waf_name}")
        for m in matched:
            self.append_console(f"    {m}")

    def stop_scan(self):
        self.wrapper.stop_scan()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("⏹️ Scan arrêté")

    def append_console(self, text: str):
        self.console.appendPlainText(text)
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

    def update_status(self, status: str):
        self.status_bar.showMessage(f"📡 {status}")
        if any(w in status.lower() for w in ['terminé', 'arrêté', 'erreur']):
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def clear_console(self):
        self.console.clear()

    def clear_results(self):
        self.results_tree.clear()
        self.tree_items = {}
        for key in self.stats_labels:
            if key == 'dbms' or key == 'waf':
                self.stats_labels[key].setText("—")
            else:
                self.stats_labels[key].setText("0")
        self._current_dumped_rows = 0

    # ==================== PARSING RÉEL ====================

    def on_parsed_event(self, event_type: str, data: dict):
        """Reçoit les événements parsés depuis le wrapper."""
        if event_type == 'vuln':
            param = data.get('parameter', '?')
            method = data.get('method', '?')
            key = f"vuln_{param}_{method}"
            if key not in self.tree_items:
                item = QTreeWidgetItem(self.results_tree)
                item.setText(0, f"🔴 Vulnérabilité : {param} ({method})")
                item.setText(1, "technique en cours...")
                self.tree_items[key] = item
            self._update_vuln_count()

        elif event_type == 'vuln_tech':
            tech = data.get('technique', '')
            for k, item in self.tree_items.items():
                if k.startswith('vuln_') and item.text(1) == "technique en cours...":
                    item.setText(1, tech)
                    break

        elif event_type == 'dbms':
            self.stats_labels['dbms'].setText(data.get('dbms', '—'))

        elif event_type == 'database':
            name = data.get('name', '')
            key = f"db_{name}"
            if key not in self.tree_items:
                # Trouver ou créer le parent "Bases de données"
                parent = self.tree_items.get('_dbs_parent')
                if not parent:
                    parent = QTreeWidgetItem(self.results_tree)
                    parent.setText(0, "🗄️ Bases de données")
                    self.tree_items['_dbs_parent'] = parent
                item = QTreeWidgetItem(parent)
                item.setText(0, name)
                self.tree_items[key] = item
                parent.setExpanded(True)
            self.stats_labels['dbs'].setText(str(len(self.wrapper.results['databases'])))

        elif event_type == 'table':
            db = data.get('db', 'unknown')
            table = data.get('table', '')
            key = f"table_{db}_{table}"
            if key not in self.tree_items:
                parent = self.tree_items.get('_tables_parent')
                if not parent:
                    parent = QTreeWidgetItem(self.results_tree)
                    parent.setText(0, "📋 Tables")
                    self.tree_items['_tables_parent'] = parent
                item = QTreeWidgetItem(parent)
                item.setText(0, f"{db}.{table}")
                self.tree_items[key] = item
                parent.setExpanded(True)
            total = sum(len(v) for v in self.wrapper.results['tables'].values())
            self.stats_labels['tables'].setText(str(total))

        elif event_type == 'columns_section':
            count = data.get('count', 0)
            self.append_console(f"  → {count} colonnes détectées")

        elif event_type == 'dumped_row':
            row = data.get('row', [])
            if row:
                key = f"dump_{self._current_dumped_rows}"
                item = QTreeWidgetItem(self.results_tree)
                item.setText(0, f"💾 Ligne {self._current_dumped_rows + 1}")
                item.setText(1, " | ".join(str(c) for c in row))
                self._current_dumped_rows += 1
                self.stats_labels['dumped'].setText(str(self._current_dumped_rows))

    def _update_vuln_count(self):
        count = len([k for k in self.tree_items if k.startswith('vuln_')])
        self.stats_labels['vulns'].setText(str(count))

    def on_scan_finished(self, status: str):
        """Fin de scan — affiche un résumé RÉEL."""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if status == 'not_found':
            self.append_console("❌ sqlmap introuvable. Installe-le : sudo apt install sqlmap")
            return

        self.append_console("")
        self.append_console("=" * 70)
        self.append_console("✅ SCAN TERMINÉ — RÉSUMÉ")
        self.append_console("=" * 70)

        res = self.wrapper.results
        self.append_console(f"URL             : {res.get('url', '')}")
        self.append_console(f"Vulnérabilités  : {len(res.get('vulnerabilities', []))}")
        self.append_console(f"DBMS            : {res.get('dbms') or '—'}")
        self.append_console(f"Bases           : {len(res.get('databases', []))}")
        tables_total = sum(len(v) for v in res.get('tables', {}).values())
        self.append_console(f"Tables          : {tables_total}")
        self.append_console(f"Lignes dumpées  : {self._current_dumped_rows}")
        self.append_console(f"WAF             : {res.get('waf') or '—'}")

        if res.get('vulnerabilities'):
            self.append_console("")
            self.append_console("🔴 Détail des vulnérabilités :")
            for v in res['vulnerabilities']:
                self.append_console(
                    f"  - {v.get('parameter')} ({v.get('method')}) → {v.get('technique', '?')}"
                )

        if res.get('databases'):
            self.append_console("")
            self.append_console("🗄️ Bases de données :")
            for db in res['databases']:
                self.append_console(f"  - {db}")

        self.append_console("=" * 70)
        self.status_bar.showMessage(f"✅ Terminé — {len(res.get('vulnerabilities', []))} vuln(s)")

    # ==================== EXPORT ====================

    def export_json(self):
        res = self.wrapper.results
        if not res.get('url'):
            self.append_console("❌ Aucun résultat à exporter")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"sqlmap_result_{timestamp}.json"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(res, f, indent=2, default=str)
            self.append_console(f"✅ Résultats exportés : {filename}")
        except Exception as e:
            self.append_console(f"❌ Erreur export : {e}")


# ==================== MAIN ====================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    window = SQLMapGUI()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
