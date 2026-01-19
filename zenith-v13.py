import urllib.parse
import sys
import re
import socket
import json
import time
import datetime

# Check dependencies
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("MISSING DEPENDENCY: pip install requests")
    sys.exit(1)

from flask import Flask, request, redirect, render_template_string, abort, jsonify, Response, stream_with_context

app = Flask(__name__)

# --- Configuration ---
ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# --- Payloads ---
SCAN_PAYLOADS = [
    # Standard
    "http://example.com", "https://example.com", "//example.com", "///example.com",
    
    # Obfuscation
    r"\/example.com", "http:example.com", "https:www.example.com", 
    "http://2130706433", "http://0177.0.0.1", "http://[::1]",
    "http://example.com%2523", "//example.com%00", 
    
    # Social Engineering
    "http://localhost.evil.com", "http://bad.com@localhost", "http://localhost@bad.com", 
    "http://www.google.com#.example.com",
    
    # XSS Context
    "javascript:alert(1)"
]

COMMON_REDIRECT_PARAMS = ['next', 'url', 'target', 'r', 'dest', 'redirect', 'return', 'returnTo', 'go', 'continue', 'path', 'out', 'view', 'link', 'destination', 'u', 'login', 'logout']

# --- Frontend Template ---
HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZENITH // V13</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-deep: #050507; --bg-panel: #0e0e12; --bg-surface: #18181f;
            --text-main: #ededed; --text-muted: #8a8a9e;
            --border: #2a2a35; --border-highlight: #3f3f50;
            
            --primary: #00f0ff; --primary-dim: rgba(0, 240, 255, 0.1); --primary-glow: rgba(0, 240, 255, 0.4);
            --secondary: #7000ff; --secondary-dim: rgba(112, 0, 255, 0.1);
            
            --danger: #ff0055; --danger-glow: rgba(255, 0, 85, 0.4);
            --success: #00ff9d; --success-glow: rgba(0, 255, 157, 0.4);
            --warning: #ffbe0b;
            
            --font-main: 'Space Grotesk', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
            
            --radius-sm: 4px; --radius-md: 8px; --radius-lg: 16px;
        }
        
        * { box-sizing: border-box; outline: none; }
        body { 
            font-family: var(--font-main); margin: 0; padding: 0; 
            background: var(--bg-deep); color: var(--text-main); 
            height: 100vh; overflow: hidden; display: flex;
        }
        
        /* Utility */
        .flex { display: flex; } .flex-col { flex-direction: column; }
        .items-center { align-items: center; } .justify-between { justify-content: space-between; }
        .gap-2 { gap: 0.5rem; } .gap-4 { gap: 1rem; }
        .hidden { display: none !important; }
        .mono { font-family: var(--font-mono); }
        .w-full { width: 100%; }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-deep); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--border-highlight); }

        /* Sidebar */
        .sidebar {
            width: 300px; background: var(--bg-panel); border-right: 1px solid var(--border);
            display: flex; flex-direction: column; padding: 24px; gap: 24px; z-index: 20;
            box-shadow: 10px 0 30px rgba(0,0,0,0.3);
        }
        .logo { 
            font-size: 1.5rem; font-weight: 700; color: white; display: flex; align-items: center; gap: 12px;
            letter-spacing: -0.03em; padding-bottom: 24px; border-bottom: 1px solid var(--border);
            text-shadow: 0 0 15px var(--primary-glow);
        }
        .logo i { color: var(--primary); }

        /* Sidebar Group */
        .group-title { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); letter-spacing: 0.1em; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
        .group-title::after { content:''; height:1px; flex:1; background: var(--border); }

        /* Inputs */
        input[type="text"], textarea {
            width: 100%; padding: 12px 14px; background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-sm);
            color: var(--text-main); font-family: var(--font-mono); font-size: 0.8rem; transition: 0.3s;
        }
        input:focus, textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 1px var(--primary-glow); background: #1a1a24; }

        /* File Drop */
        .file-drop {
            border: 1px dashed var(--border-highlight); border-radius: var(--radius-sm); padding: 20px; text-align: center;
            background: rgba(255,255,255,0.01); cursor: pointer; transition: 0.3s; position: relative; overflow: hidden;
        }
        .file-drop:hover { border-color: var(--primary); background: var(--primary-dim); }
        .file-drop.active { border-color: var(--success); background: var(--success-glow); }
        .file-drop input { position: absolute; inset: 0; opacity: 0; cursor: pointer; }

        /* Toggles */
        .toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 6px 0; cursor: pointer; }
        .toggle-switch { width: 34px; height: 18px; background: var(--border); border-radius: 10px; position: relative; transition: 0.3s; }
        .toggle-switch::after { content:''; position: absolute; top: 2px; left: 2px; width: 14px; height: 14px; background: #888; border-radius: 50%; transition: 0.3s; }
        input:checked + .toggle-switch { background: var(--primary); box-shadow: 0 0 10px var(--primary-glow); }
        input:checked + .toggle-switch::after { transform: translateX(16px); background: #000; }

        /* Buttons */
        .btn {
            width: 100%; padding: 12px; border-radius: var(--radius-sm); border: none; font-weight: 700; font-family: var(--font-main); text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.8rem;
            cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 10px; transition: 0.3s;
        }
        .btn-primary { 
            background: var(--primary); color: #000; 
            box-shadow: 0 0 15px var(--primary-glow);
        }
        .btn-primary:hover { background: #fff; box-shadow: 0 0 25px var(--primary-glow); }
        
        .btn-danger { background: var(--danger); color: white; box-shadow: 0 0 15px var(--danger-glow); }
        .btn-danger:hover { background: #ff4d85; }

        .btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text-muted); width: auto; padding: 8px 12px; }
        .btn-ghost:hover { border-color: var(--text-main); color: var(--text-main); background: var(--bg-surface); }

        .btn-target { text-align: left; justify-content: flex-start; background: var(--bg-surface); border: 1px solid var(--border); color: var(--text-muted); padding: 10px; border-radius: var(--radius-sm); font-size: 0.75rem; }
        .btn-target:hover { border-color: var(--primary); color: var(--text-main); transform: translateX(4px); }

        /* Main Content */
        .main { flex: 1; display: flex; flex-direction: column; background: var(--bg-deep); position: relative; }
        .scan-overlay { position: absolute; top:0; left:0; width:100%; height:2px; background: linear-gradient(90deg, transparent, var(--primary), transparent); z-index:50; animation: scan 1.5s infinite; display: none; }
        @keyframes scan { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }

        /* Top Bar */
        .topbar { height: 64px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 32px; background: var(--bg-panel); }
        
        /* Stats */
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; padding: 24px 32px; }
        .stat-card {
            background: var(--bg-panel); border: 1px solid var(--border); padding: 20px; border-radius: var(--radius-md);
            position: relative; overflow: hidden; display: flex; flex-direction: column; gap: 4px; transition: 0.3s;
        }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); border-color: var(--border-highlight); }
        .stat-val { font-size: 2.2rem; font-weight: 700; line-height: 1; font-family: var(--font-main); color: var(--text-main); }
        .stat-lbl { font-size: 0.7rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; }
        .stat-card.vuln .stat-val { color: var(--danger); text-shadow: 0 0 10px var(--danger-glow); }
        .stat-card.safe .stat-val { color: var(--success); text-shadow: 0 0 10px var(--success-glow); }

        /* Filter Tabs */
        .filter-tabs { display: flex; gap: 4px; background: var(--bg-surface); padding: 4px; border-radius: var(--radius-sm); border: 1px solid var(--border); }
        .tab { padding: 6px 16px; font-size: 0.75rem; font-weight: 700; color: var(--text-muted); cursor: pointer; border-radius: 2px; transition: 0.2s; font-family: var(--font-mono); }
        .tab:hover { color: var(--text-main); }
        .tab.active { background: var(--bg-panel); color: var(--text-main); border: 1px solid var(--border-highlight); }
        .tab.active[data-t="vuln"] { color: var(--danger); border-color: var(--danger); background: rgba(255,0,85,0.05); }
        .tab.active[data-t="safe"] { color: var(--success); border-color: var(--success); background: rgba(0,255,157,0.05); }

        /* Results Table */
        .table-container { flex: 1; overflow: hidden; display: flex; flex-direction: column; padding: 0 32px 16px 32px; }
        .table-scroll { flex: 1; overflow: auto; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-panel); }
        
        table { width: 100%; border-collapse: collapse; min-width: 1000px; }
        th { 
            position: sticky; top: 0; background: #131318; z-index: 10; padding: 16px; text-align: left;
            font-size: 0.7rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase; border-bottom: 1px solid var(--border); letter-spacing: 0.05em;
        }
        td { padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 0.85rem; vertical-align: middle; transition: 0.2s; }
        tr:hover td { background: var(--bg-surface); }
        
        .pill { padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; display: inline-flex; align-items: center; gap: 6px; font-family: var(--font-mono); }
        .pill-vuln { background: rgba(255,0,85,0.1); color: var(--danger); border: 1px solid rgba(255,0,85,0.2); }
        .pill-safe { background: rgba(0,255,157,0.1); color: var(--success); border: 1px solid rgba(0,255,157,0.2); }
        
        .code-snippet { background: #000; padding: 4px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 0.75rem; border: 1px solid var(--border); color: #ccc; }
        .url-truncate { max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text-muted); font-size: 0.8rem; cursor: help; }

        /* Action Buttons */
        .btn-try { 
            background: linear-gradient(90deg, var(--primary), var(--secondary)); 
            border: none; color: #fff; font-weight: 700; font-size: 0.7rem; padding: 6px 12px; border-radius: 4px; 
            text-transform: uppercase; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px;
            box-shadow: 0 0 10px rgba(112, 0, 255, 0.3); transition: 0.3s;
        }
        .btn-try:hover { box-shadow: 0 0 20px rgba(0, 240, 255, 0.5); transform: translateY(-1px); }

        .btn-inspect { background: transparent; border: 1px solid var(--border); color: var(--text-muted); padding: 5px 8px; border-radius: 4px; cursor: pointer; }
        .btn-inspect:hover { border-color: var(--primary); color: var(--primary); }

        /* Terminal Console */
        .terminal { height: 140px; background: #08080a; border-top: 1px solid var(--border); padding: 16px; font-family: var(--font-mono); font-size: 0.75rem; overflow-y: auto; color: var(--text-muted); display: flex; flex-direction: column-reverse; }
        .log-entry { margin-bottom: 4px; border-left: 2px solid transparent; padding-left: 10px; animation: slideIn 0.2s ease-out; }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        .log-info { border-color: var(--border-highlight); }
        .log-vuln { border-color: var(--danger); color: #fff; background: linear-gradient(90deg, rgba(255,0,85,0.1), transparent); }
        .log-success { border-color: var(--success); color: var(--success); }

        /* Modal */
        .modal-bg { position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); z-index: 100; display: none; align-items: center; justify-content: center; }
        .modal { background: var(--bg-panel); width: 650px; max-width: 90%; border: 1px solid var(--border); border-radius: var(--radius-lg); box-shadow: 0 0 50px rgba(0,0,0,0.5); overflow: hidden; animation: popUp 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
        @keyframes popUp { from { transform: scale(0.9); opacity: 0; } to { transform: scale(1); opacity: 1; } }
        .m-head { padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #131318; }
        .m-title { font-weight: 700; font-family: var(--font-mono); color: var(--primary); letter-spacing: 0.05em; display: flex; align-items: center; gap: 10px; }
        .m-body { padding: 24px; max-height: 60vh; overflow-y: auto; }
        .m-box { background: #000; border: 1px solid var(--border); padding: 16px; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 0.8rem; color: #d1d5db; word-break: break-all; margin-top: 8px; margin-bottom: 20px; }
        .m-label { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    </style>
</head>
<body>

    <!-- INSPECTOR MODAL -->
    <div class="modal-bg" id="modal">
        <div class="modal">
            <div class="m-head">
                <div class="m-title"><i class="fas fa-search-dollar"></i> PACKET INSPECTOR</div>
                <button class="btn-ghost" onclick="closeModal()"><i class="fas fa-times"></i></button>
            </div>
            <div class="m-body">
                <div class="m-label">REQUEST URL</div>
                <div class="m-box" id="mUrl"></div>
                
                <div class="m-label">REDIRECT LOCATION</div>
                <div class="m-box" id="mLoc" style="color: var(--warning);"></div>
                
                <div class="m-label">REPRODUCTION (CURL)</div>
                <div class="m-box" id="mCurl" style="color: var(--success);"></div>
            </div>
            <div style="padding: 20px; border-top: 1px solid var(--border); text-align: right; background: #131318;">
                <button class="btn-primary" style="width: auto; padding: 10px 20px; border-radius: 4px;" onclick="closeModal()">CLOSE</button>
            </div>
        </div>
    </div>

    <!-- SIDEBAR -->
    <div class="sidebar">
        <div class="logo"><i class="fas fa-cube"></i> ZENITH // V13</div>
        
        <div class="flex flex-col gap-4">
            <div>
                <div class="group-title">TARGET PARAMETERS</div>
                <input type="text" id="targetUrl" value="http://localhost:5000/lab/level1?next=test" placeholder="http://target.com/path?redirect=...">
            </div>
            
            <div>
                <div class="group-title">PAYLOAD INJECTION</div>
                <div class="file-drop" id="dropZone">
                    <input type="file" id="payloadFile" accept=".txt" onchange="handleFile()">
                    <div id="fileName" style="font-size:0.8rem; color:var(--text-muted); font-family:var(--font-mono);"><i class="fas fa-cloud-upload-alt"></i> LOAD PAYLOADS</div>
                </div>
                <textarea id="customPayloads" rows="3" style="margin-top:12px;" placeholder="Manual payloads (one per line)..."></textarea>
            </div>

            <div style="background:rgba(255,255,255,0.02); padding:12px; border-radius:var(--radius-sm); border:1px solid var(--border);">
                <label class="toggle-row">
                    <span style="font-size:0.8rem; font-weight:600; color:var(--text-muted);">DEFAULT LIST</span>
                    <input type="checkbox" id="useDefaults" checked hidden>
                    <div class="toggle-switch"></div>
                </label>
                <label class="toggle-row">
                    <span style="font-size:0.8rem; font-weight:600; color:var(--text-muted);">FUZZ ALL PARAMS</span>
                    <input type="checkbox" id="forceCommon" hidden>
                    <div class="toggle-switch"></div>
                </label>
            </div>
        </div>

        <div style="margin-top:auto;" class="flex flex-col gap-2">
            <button id="btnStart" class="btn btn-primary" onclick="startScan()">
                <i class="fas fa-bolt"></i> INITIATE SEQUENCE
            </button>
            <button id="btnStop" class="btn btn-danger hidden" onclick="stopScan()">
                <i class="fas fa-square"></i> TERMINATE
            </button>
        </div>

        <div>
            <div class="group-title">SIMULATION TARGETS</div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
                <button class="btn btn-target" onclick="setTarget('http://localhost:5000/lab/level1?next=test')">
                    <div style="color:var(--danger); font-weight:bold;">LEVEL 1</div>
                    <div style="font-size:0.65rem;">Unprotected</div>
                </button>
                <button class="btn btn-target" onclick="setTarget('http://localhost:5000/lab/level2?next=test')">
                    <div style="color:var(--warning); font-weight:bold;">LEVEL 2</div>
                    <div style="font-size:0.65rem;">Filter Bypass</div>
                </button>
                <button class="btn btn-target" onclick="setTarget('http://localhost:5000/lab/level4?next=test')">
                    <div style="color:var(--warning); font-weight:bold;">LEVEL 4</div>
                    <div style="font-size:0.65rem;">Flawed Match</div>
                </button>
                <button class="btn btn-target" onclick="setTarget('http://localhost:5000/lab/level3?next=test')">
                    <div style="color:var(--success); font-weight:bold;">LEVEL 3</div>
                    <div style="font-size:0.65rem;">Secure Host</div>
                </button>
            </div>
        </div>
    </div>

    <!-- MAIN DASHBOARD -->
    <div class="main">
        <div class="scan-overlay" id="scanLine"></div>
        
        <!-- Header -->
        <div class="topbar">
            <div class="flex items-center gap-4">
                <div class="mono" style="font-size:0.75rem; color:var(--primary); border:1px solid var(--primary-dim); padding:4px 8px; border-radius:4px; background:rgba(0,240,255,0.05);" id="statusText">SYSTEM READY</div>
                <div class="mono" style="font-size:0.8rem; color:var(--text-muted);" id="targetDisplay"></div>
            </div>
            <div class="flex gap-4 items-center">
                <div class="filter-tabs">
                    <div class="tab active" data-t="all" onclick="filterResults('all', this)">ALL EVENTS</div>
                    <div class="tab" data-t="vuln" onclick="filterResults('vuln', this)">VULNERABLE</div>
                    <div class="tab" data-t="safe" onclick="filterResults('safe', this)">SAFE</div>
                </div>
                <button class="btn-ghost" onclick="exportCSV()"><i class="fas fa-file-csv"></i> EXPORT</button>
            </div>
        </div>

        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-val" id="cntTotal">0</div>
                <div class="stat-lbl">REQUESTS SENT</div>
            </div>
            <div class="stat-card vuln">
                <div class="stat-val" id="cntVuln">0</div>
                <div class="stat-lbl">CRITICAL FINDINGS</div>
            </div>
            <div class="stat-card safe">
                <div class="stat-val" id="cntSafe">0</div>
                <div class="stat-lbl">SECURE RESPONSES</div>
            </div>
        </div>

        <!-- Table -->
        <div class="table-container">
            <div class="table-scroll">
                <table id="resultsTable">
                    <thead>
                        <tr>
                            <th style="width:120px">PARAMETER</th>
                            <th>PAYLOAD INJECTED</th>
                            <th style="width:80px">CODE</th>
                            <th>REDIRECT LOCATION</th>
                            <th style="width:120px">VERDICT</th>
                            <th style="width:160px; text-align:right;">OPERATIONS</th>
                        </tr>
                    </thead>
                    <tbody id="resultsBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Terminal -->
        <div class="terminal" id="console">
            <div class="log-entry log-info">> Zenith Interface V13.0 Loaded. Standing by.</div>
        </div>
    </div>

    <script>
        let abortController = null;
        let stats = { total: 0, vuln: 0, safe: 0 };
        let resultsData = [];
        let currentFilter = 'all';

        function setTarget(url) {
            document.getElementById('targetUrl').value = url;
            log(`Target selected: ${url}`, 'info');
        }

        function handleFile() {
            const f = document.getElementById('payloadFile');
            if(f.files.length) {
                document.getElementById('dropZone').classList.add('active');
                document.getElementById('fileName').innerText = f.files[0].name;
                log(`Payload list loaded: ${f.files[0].name}`, 'info');
            }
        }

        function log(msg, type='info') {
            const c = document.getElementById('console');
            const d = document.createElement('div');
            const time = new Date().toLocaleTimeString('en-US', {hour12:false});
            d.className = `log-entry log-${type}`;
            d.innerHTML = `<span style="opacity:0.5">[${time}]</span> ${msg}`;
            c.prepend(d);
        }

        function updateStats() {
            document.getElementById('cntTotal').innerText = stats.total;
            document.getElementById('cntVuln').innerText = stats.vuln;
            document.getElementById('cntSafe').innerText = stats.safe;
        }

        function filterResults(type, btn) {
            currentFilter = type;
            document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            document.querySelectorAll('#resultsBody tr').forEach(row => {
                const isVuln = row.dataset.vuln === 'true';
                if (type === 'all') row.style.display = '';
                else if (type === 'vuln') row.style.display = isVuln ? '' : 'none';
                else if (type === 'safe') row.style.display = !isVuln ? '' : 'none';
            });
        }

        // --- Scanning Logic ---
        async function startScan() {
            const url = document.getElementById('targetUrl').value;
            if(!url) return alert("Target URL Required");

            // UI Updates
            document.getElementById('btnStart').classList.add('hidden');
            document.getElementById('btnStop').classList.remove('hidden');
            document.getElementById('scanLine').style.display = 'block';
            document.getElementById('statusText').innerText = "SCANNING IN PROGRESS...";
            document.getElementById('statusText').style.color = "var(--primary)";
            document.getElementById('statusText').style.borderColor = "var(--primary)";
            document.getElementById('targetDisplay').innerText = url;
            document.getElementById('resultsBody').innerHTML = '';
            
            stats = {total:0, vuln:0, safe:0};
            resultsData = [];
            updateStats();
            log(`Scan sequence initiated for ${url}`, 'info');

            let custom = document.getElementById('customPayloads').value;
            const f = document.getElementById('payloadFile');
            if(f.files.length) custom += "\\n" + await f.files[0].text();

            abortController = new AbortController();

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        url: url,
                        custom_payloads: custom,
                        use_defaults: document.getElementById('useDefaults').checked,
                        force_common: document.getElementById('forceCommon').checked
                    }),
                    signal: abortController.signal
                });

                const reader = res.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';

                while(true) {
                    const {done, value} = await reader.read();
                    if(done) break;
                    buffer += decoder.decode(value, {stream:true});
                    const lines = buffer.split('\\n');
                    buffer = lines.pop();

                    for(const line of lines) {
                        if(line.trim()) {
                            try { addResult(JSON.parse(line)); } catch(e){}
                        }
                    }
                }
                log("Scan sequence complete.", 'success');
            } catch(e) {
                if(e.name !== 'AbortError') log(`Error: ${e.message}`, 'vuln');
                else log("Scan aborted by user.", 'info');
            } finally {
                stopUI();
            }
        }

        function stopScan() { if(abortController) abortController.abort(); stopUI(); }

        function stopUI() {
            document.getElementById('btnStart').classList.remove('hidden');
            document.getElementById('btnStop').classList.add('hidden');
            document.getElementById('scanLine').style.display = 'none';
            document.getElementById('statusText').innerText = "SYSTEM READY";
            document.getElementById('statusText').style.color = "var(--text-muted)";
            document.getElementById('statusText').style.borderColor = "var(--border-highlight)";
        }

        function addResult(res) {
            stats.total++;
            if(res.vulnerable) stats.vuln++; else stats.safe++;
            updateStats();
            
            res.id = resultsData.length;
            resultsData.push(res);

            const row = document.createElement('tr');
            row.dataset.vuln = res.vulnerable;
            
            if(currentFilter === 'vuln' && !res.vulnerable) row.style.display = 'none';
            if(currentFilter === 'safe' && res.vulnerable) row.style.display = 'none';

            const badge = res.vulnerable 
                ? `<span class="pill pill-vuln"><i class="fas fa-bug"></i> VULNERABLE</span>`
                : `<span class="pill pill-safe"><i class="fas fa-shield-alt"></i> SECURE</span>`;
            
            const codeColor = res.status_code.toString().startsWith('3') ? 'color:var(--warning)' : 'color:var(--text-muted)';
            const loc = res.location || '<span style="opacity:0.3">-</span>';

            row.innerHTML = `
                <td><span style="font-family:var(--font-mono); color:var(--primary); background:rgba(0,240,255,0.1); padding:2px 6px; border-radius:4px; font-size:0.75rem;">${res.param}</span></td>
                <td><div class="code-snippet">${res.payload}</div></td>
                <td style="font-weight:700; ${codeColor}">${res.status_code}</td>
                <td><div class="url-truncate" title="${res.location}">${loc}</div></td>
                <td>${badge}</td>
                <td style="text-align:right;">
                    <div style="display:flex; justify-content:flex-end; gap:8px;">
                        <button class="btn-inspect" onclick="inspect(${res.id})" title="Inspect"><i class="fas fa-search"></i></button>
                        <a href="${res.full_url}" target="_blank" class="btn-try">TRY IT <i class="fas fa-external-link-alt"></i></a>
                    </div>
                </td>
            `;
            document.getElementById('resultsBody').prepend(row);
            
            if(res.vulnerable) log(`VULNERABILITY DETECTED [${res.param}]`, 'vuln');
        }

        // Modal
        function inspect(idx) {
            const d = resultsData[idx];
            document.getElementById('mUrl').innerText = d.full_url;
            document.getElementById('mLoc').innerText = d.location || "N/A";
            document.getElementById('mCurl').innerText = `curl -i "${d.full_url}"`;
            document.getElementById('modal').style.display = 'flex';
        }
        function closeModal() { document.getElementById('modal').style.display = 'none'; }

        // CSV
        function exportCSV() {
            if(!resultsData.length) return alert("No data");
            let c = "Param,Payload,URL,Status,Location,Vulnerable\\n";
            resultsData.forEach(r => {
                c += `"${r.param}","${r.payload.replace(/"/g,'""')}","${r.full_url}","${r.status_code}","${(r.location||"").replace(/"/g,'""')}","${r.vulnerable}"\\n`;
            });
            const b = new Blob([c], {type:'text/csv'});
            const url = URL.createObjectURL(b);
            const a = document.createElement('a'); a.href=url; a.download='scan_report.csv'; a.click();
        }
    </script>
</body>
</html>
"""

# --- Routes ---

@app.route('/')
def home():
    return render_template_string(HOME_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    return render_template_string("<h1>Internal Dashboard</h1><p>You have arrived.</p>")

# --- SCANNER API ---

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    full_target_url = data.get('url', '').strip()
    custom_payloads_str = data.get('custom_payloads', '')
    use_defaults = data.get('use_defaults', True)
    force_common = data.get('force_common', False)
    
    parsed = urllib.parse.urlparse(full_target_url)
    query_params = urllib.parse.parse_qs(parsed.query)
    params_to_test = list(query_params.keys())
    
    if not params_to_test or force_common:
        for p in COMMON_REDIRECT_PARAMS:
            if p not in params_to_test:
                params_to_test.append(p)

    final_payloads = []
    if use_defaults:
        final_payloads.extend(SCAN_PAYLOADS)
    if custom_payloads_str:
        normalized = custom_payloads_str.replace('\r\n', '\n')
        lines = normalized.split('\n')
        for line in lines:
            if line.strip(): final_payloads.append(line.strip())

    unique_payloads = list(dict.fromkeys(final_payloads))

    def generate():
        session = requests.Session()
        session.headers.update({'User-Agent': 'Zenith/V13'})
        
        for param_name in params_to_test:
            for payload in unique_payloads:
                if parsed.query:
                    qs_parts = query_params.copy()
                    qs_parts[param_name] = [payload]
                    new_query = urllib.parse.urlencode(qs_parts, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path, 
                        parsed.params, new_query, parsed.fragment
                    ))
                else:
                    separator = '&' if '?' in full_target_url else '?'
                    test_url = f"{full_target_url}{separator}{param_name}={payload}"
                
                result = {
                    'param': param_name, 'payload': payload, 'full_url': test_url,
                    'status_code': 'ERR', 'redirect_type': '-', 'location': '', 'vulnerable': False
                }

                try:
                    resp = session.get(test_url, allow_redirects=False, timeout=3, verify=False)
                    result['status_code'] = resp.status_code
                    
                    is_vuln = False
                    loc = ""

                    if resp.status_code in [301, 302, 303, 307, 308]:
                        loc = resp.headers.get('Location', '')
                        result['redirect_type'] = 'HTTP'
                        try:
                            loc_parsed = urllib.parse.urlparse(loc)
                            if loc.strip().startswith("//"):
                                temp = urllib.parse.urlparse("http:" + loc)
                                if temp.netloc and ("example.com" in temp.netloc or "google.com" in temp.netloc): is_vuln = True
                            elif loc_parsed.netloc:
                                h = loc_parsed.hostname or ""
                                if "example.com" in payload and "example.com" in h: is_vuln = True
                                elif "google.com" in payload and "google.com" in h: is_vuln = True
                                elif "evil.com" in payload and "evil.com" in h: is_vuln = True
                                elif "bad.com" in payload and "bad.com" in h: is_vuln = True
                                elif "127.0.0.1" in h and ("2130706433" in payload or "0177.0.0.1" in payload): is_vuln = True
                                elif "::1" in h and "[::1]" in payload: is_vuln = True
                            if loc_parsed.scheme.lower() == 'javascript': is_vuln = True
                        except: pass
                        if not is_vuln and "javascript:" in loc.lower(): is_vuln = True

                    elif resp.status_code == 200:
                        meta = re.search(r'<meta\s+http-equiv=["\']?refresh["\']?\s+content=["\']?\d+;\s*url=([^"\']+)["\']?', resp.text, re.IGNORECASE)
                        if meta:
                            loc = meta.group(1)
                            result['redirect_type'] = 'Meta'
                            if "example.com" in loc or "google.com" in loc: is_vuln = True
                    
                    result['location'] = loc
                    result['vulnerable'] = is_vuln

                except Exception as e:
                    result['location'] = "Error"

                yield json.dumps(result) + "\n"

    return Response(stream_with_context(generate()), mimetype='application/x-ndjson')


# --- LAB LEVELS ---

@app.route('/lab/level1')
def lab_level_1():
    """Unsafe"""
    return redirect(request.args.get('next', '/dashboard'))

@app.route('/lab/level2')
def lab_level_2():
    """Weak Filter"""
    target = request.args.get('next', '/dashboard')
    if target.startswith("http://") or target.startswith("https://"):
        return abort(400, "Blocked by Protocol Filter")
    return redirect(target)

@app.route('/lab/level4')
def lab_level_4():
    """Flawed String Match"""
    target = request.args.get('next', '/dashboard')
    if 'localhost' in target:
        return redirect(target)
    return abort(400, "Blocked: URL must contain 'localhost'")

@app.route('/lab/level3')
def lab_level_3():
    """Secure"""
    target = request.args.get('next', '/dashboard')
    try:
        test = urllib.parse.urlparse(urllib.parse.urljoin(request.host_url, target))
        ref = urllib.parse.urlparse(request.host_url)
        if (test.netloc == '' or test.netloc == ref.netloc) or test.hostname in ALLOWED_HOSTS:
            return redirect(target)
    except: pass
    return abort(400, "Blocked by Whitelist")

if __name__ == '__main__':
    print("Starting Zenith Scanner V13 on http://localhost:5000")
    app.run(debug=True, port=5000, threaded=True)
