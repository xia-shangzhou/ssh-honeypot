#!/usr/bin/env python3
"""
SSH 蜜罐分析脚本 v2 - 两阶段分析
扫描器 vs 交互式攻击者
"""

import json
import os
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime

# === 配置 ===
LOG_DIR = os.environ.get("HONEYPOT_LOG_DIR", "./logs")
ATTEMPTS_FILE = os.path.join(LOG_DIR, "attempts.jsonl")
COMMANDS_FILE = os.path.join(LOG_DIR, "commands.jsonl")
OUTPUT_FILE = os.environ.get("HONEYPOT_OUTPUT", "/app/web/dashboard.html")
GEOIP_DB = os.environ.get("HONEYPOT_GEOIP_DB", "/app/data/GeoLite2-City.mmdb")

# 排除自己的 IP
MY_IPS = os.environ.get("HONEYPOT_EXCLUDE_IPS", "127.0.0.1,::1").split(",")


def load_jsonl(path):
    records = []
    if not os.path.exists(path):
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except:
                    pass
    return records


def geo_lookup(ip, reader):
    """IP 地理定位"""
    try:
        resp = reader.city(ip)
        return {
            "country": resp.country.names.get("zh-CN", resp.country.name or "未知"),
            "country_code": resp.country.iso_code or "XX",
            "city": resp.city.names.get("zh-CN", resp.city.name or ""),
        }
    except:
        return {"country": "未知", "country_code": "XX", "city": ""}


def classify_attackers(attempts, commands):
    """分类攻击者：扫描器 vs 交互式"""
    ip_attempts = defaultdict(list)
    for a in attempts:
        ip_attempts[a["ip"]].append(a)

    ip_commands = defaultdict(list)
    for c in commands:
        ip_commands[c["ip"]].append(c)

    scanners = []
    interactive = []

    for ip, records in ip_attempts.items():
        if ip in MY_IPS:
            continue

        info = {
            "ip": ip,
            "attempts": len(records),
            "commands": len(ip_commands.get(ip, [])),
            "usernames": Counter(r["username"] for r in records),
            "passwords": Counter(r.get("password", "") for r in records),
            "first_seen": records[0]["timestamp"],
            "last_seen": records[-1]["timestamp"],
            "cmd_list": [c["command"] for c in ip_commands.get(ip, [])],
        }

        if len(ip_commands.get(ip, [])) > 0:
            info["type"] = "interactive"
            info["risk"] = "high"
            interactive.append(info)
        elif len(records) > 20:
            info["type"] = "scanner"
            info["risk"] = "medium"
            scanners.append(info)
        elif len(records) > 5:
            info["type"] = "scanner"
            info["risk"] = "low"
            scanners.append(info)
        else:
            info["type"] = "probe"
            info["risk"] = "low"
            scanners.append(info)

    return scanners, interactive


def analyze(attempts, commands, reader):
    """主分析"""
    attempts = [a for a in attempts if a["ip"] not in MY_IPS]
    commands = [c for c in commands if c["ip"] not in MY_IPS]

    scanners, interactive = classify_attackers(attempts, commands)

    total_attempts = len(attempts)
    unique_ips = len(set(a["ip"] for a in attempts))
    total_commands = len(commands)
    unique_cmd_ips = len(set(c["ip"] for c in commands))

    # 地理分布
    country_counter = Counter()
    ip_geo = {}
    for a in attempts:
        ip = a["ip"]
        if ip not in ip_geo:
            ip_geo[ip] = geo_lookup(ip, reader)
        country_counter[ip_geo[ip]["country"]] += 1

    # Top 密码
    password_counter = Counter()
    for a in attempts:
        pw = a.get("password", "")
        if pw:
            password_counter[pw] += 1

    # Top 用户名
    username_counter = Counter()
    for a in attempts:
        username_counter[a["username"]] += 1

    # 时间分布（24小时）
    hour_counter = Counter()
    for a in attempts:
        try:
            dt = datetime.fromisoformat(a["timestamp"])
            hour_counter[dt.hour] += 1
        except:
            pass

    # 每日趋势
    day_counter = Counter()
    for a in attempts:
        try:
            dt = datetime.fromisoformat(a["timestamp"])
            day_counter[dt.strftime("%m-%d")] += 1
        except:
            pass

    # 命令分类
    cmd_categories = Counter()
    for c in commands:
        cmd = c["command"].lower().strip()
        if any(x in cmd for x in ["rm", "mkfs", "dd", "> /dev"]):
            cmd_categories["💣 破坏性命令"] += 1
        elif any(x in cmd for x in ["wget", "curl", "download"]):
            cmd_categories["📥 下载/植入"] += 1
        elif any(x in cmd for x in ["cat /etc", "passwd", "shadow", "id", "whoami", "uname"]):
            cmd_categories["🔍 信息收集"] += 1
        elif any(x in cmd for x in ["install", "apt", "yum", "pip"]):
            cmd_categories["📦 软件安装"] += 1
        elif any(x in cmd for x in ["chmod", "chown", "mkdir", "touch"]):
            cmd_categories["📁 文件操作"] += 1
        else:
            cmd_categories["❓ 其他"] += 1

    # 交互式攻击者详情
    interactive_details = []
    for info in interactive:
        geo = ip_geo.get(info["ip"], {"country": "未知", "country_code": "XX", "city": ""})
        interactive_details.append({
            **info,
            "geo": geo,
            "top_passwords": dict(info["passwords"].most_common(5)),
            "top_usernames": dict(info["usernames"].most_common(5)),
        })

    # 扫描器 Top 15
    scanner_top = sorted(scanners, key=lambda x: -x["attempts"])[:15]
    scanner_details = []
    for info in scanner_top:
        geo = ip_geo.get(info["ip"], {"country": "未知", "country_code": "XX", "city": ""})
        scanner_details.append({
            **info,
            "geo": geo,
            "top_passwords": dict(info["passwords"].most_common(3)),
            "top_usernames": dict(info["usernames"].most_common(3)),
        })

    return {
        "total_attempts": total_attempts,
        "unique_ips": unique_ips,
        "total_commands": total_commands,
        "unique_cmd_ips": unique_cmd_ips,
        "scanner_count": len(scanners),
        "interactive_count": len(interactive),
        "country_data": dict(country_counter.most_common(20)),
        "password_data": dict(password_counter.most_common(30)),
        "username_data": dict(username_counter.most_common(20)),
        "hour_data": {str(h): hour_counter.get(h, 0) for h in range(24)},
        "day_data": dict(sorted(day_counter.items())),
        "cmd_categories": dict(cmd_categories.most_common()),
        "interactive_details": interactive_details,
        "scanner_details": scanner_details,
        "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }




def generate_html(stats):
    """生成 HTML - 支持深色/浅色主题切换"""
    countries = list(stats["country_data"].keys())[:10]
    country_values = list(stats["country_data"].values())[:10]
    passwords = list(stats["password_data"].keys())[:15]
    password_values = list(stats["password_data"].values())[:15]
    hours = [f"{h:02d}" for h in range(24)]
    hour_values = [stats["hour_data"].get(str(h), 0) for h in range(24)]
    days = list(stats["day_data"].keys())
    day_values = list(stats["day_data"].values())
    usernames = list(stats["username_data"].keys())[:10]
    username_values = list(stats["username_data"].values())[:10]

    # 交互式攻击者 HTML
    interactive_html = ""
    for info in stats["interactive_details"]:
        cmds_html = "".join(f'<code>{c}</code> ' for c in info["cmd_list"][:10])
        interactive_html += f'''
        <div class="threat-card high">
            <div class="threat-header">
                <span class="ip">{info["ip"]}</span>
                <span class="country">🚩 {info["geo"]["country"]} {info["geo"]["city"]}</span>
                <span class="badge high">⚠️ 交互式攻击</span>
            </div>
            <div class="threat-body">
                <div>登录 {info["attempts"]} 次 | 执行 {info["commands"]} 条命令</div>
                <div class="cmds">{cmds_html}</div>
                <div class="meta">首次: {info["first_seen"][:19]} | 最后: {info["last_seen"][:19]}</div>
            </div>
        </div>'''
    if not interactive_html:
        interactive_html = '<div class="empty-state">🎯 暂无交互式攻击者（好消息！）</div>'

    # 扫描器 HTML
    scanner_html = ""
    for info in stats["scanner_details"]:
        risk_class = info["risk"]
        risk_label = {"high": "🔴", "medium": "🟡", "low": "🟢"}[risk_class]
        top_pw = ", ".join(f"{k}({v})" for k, v in list(info["top_passwords"].items())[:3])
        scanner_html += f'''
        <div class="threat-card {risk_class}">
            <div class="threat-header">
                <span class="ip">{info["ip"]}</span>
                <span class="country">{info["geo"]["country"]}</span>
                <span class="badge {risk_class}">{risk_label} {info["attempts"]}次尝试</span>
            </div>
            <div class="threat-body">
                <div>Top密码: {top_pw}</div>
                <div class="meta">{info["first_seen"][:19]} ~ {info["last_seen"][:19]}</div>
            </div>
        </div>'''

    cmd_cats_html = ""
    for cat, count in stats["cmd_categories"].items():
        cmd_cats_html += f'<div class="cmd-cat"><span class="cat-name">{cat}</span><span class="cat-count">{count}</span></div>'

    countries_json = json.dumps(countries, ensure_ascii=False)
    passwords_json = json.dumps(passwords, ensure_ascii=False)
    usernames_json = json.dumps(usernames, ensure_ascii=False)
    hours_json = json.dumps(hours)
    days_json = json.dumps(days, ensure_ascii=False)
    cmd_labels_json = json.dumps(list(stats["cmd_categories"].keys()), ensure_ascii=False)

    html = f'''<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🐝 SSH 蜜罐攻击分析面板</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
/* ===== CSS Variables - 双主题 ===== */
:root[data-theme="dark"] {{
    --bg-body: #0d1117;
    --bg-card: #161b22;
    --bg-card-hover: #1c2333;
    --border: #21262d;
    --border-hover: #388bfd;
    --text-primary: #c9d1d9;
    --text-secondary: #8b949e;
    --text-muted: #484f58;
    --accent-blue: #58a6ff;
    --accent-green: #3fb950;
    --accent-yellow: #d29922;
    --accent-red: #f85149;
    --accent-purple: #bc8cff;
    --accent-orange: #f0883e;
    --nav-bg: #21262d;
    --nav-text: #c9d1d9;
    --nav-hover: #388bfd;
    --code-bg: #1f2937;
    --shadow: 0 2px 8px rgba(0,0,0,0.3);
    --toggle-bg: #21262d;
    --toggle-icon: "🌙";
}}
:root[data-theme="light"] {{
    --bg-body: #f6f8fa;
    --bg-card: #ffffff;
    --bg-card-hover: #f0f3f6;
    --border: #d0d7de;
    --border-hover: #0969da;
    --text-primary: #1f2328;
    --text-secondary: #656d76;
    --text-muted: #8b949e;
    --accent-blue: #0969da;
    --accent-green: #1a7f37;
    --accent-yellow: #bf8700;
    --accent-red: #cf222e;
    --accent-purple: #8250df;
    --accent-orange: #bc4c00;
    --nav-bg: #ffffff;
    --nav-text: #1f2328;
    --nav-hover: #0969da;
    --code-bg: #f6f8fa;
    --shadow: 0 1px 4px rgba(0,0,0,0.08);
    --toggle-bg: #d0d7de;
    --toggle-icon: "☀️";
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    background: var(--bg-body);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    line-height: 1.6;
    transition: background 0.3s, color 0.3s;
}}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}

/* ===== 主题切换按钮 ===== */
.theme-toggle {{
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 1000;
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--toggle-bg);
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 6px 14px;
    cursor: pointer;
    transition: all 0.3s;
    box-shadow: var(--shadow);
    user-select: none;
}}
.theme-toggle:hover {{ border-color: var(--border-hover); transform: scale(1.05); }}
.theme-toggle .icon {{ font-size: 1.2em; }}
.theme-toggle .label {{
    font-size: 0.8em;
    color: var(--text-secondary);
    font-weight: 500;
}}

/* ===== Header ===== */
.header {{
    text-align: center;
    padding: 30px 0 20px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 30px;
}}
.header h1 {{
    font-size: 2em;
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-green), var(--accent-yellow));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 8px;
}}
.header .subtitle {{ color: var(--text-secondary); font-size: 0.95em; }}

/* ===== Nav ===== */
.nav {{ display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }}
.nav a {{
    padding: 6px 16px;
    background: var(--nav-bg);
    color: var(--nav-text);
    text-decoration: none;
    border-radius: 20px;
    font-size: 0.85em;
    border: 1px solid var(--border);
    transition: all 0.2s;
}}
.nav a:hover {{ background: var(--nav-hover); color: #fff; border-color: var(--nav-hover); }}

/* ===== Stats Grid ===== */
.stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 30px; }}
.stat-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    transition: transform 0.2s, border-color 0.2s, background 0.3s;
    box-shadow: var(--shadow);
}}
.stat-card:hover {{ transform: translateY(-2px); border-color: var(--border-hover); }}
.stat-card .number {{ font-size: 2.2em; font-weight: 700; display: block; }}
.stat-card .label {{ color: var(--text-secondary); font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
.stat-card.blue .number {{ color: var(--accent-blue); }}
.stat-card.green .number {{ color: var(--accent-green); }}
.stat-card.yellow .number {{ color: var(--accent-yellow); }}
.stat-card.red .number {{ color: var(--accent-red); }}
.stat-card.purple .number {{ color: var(--accent-purple); }}

/* ===== Section Title ===== */
.section-title {{
    font-size: 1.3em;
    margin: 30px 0 16px;
    padding-left: 12px;
    border-left: 4px solid var(--accent-blue);
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-primary);
}}

/* ===== Chart Grid ===== */
.chart-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
.chart-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    transition: background 0.3s, border-color 0.3s;
    box-shadow: var(--shadow);
}}
.chart-card h3 {{ color: var(--text-primary); margin-bottom: 16px; font-size: 1em; }}
.chart-card canvas {{ max-height: 300px; }}
.two-col {{ display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 30px; }}

/* ===== Threat Cards ===== */
.threat-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
    border-left: 4px solid var(--border);
    transition: background 0.3s, border-color 0.3s;
}}
.threat-card.high {{ border-left-color: var(--accent-red); }}
.threat-card.medium {{ border-left-color: var(--accent-yellow); }}
.threat-card.low {{ border-left-color: var(--accent-green); }}
.threat-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }}
.threat-header .ip {{ font-family: 'SF Mono', Consolas, monospace; font-weight: 600; color: var(--accent-blue); }}
.threat-header .country {{ color: var(--text-secondary); }}
.badge {{ padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 500; }}
.badge.high {{ background: rgba(248,81,73,0.12); color: var(--accent-red); }}
.badge.medium {{ background: rgba(210,153,34,0.12); color: var(--accent-yellow); }}
.badge.low {{ background: rgba(35,134,54,0.12); color: var(--accent-green); }}
.threat-body {{ font-size: 0.9em; color: var(--text-secondary); }}
.threat-body .cmds {{ margin: 8px 0; font-family: 'SF Mono', Consolas, monospace; font-size: 0.85em; }}
.threat-body .cmds code {{
    background: var(--code-bg);
    padding: 2px 6px;
    border-radius: 4px;
    margin-right: 4px;
    color: var(--accent-orange);
}}
.threat-body .meta {{ font-size: 0.8em; color: var(--text-muted); }}
.empty-state {{ text-align: center; padding: 40px; color: var(--text-secondary); font-size: 1.1em; }}

/* ===== Cmd Categories ===== */
.cmd-cat {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 16px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 8px;
    transition: background 0.3s;
}}
.cmd-cat .cat-name {{ font-size: 0.95em; color: var(--text-primary); }}
.cmd-cat .cat-count {{ font-size: 1.2em; font-weight: 700; color: var(--accent-red); }}

/* ===== Footer ===== */
.footer {{
    text-align: center;
    padding: 20px;
    color: var(--text-muted);
    font-size: 0.85em;
    border-top: 1px solid var(--border);
    margin-top: 30px;
}}

/* ===== Responsive ===== */
@media (max-width: 1024px) {{
    .stats-grid {{ grid-template-columns: repeat(3, 1fr); }}
    .chart-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .two-col {{ grid-template-columns: 1fr; }}
    .theme-toggle {{ top: 10px; right: 10px; padding: 4px 10px; }}
}}
@media (max-width: 640px) {{
    .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .chart-grid {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>

<!-- 主题切换按钮 -->
<div class="theme-toggle" onclick="toggleTheme()" title="切换主题">
    <span class="icon" id="themeIcon">🌙</span>
    <span class="label" id="themeLabel">深色</span>
</div>

<div class="container">
<div class="header">
    <h1>🐝 SSH 蜜罐攻击分析面板</h1>
    <div class="subtitle">实时监控 · 数据更新于 {stats["last_update"]}</div>
</div>
<div class="nav">
    <a href="#overview">📊 概览</a>
    <a href="#geo">🌍 地理分布</a>
    <a href="#passwords">🔑 密码分析</a>
    <a href="#time">⏰ 时间分析</a>
    <a href="#interactive">🎯 交互式攻击</a>
    <a href="#scanners">🤖 扫描器</a>
    <a href="#commands">💻 命令分析</a>
</div>
<div id="overview" class="stats-grid">
    <div class="stat-card blue"><span class="number">{stats["total_attempts"]:,}</span><span class="label">登录尝试</span></div>
    <div class="stat-card green"><span class="number">{stats["unique_ips"]}</span><span class="label">独立 IP</span></div>
    <div class="stat-card yellow"><span class="number">{stats["scanner_count"]}</span><span class="label">扫描器/Bot</span></div>
    <div class="stat-card red"><span class="number">{stats["interactive_count"]}</span><span class="label">交互式攻击者</span></div>
    <div class="stat-card purple"><span class="number">{stats["total_commands"]}</span><span class="label">执行命令</span></div>
</div>
<div id="geo" class="section-title">🌍 地理分布 & 密码分析</div>
<div class="chart-grid">
    <div class="chart-card"><h3>🏳️ 攻击来源国家 Top 10</h3><canvas id="countryChart"></canvas></div>
    <div class="chart-card"><h3>🔑 最常用密码 Top 15</h3><canvas id="passwordChart"></canvas></div>
    <div class="chart-card"><h3>👤 最常用用户名 Top 10</h3><canvas id="usernameChart"></canvas></div>
</div>
<div id="time" class="section-title">⏰ 时间分析</div>
<div class="chart-grid">
    <div class="chart-card"><h3>🕐 24小时攻击分布</h3><canvas id="hourChart"></canvas></div>
    <div class="chart-card"><h3>📅 每日攻击趋势</h3><canvas id="dayChart"></canvas></div>
    <div class="chart-card" id="commands"><h3>💻 命令分类统计</h3><canvas id="cmdChart"></canvas></div>
</div>
<div id="interactive" class="section-title">🎯 交互式攻击者（登录后执行命令）</div>
<div class="two-col">
    <div>{interactive_html}</div>
    <div>
        <div class="chart-card"><h3>📊 攻击者类型分布</h3><canvas id="typeChart"></canvas></div>
        <div style="margin-top: 16px;">{cmd_cats_html}</div>
    </div>
</div>
<div id="scanners" class="section-title">🤖 活跃扫描器 Top 15</div>
{scanner_html}
<div class="footer">🐝 SSH Honeypot Dashboard · Powered by OpenClaw · {stats["last_update"]}</div>
</div>

<script>
/* ===== 主题切换 ===== */
function getChartColors() {{
    const t = document.documentElement.getAttribute('data-theme');
    if (t === 'light') return ['#0969da','#1a7f37','#bf8700','#cf222e','#8250df','#bc4c00','#0550ae','#116329','#6e5600','#a40e26','#6639ba','#953800'];
    return ['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff','#f0883e','#79c0ff','#56d364','#e3b341','#ff7b72','#d2a8ff','#ffa657'];
}}

function getGridColor() {{
    return document.documentElement.getAttribute('data-theme') === 'light' ? '#d0d7de' : '#21262d';
}}

function getTickColor() {{
    return document.documentElement.getAttribute('data-theme') === 'light' ? '#656d76' : '#8b949e';
}}

function getLegendColor() {{
    return document.documentElement.getAttribute('data-theme') === 'light' ? '#1f2328' : '#c9d1d9';
}}

function toggleTheme() {{
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    document.getElementById('themeIcon').textContent = next === 'dark' ? '🌙' : '☀️';
    document.getElementById('themeLabel').textContent = next === 'dark' ? '深色' : '浅色';
    updateChartColors();
}}

function updateChartColors() {{
    const cc = getChartColors();
    const gc = getGridColor();
    const tc = getTickColor();
    const lc = getLegendColor();

    // 更新所有图表
    window.allCharts.forEach(c => {{
        if (c.config.type === 'doughnut') {{
            c.data.datasets[0].backgroundColor = cc;
            c.options.plugins.legend.labels.color = lc;
        }} else if (c.config.type === 'bar') {{
            c.data.datasets[0].backgroundColor = cc[0] + '44';
            c.data.datasets[0].borderColor = cc[0];
            c.options.scales.x.ticks.color = tc;
            c.options.scales.x.grid.color = gc;
            if (c.options.scales.y) {{
                c.options.scales.y.ticks.color = tc;
                if (c.options.scales.y.grid.display !== false) c.options.scales.y.grid.color = gc;
            }}
            if (c.options.plugins.legend.labels) c.options.plugins.legend.labels.color = lc;
        }} else if (c.config.type === 'line') {{
            c.data.datasets[0].borderColor = cc[0];
            c.data.datasets[0].backgroundColor = cc[0] + '22';
            c.options.scales.x.ticks.color = tc;
            c.options.scales.x.grid.color = gc;
            c.options.scales.y.ticks.color = tc;
            c.options.scales.y.grid.color = gc;
        }}
        c.update();
    }});
}}

// 初始化主题
(function() {{
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    document.getElementById('themeIcon').textContent = saved === 'dark' ? '🌙' : '☀️';
    document.getElementById('themeLabel').textContent = saved === 'dark' ? '深色' : '浅色';
}})();

const cc = getChartColors();
const gc = getGridColor();
const tc = getTickColor();
const lc = getLegendColor();

window.allCharts = [];

window.allCharts.push(new Chart(document.getElementById('countryChart'), {{
    type: 'doughnut',
    data: {{ labels: {countries_json}, datasets: [{{ data: {json.dumps(country_values)}, backgroundColor: cc, borderWidth: 0 }}] }},
    options: {{ responsive: true, plugins: {{ legend: {{ position: 'right', labels: {{ color: lc, font: {{ size: 11 }} }} }} }} }}
}}));

window.allCharts.push(new Chart(document.getElementById('passwordChart'), {{
    type: 'bar',
    data: {{ labels: {passwords_json}, datasets: [{{ data: {json.dumps(password_values)}, backgroundColor: cc[0] + '44', borderColor: cc[0], borderWidth: 1 }}] }},
    options: {{ indexAxis: 'y', responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: tc }}, grid: {{ color: gc }} }}, y: {{ ticks: {{ color: lc, font: {{ family: 'monospace', size: 11 }} }}, grid: {{ display: false }} }} }} }}
}}));

window.allCharts.push(new Chart(document.getElementById('usernameChart'), {{
    type: 'bar',
    data: {{ labels: {usernames_json}, datasets: [{{ data: {json.dumps(username_values)}, backgroundColor: cc[1] + '44', borderColor: cc[1], borderWidth: 1 }}] }},
    options: {{ indexAxis: 'y', responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: tc }}, grid: {{ color: gc }} }}, y: {{ ticks: {{ color: lc, font: {{ family: 'monospace', size: 11 }} }}, grid: {{ display: false }} }} }} }}
}}));

window.allCharts.push(new Chart(document.getElementById('hourChart'), {{
    type: 'bar',
    data: {{ labels: {hours_json}, datasets: [{{ data: {json.dumps(hour_values)}, backgroundColor: cc[2] + '44', borderColor: cc[2], borderWidth: 1 }}] }},
    options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: tc }}, grid: {{ color: gc }} }}, y: {{ ticks: {{ color: tc }}, grid: {{ color: gc }} }} }} }}
}}));

window.allCharts.push(new Chart(document.getElementById('dayChart'), {{
    type: 'line',
    data: {{ labels: {days_json}, datasets: [{{ data: {json.dumps(day_values)}, borderColor: cc[0], backgroundColor: cc[0] + '22', fill: true, tension: 0.4 }}] }},
    options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: tc }}, grid: {{ color: gc }} }}, y: {{ ticks: {{ color: tc }}, grid: {{ color: gc }} }} }} }}
}}));

window.allCharts.push(new Chart(document.getElementById('cmdChart'), {{
    type: 'doughnut',
    data: {{ labels: {cmd_labels_json}, datasets: [{{ data: {json.dumps(list(stats["cmd_categories"].values()))}, backgroundColor: [cc[3],cc[2],cc[0],cc[1],cc[4],cc[5]], borderWidth: 0 }}] }},
    options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: lc, font: {{ size: 11 }} }} }} }} }}
}}));

window.allCharts.push(new Chart(document.getElementById('typeChart'), {{
    type: 'doughnut',
    data: {{ labels: ['🤖 扫描器/Bot', '🎯 交互式攻击者'], datasets: [{{ data: [{stats["scanner_count"]}, {stats["interactive_count"]}], backgroundColor: [cc[2], cc[3]], borderWidth: 0 }}] }},
    options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: lc }} }} }} }}
}}));
</script>
</body>
</html>'''
    return html


def ensure_geolite_db():
    """自动下载 GeoLite2-City.mmdb（如果不存在）"""
    if os.path.exists(GEOIP_DB):
        return True
    os.makedirs(os.path.dirname(GEOIP_DB) or ".", exist_ok=True)
    url = "https://git.io/GeoLite2-City.mmdb"
    print(f"⬇️  正在下载 GeoLite2-City.mmdb ...")
    try:
        urllib.request.urlretrieve(url, GEOIP_DB)
        print(f"✅ 下载完成: {GEOIP_DB}")
        return True
    except Exception as e:
        print(f"⚠️  GeoIP 数据库下载失败: {e}")
        print(f"   请手动下载并放到 {GEOIP_DB}")
        print(f"   下载地址: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        return False


try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False
    print("⚠️  geoip2 未安装，地理信息将不可用。运行: pip install geoip2")


def main():
    print("加载数据...")
    attempts = load_jsonl(ATTEMPTS_FILE)
    commands = load_jsonl(COMMANDS_FILE)
    print(f"登录: {len(attempts)} 条 | 命令: {len(commands)} 条")

    reader = None
    if HAS_GEOIP2:
        if ensure_geolite_db():
            reader = geoip2.database.Reader(GEOIP_DB)
            print("GeoIP 数据库已加载")
    else:
        print("⚠️ 跳过地理信息（geoip2 未安装）")

    print("分析中...")
    stats = analyze(attempts, commands, reader)

    print("生成报告...")
    html = generate_html(stats)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"✅ 报告已生成: {OUTPUT_FILE}")

    print(f"\n=== 摘要 ===")
    print(f"登录: {stats['total_attempts']} | IP: {stats['unique_ips']} | 命令: {stats['total_commands']}")
    print(f"扫描器: {stats['scanner_count']} | 交互式攻击者: {stats['interactive_count']}")
    print(f"Top密码: {list(stats['password_data'].items())[:5]}")
    print(f"Top国家: {list(stats['country_data'].items())[:5]}")

    if reader:
        reader.close()


if __name__ == "__main__":
    main()
