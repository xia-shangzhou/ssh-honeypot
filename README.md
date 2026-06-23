# 🐝 SSH Honeypot

一个交互式 SSH 蜜罐系统，模拟真实的 Ubuntu SSH 服务器，自动记录暴力破解尝试和攻击者执行的命令，并生成可视化分析面板。

![Dashboard Preview](docs/dashboard-preview.png)

## ✨ 功能特性

- **交互式 Shell 模拟** — 攻击者登录后获得假 Shell，所有命令被记录
- **智能分类** — 自动区分扫描器/Bot 和真正的交互式攻击者
- **可视化面板** — 攻击来源地图、密码统计、时间趋势、命令分类
- **GeoIP 定位** — 自动下载 GeoLite2 数据库，定位攻击来源国家/城市
- **一键部署** — Docker Compose 开箱即用
- **低资源占用** — 内存 ~60MB，CPU < 0.1%

## 📊 面板预览

面板包含以下分析模块：
- 📈 概览统计（登录次数、独立 IP、扫描器、交互式攻击者）
- 🗺️ 攻击来源世界地图（ECharts 渲染）
- ⚡ 攻击 IP TOP 15
- 🔑 最常用密码 / 用户名 TOP 10
- 📅 每日攻击趋势
- ⏰ 24 小时攻击分布
- 💻 命令分类统计
- 🏆 交互式攻击者详情（含执行的命令）

## 🚀 快速开始

### 方式一：Docker Compose（推荐）

```bash
git clone https://github.com/yourname/ssh-honeypot.git
cd ssh-honeypot/docker

# 启动
docker compose up -d

# 查看日志
docker compose logs -f
```

访问面板：`http://localhost:8088/dashboard.html`

> 首次启动会自动下载 GeoLite2-City.mmdb（~65MB），用于 IP 地理定位。

### 方式二：手动安装

```bash
# 1. 克隆项目
git clone https://github.com/yourname/ssh-honeypot.git
cd ssh-honeypot

# 2. 安装依赖
pip install paramiko geoip2

# 3. 启动蜜罐（默认端口 22，可通过 SSH_PORT 环境变量修改）
python3 honeypot.py &

# 4. 启动面板
python3 -m http.server 8088 --directory web &

# 5. 手动更新面板
python3 analyze.py
```

### 方式三：系统服务

```bash
# 复制 service 文件
sudo cp deploy/ssh-honeypot.service /etc/systemd/system/
sudo cp deploy/ssh-dashboard.service /etc/systemd/system/

# 启用并启动
sudo systemctl enable --now ssh-honeypot ssh-dashboard
```

## ⚙️ 配置

所有配置通过环境变量控制：

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `SSH_PORT` | `22` | 蜜罐监听端口 |
| `WEB_PORT` | `8088` | Web 面板端口 |
| `HONEYPOT_LOG_DIR` | `./logs` | 日志目录 |
| `HONEYPOT_HOST_KEY` | `./keys/fake_host_key` | SSH 主机密钥路径 |
| `HONEYPOT_GEOIP_DB` | `./data/GeoLite2-City.mmdb` | GeoIP 数据库路径 |
| `HONEYPOT_BANNER` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | SSH Banner |
| `HONEYPOT_EXCLUDE_IPS` | `127.0.0.1,::1` | 分析时排除的 IP（逗号分隔） |

Docker 部署时在 `docker-compose.yml` 或 `.env` 文件中设置。

## 📁 项目结构

```
ssh-honeypot/
├── honeypot.py              # 蜜罐主程序
├── analyze.py               # 分析脚本（生成 Dashboard）
├── update-dashboard.sh      # 定时更新脚本
├── web/
│   ├── dashboard.html       # 可视化面板（首次运行后生成）
│   └── world.json           # ECharts 世界地图数据
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── docker-entrypoint.sh
│   ├── honeypot.py          # Docker 版本（路径适配）
│   ├── analyze.py           # Docker 版本
│   └── web/
├── keys/                    # SSH 主机密钥（自动生成，不提交）
├── logs/                    # 日志文件（不提交）
├── data/                    # GeoIP 数据库（自动下载，不提交）
├── .gitignore
├── LICENSE
└── README.md
```

## 📝 数据格式

### 登录记录 (logs/attempts.jsonl)

```json
{
  "timestamp": "2026-06-04T22:54:51.100224",
  "ip": "193.32.162.13",
  "port": 57216,
  "username": "root",
  "password": "123456",
  "auth_type": "password"
}
```

### 命令记录 (logs/commands.jsonl)

```json
{
  "timestamp": "2026-06-05T12:01:57.189831",
  "ip": "193.32.162.13",
  "username": "root",
  "command": "uname -s -v -n -r -m"
}
```

## 🔧 自定义

### 修改假命令响应

编辑 `honeypot.py` 中的 `FAKE_RESPONSES` 字典：

```python
FAKE_RESPONSES = {
    "uname -s -v -n -r -m": "Linux 5.15.0-94-generic ... x86_64",
    "whoami": "root",
    # 添加更多...
}
```

### 修改分析逻辑

编辑 `analyze.py` 中的 `classify_attackers()` 和 `analyze()` 函数。

## 📦 资源占用

| 资源 | Docker | 裸机 |
|------|--------|------|
| 内存 | ~60MB | ~60MB |
| CPU | < 0.1% | < 0.1% |
| 磁盘 | ~258MB（镜像） | ~65MB |
| 日志增长 | ~1MB/天 | ~1MB/天 |

## 🛡️ 安全提示

- 蜜罐端口不要映射到真实的 22 端口，除非你完全理解风险
- 日志文件包含攻击者 IP 和密码，不要公开
- GeoLite2 数据库受 MaxMind 许可证约束，本项目不直接分发
- 面板默认无认证，建议通过反向代理 + Basic Auth 保护

## 📄 License

[MIT](LICENSE)

## 🙏 致谢

- [Paramiko](https://www.paramiko.org/) — SSH 协议库
- [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) — MaxMind IP 地理定位
- [ECharts](https://echarts.apache.org/) — 可视化图表库
- [Chart.js](https://www.chartjs.org/) — 轻量图表库
