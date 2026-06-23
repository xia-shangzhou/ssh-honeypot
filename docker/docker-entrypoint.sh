#!/bin/bash
set -e

echo "🐝 SSH Honeypot starting..."

# 创建日志目录
mkdir -p /app/logs

# 启动蜜罐（后台）
echo "📡 Starting SSH honeypot on port ${SSH_PORT:-2222}..."
python3 honeypot.py &
HONEYPOT_PID=$!

# 启动 Web 面板（后台）
echo "🌐 Starting web dashboard on port ${WEB_PORT:-8088}..."
python3 -m http.server ${WEB_PORT:-8088} --directory web &
WEB_PID=$!

# 定时更新面板（每小时）
echo "⏰ Setting up hourly dashboard update..."
while true; do
    sleep 3600
    python3 analyze.py >> logs/analyze.log 2>&1
    echo "$(date) - Dashboard updated" >> logs/analyze.log
done &
CRON_PID=$!

# 等待信号
cleanup() {
    echo "🛑 Shutting down..."
    kill $HONEYPOT_PID $WEB_PID $CRON_PID 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT

echo "✅ Honeypot is running!"
echo "   SSH:     port ${SSH_PORT:-2222}"
echo "   Web UI:  http://localhost:${WEB_PORT:-8088}/dashboard.html"
echo "   Logs:    /app/logs/"

# 保持前台运行
wait
