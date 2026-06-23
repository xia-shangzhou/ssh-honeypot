#!/bin/bash
# 更新 SSH 攻击分析仪表盘
cd "$(dirname "$0")"
python3 analyze.py >> logs/analyze.log 2>&1
echo "Dashboard updated: $(date)" >> logs/analyze.log
