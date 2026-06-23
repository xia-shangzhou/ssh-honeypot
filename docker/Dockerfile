FROM python:3.11-slim

LABEL maintainer="SSH Honeypot"
LABEL description="SSH 蜜罐 - 记录暴力破解和攻击者行为"

WORKDIR /app

# 安装依赖
RUN pip install --no-cache-dir paramiko geoip2

# 复制文件
COPY honeypot.py .
COPY analyze.py .
COPY update-dashboard.sh .
COPY web/ web/

# 创建必要目录（keys 会在运行时自动生成）
RUN mkdir -p logs data keys

# 暴露端口
EXPOSE 2222 8088

# 启动脚本
COPY docker-entrypoint.sh .
RUN ["chmod", "+x", "docker-entrypoint.sh"]

ENTRYPOINT ["./docker-entrypoint.sh"]
