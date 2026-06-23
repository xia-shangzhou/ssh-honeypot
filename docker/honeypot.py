#!/usr/bin/env python3
"""
SSH Interactive Honeypot v2 - 改进版
修复：认证后不进入 shell 的问题
改进：更真实的 shell 模拟、更多命令响应
"""

import socket
import threading
import paramiko
import datetime
import json
import os
import sys
import time
import select
import logging
import traceback

# 配置
HOST = "0.0.0.0"
PORT = 22
HOST_KEY_PATH = "keys/fake_host_key"
LOG_FILE = "/app/logs/attempts.jsonl"
CMD_LOG_FILE = "/app/logs/commands.jsonl"
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

# 设置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/honeypot.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 常见命令的假输出
FAKE_RESPONSES = {
    "whoami": "root\r\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "pwd": "/root\r\n",
    "hostname": "prod-server-01\r\n",
    "uname -a": "Linux prod-server-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\r\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\r\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n"
        "mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\r\n"
    ),
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied\r\n",
    "ifconfig": (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
        "        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255\r\n"
        "        inet6 fe80::215:5dff:fe8a:1000  prefixlen 64  scopeid 0x20<link>\r\n"
        "        ether 00:15:5d:8a:10:00  txqueuelen 1000  (Ethernet)\r\n"
        "        RX packets 1523456  bytes 1023456789 (1.0 GB)\r\n"
        "        TX packets 987654  bytes 876543210 (876.5 MB)\r\n\r\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 57344\r\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
    ),
    "ip addr": (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\r\n"
        "    inet 127.0.0.1/8 scope host lo\r\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\r\n"
        "    inet 10.0.0.15/24 brd 10.0.0.255 scope global eth0\r\n"
    ),
    "w": (
        " 22:30:01 up 45 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\r\n"
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n"
        "root     pts/0    10.0.0.1         22:30    0.00s  0.05s  0.00s w\r\n"
    ),
    "uptime": " 22:30:01 up 45 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\r\n",
    "last": (
        "root     pts/0        10.0.0.1         Wed Jun  4 22:30   still logged in\r\n"
        "root     pts/0        10.0.0.1         Tue Jun  3 08:15 - 18:30  (10:15)\r\n"
        "root     pts/1        192.168.1.100    Mon Jun  2 09:00 - 17:45  (08:45)\r\n"
    ),
    "ls": "Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos\r\n",
    "ls -la": (
        "total 56\r\n"
        "drwx------ 8 root root 4096 Jun  4 22:00 .\r\n"
        "drwxr-xr-x 3 root root 4096 May  1 06:55 ..\r\n"
        "-rw------- 1 root root  5823 Jun  4 22:30 .bash_history\r\n"
        "-rw-r--r-- 1 root root 3106 Oct 15  2021 .bashrc\r\n"
        "drwx------ 3 root root 4096 May  1 07:00 .cache\r\n"
        "drwx------ 3 root root 4096 May  1 07:00 .config\r\n"
        "drwx------ 3 root root 4096 May  1 07:00 .local\r\n"
        "-rw-r--r-- 1 root root  161 Jul  9  2019 .profile\r\n"
        "-rw------- 1 root root  128 May  1 07:00 .ssh\r\n"
        "drwx------ 2 root root 4096 Jun  4 22:00 Downloads\r\n"
    ),
    "ls /": (
        "bin   dev  home  lib32   lib64   lost+found  mnt  proc  run   snap  sys  usr\r\n"
        "boot  etc  lib   libx32  media   opt         root  sbin  srv   tmp  var\r\n"
    ),
    "cat /etc/hostname": "prod-server-01\r\n",
    "cat /etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\r\n'
        'NAME="Ubuntu"\r\n'
        'VERSION_ID="22.04"\r\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\r\n'
        'ID=ubuntu\r\n'
    ),
    "df -h": (
        "Filesystem      Size  Used Avail Use% Mounted on\r\n"
        "/dev/sda1       100G   45G   50G  48% /\r\n"
        "tmpfs           3.9G     0  3.9G   0% /dev/shm\r\n"
        "/dev/sdb1       500G  128G  345G  28% /data\r\n"
    ),
    "free -h": (
        "               total        used        free      shared  buff/cache   available\r\n"
        "Mem:           7.7Gi       2.1Gi       3.2Gi       256Mi       2.4Gi       5.1Gi\r\n"
        "Swap:          2.0Gi          0B       2.0Gi\r\n"
    ),
    "ps aux": (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
        "root         1  0.0  0.1 168936 11584 ?        Ss   May01   0:15 /sbin/init\r\n"
        "root       456  0.0  0.0  72308  4320 ?        Ss   May01   0:00 /usr/sbin/cron -f\r\n"
        "root       512  0.0  0.1 277604 15420 ?        Ssl  May01   1:23 /usr/sbin/rsyslogd\r\n"
        "mysql      834  0.2  2.5 1723456 204800 ?      Sl   May01  12:45 /usr/sbin/mysqld\r\n"
        "root      1024  0.0  0.0   8812  3456 pts/0    Ss   22:30   0:00 -bash\r\n"
        "root      1089  0.0  0.0  10612  3328 pts/0    R+   22:30   0:00 ps aux\r\n"
    ),
    "netstat -tlnp": (
        "Active Internet connections (only servers)\r\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program\r\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1024/sshd\r\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1156/nginx\r\n"
        "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      1156/nginx\r\n"
        "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      834/mysqld\r\n"
    ),
    "ss -tlnp": (
        "State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process\r\n"
        "LISTEN   0        128              0.0.0.0:22            0.0.0.0:*      users:(\"sshd\",pid=1024)\r\n"
        "LISTEN   0        511              0.0.0.0:80            0.0.0.0:*      users:(\"nginx\",pid=1156)\r\n"
        "LISTEN   0        511              0.0.0.0:443            0.0.0.0:*      users:(\"nginx\",pid=1156)\r\n"
        "LISTEN   0        70             127.0.0.1:3306          0.0.0.0:*      users:(\"mysqld\",pid=834)\r\n"
    ),
    "which python3": "/usr/bin/python3\r\n",
    "python3 --version": "Python 3.10.12\r\n",
    "which gcc": "/usr/bin/gcc\r\n",
    "curl --version": "curl 7.81.0 (x86_64-pc-linux-gnu) libcurl/7.81.0\r\n",
    "wget --version": "GNU Wget 1.21.2\r\n",
    "history": "    1  apt update\r\n    2  apt upgrade -y\r\n    3  systemctl status sshd\r\n    4  cat /var/log/auth.log\r\n    5  top\r\n",
    "cat ~/.bash_history": "apt update\r\napt upgrade -y\r\nsystemctl status sshd\r\ncat /var/log/auth.log\r\ntop\r\n",
    "env": (
        "SHELL=/bin/bash\r\n"
        "USER=root\r\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
        "HOME=/root\r\n"
        "LOGNAME=root\r\n"
        "LANG=en_US.UTF-8\r\n"
    ),
    "sudo su": "",
    "su": "",
    "exit": "logout\r\n",
    "logout": "logout\r\n",
    "clear": "\033[2J\033[H",
    "reboot": "Failed to reboot: Access denied\r\n",
    "shutdown": "Failed to shutdown: Access denied\r\n",
    "systemctl status sshd": (
        "● sshd.service - OpenSSH server daemon\r\n"
        "     Loaded: loaded (/lib/systemd/system/sshd.service; enabled)\r\n"
        "     Active: active (running) since Mon 2026-05-01 06:55:00 UTC; 1 month 3 days ago\r\n"
        "   Main PID: 1024 (sshd)\r\n"
        "     CGroup: /system.slice/sshd.service\r\n"
        "             └─1024 sshd: /usr/sbin/sshd\r\n"
    ),
    "nginx -v": "nginx version: nginx/1.18.0 (Ubuntu)\r\n",
    "mysql --version": "mysql  Ver 8.0.35-0ubuntu0.22.04.1\r\n",
    "find / -name '*.conf' -readable 2>/dev/null | head -20": (
        "/etc/ssh/sshd_config\r\n"
        "/etc/nginx/nginx.conf\r\n"
        "/etc/mysql/my.cnf\r\n"
        "/etc/redis/redis.conf\r\n"
        "/etc/supervisor/supervisord.conf\r\n"
    ),
    "cat /etc/ssh/sshd_config": (
        "#       $OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tedu Exp $\r\n"
        "Port 22\r\n"
        "PermitRootLogin yes\r\n"
        "PasswordAuthentication yes\r\n"
        "ChallengeResponseAuthentication no\r\n"
        "UsePAM yes\r\n"
        "X11Forwarding yes\r\n"
        "PrintMotd no\r\n"
        "AcceptEnv LANG LC_*\r\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\r\n"
    ),
    "uname -r": "5.15.0-91-generic\r\n",
    "arch": "x86_64\r\n",
    "nproc": "4\r\n",
    "top -bn1 | head -5": (
        "top - 22:30:01 up 45 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\r\n"
        "Tasks: 187 total,   1 running, 186 sleeping,   0 stopped,   0 zombie\r\n"
        "%Cpu(s):  1.2 us,  0.5 sy,  0.0 ni, 98.0 id,  0.3 wa,  0.0 hi,  0.0 si\r\n"
        "MiB Mem :   7892.5 total,   3276.8 free,   2150.4 used,   2465.3 buff/cache\r\n"
        "MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   5421.7 avail Mem\r\n"
    ),
    "cat /proc/cpuinfo | head -20": (
        "processor\t: 0\r\n"
        "vendor_id\t: GenuineIntel\r\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\r\n"
        "cpu MHz\t\t: 2397.222\r\n"
        "cache size\t: 35840 KB\r\n"
        "cpu cores\t: 4\r\n"
    ),
    "ip route": "default via 10.0.0.1 dev eth0 proto dhcp metric 100\r\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.15\r\n",
    "cat /etc/resolv.conf": "nameserver 8.8.8.8\r\nnameserver 8.8.4.4\r\n",
    "iptables -L -n 2>/dev/null | head -15": (
        "Chain INPUT (policy ACCEPT)\r\n"
        "target     prot opt source               destination\r\n"
        "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED\r\n"
        "ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22\r\n"
        "ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80\r\n"
        "ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443\r\n"
    ),
    "who": "root     pts/0        2026-06-04 22:30 (10.0.0.1)\r\n",
    "date": datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y\r\n"),
    "cal": "     June 2026\r\nSu Mo Tu We Th Fr Sa\r\n    1  2  3  4  5  6\r\n 7  8  9 10 11 12 13\r\n14 15 16 17 18 19 20\r\n21 22 23 24 25 26 27\r\n28 29 30\r\n",
    "wget": "",
    "curl": "",
}

# 默认提示符
PROMPT = "root@prod-server-01:~# "


class InteractiveHoneypot(paramiko.ServerInterface):
    """交互式 SSH 蜜罐 - 模拟成功登录并记录命令"""

    def __init__(self, client_addr):
        self.client_addr = client_addr
        self.event = threading.Event()
        self.username = None
        self.shell_requested = False
        self.pty_requested = False

    def check_channel_request(self, kind, chanid):
        logger.debug(f"[{self.client_addr[0]}] channel request: {kind}")
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        self.username = username
        return "password,publickey"

    def check_auth_password(self, username, password):
        """接受所有密码 - 模拟成功登录"""
        logger.info(f"[{self.client_addr[0]}] AUTH SUCCESS: {username}:{password}")
        self._log_attempt(username, password, "password")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        fingerprint = key.get_fingerprint().hex()
        self._log_attempt(username, f"[publickey:{fingerprint}]", "publickey")
        return paramiko.AUTH_FAILED

    def _log_attempt(self, username, password, auth_type):
        """记录登录尝试"""
        attempt = {
            "timestamp": datetime.datetime.now().isoformat(),
            "ip": self.client_addr[0],
            "port": self.client_addr[1],
            "username": username,
            "password": password,
            "auth_type": auth_type,
        }
        logger.info(f"LOGIN: {self.client_addr[0]} user={username} pass={password} type={auth_type}")
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(attempt, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"Failed to write log: {e}")

    def check_channel_shell_request(self, channel):
        """客户端请求 shell"""
        logger.info(f"[{self.client_addr[0]}] SHELL REQUESTED!")
        self.shell_requested = True
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """客户端请求 PTY"""
        logger.info(f"[{self.client_addr[0]}] PTY REQUESTED: term={term}, {width}x{height}")
        self.pty_requested = True
        return True

    def check_channel_exec_request(self, channel, command):
        """客户端直接执行命令（非交互式）"""
        logger.info(f"[{self.client_addr[0]}] EXEC REQUEST: {command}")
        cmd_str = command.decode("utf-8", errors="replace") if isinstance(command, bytes) else str(command)
        log_command(self.client_addr, self.username or "root", cmd_str)
        return True

    def check_channel_env_request(self, channel, name, value):
        return True


def log_command(client_addr, username, command):
    """记录命令到日志"""
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": client_addr[0],
        "username": username,
        "command": command,
    }
    logger.info(f"CMD: {client_addr[0]} user={username} cmd={command}")
    try:
        with open(CMD_LOG_FILE, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"Failed to write cmd log: {e}")


def get_fake_response(cmd):
    """获取命令的假输出"""
    cmd = cmd.strip()
    if not cmd:
        return ""

    # 精确匹配
    if cmd in FAKE_RESPONSES:
        return FAKE_RESPONSES[cmd]

    # 前缀匹配（处理带参数的命令）
    for key in FAKE_RESPONSES:
        if cmd.startswith(key):
            return FAKE_RESPONSES[key]

    # cat 任意文件
    if cmd.startswith("cat "):
        return f"cat: {cmd[4:]}: No such file or directory\r\n"

    # echo 命令 - 回显内容
    if cmd.startswith("echo "):
        content = cmd[5:].strip().strip("'\"")
        return content + "\r\n"

    # cd 不产生输出
    if cmd.startswith("cd "):
        return ""

    # wget/curl - 模拟下载成功
    if cmd.startswith("wget ") or cmd.startswith("curl "):
        return ""

    # 未知命令
    return f"-bash: {cmd.split()[0]}: command not found\r\n"


def handle_interactive_session(transport, client_addr, username):
    """处理交互式 shell 会话 - 改进版"""
    channel = None
    try:
        # 等待客户端打开 channel
        logger.debug(f"[{client_addr[0]}] Waiting for channel open...")
        channel = transport.accept(30)
        if channel is None:
            logger.warning(f"[{client_addr[0]}] No channel opened within 30s")
            # 尝试接受一个额外的 channel
            try:
                channel = transport.accept(5)
            except:
                pass
            if channel is None:
                logger.warning(f"[{client_addr[0]}] Still no channel, giving up")
                return

        logger.info(f"[{client_addr[0]}] Channel opened, waiting for shell request...")

        # 等待 shell/pty 请求（最多 10 秒）
        server = InteractiveHoneypot(client_addr)
        wait_start = time.time()
        while time.time() - wait_start < 10:
            if server.shell_requested:
                break
            # 也接受可能的新 channel
            try:
                new_chan = transport.accept(0.5)
                if new_chan is not None:
                    channel = new_chan
            except:
                pass
            time.sleep(0.1)

        if not server.shell_requested:
            logger.info(f"[{client_addr[0]}] No shell request after 10s, trying to send anyway")

        logger.info(f"[{client_addr[0]}] Sending MOTD and prompt...")

        # 发送欢迎消息（模拟 MOTD）
        welcome = (
            "\r\n"
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
            "\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n"
            "\r\n"
            "Last login: {last_login}\r\n"
            "\r\n"
        ).format(
            last_login=datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y") + " from " + client_addr[0]
        )

        try:
            channel.send(welcome.encode())
        except Exception as e:
            logger.warning(f"[{client_addr[0]}] Failed to send welcome: {e}")
            return

        # 发送初始提示符
        try:
            channel.send(PROMPT.encode())
        except Exception as e:
            logger.warning(f"[{client_addr[0]}] Failed to send prompt: {e}")
            return

        logger.info(f"[{client_addr[0]}] Entering interactive loop...")

        # 进入交互循环
        command_buffer = ""
        while True:
            try:
                # 检查通道是否仍然打开
                if channel.closed:
                    logger.info(f"[{client_addr[0]}] Channel closed")
                    break

                # 使用 select 等待数据
                ready = select.select([channel], [], [], 60)
                if ready[0]:
                    data = channel.recv(4096)
                    if not data:
                        logger.info(f"[{client_addr[0]}] No data (EOF)")
                        break

                    text = data.decode("utf-8", errors="replace")
                    logger.debug(f"[{client_addr[0]}] Received {len(data)} bytes: {repr(text[:100])}")

                    for char in text:
                        if char in ('\r', '\n'):
                            # 回车 - 处理命令
                            try:
                                channel.send(b"\r\n")
                            except:
                                break

                            cmd = command_buffer.strip()
                            if cmd:
                                log_command(client_addr, username, cmd)

                                if cmd in ('exit', 'logout'):
                                    try:
                                        channel.send(b"logout\r\n")
                                        channel.close()
                                    except:
                                        pass
                                    return

                                response = get_fake_response(cmd)
                                if response:
                                    try:
                                        channel.send(response.encode())
                                    except:
                                        break

                            command_buffer = ""
                            try:
                                channel.send(PROMPT.encode())
                            except:
                                break

                        elif char == '\x7f' or char == '\x08':
                            # 退格
                            if command_buffer:
                                command_buffer = command_buffer[:-1]
                                try:
                                    channel.send(b'\b \b')
                                except:
                                    break

                        elif char == '\x03':
                            # Ctrl+C
                            try:
                                channel.send(b"^C\r\n")
                                channel.send(PROMPT.encode())
                            except:
                                break
                            command_buffer = ""

                        elif char == '\x04':
                            # Ctrl+D
                            try:
                                channel.send(b"logout\r\n")
                                channel.close()
                            except:
                                pass
                            return

                        elif char == '\x1b':
                            # 忽略转义序列（方向键等）
                            pass

                        elif ord(char) >= 32:
                            # 普通字符
                            command_buffer += char
                            try:
                                channel.send(char.encode())
                            except:
                                break

                else:
                    # 超时 - 检查是否还活着
                    if channel.closed:
                        break
                    # 发送 keepalive
                    try:
                        channel.send(b"")
                    except:
                        break

            except Exception as e:
                logger.debug(f"[{client_addr[0]}] Session error: {e}")
                break

    except Exception as e:
        logger.debug(f"[{client_addr[0]}] Session handler error: {e}")
        logger.debug(traceback.format_exc())
    finally:
        if channel and not channel.closed:
            try:
                channel.close()
            except:
                pass
        logger.info(f"[{client_addr[0]}] Session ended")


def handle_client(client_sock, client_addr):
    """处理单个连接"""
    logger.info(f"Connection from {client_addr[0]}:{client_addr[1]}")
    transport = None

    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = BANNER

        host_key = paramiko.RSAKey.from_private_key_file(HOST_KEY_PATH)
        transport.add_server_key(host_key)

        server = InteractiveHoneypot(client_addr)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            logger.warning(f"SSH negotiation failed from {client_addr[0]}: {e}")
            return

        # 处理多个可能的 channel
        while transport.is_active():
            handle_interactive_session(transport, client_addr, server.username or "root")
            # 检查是否还有活跃的 channel
            if not transport.is_active():
                break
            # 给客户端一点时间打开新 channel
            time.sleep(0.5)

    except Exception as e:
        logger.debug(f"Error handling {client_addr[0]}: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except:
                pass
        try:
            client_sock.close()
        except:
            pass


def main():
    """启动蜜罐"""
    if not os.path.exists(HOST_KEY_PATH):
        logger.error(f"Host key not found: {HOST_KEY_PATH}")
        sys.exit(1)

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(CMD_LOG_FILE), exist_ok=True)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.settimeout(60)

    try:
        server_sock.bind((HOST, PORT))
        server_sock.listen(100)
        logger.info(f"Interactive SSH Honeypot v2 listening on {HOST}:{PORT}")
        logger.info(f"Auth log: {LOG_FILE}")
        logger.info(f"Command log: {CMD_LOG_FILE}")

        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                t = threading.Thread(
                    target=handle_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Accept error: {e}")
                continue
    finally:
        server_sock.close()
        logger.info("Honeypot stopped.")


if __name__ == "__main__":
    main()
