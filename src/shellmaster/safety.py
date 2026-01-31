"""
ShellMaster 安全模块 v2.0
- 分类白名单（无条件允许 / 有限制 / 组合使用）
- 增强的黑名单检测
- 更完善的命令解析
"""

import re
from typing import Set, Dict, List, Optional

# =============================================================================
# 1. 分类白名单
# =============================================================================

# 1.1 无条件允许的命令（只读操作）
UNCONDITIONAL_ALLOW: Set[str] = {
    # 基础文件操作
    "ls", "cat", "pwd", "echo", "printf", "test", "[",
    "tail", "head", "wc", "whoami", "id", "uname", "hostname",
    "stat", "readlink", "basename", "dirname", "realpath",
    "file", "tree", "md5sum", "sha256sum", "sha1sum",
    
    # 文本处理（只读）
    "sort", "uniq", "cut", "tr", "nl", "tac", "rev",
    "grep", "egrep", "fgrep", "zgrep",
    "diff", "comm", "join", "paste", "expand", "unexpand",
    "column", "fold", "fmt",
    
    # 分页查看
    "less", "more",
    
    # 环境/变量
    "env", "printenv", "locale", "set",
    
    # 磁盘/文件系统（只读）
    "df", "du", "lsblk", "mount", "findmnt", "blkid",
    "find", "locate", "which", "whereis", "type", "command",
    
    # 进程/系统（只读）
    "ps", "pgrep", "pidof", "top", "htop", "free", "uptime", "vmstat",
    "mpstat", "iostat", "sar", "nproc", "getconf",
    "lsof", "fuser",
    
    # 系统信息
    "lscpu", "lsmem", "lspci", "lsusb", "lshw", "dmidecode",
    "uname", "hostnamectl", "timedatectl", "localectl",
    "cat /proc/cpuinfo", "cat /proc/meminfo",
    
    # 时间相关
    "date", "cal", "uptime", "timedatectl",
    
    # 用户/登录信息（只读）
    "w", "who", "users", "last", "lastlog", "finger", "pinky",
    "groups", "getent",
    
    # 服务状态（只读）
    "systemctl status", "systemctl is-active", "systemctl is-enabled",
    "systemctl list-units", "systemctl list-unit-files",
    "systemctl show", "systemctl cat",
    "service", "chkconfig",
    "journalctl", "dmesg",
    
    # 网络诊断（只读）
    "ip", "ifconfig", "ss", "netstat", "ping", "ping6",
    "dig", "nslookup", "host", "resolvectl",
    "traceroute", "tracepath", "mtr",
    "arp", "route", "routel",
    "curl", "wget",  # 有额外限制，见下方
    
    # 软件包查询（只读）
    "dpkg", "dpkg-query", "apt list", "apt show", "apt-cache", "apt-mark",
    "rpm", "yum list", "yum info", "dnf list", "dnf info",
    "pip list", "pip show", "pip freeze",
    "pip3 list", "pip3 show", "pip3 freeze",
    "conda list", "conda info",
    "snap list", "snap info",
    "flatpak list", "flatpak info",
    "npm list", "npm view",
    "gem list", "gem info",
    
    # 容器（只读）
    "docker ps", "docker images", "docker logs", "docker inspect",
    "docker stats", "docker top", "docker port", "docker diff",
    "docker history", "docker version", "docker info",
    "docker-compose ps", "docker-compose logs", "docker-compose config",
    "podman ps", "podman images", "podman logs", "podman inspect",
    
    # Git（只读）
    "git status", "git log", "git diff", "git branch", "git remote",
    "git show", "git ls-files", "git ls-tree", "git rev-parse",
    "git config --list", "git config --get",
    
    # 权限查看（只读）
    "getfacl", "getcap", "lsattr",
    "namei", "stat",
    
    # GUI/显示（只读）
    "nvidia-smi", "xhost", "xrandr", "xdpyinfo", "xwininfo",
    "loginctl", "w",
    
    # 其他工具
    "jq", "yq", "bc", "expr", "seq", "yes", "true", "false",
    "sleep",  # 有时间限制
    "timeout",
    "tee",  # 有限制
    "xargs",  # 有限制
}

# 1.2 有限制的命令（需要额外检查参数）
RESTRICTED_COMMANDS: Dict[str, Dict] = {
    "sed": {
        "forbidden_args": ["-i", "--in-place"],
        "description": "禁止原地编辑"
    },
    "awk": {
        "forbidden_patterns": [r"system\s*\(", r"print\s*>", r"getline\s*<"],
        "description": "禁止执行系统命令和文件操作"
    },
    "perl": {
        "forbidden_args": ["-i", "-e.*unlink", "-e.*system"],
        "description": "禁止原地编辑和系统调用"
    },
    "curl": {
        "forbidden_args": ["-o", "-O", "--output", "-T", "--upload-file", "-X POST", "-X PUT", "-X DELETE"],
        "allowed_args": ["-I", "-s", "-S", "-L", "-v", "--head", "-H"],
        "description": "只允许 GET/HEAD 请求"
    },
    "wget": {
        "forbidden_args": ["--post-data", "--post-file", "--method"],
        "allowed_args": ["--spider", "-q", "-S", "--server-response"],
        "description": "只允许查询，不允许下载"
    },
    "tee": {
        "allowed_targets": ["/dev/null", "/dev/stdout", "/dev/stderr", "-"],
        "description": "只允许输出到标准流"
    },
    "sleep": {
        "max_seconds": 10,
        "description": "最长等待 10 秒"
    },
}

# 1.3 只能在管道中组合使用的命令
COMBO_ONLY_COMMANDS: Set[str] = {
    "xargs",
    "parallel",
}

# =============================================================================
# 2. 黑名单（绝对禁止）
# =============================================================================

# 2.1 危险命令关键词（词边界匹配）
DANGEROUS_COMMANDS: Set[str] = {
    # 文件破坏
    "rm", "rmdir", "shred", "truncate",
    # 文件修改
    "mv", "cp",  # 可能覆盖
    "chmod", "chown", "chgrp", "chattr",
    # 磁盘/分区
    "dd", "mkfs", "fdisk", "parted", "gdisk",
    "mkswap", "swapon", "swapoff",
    "mount", "umount",  # mount 查看允许，但挂载操作禁止
    # 系统控制
    "reboot", "shutdown", "poweroff", "halt", "init",
    "systemctl start", "systemctl stop", "systemctl restart",
    "systemctl enable", "systemctl disable",
    "service start", "service stop", "service restart",
    # 用户管理
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
    "passwd", "chpasswd", "newusers",
    # 网络修改
    "iptables", "ip6tables", "nft", "ufw",
    "ip link set", "ip addr add", "ip addr del", "ip route add", "ip route del",
    "ifconfig.*up", "ifconfig.*down",
    # 包管理（安装/删除）
    "apt install", "apt remove", "apt purge", "apt autoremove",
    "apt-get install", "apt-get remove", "apt-get purge",
    "yum install", "yum remove", "yum erase",
    "dnf install", "dnf remove", "dnf erase",
    "pip install", "pip uninstall", "pip3 install", "pip3 uninstall",
    "npm install", "npm uninstall",
    # 容器修改
    "docker run", "docker exec", "docker rm", "docker rmi",
    "docker stop", "docker kill", "docker start",
    "docker-compose up", "docker-compose down", "docker-compose rm",
    # 其他危险
    "kill", "killall", "pkill",
    "crontab", "at",
    "eval", "exec",
    "nc", "ncat", "netcat",  # 可用于反弹 shell
    "ssh", "scp", "rsync",  # 远程操作
}

# 2.2 危险字符/模式
DANGEROUS_PATTERNS: List[str] = [
    r"`",                    # 命令替换
    r"\$\(",                 # 命令替换
    r"\$\{.*:-.*\}",         # 参数扩展中的命令
    r"<\(",                  # 进程替换
    r">\(",                  # 进程替换
    r">\s*[^|&]",            # 重定向到文件（允许 2>&1）
    r">>\s*",                # 追加重定向
    r"<\s*[^<]",             # 输入重定向
    r"\|\|",                 # OR 逻辑（可绕过错误）
    r"(?<!&)&(?!&)",         # 后台执行（允许 &&）
    r";\s*",                 # 命令分隔（使用 && 替代）
    r"\n",                   # 换行
    r"\r",                   # 回车
    r"\\x[0-9a-fA-F]{2}",    # 十六进制转义
    r"\\u[0-9a-fA-F]{4}",    # Unicode 转义
]

# =============================================================================
# 3. 验证函数
# =============================================================================

def _get_base_command(cmd: str) -> str:
    """提取命令的基础部分（去除 sudo 和路径）"""
    cmd = cmd.strip()
    
    # 去除 sudo
    if cmd.startswith("sudo "):
        cmd = cmd[5:].strip()
    
    # 提取第一个词
    parts = cmd.split()
    if not parts:
        return ""
    
    first_word = parts[0]
    
    # 去除路径前缀
    if "/" in first_word:
        first_word = first_word.split("/")[-1]
    
    return first_word


def _check_restricted_command(cmd: str, base_cmd: str) -> bool:
    """检查有限制的命令是否符合规则"""
    if base_cmd not in RESTRICTED_COMMANDS:
        return True
    
    rules = RESTRICTED_COMMANDS[base_cmd]
    
    # 检查禁止的参数
    if "forbidden_args" in rules:
        for forbidden in rules["forbidden_args"]:
            if forbidden in cmd:
                return False
    
    # 检查禁止的模式
    if "forbidden_patterns" in rules:
        for pattern in rules["forbidden_patterns"]:
            if re.search(pattern, cmd):
                return False
    
    # 特殊处理：sleep 时间限制
    if base_cmd == "sleep" and "max_seconds" in rules:
        match = re.search(r"sleep\s+(\d+)", cmd)
        if match and int(match.group(1)) > rules["max_seconds"]:
            return False
    
    # 特殊处理：tee 目标限制
    if base_cmd == "tee" and "allowed_targets" in rules:
        # 简单检查：tee 后面的参数应该在允许列表中
        parts = cmd.split()
        if len(parts) > 1:
            for i, p in enumerate(parts):
                if p == "tee" and i + 1 < len(parts):
                    target = parts[i + 1]
                    if target not in rules["allowed_targets"] and not target.startswith("-"):
                        return False
    
    return True


def _is_allowed_subcmd(sub: str) -> bool:
    """检查单个子命令是否允许"""
    sub = sub.strip()
    if not sub:
        return False
    
    # 允许 sudo + 白名单命令
    original_sub = sub
    if sub.startswith("sudo "):
        sub = sub[5:].strip()
    
    # 允许纯赋值（无空格，无危险字符）
    if "=" in sub and " " not in sub:
        if any(x in sub for x in ["`", "$(", "\n", "\r", ";"]):
            return False
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", sub):
            return True
    
    base_cmd = _get_base_command(sub)
    if not base_cmd:
        return False
    
    # 检查是否在无条件允许列表
    # 先检查完整匹配，再检查前缀匹配
    for allowed in UNCONDITIONAL_ALLOW:
        # 完整命令匹配（如 "systemctl status"）
        if " " in allowed:
            if sub == allowed or sub.startswith(allowed + " "):
                return True
        # 单命令匹配
        elif base_cmd == allowed:
            # 检查是否有限制
            if base_cmd in RESTRICTED_COMMANDS:
                if not _check_restricted_command(original_sub, base_cmd):
                    return False
            return True
    
    return False


def _check_dangerous_patterns(cmd: str) -> bool:
    """检查是否包含危险模式，返回 True 表示安全"""
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd):
            return False
    return True


def _check_dangerous_commands(cmd: str) -> bool:
    """检查是否包含危险命令，返回 True 表示安全"""
    cmd_lower = cmd.lower()
    
    for dangerous in DANGEROUS_COMMANDS:
        # 词边界匹配
        if " " in dangerous:
            # 多词命令（如 "systemctl start"）
            if dangerous in cmd_lower:
                return False
        else:
            # 单词命令
            if re.search(rf"\b{re.escape(dangerous)}\b", cmd_lower):
                return False
    
    return True


def is_safe_scout_cmd(cmd: str) -> bool:
    """
    检查命令是否安全（用于侦察阶段）
    
    安全规则：
    1. 不包含危险模式（命令替换、重定向等）
    2. 不包含危险命令
    3. 所有子命令都在白名单中
    
    Returns:
        bool: True 表示命令安全，可以执行
    """
    cmd = cmd.strip()
    if not cmd:
        return False
    
    # Step 1: 检查危险模式
    if not _check_dangerous_patterns(cmd):
        return False
    
    # Step 2: 检查危险命令
    if not _check_dangerous_commands(cmd):
        return False
    
    # Step 3: 拆分管道和 && 检查每个子命令
    # 注意：; 和 || 已经在危险模式中被禁止
    parts = re.split(r"\s*\|\s*|\s*&&\s*", cmd)
    
    for i, sub in enumerate(parts):
        sub = sub.strip()
        if not sub:
            continue
        
        # xargs 只能在管道后使用
        base = _get_base_command(sub)
        if base in COMBO_ONLY_COMMANDS:
            if i == 0:  # 第一个命令
                return False
        
        if not _is_allowed_subcmd(sub):
            return False
    
    return True


def get_safety_reason(cmd: str) -> Optional[str]:
    """
    获取命令被拒绝的原因（用于调试和用户反馈）
    
    Returns:
        str: 拒绝原因，如果命令安全则返回 None
    """
    cmd = cmd.strip()
    if not cmd:
        return "空命令"
    
    # 检查危险模式
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd):
            return f"包含危险模式: {pattern}"
    
    # 检查危险命令
    for dangerous in DANGEROUS_COMMANDS:
        if " " in dangerous:
            if dangerous in cmd.lower():
                return f"包含危险命令: {dangerous}"
        else:
            if re.search(rf"\b{re.escape(dangerous)}\b", cmd.lower()):
                return f"包含危险命令: {dangerous}"
    
    # 检查子命令
    parts = re.split(r"\s*\|\s*|\s*&&\s*", cmd)
    for sub in parts:
        sub = sub.strip()
        if sub and not _is_allowed_subcmd(sub):
            base = _get_base_command(sub)
            return f"命令不在白名单中: {base}"
    
    return None


# =============================================================================
# 4. 工具函数
# =============================================================================

def list_allowed_commands() -> List[str]:
    """列出所有允许的命令（用于帮助和文档）"""
    commands = sorted(UNCONDITIONAL_ALLOW)
    commands.extend([f"{cmd} (有限制)" for cmd in sorted(RESTRICTED_COMMANDS.keys())])
    return commands


def validate_command_batch(commands: List[str]) -> List[Dict]:
    """
    批量验证命令
    
    Returns:
        List[Dict]: 每个命令的验证结果
    """
    results = []
    for cmd in commands:
        is_safe = is_safe_scout_cmd(cmd)
        results.append({
            "command": cmd,
            "safe": is_safe,
            "reason": None if is_safe else get_safety_reason(cmd)
        })
    return results