import re
import shlex
from typing import Dict, List, Optional, Any
from enum import IntEnum

# =============================================================================
# 1. 枚举定义
# =============================================================================

class TaskComplexity(IntEnum):
    """任务复杂度级别"""
    TRIVIAL = 1    # 直接执行，无需侦察
    SIMPLE = 2     # 轻量侦察（1-3 条命令）
    MODERATE = 3   # 标准侦察（3-6 条命令）
    COMPLEX = 4    # 完整侦察（6+ 条命令）

# =============================================================================
# 2. 安全辅助函数
# =============================================================================

SAFE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9._:@+-]{1,128}$")
SAFE_PORT_REGEX = re.compile(r"^\d{1,5}$")
SAFE_PATH_REGEX = re.compile(r"^[a-zA-Z0-9._/~@+-]+$")


def q(s: str) -> str:
    """Shell Quote: 安全转义"""
    return shlex.quote(s)


def safe_name(s: Any) -> Optional[str]:
    """校验服务名/工具名/包名"""
    s = "" if s is None else str(s).strip()
    if s and SAFE_NAME_REGEX.match(s):
        return s
    return None


def safe_port(s: Any) -> Optional[str]:
    """校验端口号"""
    s_str = "" if s is None else str(s).strip()
    if SAFE_PORT_REGEX.match(s_str) and 0 < int(s_str) < 65536:
        return s_str
    return None


def safe_path(s: Any) -> Optional[str]:
    """校验路径（基础检查）"""
    s = "" if s is None else str(s).strip()
    if s and SAFE_PATH_REGEX.match(s):
        return s
    return None

# =============================================================================
# 3. 实体提取 (🟢 补全缺失部分)
# =============================================================================

_FILENAME_RE = re.compile(r"(?<![/\\])\b([A-Za-z0-9_-]+\.[A-Za-z0-9]{1,10})\b")
_PORT_RE = re.compile(r"(端口|port)\s*[:：]?\s*(\d{2,5})", re.IGNORECASE)
_PATH_RE = re.compile(r"(/[A-Za-z0-9._/-]+)")
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b")
_CONTAINER_RE = re.compile(r"(容器|container|docker|podman)\s*[名id]?\s*[:：]?\s*([a-zA-Z0-9_-]+)?", re.IGNORECASE)
_PID_RE = re.compile(r"(进程|pid|process)\s*[号id]?\s*[:：]?\s*(\d+)", re.IGNORECASE)
_TOOL_RE = re.compile(r"(使用|用|run|execute|启动|打开)\s*([a-zA-Z][a-zA-Z0-9_-]*)", re.IGNORECASE)

KNOWN_TOOLS = {
    "ffmpeg", "ffprobe", "ffplay",
    "vlc", "mpv", "mplayer",
    "python", "python3", "pip", "pip3",
    "node", "npm", "npx",
    "java", "javac", "mvn", "gradle",
    "gcc", "g++", "make", "cmake",
    "git", "docker", "podman",
    "vim", "nano", "emacs", "code",
    "curl", "wget", "ssh", "scp",
    "tar", "zip", "unzip", "gzip",
    "htop", "top", "ps", "kill",
    "mysql", "psql", "mongo", "redis-cli",
    "nginx", "apache", "systemctl",
    "tensorboard", "jupyter", "streamlit",
}

def extract_entities_from_query(query: str) -> Dict[str, Any]:
    """从查询中提取实体（作为 LLM 的兜底）"""
    entities = {}
    
    # 文件名
    m = _FILENAME_RE.search(query)
    if m: entities["filename"] = m.group(1)
    
    # 端口
    m = _PORT_RE.search(query)
    if m: entities["port"] = safe_port(m.group(2))
    
    # 路径
    m = _PATH_RE.search(query)
    if m: entities["path"] = m.group(1)
    
    # IP 地址
    m = _IP_RE.search(query)
    if m: entities["ip"] = m.group(1)
    
    # 域名
    m = _DOMAIN_RE.search(query)
    if m: entities["domain"] = m.group(1)
    
    # 容器
    m = _CONTAINER_RE.search(query)
    if m and m.group(2): entities["container"] = m.group(2)
    
    # 进程 ID
    m = _PID_RE.search(query)
    if m: entities["pid"] = m.group(2)
    
    # 工具名称（"使用 ffmpeg" / "用 vlc"）
    m = _TOOL_RE.search(query)
    if m:
        tool_name = m.group(2).lower()
        if tool_name in KNOWN_TOOLS:
            entities["tool"] = tool_name
    
    # 直接匹配已知工具名（不需要"使用"前缀）
    query_lower = query.lower()
    for tool in KNOWN_TOOLS:
        if tool in query_lower and "tool" not in entities:
            entities["tool"] = tool
            break
    
    return entities

# =============================================================================
# 4. Domain 侦察命令生成
# =============================================================================

class DomainScout:
    """Domain 侦察命令生成器"""
    
    @staticmethod
    def file_commands(entities: Dict, query: str) -> List[str]:
        """文件 Domain 侦察命令"""
        cmds = []
        path = entities.get("path")
        filename = entities.get("filename") or entities.get("target")
        
        if path:
            q_path = q(path)
            cmds.append(f"ls -la {q_path}")
            cmds.append(f"file {q_path}")
            cmds.append(f"stat {q_path}")
        
        if filename and not path:
            q_name = q(filename)
            cmds.append(f"find . -maxdepth 5 -name {q_name} -type f")
            cmds.append(f"find /home -maxdepth 4 -name {q_name} -type f 2>/dev/null || true")
            cmds.append(f"locate {q_name} 2>/dev/null | head -10 || true")
        
        if not path and not filename:
            cmds.append("pwd")
            cmds.append("ls -la")
        return cmds
    
    @staticmethod
    def process_commands(entities: Dict, query: str) -> List[str]:
        """进程 Domain 侦察命令"""
        cmds = []
        target = entities.get("target") or entities.get("process")
        pid = entities.get("pid")
        port = entities.get("port")
        
        if pid:
            cmds.append(f"ps -p {pid} -o pid,ppid,user,%cpu,%mem,stat,start,time,command")
            cmds.append(f"ls -l /proc/{pid}/fd 2>/dev/null | head -20 || true")
        elif target:
            q_target = q(target)
            cmds.append(f"pgrep -a {q_target}")
            cmds.append(f"ps aux | grep -i {q_target} | grep -v grep")
        elif port:
            cmds.append(f"ss -tlnp 'sport = :{port}'")
            cmds.append(f"lsof -i :{port} 2>/dev/null || true")
        else:
            cmds.append("ps aux --sort=-%mem | head -15")
            cmds.append("ps aux --sort=-%cpu | head -15")
        
        cmds.append("free -h")
        cmds.append("uptime")
        return cmds
    
    @staticmethod
    def network_commands(entities: Dict, query: str) -> List[str]:
        """网络 Domain 侦察命令"""
        cmds = []
        port = entities.get("port")
        ip = entities.get("ip")
        domain = entities.get("domain") or entities.get("target")
        
        cmds.append("ip -br addr")
        if port:
            cmds.append(f"ss -tlnp 'sport = :{port}'")
            cmds.append(f"ss -tlnp 'dport = :{port}'")
        if ip:
            cmds.append(f"ping -c 2 -W 2 {ip}")
        if domain and not ip:
            q_domain = q(domain)
            cmds.append(f"dig +short {q_domain}")
            cmds.append(f"ping -c 2 -W 2 {q_domain}")
        if not port:
            cmds.append("ss -tlnH | head -20")
        cmds.append("cat /etc/resolv.conf")
        return cmds
    
    @staticmethod
    def service_commands(entities: Dict, query: str) -> List[str]:
        """服务 Domain 侦察命令"""
        cmds = []
        service = entities.get("service") or entities.get("target")
        
        if service:
            s_service = safe_name(service)
            if s_service:
                cmds.append(f"systemctl status {s_service} --no-pager -l")
                cmds.append(f"systemctl is-active {s_service}")
                cmds.append(f"systemctl is-enabled {s_service}")
                cmds.append(f"journalctl -u {s_service} -n 30 --no-pager")
        else:
            cmds.append("systemctl list-units --type=service --state=running --no-pager")
            cmds.append("systemctl list-units --type=service --state=failed --no-pager")
        return cmds
    
    @staticmethod
    def system_commands(entities: Dict, query: str) -> List[str]:
        """系统 Domain 侦察命令"""
        return [
            "uname -a", "cat /etc/os-release", "hostnamectl",
            "uptime", "free -h", "df -hT", "lscpu | head -20", "date"
        ]
    
    @staticmethod
    def software_commands(entities: Dict, query: str) -> List[str]:
        """软件 Domain 侦察命令"""
        cmds = ["command -v apt dpkg pip pip3 snap flatpak conda"]
        package = entities.get("package") or entities.get("target")
        if package:
            s_pkg = safe_name(package)
            if s_pkg:
                cmds.append(f"dpkg -l {s_pkg} 2>/dev/null || true")
                cmds.append(f"apt-cache policy {s_pkg} 2>/dev/null || true")
                cmds.append(f"pip3 show {s_pkg} 2>/dev/null || true")
                cmds.append(f"snap list {s_pkg} 2>/dev/null || true")
                cmds.append(f"which {s_pkg} 2>/dev/null || true")
        return cmds
    
    @staticmethod
    def storage_commands(entities: Dict, query: str) -> List[str]:
        """存储 Domain 侦察命令 (增强版 v2.1)"""
        cmds = []
        path = entities.get("path")
        target = entities.get("target")
        
        # === 1. 基础全量信息 (增强) ===
        cmds.append("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,LABEL,MODEL,FSTYPE,UUID,PARTLABEL")
        cmds.append("df -hT")
        cmds.append("findmnt -l -o TARGET,SOURCE,FSTYPE,LABEL")
        
        if path:
            q_path = q(path)
            cmds.append(f"df -hT {q_path}")
            cmds.append(f"du -sh {q_path}")
            cmds.append(f"ls -la {q_path}")
        
        if target:
            # === 2. 针对性搜索 ===
            q_target = q(f"*{target}*")
            cmds.append(f"find /mnt /media /run/media -maxdepth 2 -type d -iname {q_target} 2>/dev/null || true")
            cmds.append("blkid")
            
            # === 3. 模糊搜索兜底策略 (修复版) ===
            # 如果 grep 失败，列出所有非 loop/ram 设备
            cmds.append(f"lsblk -o NAME,SIZE,MODEL,LABEL,MOUNTPOINT | grep -v 'loop\\|ram' | grep -i {q(target)} || lsblk -e7 -o NAME,SIZE,MODEL,LABEL,MOUNTPOINT")
        
        return cmds
    
    @staticmethod
    def container_commands(entities: Dict, query: str) -> List[str]:
        """容器 Domain 侦察命令"""
        cmds = ["command -v docker podman docker-compose"]
        container = entities.get("container") or entities.get("target")
        if container:
            q_container = q(container)
            cmds.append(f"docker ps -a --filter name={q_container} --format 'table {{{{.ID}}}}\\t{{{{.Image}}}}\\t{{{{.Status}}}}\\t{{{{.Names}}}}'")
            cmds.append(f"docker inspect {q_container} 2>/dev/null | head -50 || true")
            cmds.append(f"docker logs --tail 30 {q_container} 2>/dev/null || true")
        else:
            cmds.append("docker ps --format 'table {{.ID}}\\t{{.Image}}\\t{{.Status}}\\t{{.Names}}'")
            cmds.append("docker images --format 'table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}'")
        return cmds
    
    @staticmethod
    def user_commands(entities: Dict, query: str) -> List[str]:
        """用户 Domain 侦察命令"""
        cmds = ["id", "whoami", "groups"]
        user = entities.get("user") or entities.get("target")
        path = entities.get("path")
        
        if user:
            q_user = q(user)
            cmds.append(f"id {q_user} 2>/dev/null || true")
            cmds.append(f"getent passwd {q_user}")
        if path:
            q_path = q(path)
            cmds.append(f"ls -la {q_path}")
            cmds.append(f"getfacl {q_path} 2>/dev/null || true")
            cmds.append(f"stat {q_path}")
        cmds.append("w")
        cmds.append("last -5")
        return cmds
    
    @staticmethod
    def log_commands(entities: Dict, query: str) -> List[str]:
        """日志 Domain 侦察命令"""
        cmds = []
        service = entities.get("service") or entities.get("target")
        if service:
            s_service = safe_name(service)
            if s_service:
                cmds.append(f"journalctl -u {s_service} -n 50 --no-pager")
                cmds.append(f"journalctl -u {s_service} -p err -n 20 --no-pager")
                cmds.append(f"find /var/log -maxdepth 2 -name '*{s_service}*' -type f 2>/dev/null")
        else:
            cmds.append("journalctl -p err -n 30 --no-pager")
            cmds.append("dmesg | tail -30")
            cmds.append("ls -lt /var/log/*.log 2>/dev/null | head -10")
        return cmds


def get_scout_commands(domains: List[str], entities: Dict, query: str, complexity: TaskComplexity) -> List[str]:
    """根据 Domain 和复杂度生成侦察命令"""
    if complexity == TaskComplexity.TRIVIAL:
        return []
    
    cmd_set: List[str] = []
    domain_methods = {
        "file": DomainScout.file_commands,
        "process": DomainScout.process_commands,
        "network": DomainScout.network_commands,
        "service": DomainScout.service_commands,
        "system": DomainScout.system_commands,
        "software": DomainScout.software_commands,
        "storage": DomainScout.storage_commands,
        "container": DomainScout.container_commands,
        "user": DomainScout.user_commands,
        "log": DomainScout.log_commands,
    }
    
    for domain in domains:
        if domain in domain_methods:
            domain_cmds = domain_methods[domain](entities, query)
            if complexity == TaskComplexity.SIMPLE:
                domain_cmds = domain_cmds[:3]
            elif complexity == TaskComplexity.MODERATE:
                domain_cmds = domain_cmds[:5]
            cmd_set.extend(domain_cmds)
    
    seen = set()
    unique_cmds = []
    for c in cmd_set:
        if c not in seen:
            unique_cmds.append(c)
            seen.add(c)
    
    max_cmds = {
        TaskComplexity.SIMPLE: 5,
        TaskComplexity.MODERATE: 10,
        TaskComplexity.COMPLEX: 20,
    }
    return unique_cmds[:max_cmds.get(complexity, 10)]

# =============================================================================
# 5. 事实提取
# =============================================================================

def extract_facts(results: List[Dict], entities: Dict, query: str) -> str:
    """从侦察结果中提取结构化事实"""
    facts: List[str] = []
    raw_outputs: List[str] = []
    
    for res in results:
        cmd = res.get("cmd", "")
        out = res.get("stdout", "") or ""
        err = res.get("stderr", "") or ""
        rc = int(res.get("rc", 0))
        
        if out.strip(): raw_outputs.append(f"$ {cmd}\n{out[:1000]}")
        elif err.strip() and rc != 0: raw_outputs.append(f"$ {cmd}\n[ERROR] {err[:500]}")
        
        # === 文件相关 ===
        if cmd.startswith("ls -"):
            if rc == 0 and out.strip():
                facts.append(f"FILE_EXISTS: {cmd.split()[-1]}")
                for line in out.splitlines():
                    if line.startswith("-") or line.startswith("d"):
                        parts = line.split()
                        if len(parts) >= 9:
                            facts.append(f"FILE_INFO: {parts[8]} (perm={parts[0]}, size={parts[4]}, owner={parts[2]})")
            elif rc != 0: facts.append(f"FILE_NOT_FOUND: {cmd.split()[-1]}")
        
        if cmd.startswith("find ") and rc == 0:
            paths = [l.strip() for l in out.splitlines() if l.strip() and not "__pycache__" in l]
            if paths: facts.append(f"FOUND_FILES: {', '.join(paths[:10])}")
        
        # === 进程相关 ===
        if cmd.startswith("ps ") or "pgrep" in cmd:
            if rc == 0 and out.strip():
                lines = [l for l in out.splitlines() if l.strip()]
                if lines:
                    facts.append(f"PROCESS_FOUND: {len(lines)} matches")
                    for line in lines[:5]: facts.append(f"  PROC: {line[:200]}")
        
        if "top" in cmd or cmd.startswith("free"):
            if rc == 0 and out.strip(): facts.append(f"RESOURCE_INFO: {out[:300]}")
        
        # === 网络相关 ===
        if cmd.startswith("ss ") and "sport" in cmd:
            port = re.search(r"sport\s*=\s*:(\d+)", cmd)
            if port:
                port_num = port.group(1)
                if out.strip():
                    facts.append(f"PORT_{port_num}_LISTENING: yes")
                    m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', out)
                    if m: facts.append(f"PORT_{port_num}_PROCESS: {m.group(1)} (PID={m.group(2)})")
                else: facts.append(f"PORT_{port_num}_LISTENING: no")
        
        # === 服务相关 ===
        if "systemctl status" in cmd:
            if "Active: active (running)" in out: facts.append("SERVICE_STATUS: running")
            elif "Active: inactive" in out: facts.append("SERVICE_STATUS: inactive")
            elif "Active: failed" in out: facts.append("SERVICE_STATUS: failed")
        
        if "journalctl" in cmd and rc == 0:
            error_lines = [l for l in out.splitlines() if "error" in l.lower() or "fail" in l.lower()]
            if error_lines:
                facts.append(f"LOG_ERRORS: {len(error_lines)} error entries found")
                facts.append(f"  LAST_ERROR: {error_lines[-1][:200]}")
        
        # === 容器相关 ===
        if "docker ps" in cmd and rc == 0:
            lines = [l for l in out.splitlines() if l.strip() and not l.startswith("CONTAINER")]
            if lines:
                facts.append(f"DOCKER_CONTAINERS: {len(lines)} running")
                for line in lines[:5]: facts.append(f"  CONTAINER: {line[:150]}")
            else: facts.append("DOCKER_CONTAINERS: none running")
        
        # === 软件包相关 ===
        if cmd.startswith("dpkg -l") and rc == 0 and "ii" in out:
            facts.append(f"PACKAGE_INSTALLED: {cmd.split()[-1]} (dpkg)")
        
        if cmd.startswith("which") or cmd.startswith("command -v"):
            if rc == 0 and out.strip(): facts.append(f"TOOL_FOUND: {out.strip()}")
            elif rc != 0:
                tool = cmd.split()[-1]
                facts.append(f"TOOL_NOT_FOUND: {tool}")
        
        # === 系统信息 ===
        if cmd.startswith("uname") and rc == 0: facts.append(f"SYSTEM_INFO: {out.strip()}")
        if cmd.startswith("df") and rc == 0: facts.append(f"DISK_USAGE:\n{out[:500]}")
        if cmd.startswith("lsblk") and rc == 0: facts.append(f"BLOCK_DEVICES:\n{out[:500]}")
    
    facts_str = "\n".join(facts) if facts else "No structured facts extracted."
    raw_str = "\n---\n".join(raw_outputs[:15]) if raw_outputs else "No raw output."
    return f"[EXTRACTED FACTS]\n{facts_str}\n\n[RAW SCOUT OUTPUT]\n{raw_str}"