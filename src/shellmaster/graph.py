import json
import subprocess
import re
import time
import os
import datetime
from typing import TypedDict, Dict, Any, List, Optional, Tuple
from langgraph.graph import StateGraph, END
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from .utils import get_system_context
from .database import KnowledgeBase
from .safety import is_safe_scout_cmd, get_safety_reason

# 🟢 引入拆分后的 Domain 模块
from .domains import (
    TaskComplexity, 
    get_scout_commands, 
    extract_facts,
    safe_port,
    extract_entities_from_query # 确保这个也在 domains.py 里，或者保留在 graph.py (原代码在 graph.py)
)
# 注意：如果是你上一版提供的代码，extract_entities_from_query 等正则逻辑还在 graph.py 里
# 为了保持你提供的代码结构不报错，我保留原来的正则逻辑在下面

# =============================================================================
# 1. 常量与配置
# =============================================================================

# 支持的 Domain 列表
SUPPORTED_DOMAINS = [
    "file", "process", "network", "service", "system",
    "software", "storage", "container", "user", "log"
]

# 直接执行的简单命令模式（Level 1）
TRIVIAL_PATTERNS = [
    r"^(pwd|当前目录|当前路径|我在哪)$",
    r"^(whoami|我是谁|当前用户)$",
    r"^(date|时间|日期|几点|什么时候)$",
    r"^(uptime|运行时间|开机多久)$",
    r"^(hostname|主机名)$",
    r"^(uname|系统版本|内核版本)$",
    r"^(id|用户id|用户信息)$",
    r"^(df|磁盘空间|磁盘使用)$",
    r"^(free|内存|内存使用)$",
]

# 诊断类关键词（触发 Level 3+）
DIAGNOSTIC_KEYWORDS = [
    "为什么", "怎么回事", "排查", "诊断", "问题",
    "不工作", "失败", "错误", "异常", "故障",
    "无法", "不能", "连不上", "打不开", "起不来",
]

TRIVIAL_COMMANDS = {
    "pwd": "pwd",
    "当前目录": "pwd",
    "当前路径": "pwd",
    "我在哪": "pwd",
    "whoami": "whoami",
    "我是谁": "whoami",
    "当前用户": "whoami",
    "date": "date",
    "时间": "date '+%Y-%m-%d %H:%M:%S'",
    "日期": "date '+%Y-%m-%d'",
    "几点": "date '+%H:%M:%S'",
    "uptime": "uptime",
    "运行时间": "uptime",
    "开机多久": "uptime",
    "hostname": "hostname",
    "主机名": "hostname",
    "id": "id",
    "用户id": "id",
    "df": "df -h",
    "磁盘空间": "df -h",
    "磁盘使用": "df -h",
    "free": "free -h",
    "内存": "free -h",
    "内存使用": "free -h",
}

# =============================================================================
# 2. 实体提取（正则兜底 - 保留原逻辑）
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
    "ffmpeg", "ffprobe", "ffplay", "vlc", "mpv", "mplayer",
    "python", "python3", "pip", "pip3", "node", "npm", "npx",
    "java", "javac", "mvn", "gradle", "gcc", "g++", "make", "cmake",
    "git", "docker", "podman", "vim", "nano", "emacs", "code",
    "curl", "wget", "ssh", "scp", "tar", "zip", "unzip", "gzip",
    "htop", "top", "ps", "kill", "mysql", "psql", "mongo", "redis-cli",
    "nginx", "apache", "systemctl", "tensorboard", "jupyter", "streamlit",
}

def extract_entities_from_query(query: str) -> Dict[str, Any]:
    """从查询中提取实体（作为 LLM 的兜底）"""
    entities = {}
    m = _FILENAME_RE.search(query)
    if m: entities["filename"] = m.group(1)
    m = _PORT_RE.search(query)
    if m: entities["port"] = safe_port(m.group(2))
    m = _PATH_RE.search(query)
    if m: entities["path"] = m.group(1)
    m = _IP_RE.search(query)
    if m: entities["ip"] = m.group(1)
    m = _DOMAIN_RE.search(query)
    if m: entities["domain"] = m.group(1)
    m = _CONTAINER_RE.search(query)
    if m and m.group(2): entities["container"] = m.group(2)
    m = _PID_RE.search(query)
    if m: entities["pid"] = m.group(2)
    m = _TOOL_RE.search(query)
    if m:
        tool_name = m.group(2).lower()
        if tool_name in KNOWN_TOOLS: entities["tool"] = tool_name
    
    query_lower = query.lower()
    for tool in KNOWN_TOOLS:
        if tool in query_lower and "tool" not in entities:
            entities["tool"] = tool
            break
    return entities

# =============================================================================
# 3. 复杂度评估
# =============================================================================

def assess_complexity(query: str, intent: Dict) -> TaskComplexity:
    """评估任务复杂度"""
    query_lower = query.lower().strip()
    for pattern in TRIVIAL_PATTERNS:
        if re.match(pattern, query_lower, re.IGNORECASE):
            return TaskComplexity.TRIVIAL
    for keyword in DIAGNOSTIC_KEYWORDS:
        if keyword in query:
            return TaskComplexity.COMPLEX
    
    domains = intent.get("domains", [])
    if len(domains) >= 3: return TaskComplexity.COMPLEX
    elif len(domains) == 2: return TaskComplexity.MODERATE
    
    entities = intent.get("entities", {})
    has_target = any([entities.get(k) for k in ["target", "path", "filename", "port", "service", "container"]])
    
    if has_target: return TaskComplexity.SIMPLE
    else: return TaskComplexity.MODERATE

# =============================================================================
# 4. 状态定义 (🟢 修改：增加 logs 字段)
# =============================================================================

class AgentState(TypedDict):
    query: str
    intent: Dict
    complexity: int
    context: str
    scout_info: str
    examples: str
    command: str
    error: Optional[str]
    # 🟢 新增：日志列表，用于记录全链路思考过程
    logs: List[str]

# =============================================================================
# 5. JSON 解析容错
# =============================================================================

def fix_json_string(s: str) -> str:
    s = re.sub(r"```json\s*", "", s)
    s = re.sub(r"```\s*", "", s)
    s = s.strip()
    match = re.search(r"\{[\s\S]*\}", s)
    if match: s = match.group(0)
    s = s.replace("'", '"')
    s = re.sub(r",\s*}", "}", s)
    s = re.sub(r",\s*]", "]", s)
    return s

def parse_json_safe(s: str, default: Dict = None) -> Tuple[Dict, Optional[str]]:
    if default is None: default = {}
    try:
        return json.loads(s), None
    except json.JSONDecodeError as e:
        fixed = fix_json_string(s)
        try:
            return json.loads(fixed), None
        except json.JSONDecodeError:
            return default, str(e)

# =============================================================================
# 6. Prompt 模板
# =============================================================================

INTENT_PROMPT = """You are a Linux Intent Parser. Analyze the user's query and output structured JSON.

[User Query]: {query}

[Supported Domains]:
- file: 文件/目录操作（查找、查看、统计、权限）
- process: 进程管理（列表、资源占用、信号）
- network: 网络诊断（端口、连接、DNS、ping）
- service: 服务管理（systemd 服务状态、启停）
- system: 系统信息（硬件、内核、时间、资源）
- software: 软件包管理（安装查询、依赖）
- storage: 存储设备（磁盘、分区、挂载）
- container: 容器管理（docker/podman）
- user: 用户/权限（账户、sudo、ACL）
- log: 日志分析（journalctl、应用日志）

[Output Schema]:
{{
    "domains": ["domain1", "domain2"],  // 1-3 个最相关的 domain
    "action": "描述用户想要执行的操作",
    "entities": {{
        "target": "操作目标（文件名/服务名/进程名等）",
        "path": "文件路径（如果有）",
        "port": "端口号（如果有）",
        "service": "服务名（如果有）",
        "package": "软件包名（如果有）",
        "container": "容器名或ID（如果有）",
        "user": "用户名（如果有）",
        "ip": "IP地址（如果有）",
        "pid": "进程ID（如果有）"
    }},
    "complexity": 1-4  // 1=直接命令, 2=简单, 3=中等, 4=复杂诊断
}}

[Important Rules]:
1. ONLY output valid JSON
2. Do NOT guess paths - leave path empty if not explicitly provided
3. complexity=1 for simple commands like pwd/whoami/date
4. complexity=4 for diagnostic queries

Output JSON:"""

GENERATE_PROMPT = """You are a Linux Shell Expert. Generate a command based on the user's request.

[User Query]: {query}

[Intent]: {intent}

[System Context]:
{context}

[Scout Report]:
{scout_info}

[Examples from Knowledge Base]:
{examples}

[Command Generation Rules]:
1. Generate ONE command or a short pipeline
2. ALWAYS generate a command that attempts to fulfill the user's request
3. If Scout Report shows FOUND_FILES with paths, prefer using those exact paths
4. If user explicitly mentions a path, USE that path directly even if scout didn't find it
5. If user mentions a tool (like ffmpeg), generate the command using that tool
6. Do NOT refuse to generate commands just because a tool or path wasn't found in scout
7. Do NOT use sudo unless necessary

[Output Format]:
Return ONLY the bash command, no explanation.

Command:"""

# =============================================================================
# 7. ShellGraph 主类 (🟢 大幅增强日志记录)
# =============================================================================

class ShellGraph:
    """ShellMaster 主图类"""
    
    def __init__(self, llm, max_retries: int = 3):
        self.llm = llm
        self.max_retries = max_retries
        
        # 确保 HuggingFace 镜像环境变量，解决模型下载问题
        os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
        
        try:
            self.kb = KnowledgeBase()
        except Exception:
            self.kb = None
    
    def _invoke_llm_with_retry(self, prompt: ChatPromptTemplate, params: Dict) -> Tuple[str, str]:
        """
        带重试的 LLM 调用
        Returns: (result_content, formatted_prompt_text)
        """
        last_error = None
        
        # 获取格式化后的 Prompt 文本，用于日志记录
        try:
            formatted_prompt = prompt.format(**params)
        except Exception:
            formatted_prompt = "Error formatting prompt"

        for attempt in range(self.max_retries):
            try:
                chain = prompt | self.llm
                result = chain.invoke(params)
                return result.content, formatted_prompt
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    time.sleep(0.5 * (attempt + 1))
        
        raise last_error
    
    def _log(self, state: AgentState, step_name: str, content: str):
        """辅助函数：添加日志到状态"""
        current_logs = state.get("logs", [])
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        entry = f"\n{'='*20} [{timestamp}] STEP: {step_name} {'='*20}\n{content}\n"
        return current_logs + [entry]
    
    def refine_node(self, state: AgentState) -> Dict:
        """意图解析节点"""
        query = state["query"]
        logs = state.get("logs", [])
        
        # 检查是否是简单命令
        query_normalized = query.strip().lower()
        if query_normalized in TRIVIAL_COMMANDS:
            logs = self._log(state, "REFINE_NODE", f"Trivial command detected: {query_normalized}")
            return {
                "intent": {"domains": ["file"], "action": "simple command", "entities": {}},
                "complexity": TaskComplexity.TRIVIAL,
                "command": TRIVIAL_COMMANDS[query_normalized],
                "logs": logs
            }
        
        # LLM 解析
        prompt = ChatPromptTemplate.from_template(INTENT_PROMPT)
        default_intent = {"domains": ["file"], "action": "unknown", "entities": {}, "complexity": 2}
        
        try:
            # 🟢 调用并记录日志
            result_str, prompt_text = self._invoke_llm_with_retry(prompt, {"query": query})
            
            log_content = f"[INPUT PROMPT]:\n{prompt_text}\n\n[RAW LLM OUTPUT]:\n{result_str}"
            logs = self._log(state, "REFINE_NODE (Intent Parsing)", log_content)
            
            intent, error = parse_json_safe(result_str, default_intent)
            if error:
                intent = default_intent.copy()
                intent["_parse_error"] = error
        except Exception as e:
            intent = default_intent.copy()
            intent["_llm_error"] = str(e)
            logs = self._log(state, "REFINE_NODE_ERROR", str(e))
        
        # 验证修正逻辑
        if not intent.get("domains"): intent["domains"] = ["file"]
        if isinstance(intent["domains"], str): intent["domains"] = [intent["domains"]]
        intent["domains"] = [d for d in intent["domains"] if d in SUPPORTED_DOMAINS]
        if not intent["domains"]: intent["domains"] = ["file"]
        
        intent.setdefault("entities", {})
        regex_entities = extract_entities_from_query(query)
        for key, value in regex_entities.items():
            if value and not intent["entities"].get(key):
                intent["entities"][key] = value
        
        target = intent["entities"].get("target")
        if target and target.startswith("/") and not intent["entities"].get("path"):
            intent["entities"]["path"] = target
        if target and str(target).isdigit() and not intent["entities"].get("port"):
            intent["entities"]["port"] = str(target)
        
        llm_complexity = intent.get("complexity", 2)
        assessed_complexity = assess_complexity(query, intent)
        final_complexity = max(llm_complexity, assessed_complexity)
        
        return {
            "intent": intent,
            "complexity": final_complexity,
            "logs": logs
        }
    
    def retrieve_node(self, state: AgentState) -> Dict:
        """知识库检索节点"""
        examples = "No examples found."
        if self.kb:
            try:
                results = self.kb.search(state["query"], k=5, threshold=1.5)
                if results: examples = results
            except Exception: pass
        
        # 🟢 记录日志
        logs = self._log(state, "RETRIEVE_NODE (RAG)", f"Found Examples:\n{examples}")
        
        return {
            "context": get_system_context(),
            "examples": examples,
            "logs": logs
        }
    
    def scout_node(self, state: AgentState) -> Dict:
        """系统侦察节点"""
        logs = state.get("logs", [])
        
        if state.get("complexity") == TaskComplexity.TRIVIAL:
            return {"scout_info": "[TRIVIAL TASK - No scout needed]", "logs": logs}
        
        intent = state["intent"]
        query = state["query"]
        complexity = TaskComplexity(state.get("complexity", TaskComplexity.MODERATE))
        
        scout_cmds = get_scout_commands(
            intent.get("domains", ["file"]),
            intent.get("entities", {}),
            query,
            complexity
        )
        
        # 🟢 记录计划命令
        logs = self._log(state, "SCOUT_PLANNING", f"Generated Scout Commands:\n{json.dumps(scout_cmds, indent=2)}")
        
        if not scout_cmds:
            return {"scout_info": "[No scout commands generated]", "logs": logs}
        
        exec_results: List[Dict] = []
        failed_count = 0
        
        for cmd in scout_cmds:
            if not is_safe_scout_cmd(cmd):
                reason = get_safety_reason(cmd)
                exec_results.append({"cmd": cmd, "stdout": "", "stderr": f"BLOCKED: {reason}", "rc": 126})
                continue
            
            try:
                proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=10)
                exec_results.append({"cmd": cmd, "stdout": proc.stdout, "stderr": proc.stderr, "rc": proc.returncode})
                if proc.returncode != 0: failed_count += 1
            except subprocess.TimeoutExpired:
                exec_results.append({"cmd": cmd, "stdout": "", "stderr": "TIMEOUT", "rc": 124})
                failed_count += 1
            except Exception as e:
                exec_results.append({"cmd": cmd, "stdout": "", "stderr": str(e), "rc": 1})
                failed_count += 1
        
        warning = "[WARNING] Most scout commands failed." if failed_count > len(scout_cmds) * 0.7 else ""
        facts = extract_facts(exec_results, intent.get("entities", {}), query)
        if warning: facts = warning + "\n\n" + facts
        
        # 🟢 记录侦察结果
        logs = self._log(state, "SCOUT_RESULTS", facts)
        
        return {"scout_info": facts, "logs": logs}
    
    def generate_node(self, state: AgentState) -> Dict:
        """命令生成节点"""
        logs = state.get("logs", [])
        
        if state.get("command"): return {}
        
        prompt = ChatPromptTemplate.from_template(GENERATE_PROMPT)
        
        try:
            params = {
                "query": state["query"],
                "intent": json.dumps(state["intent"], ensure_ascii=False, indent=2),
                "context": state.get("context", "Ubuntu Linux"),
                "scout_info": state.get("scout_info", "No scout info"),
                "examples": state.get("examples", "No examples"),
            }
            
            # 🟢 调用并记录日志
            result_str, prompt_text = self._invoke_llm_with_retry(prompt, params)
            
            log_content = f"[FINAL PROMPT]:\n{prompt_text}\n\n[RAW LLM OUTPUT]:\n{result_str}"
            logs = self._log(state, "GENERATE_NODE (Final Thinking)", log_content)
            
            command = result_str.strip()
            command = re.sub(r"^```bash\s*", "", command)
            command = re.sub(r"^```\s*", "", command)
            command = re.sub(r"\s*```$", "", command)
            command = command.strip()
            if "\n" in command and not command.startswith("echo"):
                lines = [l.strip() for l in command.split("\n") if l.strip() and not l.startswith("#")]
                if lines: command = lines[0]
            
            return {"command": command, "logs": logs}
            
        except Exception as e:
            error_msg = f"Error in generation: {e}"
            logs = self._log(state, "GENERATE_ERROR", error_msg)
            return {
                "command": f'echo "命令生成失败: {str(e)}"',
                "error": str(e),
                "logs": logs
            }
    
    def should_skip_scout(self, state: AgentState) -> str:
        if state.get("complexity") == TaskComplexity.TRIVIAL:
            return "generate"
        return "scout"
    
    def build(self):
        workflow = StateGraph(AgentState)
        workflow.add_node("refine", self.refine_node)
        workflow.add_node("retrieve", self.retrieve_node)
        workflow.add_node("scout", self.scout_node)
        workflow.add_node("generate", self.generate_node)
        
        workflow.set_entry_point("refine")
        workflow.add_edge("refine", "retrieve")
        workflow.add_conditional_edges("retrieve", self.should_skip_scout, {"scout": "scout", "generate": "generate"})
        workflow.add_edge("scout", "generate")
        workflow.add_edge("generate", END)
        
        return workflow.compile()

def create_shell_graph(llm) -> StateGraph:
    graph = ShellGraph(llm)
    return graph.build()

def run_query(graph, query: str) -> str:
    result = graph.invoke({"query": query})
    return result.get("command", "No command generated")