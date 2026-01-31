
# ShellMaster 🐚

**ShellMaster (sm)** 是一个基于 AI 的智能 Linux 终端助手。它能将你的自然语言指令（如“查找最大的文件”、“使用 ffmpeg 录屏”）转化为准确、安全的 Shell 命令。

它不仅是简单的翻译，还具备 **RAG（检索增强生成）** 和 **系统侦察** 能力，能根据你的系统环境（Ubuntu/CentOS、X11/Wayland）生成最合适的命令。

## ✨ 主要功能

* **自然语言转 Shell**: 支持中文/英文输入，自动生成复杂命令（ffmpeg, docker, k8s 等）。
* **智能侦察 (Scout)**: 在生成命令前，自动检查系统版本、已安装工具和文件路径，防止“幻觉”。
* **RAG 知识库**: 内置高质量命令库，通过向量检索提供最佳实践参考。
* **安全守卫 (Safety)**: 自动拦截高危命令（如 `rm -rf /`）和危险的重定向操作。
* **全链路日志**: 支持 `--debug` 模式，查看 AI 的完整思考过程。

## 🛠️ 安装指南

### 1. 克隆仓库
```bash
git clone [https://github.com/你的用户名/shellmaster.git](https://github.com/你的用户名/shellmaster.git)
cd shellmaster

```

### 2. 创建环境并安装依赖

建议使用 Conda 或 venv (Python 3.10+)：

```bash
conda create -n sm python=3.10
conda activate sm
pip install -r requirements.txt

```

### 3. 以开发者模式安装

这样你可以随时修改代码并立即生效：

```bash
pip install -e .

```

### 4. 初始化模型与数据库 (关键步骤)

由于模型和向量数据库被 `.gitignore` 忽略了，首次运行需要生成它们：

* **下载 Embedding 模型** (解决国内网络问题):
```bash
python download_em.py

```


* **构建本地向量知识库** (RAG):
```bash
python ingest_nl2bash.py

```



## 🚀 启动本地模型 (vLLM)

本项目依赖 OpenAI 兼容接口。建议使用 vLLM 部署 Qwen2.5-7B 模型。

请在另一个终端窗口中运行以下命令（请修改 `--model` 为你的实际路径）：

```bash
python -m vllm.entrypoints.openai.api_server \
    --model /home/nav/project/models/Qwen/Qwen2.5-7B-Instruct \
    --served-model-name Qwen-7B \
    --quantization bitsandbytes \
    --load-format bitsandbytes \
    --trust-remote-code \
    --dtype half \
    --gpu-memory-utilization 0.80 \
    --max-model-len 4096 \
    --enforce-eager \
    --port 8000 \
    --api-key EMPTY

```

> **注意**：
> * 确保你已经安装了 `vllm` 和 `bitsandbytes`。
> * 该命令使用了 8-bit 量化以节省显存。
> 
> 

## ⚙️ 客户端配置

在模型启动后，配置 `sm` 连接到本地服务：

```bash
sm --config

```

* **Base URL**: `http://localhost:8000/v1`
* **Model Name**: `Qwen-7B` (需与启动命令中的 `--served-model-name` 一致)
* **API Key**: `EMPTY`

## 🎮 使用方法

### 基础用法

直接在 `sm` 后面跟上你的需求：

```bash
sm "查询我挂载的Lenovo硬盘还有多少空间"

```

### Debug 模式

如果你想看 AI 是怎么思考的，或者为什么命令生成错了，加上 `--debug`：

```bash
sm "使用ffmpeg录制屏幕" --debug

```

## 📂 项目结构

* `src/shellmaster/`: 核心源码
* `graph.py`: LangGraph 状态机与核心逻辑
* `domains.py`: 领域知识与系统侦察逻辑
* `safety.py`: 安全拦截与白名单机制
* `database.py`: 向量数据库管理


* `data/`: 原始训练数据 (NL2Bash)

## ⚠️ 注意事项

* 本项目默认配置了国内 HF 镜像 (`hf-mirror.com`) 以加速模型下载。
* 虽然有安全检查，但在执行生成的命令（尤其是涉及删除操作）前，请务必进行人工确认。

---

