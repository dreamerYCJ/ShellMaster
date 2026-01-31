import os
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings # 需要更新 pip install langchain-huggingface
from langchain_core.documents import Document
from rich.console import Console
from rich.progress import track

console = Console()

# === 配置 ===
NL_FILE = "./data/all.nl"
CM_FILE = "./data/all.cm"
DB_PATH = "./src/shellmaster/chroma_db"  # 数据库存放在包内，方便读取

def main():
    # 1. 检查文件
    if not os.path.exists(NL_FILE) or not os.path.exists(CM_FILE):
        console.print("[red]Error: Data files not found in ./data/[/red]")
        return

    # 2. 读取文件 (按行对齐)
    console.print("[yellow]Reading files...[/yellow]")
    with open(NL_FILE, "r", encoding="utf-8", errors="ignore") as f_nl:
        nl_lines = f_nl.readlines()
    with open(CM_FILE, "r", encoding="utf-8", errors="ignore") as f_cm:
        cm_lines = f_cm.readlines()

    if len(nl_lines) != len(cm_lines):
        console.print(f"[red]Warning: Line counts mismatch! NL: {len(nl_lines)}, CM: {len(cm_lines)}[/red]")
        # 取最小长度，防止报错
        min_len = min(len(nl_lines), len(cm_lines))
        nl_lines = nl_lines[:min_len]
        cm_lines = cm_lines[:min_len]

    # 3. 构建 Documents
    docs = []
    console.print(f"[cyan]Processing {len(nl_lines)} pairs...[/cyan]")
    
    for nl, cm in zip(nl_lines, cm_lines):
        nl = nl.strip()
        cm = cm.strip()
        if not nl or not cm: continue # 跳过空行
        
        # page_content 是自然语言 (用于检索)
        # metadata 是对应的命令 (作为参考答案)
        docs.append(Document(page_content=nl, metadata={"cmd": cm}))

    # 4. 向量化并入库
    console.print("[bold green]Initializing Vector Store (this may take a while)...[/bold green]")
    
    # 使用轻量级模型 (下载一次后会在本地缓存)
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    # 批量插入 (防止内存溢出)
    batch_size = 1000
    vector_store = Chroma(embedding_function=embeddings, persist_directory=DB_PATH)
    
    for i in track(range(0, len(docs), batch_size), description="Ingesting..."):
        batch = docs[i : i + batch_size]
        vector_store.add_documents(batch)

    # 5. 持久化
    # Chroma 新版本会自动持久化，但在脚本结束时确保万无一失
    console.print(f"[bold green]Success! Database saved to {DB_PATH}[/bold green]")

if __name__ == "__main__":
    main()