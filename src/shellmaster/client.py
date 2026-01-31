import sys
import os
import subprocess
import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.prompt import Confirm
from langchain_openai import ChatOpenAI

# 相对引用
from .graph import ShellGraph
from .config import save_config, load_config

console = Console()

@click.command()
@click.argument("query", nargs=-1)
@click.option("--debug", is_flag=True, help="Show scout logs")
@click.option("--config", is_flag=True, help="Configure settings")
def main(query, debug, config):
    """ShellMaster: AI-powered Linux Assistant"""
    
    # === 1. 配置模式 ===
    if config:
        url = click.prompt("Base URL", default="http://localhost:8000/v1")
        model = click.prompt("Model Name", default="Qwen-7B")
        save_config({"base_url": url, "model": model, "api_key": "EMPTY"})
        console.print("[green]Saved![/green]")
        return

    # === 2. 检查输入 ===
    q_str = " ".join(query)
    if not q_str:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        return

    # === 3. 环境准备 (代理清除 & 镜像设置) ===
    # 强制清除系统代理
    for key in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
        os.environ.pop(key, None)
    
    # 设置国内镜像
    os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

    # === 4. 初始化 LLM ===
    conf = load_config()
    if not conf.get("base_url"):
        console.print("[yellow]Tip: Run 'sm --config' to set up your LLM first.[/yellow]")
        return

    try:
        llm = ChatOpenAI(
            base_url=conf["base_url"],
            api_key=conf["api_key"],
            model=conf["model"],
            temperature=0,
            request_timeout=60,
            max_retries=2
        )
    except Exception as e:
        console.print(f"[bold red]LLM Init Error:[/bold red] {e}")
        return

    # === 5. 构建图 (耗时操作) ===
    # 🟢 优化体验：显示加载动画
    with console.status("[bold green]🐢 Loading AI modules (Embeddings)...[/bold green]", spinner="dots"):
        try:
            agent = ShellGraph(llm).build()
        except Exception as e:
            console.print(f"[bold red]Graph Init Error:[/bold red] {e}")
            return
    
    # === 6. 执行侦察与生成 ===
    with console.status("[bold cyan]🕵️  Scouting system & Planning...[/bold cyan]", spinner="dots"):
        try:
            res = agent.invoke({"query": q_str})
        except Exception as e:
            console.print(f"[red]Agent Execution Error: {e}[/red]")
            if debug:
                import traceback
                traceback.print_exc()
            return

    # === 7. 结果展示 ===
    # Debug 模式
    if debug:
        scout_info = res.get("scout_info", "No info")
        intent_info = res.get("intent", {})
        console.print(Panel(f"Intent: {intent_info}\n\n{scout_info}", title="🕵️ Debug Info", border_style="dim"))

    # 错误处理
    if res.get("error"):
        console.print(f"[red]Error: {res['error']}[/red]")
        return

    # 显示命令
    cmd = res.get("command", "")
    if not cmd:
        console.print("[yellow]No command generated. Try rephrasing your request.[/yellow]")
        return

    console.print(Panel(Syntax(cmd, "bash", theme="monokai"), title="🤖 Suggested Command", border_style="green"))

    # === 8. 交互执行 ===
    if Confirm.ask("🚀 Execute?"):
        is_interactive = any(x in cmd for x in ["vim", "nano", "sudo", "ssh", "top", "htop", "less", "more"])
        
        try:
            if is_interactive:
                subprocess.run(cmd, shell=True)
            else:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if proc.stdout:
                    console.print(Panel(proc.stdout.strip(), title="Output", border_style="blue"))
                if proc.stderr:
                    console.print(Panel(proc.stderr.strip(), title="Error", border_style="red"))
        except KeyboardInterrupt:
            console.print("\n[yellow]Execution cancelled.[/yellow]")

if __name__ == "__main__":
    main()