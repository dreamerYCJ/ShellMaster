import os
from modelscope import snapshot_download

# 1. 获取当前脚本所在的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))

# 2. 指定下载目标目录
# 这里设置为当前目录下的 'Qwen2.5-7B-Instruct' 文件夹
# ModelScope 默认会在 cache_dir 下建立 'Qwen/Qwen2.5-7B-Instruct' 的结构
cache_path = os.path.join(current_dir, "models") 

print(f"🚀 正在通过 ModelScope (国内源) 下载 Qwen2.5-7B-Instruct...")
print(f"📂 下载缓存目标路径: {cache_path}")

try:
    model_dir = snapshot_download(
        'Qwen/Qwen2.5-7B-Instruct', 
        cache_dir=cache_path,  # 指定下载位置
        revision='master'      # 版本
    )
    print(f"\n✅ 下载成功！")
    print(f"📦 模型实际存储路径: {model_dir}")
except Exception as e:
    print(f"\n❌ 下载失败: {e}")