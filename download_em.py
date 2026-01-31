import os
import sys

# 🟢 关键：在导入 langchain 之前设置国内镜像
print("🔄 设置 HF 国内镜像源 (hf-mirror.com)...")
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    print("❌ 缺少依赖，请先安装: pip install langchain-huggingface sentence-transformers")
    sys.exit(1)

def main():
    model_name = "all-MiniLM-L6-v2"
    print(f"🚀 开始下载模型: {model_name}")
    print("⏳ 这可能需要几分钟 (约 100MB)...")

    try:
        # 初始化会触发自动下载
        embeddings = HuggingFaceEmbeddings(model_name=model_name)
        
        # 简单测试一下，确保加载成功
        test_vec = embeddings.embed_query("hello")
        
        print("\n✅ 下载并加载成功！")
        print(f"📦 模型已缓存到本地 (向量维度: {len(test_vec)})")
        print("🎉 现在你可以直接运行 'sm' 命令了，无需再联网下载模型。")
        
    except Exception as e:
        print(f"\n❌ 下载失败: {e}")
        print("👉 请检查网络，或确保能访问 https://hf-mirror.com")

if __name__ == "__main__":
    main()