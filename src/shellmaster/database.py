import os
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

class KnowledgeBase:
    def __init__(self):
        # 1. 初始化 Embedding 模型 (必须与 ingest 脚本保持一致)
        # 使用本地轻量级模型，首次运行会自动下载到缓存
        self.embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        
        # 2. 确定数据库路径 (相对于当前文件)
        # 这样无论你在哪里运行 sm 命令，它都能找到包内的 chroma_db
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_path = os.path.join(current_dir, "chroma_db")
        
        self.ready = False
        if os.path.exists(self.db_path):
            try:
                self.vector_store = Chroma(
                    embedding_function=self.embeddings, 
                    persist_directory=self.db_path
                )
                self.ready = True
            except Exception as e:
                # 数据库加载失败不应导致程序崩溃，只是 RAG 功能失效
                print(f"Warning: Failed to load Vector DB: {e}")
        else:
            # 数据库不存在 (可能还没运行 ingest 脚本)
            pass

    def search(self, query, k=3, threshold=1.5):
        """
        检索相似的高质量命令作为参考
        :param k: 返回结果数量
        :param threshold: (预留) 相似度阈值过滤
        """
        if not self.ready:
            return ""
        
        try:
            # 语义检索
            results = self.vector_store.similarity_search(query, k=k)
            
            # 格式化输出给 LLM 看
            formatted_examples = []
            for doc in results:
                cmd = doc.metadata.get('cmd', '').strip()
                desc = doc.page_content.strip()
                formatted_examples.append(f"User Goal: {desc}\nReference Command: {cmd}")
                
            return "\n---\n".join(formatted_examples)
        except Exception as e:
            return f"Error retrieval: {e}"