import os
import json

CONFIG_FILE = os.path.expanduser("~/.shellmaster_config.json")

def load_config():
    defaults = {
        "model": "Qwen-7B",
        "base_url": "http://localhost:8000/v1",
        "api_key": "EMPTY"
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return {**defaults, **json.load(f)}
        except:
            pass
    return defaults

def save_config(conf):
    with open(CONFIG_FILE, "w") as f:
        json.dump(conf, f)