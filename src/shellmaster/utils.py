import platform
import os

def get_system_context():
    return f"OS: {platform.system()} {platform.release()}, Shell: {os.environ.get('SHELL', '/bin/bash')}, CWD: {os.getcwd()}"