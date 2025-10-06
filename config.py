import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from ~/workspace/forensic_message_analyzer/
env_path = Path.home() / "workspace" / "forensic_message_analyzer" / ".env"
if env_path.exists():
    load_dotenv(env_path)
else:
    # Fallback to local .env if it exists
    load_dotenv()
    print(f"Warning: {env_path} not found, using local .env or environment variables")

# ...existing code...