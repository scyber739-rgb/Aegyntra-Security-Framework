import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()
APP_ROOT=Path(__file__).resolve().parent.parent
DATA_DIR=Path(os.getenv("AEGYNTRA_DATA_DIR",str(APP_ROOT/"data"))).expanduser().resolve()
VAULT_ROOT=DATA_DIR/"vaults"; DB_PATH=DATA_DIR/"aegyntra.sqlite3"
MAX_UPLOAD_BYTES=max(1,int(os.getenv("AEGYNTRA_MAX_UPLOAD_MB","15")))*1024*1024
API_TOKEN=os.getenv("AEGYNTRA_API_TOKEN","").strip()
for p in (DATA_DIR,VAULT_ROOT): p.mkdir(parents=True,exist_ok=True)
