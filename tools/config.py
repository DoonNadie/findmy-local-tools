"""Public configuration; state stays outside the Git checkout by default."""
import os
from pathlib import Path
REPO=Path(__file__).resolve().parent.parent
TOOLS=REPO/'tools'
STATE=Path(os.environ.get('FINDMY_TOOLS_HOME',str(Path.home()/'Library/Application Support/findmy-local-tools'))).expanduser()
if not STATE.is_absolute() or '..' in STATE.parts:
    raise ValueError('FINDMY_TOOLS_HOME must be an absolute path without ..')
