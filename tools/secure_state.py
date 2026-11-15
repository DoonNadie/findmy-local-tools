"""AES-256-GCM local state; random key lives in macOS Keychain, never argv/files."""
import os, subprocess, tempfile, hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import STATE,TOOLS
MAGIC=b'FMLT1\x00'
_key=None

def key():
    global _key
    if _key is None:
        helper=STATE/'resources/keychain-key'
        expected=(STATE/'resources/keychain-helper.sha256').read_text().strip()
        if helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest()!=expected:
            raise RuntimeError('Keychain helper integrity check failed')
        r=subprocess.run([str(helper)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        if r.returncode or len(r.stdout)!=32:raise RuntimeError('macOS Keychain unavailable; no plaintext fallback')
        _key=r.stdout
    return _key

def logical_path(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('State path traversal rejected')
    path.relative_to(STATE)
    for ancestor in [path,*path.parents]:
        if ancestor==STATE.parent:break
        if ancestor.is_symlink():raise ValueError('State symlink ancestor rejected')
    return path

def sealed_path(path):
    return Path(str(logical_path(path))+'.aesgcm')

def aad(path):return str(logical_path(path).relative_to(STATE)).encode()
def exists(path):return sealed_path(path).is_file()
def read_bytes(path):
    p=sealed_path(path)
    if p.is_symlink():raise ValueError('Encrypted-state symlink rejected')
    raw=p.read_bytes()
    if not raw.startswith(MAGIC):raise ValueError('Invalid encrypted-state format')
    n=len(MAGIC)
    return AESGCM(key()).decrypt(raw[n:n+12],raw[n+12:],aad(path))
def read_text(path):return read_bytes(path).decode()
def write_bytes(path,data):
    p=sealed_path(path)
    p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if p.is_symlink():raise ValueError('Encrypted-state symlink rejected')
    nonce=os.urandom(12)
    raw=MAGIC+nonce+AESGCM(key()).encrypt(nonce,data,aad(path))
    fd,tmp=tempfile.mkstemp(prefix='.sealed-',dir=p.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def entries(directory,suffix):
    return [Path(str(p)[:-7]) for p in Path(directory).glob('*'+suffix+'.aesgcm')]
