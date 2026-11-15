"""Credential-free local Anisette proof. No library downloads or public server."""
import argparse, json, logging, os, tempfile, types, signal, tomllib, io, sys, hashlib
from pathlib import Path
from urllib.parse import urlparse
sys.path.insert(0,str(Path(__file__).resolve().parent))
import secure_state as vault
from anisette import Anisette
import anisette.anisette as anisette_impl
_original_get_libs=anisette_impl._get_libs

def local_only_libs(file=None):
    if file is None or (isinstance(file,str) and '://' in file):
        raise ValueError("Implicit or remote library download forbidden")
    return _original_get_libs(file)
anisette_impl._get_libs=local_only_libs


def main():
    os.umask(0o077)
    signal.alarm(45)
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--headers", action="store_true")
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args()
    config = None
    if args.profile:
        from anisette._device import AnisetteDeviceConfig
        profile = tomllib.loads(vault.read_text(args.profile))
        sw = profile["software"]; device = profile["device"]
        config = AnisetteDeviceConfig.default()
        config.unique_device_id = device["device_uuid"]
        config.server_friendly_description = f'<{sw["model"]}> <macOS;{sw["os_version"]};{sw["build"]}> <com.apple.AuthKit/1 (com.apple.akd/1.0)>'
    if not args.apk.is_file() or args.apk.is_symlink():
        raise ValueError("Reviewed local APK required")
    if args.state.is_symlink():
        raise ValueError("State must not be a symlink")
    args.state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    pin=(vault.STATE/'resources/apple-local-libs.sha256').read_text().strip()
    if hashlib.sha256(args.apk.read_bytes()).hexdigest()!=pin:
        raise ValueError("Runtime library checksum mismatch")
    ani = Anisette.load(io.BytesIO(vault.read_bytes(args.state))) if vault.exists(args.state) else Anisette.init(args.apk, default_device_config=config)
    session = ani._ani_provider.provisioning_session
    def request(self, method, url, extra_headers, data=None, cache_key=None):
        parsed = urlparse(url)
        if parsed.scheme != "https" or not (parsed.hostname == "apple.com" or (parsed.hostname or "").endswith(".apple.com")) or parsed.username or parsed.password or parsed.port not in (None,443):
            raise ValueError("Non-Apple HTTPS endpoint rejected")
        headers = self._ProvisioningSession__headers | extra_headers
        response = self._http.request(method,url,body=data,headers=headers,timeout=10.0,redirect=False,retries=False)
        if response.status != 200 or len(response.data) > 2000000:
            raise ValueError("Unexpected Apple provisioning response")
        return response.data
    session._request = types.MethodType(request, session)
    headers = ani.get_data()
    required = ("X-Apple-I-MD", "X-Apple-I-MD-M")
    if not all(headers.get(k, "").strip() for k in required):
        raise ValueError("Empty local identity")
    buffer=io.BytesIO()
    ani.save_all(buffer)
    vault.write_bytes(args.state,buffer.getvalue())
    if args.headers:
        print(json.dumps(headers))  # private subprocess pipe only, never a diagnostic log
    else:
        print(json.dumps({"local_identity_nonempty":True,"account_credentials_used":False,"public_anisette_used":False}))

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Local Anisette probe failed: " + type(error).__name__)
        raise SystemExit(1)
