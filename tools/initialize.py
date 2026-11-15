"""Explicit local setup. No network downloads and no automatic key export."""
import argparse, hashlib, json, os, platform, plistlib, shutil, subprocess, sys, uuid, zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from config import STATE,TOOLS
import secure_state as vault
from findmy import FindMyAccessory


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--libs',type=Path,required=True,help='Reviewed local ZIP with libstoreservicescore.so and libCoreADI.so')
    p.add_argument('--accessory',type=Path,action='append',required=True,help='Own exported accessory JSON (repeatable)')
    args=p.parse_args()
    if platform.system()!='Darwin':raise RuntimeError('macOS only')
    if STATE.exists() and (STATE.is_symlink() or STATE.stat().st_mode & 0o077):
        raise RuntimeError('State directory must be private (0700) and not a symlink')
    if not args.libs.is_file() or args.libs.stat().st_size>32000000:raise ValueError('Local library bundle missing or too large')
    with zipfile.ZipFile(args.libs) as z:
        for name in ['libstoreservicescore.so','libCoreADI.so']:
            if name not in z.namelist() or z.getinfo(name).file_size>32000000:raise ValueError('Unexpected library bundle layout')
    data=[]
    destination_ids=set()
    for file in args.accessory:
        d=json.loads(file.read_text());FindMyAccessory.from_json(d)
        identity=d.get('identifier')
        if not identity or identity in destination_ids:raise ValueError('Each accessory requires a distinct nonempty identifier')
        destination_ids.add(identity);data.append(d)
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    resources=STATE/'resources'
    vault.logical_path(resources)
    resources.mkdir(mode=0o700,exist_ok=True)
    for name in ['keychain-key','keychain-helper.sha256','apple-local-libs.zip','apple-local-libs.sha256']:
        vault.logical_path(resources/name)
    helper=resources/'keychain-key'
    expected=resources/'keychain-helper.sha256'
    if helper.exists():
        if not expected.exists() or hashlib.sha256(helper.read_bytes()).hexdigest()!=expected.read_text().strip():
            raise RuntimeError('Existing helper has no matching pin; review before rebuilding')
    else:
        subprocess.run(['swiftc',str(TOOLS/'keychain_key.swift'),'-o',str(helper)],check=True)
        subprocess.run(['codesign','--force','--sign','-','--identifier','org.findmy-local-tools.keychain-helper',str(helper)],check=True)
        helper.chmod(0o700)
        expected.write_text(hashlib.sha256(helper.read_bytes()).hexdigest()+'\n')
    if not any(STATE.rglob('*.aesgcm')):
        r=subprocess.run([str(helper),'--create'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        if r.returncode or len(r.stdout)!=32:raise RuntimeError('Keychain creation failed; unlock/approve locally')
    vault.key() # Never generate a replacement key when encrypted state exists.
    lib=resources/'apple-local-libs.zip'
    if lib.exists() and lib.read_bytes()!=args.libs.read_bytes():raise RuntimeError('Refusing to replace existing libraries')
    shutil.copyfile(args.libs,lib) if args.libs.resolve()!=lib.resolve() else None
    lib.chmod(0o600)
    (resources/'apple-local-libs.sha256').write_text(hashlib.sha256(lib.read_bytes()).hexdigest()+'\n')
    profile=STATE/'device-profile.toml'
    if not vault.exists(profile):
        def value(*cmd):return subprocess.check_output(cmd,text=True).strip()
        info=plistlib.loads(Path('/System/Library/Frameworks/CFNetwork.framework/Resources/Info.plist').read_bytes())
        sw={'model':value('sysctl','-n','hw.model'),'os_version':value('sw_vers','-productVersion'),'build':value('sw_vers','-buildVersion'),'cfnetwork_version':info['CFBundleVersion'],'darwin_version':value('uname','-r')}
        text='[device]\ndevice_uuid = '+json.dumps(str(uuid.uuid4()).upper())+'\n\n[software]\n'
        text+=''.join(k+' = '+json.dumps(v)+'\n' for k,v in sw.items())
        vault.write_bytes(profile,text.encode())
    for d in data:
        identity=d['identifier']
        name='accessory-'+hashlib.sha256(identity.encode()).hexdigest()[:16]+'.json'
        vault.write_bytes(STATE/'keys'/name,json.dumps(d).encode())
    print('Setup complete. Imported accessories are encrypted; source JSON files were not deleted.')
    print('Run query_locations.py in a terminal for account authentication. No key export was performed.')

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('Setup failed:',type(error).__name__,file=sys.stderr)
        raise SystemExit(1)
