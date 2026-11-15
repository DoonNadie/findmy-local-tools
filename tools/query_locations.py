"""Query owner's AirTags using local Anisette; never persist account password."""
import asyncio, getpass, json, logging, os, subprocess, sys, tempfile, plistlib, tomllib, base64, fcntl
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
from findmy import FindMyAccessory
from findmy.reports.account import AsyncAppleAccount
from findmy.reports.anisette import BaseAnisetteProvider
from findmy.reports.state import LoginState
from findmy.reports.twofactor import SmsSecondFactorMethod
from findmy.util.http import HttpSession

sys.path.insert(0,str(Path(__file__).resolve().parent))
import secure_state as vault
from config import STATE,TOOLS
SESSION=STATE/'reports_session.json'
RESULT=STATE/'latest_locations.json'

def private_json(path,data):
    vault.write_bytes(path,json.dumps(data).encode())

class LocalPipe(BaseAnisetteProvider):
    def __init__(self):
        super().__init__()
        self.data={}
    @property
    def otp(self):return self.data['X-Apple-I-MD']
    @property
    def machine(self):return self.data['X-Apple-I-MD-M']
    @property
    def client(self):return self.data['X-MMe-Client-Info']
    async def get_headers(self,*args,**kwargs):
        cmd=[sys.executable,'-I',str(TOOLS/'local_anisette_probe.py'),'--apk',str(STATE/'resources/apple-local-libs.zip'),'--state',str(STATE/'local-ani/export-state.bin'),'--profile',str(STATE/'device-profile.toml'),'--headers']
        r=await asyncio.to_thread(subprocess.run,cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=50)
        if r.returncode or len(r.stdout)>65536:raise RuntimeError('Local identity failed')
        self.data=json.loads(r.stdout)
        return await super().get_headers(*args,**kwargs)
    def to_json(self,*args):return {'type':'localPipe'}
    @classmethod
    def from_json(cls,*args,**kwargs):return cls()
    async def close(self):pass

# Preserve TLS validation; forbid redirects and non-Apple endpoints.
original_request=HttpSession.request
async def apple_request(self,method,url,**kwargs):
    p=urlparse(url)
    if p.scheme!='https' or not ((p.hostname or '').endswith('.apple.com') or (p.hostname or '').endswith('.icloud.com')) or p.username or p.password or p.port not in (None,443):
        raise ValueError('Non-Apple HTTPS endpoint rejected')
    auth=kwargs.pop('auth',None)
    if auth is not None:
        login,secret=auth if isinstance(auth,tuple) else (auth.login,auth.password)
        headers=dict(kwargs.get('headers',{}))
        headers['Authorization']='Basic '+base64.b64encode((str(login)+':'+secret).encode()).decode()
        kwargs['headers']=headers
    kwargs['allow_redirects']=False
    return await original_request(self,method,url,**kwargs)
HttpSession.request=apple_request

def mobileme_status(data):
    delegate=data.get("delegates",{}).get("com.apple.mobileme",{})
    status=delegate.get("status")
    return data.get("status") if status is None else status

class QueryAccount(AsyncAppleAccount):
    async def _login_mobileme(self):
        # Preserve reusable tokens before delegate negotiation; no raw password saved.
        saved=self.to_json();saved["account"]["password"]=None
        private_json(SESSION,saved)
        body={"apple-id":self._username,"delegates":{"com.apple.mobileme":{}},"password":self._login_state_data["idms_pet"],"client-id":self._uid}
        headers={"X-Apple-ADSID":self._login_state_data["adsid"],"User-Agent":"com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0","X-Mme-Client-Info":"<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"}
        await self.get_anisette_headers()
        headers.update(self._anisette.data)
        profile=tomllib.loads(vault.read_text(STATE/'device-profile.toml'))
        sw=profile['software']
        headers['User-Agent']=f"com.apple.iCloudHelper/282 CFNetwork/{sw['cfnetwork_version']} Darwin/{sw['darwin_version']}"

        response=await self._http.post(self._ENDPOINT_LOGIN_MOBILEME,auth=(self._username or "",self._login_state_data["idms_pet"]),data=plistlib.dumps(body),headers=headers)
        data=response.plist()
        status=mobileme_status(data)
        if status != 0:
            
            delegate=data.get("delegates",{}).get("com.apple.mobileme",{})
            print("Delegate response structure:",list(data.keys()),"delegate fields:",list(delegate.keys()),file=sys.stderr)
            raise RuntimeError("MobileMe delegate status=" + str(status) + " HTTP="+str(response.status_code))
        delegate=data.get("delegates",{}).get("com.apple.mobileme",{})
        return self._set_login_state(LoginState.LOGGED_IN,{"dsid":data["dsid"],"mobileme_data":delegate["service-data"]})

async def main():
    os.umask(0o077);logging.disable(logging.CRITICAL)
    lock_fd=os.open(STATE/'.query.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    query_lock=os.fdopen(lock_fd,'a+b')
    try:fcntl.flock(query_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        query_lock.close()
        raise RuntimeError('A location query is already running')
    saved=json.loads(vault.read_text(SESSION)) if vault.exists(SESSION) else None
    if saved:saved['account']['password']=None
    account=QueryAccount(LocalPipe(),state_info=saved)
    try:
        if account.login_state==LoginState.AUTHENTICATED:
            await account._login_mobileme()
        if account.login_state!=LoginState.LOGGED_IN:
            if not sys.stdin.isatty():raise RuntimeError('Interactive login required; run this script in a terminal')
            print('FindMy query: credentials stay in this terminal; tokens are saved encrypted, not the account password.',file=sys.stderr)
            print('Apple ID: ',end='',file=sys.stderr,flush=True)
            user=sys.stdin.readline().strip();password=getpass.getpass('Password: ')
            if not user or not password:raise ValueError('Empty credentials')
            status=await account.login(user,password);password=None
            if status==LoginState.REQUIRE_2FA:
                methods=await account.get_2fa_methods()
                methods=sorted(methods,key=lambda m:not isinstance(m,SmsSecondFactorMethod))
                for i,m in enumerate(methods):print(i,'SMS' if isinstance(m,SmsSecondFactorMethod) else 'Trusted device',file=sys.stderr)
                print('2FA method [0, SMS preferred]: ',end='',file=sys.stderr,flush=True)
                choice=sys.stdin.readline().strip();method=methods[int(choice or '0')]
                await method.request()
                await method.submit(getpass.getpass('2FA code: '))
            if account.login_state!=LoginState.LOGGED_IN:raise RuntimeError('Login incomplete')
        account._password=None
        mapping=account.to_json();mapping['account']['password']=None
        private_json(SESSION,mapping)
        accessories=[]
        for p in vault.entries(STATE/'keys','.json'):
            data=json.loads(vault.read_text(p))
            if data.get('name'):
                accessories.append(FindMyAccessory.from_json(data))
        if not accessories:raise RuntimeError('No imported accessories')
        results=[]
        for accessory in accessories:
            report=await account.fetch_location(accessory)
            row={'name':accessory.name,'found':report is not None}
            if report:
                row.update(timestamp=report.timestamp.isoformat(),latitude=report.latitude,longitude=report.longitude,accuracy_m=report.horizontal_accuracy)
            results.append(row)
        private_json(RESULT,{'queried_at':datetime.now(timezone.utc).isoformat(),'results':results})
        if '--json' in sys.argv:
            print(json.dumps({'queried_at':datetime.now(timezone.utc).isoformat(),'results':results},ensure_ascii=False))
        print('Query completed; encrypted result saved.',file=sys.stderr)
        for row in results:print(row['name'],row.get('timestamp','No reports returned'),file=sys.stderr)
    finally:
        await account.close()
        query_lock.close()

if __name__=='__main__':
    if '--help' in sys.argv or '-h' in sys.argv:
        print('Usage: python -I tools/query_locations.py [--json]\nQueries imported accessories; authenticate interactively when required.')
        raise SystemExit(0)
    try:asyncio.run(main())
    except Exception as error:
        print('Query stopped:',type(error).__name__,file=sys.stderr)
        if str(error).startswith(('MobileMe delegate status=', 'Error response for GSA request:')):
            print(str(error),file=sys.stderr)
        raise SystemExit(1)
