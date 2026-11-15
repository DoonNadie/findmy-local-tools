import Foundation
import Security
let base: [String:Any] = [kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"org.findmy-local-tools.encrypted-state.v1",kSecAttrAccount as String:"state-aes256-key",kSecAttrSynchronizable as String:false]
let loginPath=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Keychains/login.keychain-db").path
var login:SecKeychain?
guard SecKeychainOpen(loginPath,&login)==errSecSuccess, let loginKeychain=login else {
    fputs("Login Keychain unavailable; no fallback\n",stderr);exit(5)
}
var query=base
query[kSecMatchSearchList as String]=[loginKeychain]
query[kSecReturnData as String]=true
query[kSecMatchLimit as String]=kSecMatchLimitOne
var item:CFTypeRef?
var status=SecItemCopyMatching(query as CFDictionary,&item)
if status==errSecItemNotFound && CommandLine.arguments.contains("--create") {
    var bytes=[UInt8](repeating:0,count:32)
    guard SecRandomCopyBytes(kSecRandomDefault,bytes.count,&bytes)==errSecSuccess else { exit(2) }
    var add=base
    add[kSecUseKeychain as String]=loginKeychain
    add[kSecValueData as String]=Data(bytes)
    add[kSecAttrLabel as String]="FindMy Local Tools — encrypted state"
    status=SecItemAdd(add as CFDictionary,nil)
    guard status==errSecSuccess else { fputs("Keychain creation failed (\(status))\n",stderr);exit(3) }
    status=SecItemCopyMatching(query as CFDictionary,&item)
}
guard status==errSecSuccess, let data=item as? Data, data.count==32 else {
    fputs("Keychain access failed (\(status)); no plaintext fallback\n",stderr);exit(4)
}
FileHandle.standardOutput.write(data)
