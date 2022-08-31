# RemoteUploader

Upload to a specific web server and run remotely

# Details of this vulnerable
        
1: check()
        rhosts={target_host} # Target host
        rports={target_port} # Target port
                
https://github.com/TakenoSite/Simple-CVE-2021-36260
       


# Module

1: RemoteUploader.ServerModule()

        lport:int, # Pleass 0x01 ~ 0xff in range  
        lhost:str, # Your IP address 
        Path:str   # File path


2: RemoteUploader.UploadModule()

        lhost:str,       # Local IP or Global IP
        lport:int,       # Download server port
        rhost:list,      # Target rhost in list only 
        rport:int,       # Target port
        ThreadNum=1,     # Thread enabled for multiple targets
        execution=False, # True if it is an executable 
        delete=False,    # Delete files after execution
        Tor=False        # Tor Netwoek 
        
