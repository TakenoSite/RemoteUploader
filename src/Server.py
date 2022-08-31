from flask import Flask,send_file,request
import sys 

server = Flask("__name__")

file = None
def filePath(Path:str):
    global file
    file = Path

@server.route("/h/arm5")
def download():
    return send_file(file)
    
@server.route("/")
def check():
    print("IP :{ip}".format(ip=request.remote_addr))
    return "Honey pod 1.2.5   Your IP Address -> {}".format(request.remote_addr)
    
