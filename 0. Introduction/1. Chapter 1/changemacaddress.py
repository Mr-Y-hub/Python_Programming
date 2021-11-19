import subprocess
if __name__ == "__main__":
    interface="eth0"
    newmac="00:13:33:92:34"
    
    print("[+] Shutting down the interface ...")
    subprocess.run(["ifconfig",interface,"down"])
    
    print("[+] Changing the interface hw address of ",interface,"to",newmac)
    subprocess.run(["ifconfig",interface,"hw","ether",newmac])
    
    print("[+] MAC address changed to ", newmac)
    subprocess.run(["ifconfig",interface,"up"])
    print("[+] Network interface turned on")
    
    