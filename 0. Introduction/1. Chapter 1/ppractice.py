from subprocess import Popen, PIPE
import os
dir=os.getcwd()
os.system("g++ question.cpp -o quest")
pp=dir+"./quest"
p=Popen([pp],stdout=PIPE,stdin=PIPE)
pay="4"*10000
output  = p.communicate(bytes(pay))
print(output)

