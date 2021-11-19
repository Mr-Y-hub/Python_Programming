num=0
pos=0
neg=0
zer=0
while num != -1 :
    num = int(input("\n Enter a Number"))
    if num > 0:
        pos=pos+1
    elif num == 0:
        zer=zer+1
    else:
        neg=neg+1

print("Positive Numbers:"+str(pos))
print("Negative Numbers:"+str(neg))
print("Number of Zeros :"+str(zer))



