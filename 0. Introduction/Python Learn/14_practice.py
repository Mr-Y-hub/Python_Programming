p = 3
n = int(input("Enter a number"))
for i in range(n,2,-1):
    for j in range(i,2,-1):
        if i/j==0 :
            p=1
    if (p==1):
        pass
    else:
        print(n)

