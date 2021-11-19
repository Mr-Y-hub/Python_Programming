

def maxPer(stud, per) :

    mp = max(per)
    c = 0

    for i in per :

        if i == mp :
            print(f"Max. percentage is {mp} which is obtained by {stud[c]}")

        else :
            c += 1

n = int(input("Enter no. of students : "))
lstud = []
lsub = []
lper = []

print()

print("Enter Students Names : ")
for i in range(n) :
    m = input(f"Enter Student {i+1} name : ")
    lstud.append(m)

print()

print("Enter 4 Subject Names : ")
for i in range(4) :
    m = input(f"Enter Subject {i+1} name : ")
    lsub.append(m)

print()

for j in lstud :

    sum = 0
    per = 0

    lmarks = []

    print(f"Entries for {j} : ")
    print()

    for i in range(4) :
        m = int(input(f"Enter marks obtained in {lsub[i]} : "))
        lmarks.append(m)
        sum += m
    
    print(f"Marks Details of {j} : {dict(zip(lsub, lmarks))}")
    print()

    per = (sum/400) * 100
    lper.append(per)

maxPer(lstud, lper)     