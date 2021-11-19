n = int(input("Enter a no. : "))
a = set()

while n>0 :
    ld = n%10
    a.add(ld)
    n = n//10   #   INTEGER Division

print(f"Digits of {n} as a SET : {a}")