def inpLen() :

    a = int(input("Enter side 1 length : "))
    b = int(input("Enter side 2 length : "))
    c = int(input("Enter side 3 length : "))

    assert a+b > c and a+c > b and b+c > a

    peri = a+b+c
    sp = peri/2
    area = pow((sp*(sp-a)*(sp-b)*(sp-c)), 0.5)

    tup = (peri, area)
    print(f"Perimeter and Area respectively are {tup}")

def main() :

    inpLen()

main()
