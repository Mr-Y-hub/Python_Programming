def fac(n) :
    
    prod = 1

    for i in range(1, n+1) :
        prod *= i

    return prod

def sumSeries(n, x) :

    sum = 0

    for i in range(n+1) :

        if i%2 == 0 :
            sum += pow(x, 2*i) / fac(2*i)

        else :
            sum -= pow(x, 2*i) / fac(2*i)

    return sum

def main() :

    n = int(input("Enter limit : "))
    x = int(input("Enter value of 'x' : "))

    print(sumSeries(n, x))

main()