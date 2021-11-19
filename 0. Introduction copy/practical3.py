def factorial(x):
    fact = 1
    for i in range(1, x+1):
        fact = fact*i
    return fact


def function(n):   
    a = 0
    b = 1
    if n < 0:
        print("Incorrect input")
    elif n == 0:
        return a
    elif n == 1:
        return b
    else:
        for i in range(2, n):
            c = a + b
            a = b
            b = c
        return b
        


def main():
    n = eval(input("Enter the value of n:"))
    ls=[]
    ls.append(function(n))
    ls.append(factorial(n))
    print(ls)

if __name__ == '__main__':
    main()