 def main():
    print("Enter a numer :")
    num = int(input())
    print("Sum of digits is :",sumDigits(num))
    
def sumDigits(num):  
    sum = 0
    while (num != 0):       
        sum = sum + (num % 10)
        num = num//10    
    return sum
     

if __name__=='__main__':
    main()