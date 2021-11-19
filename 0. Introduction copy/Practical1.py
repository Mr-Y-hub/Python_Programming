import math

def triangle(side1, side2, side3):
    assert side1+side3 >= side2 and side2+side3 >= side1 and side1+side2 >= side3,'Third side is greater than the sum of first and second '
    perimeter = side2 + side1 + side3
    s = (perimeter/2)
    area = (math.sqrt(s*(s-side1)*(s-side2)*(s-side3)))
    ls = [perimeter, area]
    return ls

def main():
    side1 = (input("Enter first side:"))
    side2 = eval(input("Enter first side:"))
    side3 = eval(input("Enter first side:"))
    print(triangle(side1, side2, side3))
    
if __name__ == '__main__':
    main()