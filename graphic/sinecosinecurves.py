import matplotlib.pyplot as plt
import math

def sine_curve():
    # y = sin(degree)
    degrees = [x for x in range(0,360+1)]
    y = [math.sin(math.radians(i)) for i in degrees]
    plt.subplot(2,2,1)
    plt.plot(y)
    plt.xlabel('x')
    plt.ylabel('sin(x)')
    plt.title('y = sin(x)')

def cosine_curve():
    # y = cos(degree)
    degrees = [x for x in range(0,360+1)]
    y = [math.cos(math.radians(i)) for i in degrees]
    plt.subplot(2,2,3)
    plt.plot(y)
    plt.xlabel('x')
    plt.ylabel('cos(x)')
    plt.title('y = cos(x)')

def poly_curve():
    # y = x**2
    x = [i for i in range(10+1)]
    y = [i**2 for i in x]
    plt.subplot(2,2,2)
    plt.plot(y)
    plt.xlabel('x')
    plt.ylabel('x^2')
    plt.title('y = x^2')

def exp_curve():
    # y = Exp(x)
    x = [i for i in range(10+1)]
    y = [math.exp(i) for i in x]
    plt.subplot(2,2,4)
    plt.plot(y)
    plt.xlabel('x')
    plt.ylabel('exp(x)')
    plt.title('y = exp(x)')

def main():

    sine_curve()
    cosine_curve()
    exp_curve()
    poly_curve()
    plt.tight_layout()
    plt.show()

main()