def histogram(l):
    print("\nHistogram: ")
    for n in l:
        output = ''
        times = n
        while(times > 0):
          output += '*'
          times = times - 1
        print(output)
    return

def main():
    l = []
    print("Enter numbers, press -1 to end: ")
    while(1):
        i = int(input())
        if(i == -1):
            break;
        l.append(i)
    histogram(l)
    return

main()