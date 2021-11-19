def main():
    s = "YashPatidar"
    print ("The original string  is : ",end="")
    print (s)  
    print ("The reversed string is : ",end="")
    print (reverse(s))

def reverse(s):
        str = ""
        for i in s:
            str = i + str
        return str
  
if __name__=='__main__':
    main()