def operations(choice):
    strng = input("Enter string:")
    if choice == 1:
        return len(strng)
    elif choice == 2:
        strng2 = input("Enter First string:")
        strng3 = input("Enter Second string:")
        return max(strng,strng2,strng3)
    elif choice ==3:
        vowels="AEIOUaeiou"
        k="#"
        for ele in vowels:
            strng = strng.replace(ele, k)
        return strng
    elif choice== 4:
        words= str.split(strng)
        return len(words)
    else:
        l=0
        h = len(strng)-1
        while l<len(strng)/2:
            if strng[l] != strng[h]:
                return "Not palindrome"
            l= l+1
            h= h-1
        return "Given String is Palindrome"

def main():
    print("Choose one of the following:")
    print("1. To find the length of string.")
    print("2. To return maximum of three strings.")
    print("3. To replace all vowels with“#”")
    print("4. To find number of words in the given string.")
    print("5. To check whether the string is a palindrome or not")
    choice = eval(input())
    if choice in range(1,6):
        print(operations(choice))
    else:
        print("Enter valid choice.")


if __name__=='__main__':
    main()