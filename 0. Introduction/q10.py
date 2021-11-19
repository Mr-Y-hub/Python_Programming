sen = input("Enter a sentence : ")

freq = {}

for i in sen :

    if i in freq :
        freq[i] += 1

    else :
        freq[i] = 1

print(f"Count of all characters in {sen} is : {str(freq)}")
