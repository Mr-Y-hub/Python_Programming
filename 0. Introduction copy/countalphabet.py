import randdd
def main():
    
    chars = createList()
    print("The lowercase letters are:")
    displayList(chars)

    
    counts = countLetters(chars)

    
    print("The occurrences of each letter are:")
    displayCounts(counts)


def countLetters(chars):

    counts = 26 * [0]


    for i in range(len(chars)):
        counts[ord(chars[i]) - ord('a')] += 1

    return counts



def displayCounts(counts):
    for i in range(len(counts)):
        if (i + 1) % 10 == 0:
            print(counts[i], chr(i + ord('a')))
        else:
            print(counts[i], chr(i + ord('a')), end=' ')

def createList():

    chars = []


    for i in range(100):
        chars.append(randdd.getRandomLowerCaseLetter())


    return chars



def displayList(chars):

    for i in range(len(chars)):
        if (i + 1) % 20 == 0:
            print(chars[i])
        else:
            print(chars[i], end=' ')

main()  

