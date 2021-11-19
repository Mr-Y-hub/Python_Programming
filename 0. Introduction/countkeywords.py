import os.path
import sys

def main():
    keyWords = {"and", "as", "assert", "break", "class",
        "continue", "def", "del", "elif", "else",
        "except", "False", "finally", "for", "from",
        "global", "if", "import", "in", "is", "lambda",
        "None", "nonlocal", "not", "or", "pass", "raise",
        "return", "True", "try", "while", "with", "yield"}
    
    test="yes you and me as assert break this situation"

    text = test.split()

    count = 0
    for word in text:
        if word in keyWords :
            count += 1
 
    print("The number of keywords in", count)
 
main()