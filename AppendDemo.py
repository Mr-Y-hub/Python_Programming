

def main():
    # Open file for appending data
    outfile = open("info.txt", 'a')
    outfile.write("\nPython is interpreted\n")
    outfile.close()   # Close the file


if __name__ == '__main__':
    main()