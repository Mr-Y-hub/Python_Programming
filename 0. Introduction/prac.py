def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    result = evaluate(ticket)
    # if (result):
    #     print("Valid ticket.")
    # else:
    #     print("Invalid ticket.")
    # ticket.close

main()
