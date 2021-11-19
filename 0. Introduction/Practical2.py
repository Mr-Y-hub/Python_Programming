def totalSales(weeklyS):
    data = []
   
    monthlyS = sum(weeklyS)
    data.append(monthlyS)

    if data[0] > 50000:
        data.append(5/100*data[0])
    else:
        data.append(0)
    if data[0] > 80000:
        data.append("Excellent")
    elif data[0] > 60000:
        data.append("Good")
    elif data[0] > 40000:
        data.append("Average")
    else:
        data.append("Work Hard")

    print("Total sales:", data[0])
    print("Commission:", data[1])
    print("Remarks:", data[2])


def main():
    weeklyS = []
    for i in range(4):
        print("Enter the sales done in week ", i+1, ":")
        weeklyS.append(eval(input()))

    totalSales(weeklyS)


if __name__ == '__main__':
    main()
