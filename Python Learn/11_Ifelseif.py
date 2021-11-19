num = int( input("Enter any number"))
print("* "*num)
for i in range (num-2):
    print("*"+" "*((num-2)*2+1)+"*")
print("* "*num)

# * * * * *
# *       *
# *       *
# *       *
# * * * * *