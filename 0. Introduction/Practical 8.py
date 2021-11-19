ls = [5,6,7,2,11,155]
print(ls)
size= len(ls)
numeric = string = 0
for i in range(size):
    if type(ls[i])== int or type(ls[i])== float:
        numeric = numeric + 1
    elif type(ls[i]) == str:
        string = string + 1

if numeric == size:
    print("List is numeric")
    count = 0
    for i in range(size):
        if ls[i] % 2 != 0:
            count = count + 1
    print("Number of odd values in list are :", count)
elif string == size:
    print("List contains all strings")
    print("Maximum of the strings is ", max(ls))
else:
    print("List contains both string and numeric elements")
k = size - 1

print("List in reverse order is:", end=" ")
print(ls.reverse())


element = eval(input("Enter the element you want to search: "))
for i in range(size):
    notfound = 0
    if ls[i] == element:
        print("yes, the element is found at ", i+1, " position")
    else:
        notfound = notfound + 1
if notfound== size:
    print("Element not found")

element = eval(input(" Enter an element you want to delete "))
ls.remove(element)
print(element, " is deleted from the list.")

ls.sort(reverse=True)
print("List after descending order sorting is ", ls)

lst1 = input("Enter list 1 elements by a single spacing between the elements: ")
lst2 = input("Enter list 2 elements by a single spacing between the elements: ")
mylist1 = lst1.split()
mylist2 = lst2.split()
mycommon = []
for ch1 in mylist1:
    for ch2 in mylist2:
        if ch1 == ch2:
            mycommon.append(ch1)
print("Common elements in the two list entered is: ", mycommon)