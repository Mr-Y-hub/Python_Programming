def linearSearch(l,key):
  for i in range(len(l)):
    if key==l[i]:
      return i
  return -1

list1 = [1,5,3,2,-1,-3,7,2]
i = linearSearch(list1,4)
j = linearSearch(list1,-4)
k = linearSearch(list1,-3)
print(i,j,k)