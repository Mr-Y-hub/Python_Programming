def binarySearch(l,key):
  low = 0
  high = len(l)-1
  while high>low:
    mid  = (low+high)//2
    if key<l[mid]:
      high = mid-1
    elif key==l[mid]:
      return mid
    else:
      low=mid+1
  return -low-1

list2 = [2,1,7,11,1,5,50,59,60,6,99,75,86]
i = binarySearch(list2,2)
j = binarySearch(list2,11)
k = binarySearch(list2,12)
l = binarySearch(list2,1)
m = binarySearch(list2,3)
print(i,j,k,l,m)