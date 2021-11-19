unsorted_list = [20, 7, 3, 4, 12, 15, 2, 1]

def selection_sort(a):
	for j in range(len(a)-1):
		minimum = j
		for i in range(j+1, len(a)):
			if(a[i]<a[minimum]):
				minimum = i 
		a[j],a[minimum]=a[minimum],a[j]
	print("after selection sort:")
	print(a)

selection_sort(unsorted_list)

