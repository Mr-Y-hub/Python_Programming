import matplotlib.pyplot as plt

dataele = eval(input("Enter the intergers  :  "))
plt.hist(dataele,color='green',histtype='bar')
plt.xlabel('Elements')
plt.ylabel('Frequency')
plt.title('HISTOGRAM')
k=0
m=10
plt.xlim(k,m)
plt.ylim(k,m)
plt.show()