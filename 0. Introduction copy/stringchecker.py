#  def main():
#     str1 = (input("Enter a string"))
#     str2 = (input("Enter a string"))
#     func(str1,str2)
# def func(str1,str2):  
#     count =0
#     for i in str1 :
        
     

# if __name__=='__main__':
#     main()
str='yaash'

# for i in range(0, len(str)):  
#     count = 0
#     for j in range(i,0,-1):  
#         if(str[i] == str[j]):  
#             print("yash",i,j)
#             break
        
string1="yaash" 
string2="yaassssssh" 
count=0
if(len(string1)<len(string2)): 
	for i in string1: 
		if(i in string2): 
			count=count+1
else: 
	for i in string2: 
		if(i in string1): 
			count=count+1
print("Common character are:",count) 
