def insertionsort(A):
    
    for j in range(1,len(A)):
        key = A[j] 

        i = j-1 
        
        while (i > -1) and key < A[i]: 
            A[i+1]=A[i]
            i=i-1 
        
        A[i+1] = key
    return A



if __name__=="__main__":
    x = [5,2,4,6,1,3]
    insertionsort(x)
    print (x)