t1 = (1,2,5,7,9,2,4,6,8,10)
t1_list = list(t1)



t2_list = []

for i in t1 :

    if i%2 == 0 :
        t2_list.append(i)

t2 = tuple(t2_list)
print(f"Even nos. in {t1} = {t2}")



t2 = (11,13,15)
t2_list = list(t2)

t3_list = t1_list + t2_list
t3 = tuple(t3_list)

print(f"{t1} + {t2} = {t3}")


m1 = max(t1_list)
m2 = min(t1_list)

print(f"Max. value in {t1} is {m1}")
print(f"Min. value in {t1} is {m2}")