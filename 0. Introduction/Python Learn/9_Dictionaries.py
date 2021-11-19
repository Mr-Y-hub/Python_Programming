atom = { " Yash " : " Patidar ", " Shivanarayan " : " Patidar ", " DurgaPaidar" : " Understand "}
onemore = { "tup":"(1,2,3)"}
print(atom[" Yash "])
print(onemore["tup"])
atom.update({" Van":" Sharma "})
print(atom)
sawan = { 1:2}
atom.update(sawan)
print(atom.get(" Patidar "))
print(atom)
atom.update({" Yash ":" Sharma "})
print(atom)