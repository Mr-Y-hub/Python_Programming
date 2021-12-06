class Student:
    strength = 0
    maxAvgMarks = 0.0

    def __init__(self):
        self.name = ''
        self.marks = [0,0,0]
        Student.strength += 1
        

    def enterDetails(self):
        self.name = input("Enter the Name of Student : ")
        subject = ('DS','PY','OS')

        print("Enter the marks in the following 3 subject :-")
        for i in range(3):
            x = int(input(str(subject[i] + " : ")))
            self.marks[i] = x

        avg = sum(self.marks) / 3

        if avg > Student.maxAvgMarks:
            Student.maxAvgMarks = avg

    def displayDetails(self):
        print("Name : ",self.name)
        print("Marks in Subjects :- ",self.marks)

def main():
    n = int(input("Enter the No of Student : "))
    print()
    StudentList = []

    for i in range(n):
        x = Student()
        x.enterDetails()
        StudentList.append(x)

    print()
    print("Details of Students :- ")

    for i in range(n):
        print("Student ",i+1," :-")
        StudentList[i].displayDetails()
        print()

    print("Maximum Avg marks of Student : ",Student.maxAvgMarks)

main()           
            
