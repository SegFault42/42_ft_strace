import sys

file = open("./syscall_tbl", "r");
syscall_tbl = file.read()

syscall_tbl = syscall_tbl.split('\n')

def to_upper(oldList):
    newList = []
    for element in oldList:
        element = element.replace(' ', '_')
        element = element.replace('*', 'PTR')
        newList.append(element.upper())
        newList[0] = newList[0].lower()
    return newList

def body():
    for i in syscall_tbl:
        i = i.split(', ')
        i = to_upper(i)
        for a in i:
            sys.stdout.write(a + ', ')
        print ''
    print i

body()
