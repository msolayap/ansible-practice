
from pprint import pprint

picklist = [
    'cat',
    'jimmy',
    'cow',
    'sparrow'
]

inputdict = {
    'cat' : 1,
    'dog' : 1,
    'kitty' : 1,
    'cow' : 2,
    'sparrow': 'brown',
    'jimmy': 'black',
    'pooran': 'small'
}

def mydict_filter(d):
    return ( True if d[0] in picklist else False)

#flist = {k:v for k,v in inputdict.items() if k in picklist}

nflist = dict(filter(mydict_filter, inputdict.items()))
print(nflist)

mylist = [ None, None] 

host = next((val for val in mylist if val is not None), None)

print("host val is : {}".format(host))
