

inputvals =  ["1", 1,  "true", "yes", "0", 0, "false", "no", -1, [], {}]

import re

true_expression = re.compile(r'^(1|true|yes)$', re.IGNORECASE)
false_expression = re.compile(r'^(0|false|no)$', re.IGNORECASE)

for v in inputvals:
    
    if true_expression.match(str(v)):
        print("True")
    elif false_expression.match(str(v)):
        print("False")
    else:
        print("None")


host = input("Enter hostname: ")
print( re.search(r'[^a-z\-.0-9]', host, re.IGNORECASE) );




