
import time

def generator():
    for i in range(6):
        yield (i*5);
        time.sleep(5);


myiter = generator();

while(i = next(myiter)):
    print(i)