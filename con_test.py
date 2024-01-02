#con_test.py 


import time ;
import atexit;


start = time.perf_counter()
def __atexit():
    end = time.perf_counter();
    print("Finished in {} seconds".format(round(end-start, 2)))
atexit.register(__atexit)


def do_something2(du=1):
    print("sleeping for {} seconds".format(du))
    time.sleep(du)
    return("done sleeping {} seConds !!".format(du))

print ("Concurrency with map ...")

results = []
with concurrent.futures.ProcessPoolExecutor() as executor:
   secs = [5,4,3,2,1]
   results = executor.map(do_something2, secs);

   for result in results:
       print(result);


