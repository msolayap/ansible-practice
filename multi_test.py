#con_test.py 


import time ;
import atexit;


start = time.perf_counter()
def __atexit():
    end = time.perf_counter();
    print("Finished in {} seconds".format(round(end-start, 2)))
atexit.register(__atexit)


def do_something(du=1):
    print("sleeping for {} seconds".format(du))
    time.sleep(du)
    print("done sleeping {} seconds !!".format(du))

def do_something2(du=1):
    print("sleeping for {} seconds".format(du))
    time.sleep(du)
    return("done sleeping {} seConds !!".format(du))

# sequential execution
#for i in range(0, 5, 1):
#    do_something(i);
    
# parallel execution

#import multiprocessing

#print ("Multiprocessing test ... ");
#plist = []
#for i in range(0,5,1):
#    p = multiprocessing.Process(target=do_something, args=[i])
#    plist.append(p)
#    p.start()
#
#for i in plist:
#    i.join()


print ("Concurrency test ...");
import concurrent.futures

#results = []
#with concurrent.futures.ProcessPoolExecutor() as executor:
#    secs = [5,4,3,2,1]
#   results = [executor.submit(do_something2,i) for i in secs]
#
#    for f in concurrent.futures.as_completed(results):
#        print(f.result())


print ("Concurrency with map ...")

results = []
with concurrent.futures.ProcessPoolExecutor() as executor:
   secs = [5,4,3,2,1]
   results = executor.map(do_something2, secs);

   for result in results:
       print(result);


