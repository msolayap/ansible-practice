#python


# date time and hashlib hmacsha256 test script.

import time
import hashlib 
import hmac

epochTime = str(int(time.time())).encode();
api_key = b"APPKEY759512020091415435175420415"

print ( "type of epochTime: %s, api_key: %s" % (type(epochTime), type(api_key)))
x_digest = hmac.new(api_key, epochTime, digestmod=hashlib.sha256).hexdigest(); 

print ("x-digest ", x_digest)