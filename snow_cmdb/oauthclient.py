
import time
import json ;
from datetime import datetime
from pprint import pprint


class OAuthToken:
    """Class to hold Token information and provides verification methods for the validity of the token
    Args:
        token: actual token string
        token_expires_in: validity of token in seconds from the token generation time - e.g 300 = 5 minutes
        token_fetched_at: token reception time or current time.
        token_type: type of token - default Bearer

    Returns:
        OAuthToken Object

    EXAMPLES:

    token_response = b"
    {
        "token_type": "Bearer",
        "expires_in": 3599,
        "ext_expires_in": 3599,
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi",
    }
    "
    td =  json.loads(token_response) ;

    token = OAuthToken(
            token=td['access_token'],
            token_expires_in=td['expires_in'], 
            token_fetched_at=datetime.now(), 
            token_type=td['token_type']
            );

    print("Token {}".format(("expired" if token.is_expired() == True else "valid")));

    print(token.get_token_type());
"""

    def __init__(self, 
                 token:str, 
                 token_expires_in:int=0, 
                 token_fetched_at=datetime.now(),
                 token_type:str="Bearer"):
        
        self.access_token = token ;
        self.token_expires_in = token_expires_in

        self.expiry_timestamp = int(token_fetched_at.timestamp()) + int(token_expires_in);
        self.token_type = token_type
    
    def get_access_token(self):
        return(self.access_token)
        
    def get_expires_in(self):
        return self.token_expires_in
        
    def get_token_type(self):
        return self.token_type
    
    def get_token_fetched_at(self):
        return self.token_fetched_at 

    def is_expired(self, by_time=datetime.now()):
        """Method to verify the token's validity. i.e if its expired or valid. 
        
        Parameters:
            by_time: int
                a timestamp to compare the token's expiry time against. 
                by default this is current time.
        Returns: bool
            True - if the token expired
            False - token not expired or still valid.

        """
        print("by_time: {}, expiry: {}".format(by_time.ctime(), 
                                               datetime.fromtimestamp(self.expiry_timestamp).ctime())
        );

        if(self.expiry_timestamp <= by_time.timestamp()):
            """Token expired"""
            return(True);
        else:
            """Token still valid"""
            return(False);
                

class OAuthClient:
    def __init__(self):
        pass
    def acquire_token(self):
        pass


token_response = b"""
{
    "token_type": "Bearer",
    "expires_in": 3599,
    "ext_expires_in": 3599,
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi"
}
"""
td =  json.loads(token_response) ;

token = OAuthToken(
        token=td['access_token'],
        token_expires_in=td['expires_in'], 
        token_fetched_at=datetime.fromtimestamp(1702470013), 
        token_type=td['token_type']
        );

print("Token {}".format(("expired" if token.is_expired() == True else "valid")));

print(token.get_token_type());