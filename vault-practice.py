#!env python3

# This file will read a vault data pythonically, modifies a portion of the data and 
# write the data to the vault file again with same secret.

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils._text import to_text, to_bytes, to_native
from ansible.parsing import vault
from ansible.parsing.vault import VaultSecret
import time
import json
import pprint ;
from datetime import datetime

vault_password_file="./passfile"
vault_file="vault_access_token"

print("Imports successful");

decrypted_data = None;
encrypted_data = None;
vault_password = None;

with open(vault_file, "r") as vf:
  encrypted_data = vf.read();

with open(vault_password_file, "r") as vpf:
  vault_password = vpf.read();

vault_ref = vault.VaultLib(
  [("default", VaultSecret(_bytes=to_bytes(vault_password.strip())))]
);

#TODO: decrypt can be passed with filenamE
if(vault.is_encrypted(encrypted_data)):
	decrypted_data = vault_ref.decrypt(encrypted_data.strip());

token_data = None;

if(decrypted_data != None):
	token_data = json.loads(decrypted_data);


#pprint.pprint(token_data);

token_fetched_at =  token_data['fetched_time'];


current_ts = int(time.time());

if(int(token_fetched_at) < int(current_ts)):
  print ("token valid");
else:
  print("token expired");

token_data['fetched_time'] = current_ts ;

token_data_json = json.dumps(token_data, indent=4);

encrypted_data = vault_ref.encrypt(token_data_json, secret=VaultSecret(_bytes=to_bytes(vault_password.strip())));

with open(vault_file, "w") as vf:
  vf.write(to_text(encrypted_data));

print ("Vault written with new timestamp");
