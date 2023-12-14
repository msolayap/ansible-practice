#env python3

from ansible_vault import Vault


filename='vault_access_token' ;
vault = Vault('master123');

with open(filename, 'r') as f :
  print(f.read());

data = vault.load(open(filename).read());

print(data);

print ("Encrypting again with different password");

vault2 = Vault('master234');
vault2.dump(data, open('vault2', 'w'));

print(vault.dump(data));

