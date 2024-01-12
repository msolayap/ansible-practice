import logging

# Ansbile libraries
from ansible.parsing import vault
from ansible.parsing.vault import VaultSecret
from ansible.module_utils._text import to_bytes

from abc import ABC, abstractmethod

class CredentialsStore(ABC):
    """abstract class for Credentials Storage/retrieval"""

    
    def __init__(self):
        pass
    
    @abstractmethod
    def get_credentials(self):
        pass

class CredentialsStoreVault(CredentialsStore):
    """Class to provide methods to read credentials stored in ansible_vault format.
    
    This is concrete implementation of CredentialsStore class
    The idea is to provide many implementations of CredentialsStore
    """

    def __init__(self, vault_file, vault_key_file):

        self._vault_file =  vault_file;
        self._vault_key_file = vault_key_file

    def get_credentials(self):
        try:
            with open(self._vault_key_file, "r") as vkf:
                vault_password = vkf.read();
            
            with open(self._vault_file, "r") as vf:
                encrypted_data = vf.read()
                                
                vault_ref = vault.VaultLib(
                    [("default", VaultSecret(_bytes=to_bytes(vault_password.strip())))]
                )
                
                decrypted_data = vault_ref.decrypt(encrypted_data.strip())

                if(decrypted_data != None):
                    return (decrypted_data);
    
        except Exception as e:

            logging.exception("Cannot Open vault_file %s", self._vault_file)