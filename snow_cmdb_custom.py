#!/bin/env python3

from __future__ import absolute_import, division, print_function

import os
import traceback
import re
from pprint import pprint

from snow_client.snow_cmdb import  OAuthCredentials, SnowApiAuth, SnowTableApi, SnowCmdbCIGenericParser
from snow_client.utils.credentialstore import CredentialsStoreVault

__metaclass__ = type

DOCUMENTATION = r"""
    name: snow_cmdb_custom
    plugin_type: inventory
    short_description: Returns Ansible inventory from Servicenow API
    description: Returns Ansible inventory Servicenow
    options:
      plugin:
          description: snow_cmdb_custom
          required: True
          type: string
          choices: ['snow_cmdb_custom']
      snow_cmdb_classes:
        description: List of locations to pull data from (URL(s) and/or file paths)
        required: True
      iag_vault_password_file:
        description: File containing vault password to decrypt the contents of file specified in -cms_vault_encrypted_file- config
        required: True
      snow_vault_encrypted_oauth_credentials:
        description: File to keep encrypted OAuth credentials to communicate with SNOW instance
        required: False
      snow_instance:
        description: Servicenow instance name
        required: True
      snow_page_limit:
        description: while fetching Snow API, page_limit setting to use per API call.
      snow_concurrent_max_workers:
        description: max_workers configuration for concurrent operation
        required: False
        type: int
      snow_ci_filter:
        description: Filter to be applied on each CI record. - TODO
        required: False
      snow_active_ci_only:
        description: Provide only active CIs from CMDB. the logic of active is coded inside.
        required: False
        type: boolean
    extends_documentation_fragment:
      - inventory_cache
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils._text import to_bytes, to_native, to_text

from ansible.plugins.inventory import BaseInventoryPlugin, Cacheable, Constructable


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = "snow_cmdb_custom"

    def verify_file(self, path):
        """Return true/false if this is possibly a valid file for this plugin
        to consume.

        Args:
            path (TYPE): Description

        Returns:
            TYPE: Description
        """
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current
            # user
            #if os.path.basename(path) == "snow_cmdb_custom.yml":
            #    valid = True
            pass
        return(True)

    def parse(self, inventory, loader, path, cache):
        """Populates the dynamic inventory (either from external data or from
        the cache)

        Args:
            inventory (TYPE): Description
            loader (TYPE): Description
            path (TYPE): Description
            cache (TYPE): Description
        """
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # Although the cache shouldn't be used to populate the inventory when being refreshed,
        # the cache should be updated with the new inventory if the user has enabled caching
        # (see https://docs.ansible.com/ansible/2.9/dev_guide/developing_inventory.html)

        # get the user's cache option to see if it is enabled
        self._read_config_data(path)
        cache_enabled = self.get_option("cache")
        hosts = [] ;
        groups = [];

        inventory_data = None
        if not cache_enabled:
            self.display.verbose(msg=to_text("Caching of inventory is DISABLED"))
            update_cache = False
        else:
            self.display.verbose(msg=to_text("Caching of inventory is ENABLED"))
            # If cache is False it is being refreshed and can therefore be updated
            update_cache = not cache
            # Get unique key for cache
            cache_key = self.get_cache_key(path)

            if not update_cache:
                # Attempt to read inventory from the cache if inventory isn't being refreshed
                try:
                    hosts, groups = inventory_data = self._cache[cache_key]
                    self.display.verbose(
                        msg=to_text(
                            "Retrieved {host_num} host(s) and {grp_num} group(s) from"
                            " the inventory cache.".format(
                                host_num=len(hosts), grp_num=len(groups)
                            )
                        )
                    )
                    if len([host for host in hosts if host != "localhost"]) == 0:
                        # Cached inventory contains no hosts so it needs to be updated
                        self.display.verbose(
                            msg=to_text(
                                "Cache does NOT contain any hosts from external data"
                                " sources (triggering cache update)"
                            )
                        )
                        update_cache = True
                except KeyError:
                    # No cache or cache expired so it needs to be updated
                    self.display.verbose(
                        msg=to_text("Cache empty or expired (triggering cache update)")
                    )
                    update_cache = True

        if update_cache or not cache_enabled:
            # Get new data
            self.display.verbose(msg=to_text("Pulling data from Servicenow..."))
            try:
                
                hosts, groups = inventory_data = self.get_snow_cmdb_records()
                
            except Exception as e:
                self.display.warning(
                    msg=to_text(
                        "Failed to retrieve records from inventory source: {e}".format(
                            e=e
                        )
                    )
                )
            else:
                self.display.verbose(
                    msg=to_text(
                        "Discovered {host_num} host(s) and {grp_num} group(s).".format(
                            host_num=len(hosts), grp_num=len(groups)
                        )
                    )
                )

        if update_cache:
            # Set the cache
            if inventory_data:
                self._cache[cache_key] = inventory_data
                self.display.verbose(
                    msg=to_text("Updated cache with new inventory data successfully")
                )
            else:
                self.display.warning(
                    msg=to_text("Cache update failed (inventory is stale)")
                )
                try:
                    hosts, groups = self._cache[cache_key]
                except KeyError as e:
                    self.display.warning(
                        msg=to_text(
                            "Unable to pull stale cache contents (cache key {e} does"
                            " not exist!)".format(e=e)
                        )
                    )
                    raise

        self.populate(hosts, groups)

   
    # This method can be removed once we migrate to CMS
    def get_snow_cmdb_records(self):
        """Pulls CMDB records from SNOW as per the class details provided in configuration

        Returns:
            TYPE: two itemed array. (hosts, groups)

        Raises:
            AnsibleError: Description
            AnsibleParserError: Description
        """
        encrypted_vault_file = self.get_option("snow_vault_encrypted_oauth_credentials")
        vault_password_file = self.get_option("iag_vault_password_file")

        snow_instance    = self.get_option("snow_instance")
        snow_page_limit = self.get_option("snow_page_limit")
        snow_cmdb_classes = self.get_option("snow_cmdb_classes")

        """ return datatype structure"""
        _hosts = {}; # dict with key: hostname, val: another dict with hostvar:hostval
        _hosts["localhost"] = {
                "ansible_connection": "local",
                "ansible_host": "localhost",
        }
        _groups = {}
            
        container_py_interpreter  = "/opt/app-root/bin/python" ;
        if os.path.isfile(container_py_interpreter):
            _hosts["localhost"]["ansible_python_interpreter"] = container_py_interpreter

        
        try:
            credstore = CredentialsStoreVault(encrypted_vault_file, vault_password_file)
            credentials = OAuthCredentials(json_data=credstore.get_credentials())
            auth = SnowApiAuth(credentials);
            
            auth.refresh_token();
            snow_api = SnowTableApi(snow_instance, auth, page_limit=snow_page_limit)
            ci_parser = SnowCmdbCIGenericParser();

            
            for cmdb_class  in snow_cmdb_classes:
                
                """ add the group mentioned for the class to the inventory"""
                class_group_name = snow_cmdb_classes[cmdb_class].get("groupname","all");
                _groups[class_group_name] = [] 
                #self.inventory.add_group(class_group_name)

                for ci_list in snow_api.get_ci_list(cmdb_class):
                    
                    for ci_data in ci_list:
                        
                        """load current CI record in parser"""
                        ci_parser.ci_details = ci_data
                        # process the records. set hostname, ip address, etc,
                        ci_detail = ci_parser.process_ci_record(snow_cmdb_classes[cmdb_class])

                        if ( ci_detail ):
                            
                            self.display.verbose(msg=to_text("inserting ci %s" % (ci_detail['x_ci_identifier'])) )
                            
                            _hostname = ci_detail.get('x_ci_identifier',None)

                            if ( _hostname == None ):
                                continue

                            # if the user/config not preferred any attrib for ansible_hostname,
                            # lets set our x_ci_identifier as one.
                            
                            if("ansible_hostname" not in ci_detail):
                                ci_detail["ansible_hostname"] = _hostname
                            
                            # remove our meta key for hostname    
                            ci_detail.pop("x_ci_identifier")

                            
                            
                            # """ to align with cache handling, we will defer adding of hosts/groups to later time"""
                            # """ add ci to its class group"""
                            # self.inventory.add_host(host=_hostname, group=class_group_name)
                            _groups[class_group_name].append(_hostname)

                            _safe_hostname = str(_hostname)

                            self.display.debug(msg=to_text("Inserting record: {}".format(_safe_hostname)) );
                                                            
                            if (_safe_hostname not in _hosts.keys()):
                                    
                                _hosts[_safe_hostname] = {}
                                
                            else:
                                """ duplicate variable for record """
                                self.display.warning(msg=to_text("Duplicate CI encountered %s" % (_safe_hostname)))
                                continue
                            
                            for variable, value in ci_detail.items():
                                
                                #self.inventory.set_variable(_hostname, variable, value)
                                
                                if (variable not in _hosts[_safe_hostname].keys()):
                                    
                                    _hosts[_safe_hostname][variable] = value
                                
                                else:
                                    """ duplicate variable for record """
                                    self.display.warning(msg=to_text("Duplicate variable %s" % (variable)))
                                    continue

        except Exception as e:
            self.display.error(to_text(traceback.format_exc()))
            raise AnsibleError(
                "Error while fetching inventory from snow. Exception {e}".format(
                    e=to_native(e)
                )
            )
        
        return ( (_hosts, _groups) )


    def _get_valid_group_name(self, group_name):
        """Summary.
        Make the inventory groupname a valid variable name

        Args:
            group_name (TYPE): Description

        Returns:
            TYPE: Description
        """
        if (not group_name):
            return(group_name);
    
        groupname_invalid_chars = re.compile(r'[\W]',re.I);
        groupname_replace_char = "_"
    
        # replace non-alphanumeric chars with _
        new_group_name = groupname_invalid_chars.sub(groupname_replace_char, group_name) ;
        # prefix any digit in the beginning with _
        new_group_name = re.sub('^(\d)','_\\1',new_group_name);
    
        return(new_group_name)
    

    def populate(self, hosts, groups):
        """Populates inventory.

        Args:
            hosts (TYPE): Description
            groups (TYPE): Description
        """
        if(groups):
            for group, members in groups.items():
                self.inventory.add_group(group)
                for member in members:
                    self.inventory.add_host(host=member, group=group)
        if(hosts):
            for host in hosts:
                self.inventory.add_host(host=host)
                for variable, value in hosts[host].items():
                    self.inventory.set_variable(host, variable, value)
