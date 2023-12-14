# -*- coding: utf-8 -*-
"""Summary.

Attributes:
    DOCUMENTATION (TYPE): Description
    thread_local (TYPE): Description
"""
from __future__ import absolute_import, division, print_function

import concurrent.futures
import json
import os
import threading
import time
import traceback
import re
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urlparse
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlunparse

import requests

from requests.adapters import HTTPAdapter

__metaclass__ = type

DOCUMENTATION = r"""
    author: vpk
    name: snow_cmdb
    plugin_type: inventory
    short_description: Inventory source from Servicenow CMDB Instance API
    description:
      - Builds inventory using ServiceNow CMDB instance api
      - using OAuth2 client_credentials grant-type authentication via internal APIGEE
      - Requires a configuration file ending in C(snow_cmdb.yml) or C(snow_cmdb.yaml).
      - The plugin sets host variables denoted by I(columns).
    options:
      plugin:
        description: Name of the servicenow cmdb inventory plugin
        required: true
        choices: ['snow_cmdb']
      vault_password_file:
        description: File containing vault password to decrypt the contents of file specified in -cms_vault_encrypted_file- config
        required: true
      vault_oauth_secrets:
        description: OAuth and APIGEE secrets to be kept in this file.
        required: true
      vault_token_file:
        description: OAuth temporary token storage - to be kept refreshed by some other process
        required: true
      ci_attributes:
        description:
          - List of attributes from CI records to be converted to hostvars
        type: list
        elements: str
        default: [name, host_name, fqdn, ip_address]
      instance:
        description: Servicenow Instance name
        required: true
      cmdb_classes
        description: list of CMDB classes to fetch inventory from
        type: list
        elements: str
        required: false
        default: cmdb_ci_server
    extends_documentation_fragment:
      - inventory_cache
    cache:
      required: false
      default: true
    cache_key:
      required: true
    cache_timeout:
      required: false
      default: 7200
    cache_connection:
      required: true
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.parsing import vault
from ansible.parsing.vault import VaultSecret
from ansible.plugins.inventory import BaseInventoryPlugin, Cacheable, Constructable


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = "snow_cmdb"

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
            if os.path.basename(path) == "snow_cmdb.yml":
                valid = True
        return valid

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

        # Although the cache shouldn’t be used to populate the inventory when being refreshed,
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
            self.display.verbose(msg=to_text("Pulling data from CMDB..."))
            try:
                hosts, groups = inventory_data = self.get_inventory_data()
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

    def get_inventory_data(self):
        """Pulls data from external sources and processes ready for either
        caching or populating the inventory.

        Returns:
            TYPE: Description
        """
        try:
            return self.parse_cms_records(self.get_cms_records())
            # return self.parse_cms_records(self.get_cms_records_multithreaded())
        except :
            self.display.error(to_text(traceback.format_exc()))

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


    def get_requests_session(
        self,
        headers=None,
        skip_cert_validation=True,
        ca_cert_path="",
        timeout=300,
        cms_username="",
        cms_password="",
    ):
        """Summary.

        Args:
            headers (None, optional): Description
            skip_cert_validation (bool, optional): Description
            ca_cert_path (str, optional): Description
            timeout (int, optional): Description
            cms_username (str, optional): Description
            cms_password (str, optional): Description

        No Longer Returned:
            TYPE: Description
        """
        try:
            requests_session = requests.Session()

            if headers is None:
                headers = {
                    "content-type": "application/json",
                    "accept": "application/json",
                    "ApplicationKey" : "cms"
                }

            if skip_cert_validation:
                self.display.verbose("Alert !!***  Skipping cert validation ***");
                requests_session.verify = False
            elif ca_cert_path:
                requests_session.verify = str(ca_cert_path)
                self.display.verbose("Using CA-CERT: {} ".format(str(ca_cert_path)) );

            if headers:
                requests_session.headers = headers

            if timeout:
                requests_session.timeout = timeout

            if cms_username and cms_password:
                requests_session.auth = (cms_username, cms_password)

            # code to handle max retries when certificate check is enabled
            adapter = HTTPAdapter(max_retries=10);
            requests_session.mount('http://', adapter);
            requests_session.mount('https://', adapter);


            return requests_session
        except:
            self.display.warning("Exception at getting request session");
            self.display.error(to_text(traceback.format_exc()))

    def get_cms_auth_token(
        self,
        parsed,
        cms_username,
        cms_password,
        payload=None,
        headers=None,
        ca_cert_path="",
        skip_cert_validation=True,
        timeout=300,
        cms_auth_token_expire_limit=180,
    ):
        """Get cms auth token.

        Args:
            parsed (TYPE): Description
            cms_username (TYPE): Description
            cms_password (TYPE): Description
            payload (None, optional): Description
            headers (None, optional): Description
            ca_cert_path (str, optional): Description
            skip_cert_validation (bool, optional): Description
            timeout (int, optional): Description
            cms_auth_token_expire_limit (int, optional): Description
        """
        try:
            cms_auth_token = None
            cms_auth_session = None

            if not headers:
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "ApplicationKey": "cms",
                }

            cms_auth_session = self.get_requests_session(
                headers,
                skip_cert_validation,
                ca_cert_path,
                timeout,
                cms_username,
                cms_password,
            )

            self.display.verbose(
                msg=to_text(
                    "Retrieving CMS API auth token from url: {url} with username: {cms_username} and timeout: {cms_timeout}".format(
                        url=parsed.geturl(),
                        cms_username=cms_username,
                        cms_timeout=timeout,
                    )
                )
            )

            response = cms_auth_session.post(
                url=parsed.geturl(), data=json.dumps(payload), headers=headers
            )
            self.display.verbose(msg=to_text("Response from Auth URL: {}".format(response.text)));

            # Check for HTTP codes other than 200
            if response.status_code != requests.codes.ok:
                self.display.warning(
                    msg=to_text(
                        "url: {} status_code: {} headers: {} text: {}".format(
                            parsed.geturl(),
                            response.status_code,
                            response.headers,
                            response.text,
                        )
                    )
                )
                # response.raise_for_status()

            if (
                response.status_code == requests.codes.ok
                and response
                and response.json()
            ):
                cms_auth_token = (
                    response.json().get("token", {}).get("access_token", "")
                )
                cms_auth_token_expires_in = (
                    response.json().get("token", {}).get("expires_in", "")
                )

                self.display.verbose(
                    msg=to_text(
                        "cms_auth_token: {} cms_auth_token_expires_in: {}".format(
                            cms_auth_token, cms_auth_token_expires_in
                        )
                    )
                )

                # Determine if the CMS API auth token has expired
                if (
                    cms_auth_token_expires_in
                    and cms_auth_token_expires_in < cms_auth_token_expire_limit
                ):
                    self.display.verbose(
                        msg=to_text(
                            "cms_auth_token_expires_in: {} ... sleeping for: {} before generating new cms_auth_token ... ".format(
                                cms_auth_token_expires_in,
                                cms_auth_token_expire_limit + 15,
                            )
                        )
                    )

                    time.sleep(cms_auth_token_expire_limit + 15)

                    # Get new CMS API auth token as earlier one was close to expiration
                    return self.get_cms_auth_token(
                        parsed,
                        cms_username,
                        cms_password,
                        payload,
                        headers,
                        ca_cert_path,
                        skip_cert_validation,
                        timeout,
                        cms_auth_token_expire_limit,
                    )

                return cms_auth_token, cms_auth_token_expires_in
        except Exception as e:
            self.display.error(to_text(traceback.format_exc()))

    def get_cms_records_data(
        self,
        parsed,
        session,
    ):
        """Get cms records data.

        Args:
            parsed (TYPE): Description
            session (None, optional): Description

        Deleted Parameters:
            cms_auth_token (TYPE): Description
            headers (None, optional): Description
            ca_cert_path (str, optional): Description
            skip_cert_validation (bool, optional): Description
            timeout (int, optional): Description
        """
        try:
            self.display.verbose(
                msg=to_text(
                    "Retrieving CMS API CI data from url: {url}".format(
                        url=parsed.geturl(),
                    )
                )
            )
            # Mark this current link as fetched, so we dont fetch again in second phase
            self.multi_paged_locations[parsed.geturl()] = True;
            response = session.get(url=parsed.geturl())

            # Check for HTTP codes other than 200
            if response.status_code != requests.codes.ok:
                self.display.warning(
                    msg=to_text(
                        "url: {} status_code: {} headers: {} text: {}".format(
                            parsed.geturl(),
                            response.status_code,
                            response.headers,
                            response.text,
                        )
                    )
                )
                # response.raise_for_status()

            page_details = None;
            if (
                response.status_code == requests.codes.ok
                and response
                and response.json()
            ):
                # Read the PageDetails header to see if we are reading a multi-page response.
                page_details = response.headers['PageDetails'] if 'PageDetails' in response.headers else None;
                
                if (page_details):
                    self.display.verbose(msg=to_text("PageDetails  {} of link  {}".format(page_details, parsed.geturl())));
                    # Read the pageDetails header value and get totalPages in it. if its above 1, then we are reading a multi-page response.
                    page_details_dict = json.loads(str(page_details));

                    total_response_pages = page_details_dict.get('totalPages', 1);

                    current_page_number  = page_details_dict.get('pageNumber', 1);
                    # prepare the dynamic urls of further pages in this response and add it to a dict for further reading in next phase

                    if(total_response_pages > 1 and current_page_number == 1):
                        self.display.verbose("Response data multi pages. Preparing dynamic URLs for further pages");
                        for page in range(2,total_response_pages+1):
                            # add/replace pageNumber param to the URL for further fetch

                            query_dict = dict(parse_qs(parsed.query));
                            query_dict['pageNumber'] = [str(page)];
                            next_page_url = urlunparse(
                                (
                                    parsed.scheme,
                                    parsed.netloc,
                                    parsed.path,
                                    parsed.params,
                                    urlencode(query_dict, doseq=True),
                                    None
                                )
                            );

                            self.display.verbose("Next page formed: {}".format(next_page_url));

                            # Append the new location if its not there already
                            if not next_page_url in self.multi_paged_locations:
                               self.multi_paged_locations[next_page_url] = False;
                
                # return the records read out of this link
                data = response.json()

                return data
        except:
            self.display.error(to_text(traceback.format_exc()))


    def get_cms_records(self):
        """Pulls CMS records from URLs/files listed in the locations option.

        Returns:
            TYPE: Description

        Raises:
            AnsibleParserError: Description
        """
        try:
            ca_cert_path = None ;
            cmdb_request_timeout = None ;
            cms_data_session = None
            cms_username = None;
            cms_password = None ;
            locations = self.get_option("locations")
            # variable to track whether a particular location url is fetched. anything not fetched would be fetched again.
            # this is to read responses spanning to multiple pages.
            self.multi_paged_locations = {};
            records = []
            locations_has_http = False
            skip_cert_validation =  None ;
            self.cms_vault_encrypted_file =  None;
            self.iag_vault_password_file  =  None ;


            if isinstance(locations, str):
                locations = [locations]

            elif not isinstance(locations, list):
                raise AnsibleParserError(
                    "Option 'locations' must be a list of URLs and/or file paths or a"
                    " single URLs or file path"
                )

            for location in locations:
                if location and str(location).strip().lower().startswith("http"):
                    locations_has_http = True
                    break


            # If processing CMS location URLs get CMS API auth token and CMS API data session
            if locations_has_http:
                ca_cert_path = self.get_option("ca_cert_path")
                skip_cert_validation = self.get_option("skip_cert_validation")
                cmdb_request_timeout = self.get_option("cmdb_request_timeout")
                cms_username = self.get_option("cms_username")
                cms_password = self.get_option("cms_password")
                self.cms_username = cms_username ;
                self.cms_password = cms_password
                self.cms_vault_encrypted_file = self.get_option("cms_vault_encrypted_file")
                self.iag_vault_password_file  = self.get_option("iag_vault_password_file")

                if not (self.cms_username and self.cms_password):
                    self.get_cms_credentials_from_ansible_vault()
                    cms_username = self.cms_username
                    cms_password = self.cms_password

                if not(self.cms_username and self.cms_password):
                    self.display.error(to_text("Alert !!! CMS username and password was not set in configuration or from vault file: %s" % (self.cms_vault_encrypted_file)));

                headers = {
                    "content-type": "application/json",
                    "accept": "application/json",
                }

                cms_data_session = self.get_requests_session(
                    headers,
                    skip_cert_validation,
                    ca_cert_path,
                    cmdb_request_timeout,
                    cms_username,
                    cms_password
                )

            if locations_has_http:
                for location in locations:
                    self.multi_paged_locations[urlparse(location).geturl()] = False;

            # Phase 1 locations fetching
            # Fetch the locations read from configuration
            for location in locations:
                try:
                    data = []
                    if locations_has_http:
                        parsed = urlparse(location)
                        # Retrieve CMS CI data using provided data location URL
                        data = self.get_cms_records_data(parsed, cms_data_session)
                    else:
                        data = self.get_records_from_file(location) or []

                    if data and isinstance(data, list):
                        records += data
                    elif data and isinstance(data, str):
                        records.append(data)
                except:
                    self.display.error(to_text(traceback.format_exc()))

            for (location,state) in self.multi_paged_locations.items():
                if(state == False):
                    try:
                        data = []
                        parsed = urlparse(location)
                        # Retrieve CMS CI data using provided dynamically formed location URL
                        self.display.verbose("Fetching Multi page response : {}".format(parsed.geturl()));
                        data = self.get_cms_records_data(parsed, cms_data_session)

                        if data and isinstance(data, list):
                            records += data
                        elif data and isinstance(data, str):
                            records.append(data)
                    except:
                        self.display.error(to_text(traceback.format_exc()))

            return records
        except:
            self.display.error(to_text(traceback.format_exc()))


    def get_device_hostname_from_cms_record(self, record):
        """Get device hostname from cms record.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        try:
            # Get device hostname
            device_hostname = ""
            if record.get("name", ""):
                device_hostname = record.get("name", "").lower()
            elif record.get("assetTag", ""):
                device_hostname = record.get("assetTag", "").lower()
            elif record.get("fqdn", ""):
                device_hostname = record.get("fqdn", "").lower()

            device_hostname = to_text(device_hostname)
            return device_hostname
        except:
            self.display.error(to_text(traceback.format_exc()))


    def parse_cms_records(self, records):
        """description: Function to parse incoming CI record
        Args:
            records (TYPE): Description

        Returns:
            TYPE: Description
        """
        self.exclude_devices_with_cmdb_status = self.get_option("exclude_devices_with_cmdb_status")
        if(not records):
            return(None, None)
        try:
            groups = {}
            self.display.verbose(
                msg=to_text(
                    "Record 1: processing 'localhost' (this Ansible Control Machine)"
                )
            )

            hosts = {
                "localhost": {
                    "ansible_connection": "local",
                    "ansible_host": "localhost",
                }
            }
            container_py_interpreter  = "/opt/app-root/bin/python" ;
            if os.path.isfile(container_py_interpreter):
                hosts["localhost"]["ansible_python_interpreter"] = container_py_interpreter

            for record_index, record in enumerate(records or []):
                if record:
                    try:
                        device_hostname = self.get_device_hostname_from_cms_record(
                            record
                        )
                        device_ip_address = ""
                        device_cmdb_status = ""

                        if not device_hostname or len(device_hostname) < 5:
                            self.display.warning(
                                msg=to_text(
                                    "Record {n}: invalid name '{name}' found (skipping"
                                    " {name}) record: {record_text}".format(
                                        n=record_index,
                                        name=device_hostname,
                                        record_text=to_text(record),
                                    )
                                )
                            )
                        else:
                            self.display.verbose(
                                msg=to_text(
                                    "Record {n}: processing '{device_hostname}'".format(
                                        n=record_index, device_hostname=device_hostname
                                    )
                                )
                            )

                            # Retrieve the device primary IP Address
                            device_ip_address = (
                                self.get_device_ip_address_from_cms_record(record) or ""
                            )
                            if not device_ip_address:
                                self.display.warning(
                                    msg=to_text(
                                        "Record {n}: No primary IP address found"
                                        " (skipping {device_hostname})".format(
                                            n=record_index,
                                            device_hostname=device_hostname,
                                        )
                                    )
                                )
                            else:
                                # Add device CMDB status
                                device_cmdb_status = (
                                    self.get_device_cmdb_status_from_cms_record(record)
                                    or ""
                                )
                                if (
                                    device_cmdb_status
                                    and device_cmdb_status.lower().strip()
                                    not in self.exclude_devices_with_cmdb_status
                                ):
                                    hosts.setdefault(device_hostname, {})[
                                        "cmdb_status"
                                    ] = device_cmdb_status

                                    # Add device IP Address
                                    hosts.setdefault(device_hostname, {})[
                                        "ansible_host"
                                    ] = device_ip_address

                                    # Add device macaddress
                                    device_mac_address = (
                                        self.get_device_mac_address_from_cms_record(
                                            record
                                        )
                                        or ""
                                    )
                                    if device_mac_address:
                                        hosts.setdefault(device_hostname, {})[
                                            "macaddress"
                                        ] = device_mac_address

                                    # Create groups and add hosts
                                    group_names = (
                                        self.get_device_sites_from_cms_record(record)
                                        or []
                                    )
                                    for group_name in group_names:
                                        groups.setdefault(group_name, set()).add(
                                            device_hostname
                                        )
                                else:
                                    self.display.warning(
                                        msg=to_text(
                                            "Record {n}: Excluding device due to CMDB status (skipping {device_hostname} with cmdb_status: {device_cmdb_status})".format(
                                                n=record_index,
                                                device_hostname=device_hostname,
                                                device_cmdb_status=device_cmdb_status,
                                            )
                                        )
                                    )
                    except:
                        self.display.warning(
                            msg=to_text(
                                "Exception while trying to process record_index: {}"
                                " record: {} exception: {}".format(
                                    record_index,
                                    to_text(record),
                                    to_text(traceback.format_exc()),
                                )
                            )
                        )

            # Remove any hosts that do not an IP/device_ip_address
            hosts = {k: v for (k, v) in hosts.items() if "ansible_host" in v.keys()}
            self.display.verbose(msg=to_text("hosts: {}".format(hosts)))

            # Create a unique list of groups for valid host names and convert the hosts set array to list
            all_device_hostnames = list(set(hosts.keys()))
            groups = {
                k: list(v.intersection(all_device_hostnames))
                for (k, v) in groups.items()
                if k and v and v.intersection(all_device_hostnames)
            }

            self.display.verbose(
                msg=to_text("all_device_hostnames: {}".format(all_device_hostnames))
            )

            self.display.verbose(msg=to_text("groups: {}".format(groups)))

            return (hosts, groups)
        except Exception as e:
            self.display.error(to_text(traceback.format_exc()))
    
    