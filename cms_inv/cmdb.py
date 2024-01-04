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
    name: cmdb
    plugin_type: inventory
    short_description: Returns Ansible inventory from CMDB API
    description: Returns Ansible inventory from CMDB API
    options:
      plugin:
          description: Name of the plugin
          required: true
          choices: ['cmdb']
      locations:
        description: List of locations to pull data from (URL(s) and/or file paths)
        required: true
      ca_cert_path:
        description: Path to CA certificate file
        required: false
      skip_cert_validation:
        description: Validate SSL certificate (yes/no)
        required: true
        type: bool
      cms_password:
        description: Password for CMS API
        required: false
      cms_username:
        description: Username for CMS API
        required: false
      iag_vault_password_file:
        description: File containing vault password to decrypt the contents of file specified in -cms_vault_encrypted_file- config
        required: false
      cms_vault_encrypted_file:
        description: Alternate to providing username/password, CMS API credentials can be kept in a vault file.
        required: false
      cms_url_auth:
        description: CMS Auth URL
        required: false
      cmdb_request_timeout:
        description: timeout for API
        required: false
      cms_number_of_threads:
        description: thread count for cms api call
        required: false
        type: int
      exclude_devices_with_cmdb_status:
        description: CMDB device exclusions
        required: false
    extends_documentation_fragment:
      - inventory_cache
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.parsing import vault
from ansible.parsing.vault import VaultSecret
from ansible.plugins.inventory import BaseInventoryPlugin, Cacheable, Constructable

thread_local = threading.local()


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):



    NAME = "cmdb"

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
            if os.path.basename(path) == "cmdb_config.yml":
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

    # This method can be removed once we migrate to CMS
    def get_cmdb_records(self):
        """Pulls CMDB records from URLs/files listed in the locations option.

        Returns:
            TYPE: Description

        Raises:
            AnsibleError: Description
            AnsibleParserError: Description
        """
        ca_cert_path = self.get_option("ca_cert_path")
        skip_cert_validation = self.get_option("skip_cert_validation")
        locations = self.get_option("locations")
        cmdb_request_timeout = self.get_option("cmdb_request_timeout")

        if isinstance(locations, str):
            locations = [locations]
        elif not isinstance(locations, list):
            raise AnsibleParserError(
                "Option 'locations' must be a list of URLs and/or file paths or a"
                " single URLs or file path"
            )

        session = None
        records = []
        for location in locations:
            parsed = urlparse(location)
            if parsed.scheme in ["http", "https"]:
                if not session:
                    session = requests.Session()
                    if skip_cert_validation:
                        session.verify = False
                    elif ca_cert_path:
                        session.verify = str(ca_cert_path)
                # Hit API
                try:
                    # timeout = 120
                    timeout = cmdb_request_timeout
                    req = requests.Request("GET", parsed.geturl()).prepare()
                    self.display.verbose(
                        msg=to_text(
                            "Retrieving dynamic CMDB records (using {t} second"
                            " timeout): {method} {url}".format(
                                method=req.method, url=req.url, t=timeout
                            )
                        )
                    )
                    res = session.send(req, timeout=timeout)
                    res.raise_for_status()
                except Exception as e:
                    raise AnsibleError(
                        "Error while fetching inventory from {url}. Exception {e}".format(
                            url=to_text(location), e=to_native(e)
                        )
                    )
                data = res.json()
            else:
                # Read file
                self.display.verbose(
                    msg=to_text(
                        "Retrieving static CMDB records: FILE {path}".format(
                            path=location
                        )
                    )
                )
                with open(location, "r") as f:
                    content = f.read()
                    try:
                        data = json.loads(content)
                    except Exception:
                        raise AnsibleError(
                            "Error parsing JSON file {file}".format(file=location)
                        )

            if isinstance(data, list):
                records += data
            else:
                records.append(data)
        return records

    # This method can be removed once we migrate to CMS
    def process_cmdb_records(self, records):
        """Extracts required data from CMDB records and transforms it in to a
        tuple containing hosts and groups.

        Sample record format:
            {
                "name": "S639527DC3VL101",
                "status": [
                    {
                        "source": "EDGE",
                        "status": "Active"
                    }
                ]
                "ipAddresses": [
                    {
                        "id": 1117511,
                        "value": "10.102.65.30",
                        "primary": true
                    }
                ],
                "site": [
                    {
                        "logicalName": "S639527",
                        "type": "OWNER"
                    },
                    {
                        "logicalName": "ZZDC3",
                        "type": "PHYSICAL"
                    }
                ]
            }

        Args:
            records (TYPE): Description

        Returns:
            TYPE: Description
        """

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

        for index, record in enumerate(records, start=1):
            if record:
                try:
                    record_num = index + 1

                    # Retrieve the device hostname from CMDB record
                    inventory_hostname = ""
                    if record.get("name", ""):
                        inventory_hostname = record.get("name", "").lower()
                    elif record.get("hostName", ""):
                        inventory_hostname = record.get("hostName", "").lower()
                    inventory_hostname = to_text(inventory_hostname)

                    if not inventory_hostname or len(inventory_hostname) < 5:
                        self.display.warning(
                            "Record {n}: invalid name '{name}' found (skipping {name})"
                            " record: {record_text}".format(
                                n=record_num,
                                name=inventory_hostname,
                                record_text=to_text(record),
                            )
                        )
                        continue

                    self.display.verbose(
                        msg=to_text(
                            "Record {n}: processing '{inventory_hostname}'".format(
                                n=record_num, inventory_hostname=inventory_hostname
                            )
                        )
                    )

                    # Retrieve the device primary IP Address from CMDB record
                    ansible_host = ""
                    if record.get("ipAddresses", []):
                        ansible_hosts = [
                            item.get("value", "")
                            for item in record.get("ipAddresses", []) or []
                            if item.get("primary", False) and item.get("value", "")
                        ]
                        ansible_host = ansible_hosts[0] if ansible_hosts else ""

                    if not ansible_host and record.get("managementIp", ""):
                        ansible_host = record.get("managementIp", "")

                    ansible_host = to_text(ansible_host)

                    if not ansible_host:
                        self.display.warning(
                            "Record {n}: No primary IP address found (skipping"
                            " {inventory_hostname})".format(
                                n=record_num, inventory_hostname=inventory_hostname
                            )
                        )
                        continue

                    # If inventory_hostname not in hosts add hostname and ipaddress to hosts. Perform check in case of duplicate records.
                    if not hosts.get(inventory_hostname, {}).get("ansible_host", ""):
                        hosts.setdefault(inventory_hostname, {})[
                            "ansible_host"
                        ] = ansible_host
                        hosts.setdefault(inventory_hostname, {})["cmdb_status"] = ""
                    # else:
                    #     self.display.warning("Record {record_num}: IP address {ansible_host} already present (skipping host {inventory_hostname}))".format(n=record_num, inventory_hostname=inventory_hostname, ansible_host=ansible_host))

                    # CMDB component status
                    if record.get("status", []) and not hosts.get(
                        inventory_hostname, {}
                    ).get("cmdb_status", ""):
                        cmdb_statuses = [
                            status.get("status", "")
                            for status in record.get("status", []) or []
                            if status.get("source", "") == "VANTIVE"
                            and status.get("status", "")
                        ]
                        cmdb_status = to_text(cmdb_statuses[0] if cmdb_statuses else "")
                        if cmdb_status:
                            hosts.setdefault(inventory_hostname, {})[
                                "cmdb_status"
                            ] = cmdb_status

                    # Ownership Vantive siteID: Create groups & add hosts if data is present
                    group_names = self._get_ownership_site(record) or []
                    [
                        groups.setdefault(
                            self._get_valid_group_name(group_name), set()
                        ).add(inventory_hostname)
                        for group_name in group_names
                    ]

                    # Physical Vantive siteID: Create groups & add hosts if data is present
                    group_names = self._get_physical_site(record) or []
                    [
                        groups.setdefault(
                            self._get_valid_group_name(group_name), set()
                        ).add(inventory_hostname)
                        for group_name in group_names
                    ]

                except:
                    self.display.warning(
                        "Exception while trying to process record_num: {} record: {}"
                        " exception: {}".format(
                            record_num, to_text(record), to_text(traceback.format_exc())
                        )
                    )

        # Remove any hosts that have a cmdb_status and not an IP/ansible_host
        hosts = {k: v for (k, v) in hosts.items() if "ansible_host" in v.keys()}

        # Create a unique list of groups for valid host names and convert the hosts set array to list
        all_hosts = hosts.keys()
        groups = {
            k: list(v.intersection(all_hosts))
            for (k, v) in groups.items()
            if k and v and v.intersection(all_hosts)
        }

        return (hosts, groups)

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

    # This method can be removed once we migrate to CMS
    def _get_ownership_site(self, record):
        """Summary.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        return [
            site.get("logicalName", "")
            for site in record.get("site", []) or []
            if site.get("type", "") == "OWNER" and site.get("logicalName", "")
        ]

    # This method can be removed once we migrate to CMS
    def _get_physical_site(self, record):
        """Summary.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        return [
            site.get("logicalName", "")
            for site in record.get("site", []) or []
            if site.get("type", "") == "PHYSICAL" and site.get("logicalName", "")
        ]

    # This method can be removed once we migrate to CMS
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

    def get_records_from_file(self, location):
        """Get records from file.

        Args:
            location (TYPE): Description

        Raises:
            AnsibleError: Description
        """
        try:
            # Read file
            if os.path.isfile(location):
                self.display.verbose(
                    msg=to_text(
                        "Retrieving static CMDB records: FILE {path}".format(
                            path=location
                        )
                    )
                )

                with open(location, "r") as f:
                    content = f.read()
                    try:
                        data = json.loads(content)
                    except Exception:
                        raise AnsibleError(
                            "Error parsing JSON file {file}".format(file=location)
                        )
            else:
                self.display.warning(
                    msg=to_text(
                        "Missing file: {} ... skipping data file load".format(location)
                    )
                )
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
            cms_username = None ;
            cms_password = None ;
            cms_url_auth = None ;
            cms_auth_token = None
            cms_auth_token_expires_in = 0
            cms_data_session = None
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
                cms_url_auth = self.get_option("cms_url_auth")
                cms_username = self.get_option("cms_username")
                cms_password = self.get_option("cms_password")
                self.cms_vault_encrypted_file = self.get_option("cms_vault_encrypted_file")
                self.iag_vault_password_file  = self.get_option("iag_vault_password_file")

                if not (cms_username and cms_password):
                    self.get_cms_credentials_from_ansible_vault()
                    cms_username = self.cms_username
                    cms_password = self.cms_password

                if not(self.cms_username and self.cms_password):
                    self.display.error(to_text("Alert !!! CMS username and password was not set in configuration or from vault file: %s" % (self.cms_vault_encrypted_file)));

                headers = {
                    "content-type": "application/json",
                    "accept": "application/json",
                    "applicationkey": "cms",
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

    # This method can be removed once we migrate to CMS
    def get_device_hostname_from_cmdb_record(self, record):
        """Get device hostname from cmdb record.

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
            elif record.get("hostName", ""):
                device_hostname = record.get("hostName", "").lower()

            device_hostname = to_text(device_hostname)
            return device_hostname
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

    # This method can be removed once we migrate to CMS
    def get_device_ip_address_from_cmdb_record(self, record):
        """Get device ip address from cmdb record.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        try:
            # Get device primary IP Address
            device_ip_address = ""

            # Process CMDB API record data format
            if record.get("ipAddresses", []):
                device_ip_addresses = [
                    item.get("value", "")
                    for item in record.get("ipAddresses", []) or []
                    if item.get("primary", False) and item.get("value", "")
                ]
                device_ip_address = (
                    device_ip_addresses[0] if device_ip_addresses else ""
                )

                if not device_ip_address and record.get("managementIp", ""):
                    device_ip_address = record.get("managementIp", "")

            device_ip_address = to_text(device_ip_address)
            return device_ip_address
        except:
            self.display.error(to_text(traceback.format_exc()))

    def get_device_ip_address_from_cms_record(self, record):
        """Get device ip address from cms record.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        try:
            device_ip_address = ""
            device_ip_addresses = []

            # Process CMS record data format
            if record.get("ciInterfaces", []):
                for item in record.get("ciInterfaces", []) or []:
                    if (
                        item.get("type", "")
                        and item.get("type", "").lower() in ["primary"]
                        and item.get("ipAddressV4", "")
                    ):
                        device_ip_addresses.append(item.get("ipAddressV4", ""))

            # Get IP address from relationships
            if not device_ip_addresses and record.get("relationships", []):
                for relationships_item in record.get("relationships", []) or []:
                    for item in relationships_item.get("ciInterfaces", []) or []:
                        if (
                            item.get("type", "")
                            and item.get("type", "").lower() in ["primary"]
                            and item.get("ipAddressV4", "")
                        ):
                            device_ip_addresses.append(item.get("ipAddressV4", ""))

            device_ip_address = device_ip_addresses[0] if device_ip_addresses else ""

            device_ip_address = to_text(device_ip_address)
            return device_ip_address
        except:
            self.display.error(to_text(traceback.format_exc()))

    # This method can be removed once we migrate to CMS
    def get_device_cmdb_status_from_cmdb_record(self, record):
        """Get device cmdb status from cmdb record.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        try:
            # Get device CMDB status
            device_cmdb_status = ""
            for status in record.get("status", []):
                if status.get("source", "") == "VANTIVE" and status.get("status", ""):
                    device_cmdb_status = status.get("status", "")
                    break

            device_cmdb_status = to_text(device_cmdb_status)
            return device_cmdb_status
        except:
            self.display.error(to_text(traceback.format_exc()))

    def get_device_cmdb_status_from_cms_record(self, record):
        """Get device cmdb status from cms record.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        try:
            # Get device CMDB status
            device_cmdb_status = ""
            if (
                record.get("primarySource", "")
                and record.get("primarySource", "").upper() == "VANTIVE"
                and record.get("status", "")
            ):
                device_cmdb_status = record.get("status", "")
                device_cmdb_status = to_text(device_cmdb_status)
                return device_cmdb_status
        except:
            self.display.error(to_text(traceback.format_exc()))

    # This method can be removed once we migrate to CMS
    def get_device_sites_from_cmdb_record(self, record):
        """Get device sites from cms record.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        try:
            # Get device sites
            device_site_names = set()
            for site in record.get("site", []) or []:
                if (
                    site.get("type", "")
                    and site.get("type", "") in ["OWNER", "PHYSICAL"]
                    and site.get("logicalName", "")
                ):
                    device_site_names.add(site.get("logicalName", ""))

            return list(device_site_names)
        except:
            self.display.error(to_text(traceback.format_exc()))

    def get_device_sites_from_cms_record(self, record):
        """Get device sites from cms record.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        try:
            # Get device CMDB status
            device_site_names = set()

            for record_site in record.get("site", []):
                if (
                    record_site.get("relType", "").strip()
                    and record_site.get("relType", "").strip().upper()
                    in [
                        "PHYSICAL",
                        "OWNERSHIP",
                    ]
                    and record_site.get("sourceId", "")
                ):
                    device_site_names.add(
                        self._get_valid_group_name(record_site.get("sourceId", ""))
                    )

            return list(device_site_names)
        except:
            self.display.error(to_text(traceback.format_exc()))

    def get_device_mac_address_from_cms_record(self, record):
        """Get device mac address from cms record.

        Args:
            record (TYPE): Description

        Returns:
            TYPE: Description
        """
        try:
            # Get device mac address
            return record.get("macAddress", "")
        except:
            self.display.error(to_text(traceback.format_exc()))

    def parse_cms_records(self, records):
        """Extracts required data from CMDB records and transforms it in to a
        tuple containing hosts and groups.

        Sample record format:
            {
                "id": 485671,
                "name": "DC3LOGSERV1.NA.MSMPS.NET",
                "ciClass": "Server",
                "ciSubClass": "Virtual",
                "assetTag": "",
                "primarySource": "Vantive",
                "description": "",
                "status": "Installed",
                "serialNumber": "",
                "modelNumber": "",
                "macAddress": "",
                "recordQualityScore": "-1",
                "vendor": "",
                "mostRecentDiscovery": null,
                "operationalStatus": "",
                "productModelId": 558,
                "serviceId": 38227,
                "nodeId": -1,
                "federalFlag": false,
                "fqdn": "",
                "tags": "",
                "installedDate": "2020-05-05 00:00:00",
                "decomDate": null,
                "productModel": {
                    "id": 558,
                    "name": "SAVVIS Hosting Server",
                    "version": "VIHN",
                    "group": "SAVVIS Hosting Server",
                    "manufacturer": "Unknown Vendor for Conversion",
                    "modelNumber": "SHS",
                    "shortDescription": "SHS"
                },
                "product": {
                    "id": 1,
                    "name": "Custom Managed Server",
                    "version": "1.0"
                },
                "service": {
                    "id": 38227,
                    "sourceId": "873874",
                    "status": "Active",
                    "productId": 1,
                    "billingSite": {
                        "id": 431,
                        "sourceId": "BILLTO",
                        "name": "SAVVIS Generic Billing Site",
                        "type": "Customer",
                        "relId": null,
                        "relType": "Billing",
                        "parentSiteId": 0,
                        "amId": null,
                        "busOrgId": null,
                        "glmId": "PL0001247655",
                        "federalFlag": false,
                        "departmentName": "POR000000000312",
                        "departmentNumber": "POR000000000312",
                        "departmentId": "328198E6-5CB3-4A8D-929D-C3650BCB3A11",
                        "invoiceDisplay": null,
                        "billingModelId": null,
                        "organizationName": "Savvis",
                        "organizationNumber": "0050568A-0120-11E3-E4CA-5005707CD9CC"
                    },
                    "parentService": null
                },
                "site": [
                    {
                        "id": 286,
                        "sourceId": "ZZDC3",
                        "name": "Cyxtera",
                        "type": "Data Center",
                        "relId": 528152,
                        "relType": "Physical",
                        "parentSiteId": 0,
                        "amId": null,
                        "busOrgId": null,
                        "glmId": "PL0000060366",
                        "federalFlag": false,
                        "departmentName": "Savvis",
                        "departmentNumber": "POR000000000312",
                        "departmentId": "328198E6-5CB3-4A8D-929D-C3650BCB3A11",
                        "invoiceDisplay": null,
                        "billingModelId": null,
                        "organizationName": "Savvis",
                        "organizationNumber": "0050568A-0120-11E3-E4CA-5005707CD9CC"
                    },
                    {
                        "id": 431,
                        "sourceId": "BILLTO",
                        "name": "SAVVIS Generic Billing Site",
                        "type": "Customer",
                        "relId": 11046094,
                        "relType": "Billing",
                        "parentSiteId": 0,
                        "amId": null,
                        "busOrgId": null,
                        "glmId": "PL0001247655",
                        "federalFlag": false,
                        "departmentName": "POR000000000312",
                        "departmentNumber": "POR000000000312",
                        "departmentId": "328198E6-5CB3-4A8D-929D-C3650BCB3A11",
                        "invoiceDisplay": null,
                        "billingModelId": null,
                        "organizationName": "Savvis",
                        "organizationNumber": "0050568A-0120-11E3-E4CA-5005707CD9CC"
                    },
                    {
                        "id": 1625,
                        "sourceId": "S606840",
                        "name": "SAVVIS IT - Hosting Infrastructure",
                        "type": "Customer",
                        "relId": 528153,
                        "relType": "Ownership",
                        "parentSiteId": 0,
                        "amId": null,
                        "busOrgId": null,
                        "glmId": "PL0001247655",
                        "federalFlag": false,
                        "departmentName": "Savvis",
                        "departmentNumber": "POR000000000312",
                        "departmentId": "328198E6-5CB3-4A8D-929D-C3650BCB3A11",
                        "invoiceDisplay": null,
                        "billingModelId": null,
                        "organizationName": "Savvis",
                        "organizationNumber": "0050568A-0120-11E3-E4CA-5005707CD9CC"
                    }
                ],
                "customer": {
                    "id": 851,
                    "name": "SAVVIS",
                    "type": "Customer",
                    "sourceId": "135848",
                    "ultimateCustomerNumber": "1-AEU-307-UC"
                },
                "serverConfig": {
                    "id": 43414,
                    "type": "Virtual",
                    "chassisType": "",
                    "cpuName": "",
                    "cpuCoreCount": 0,
                    "cpuCoreThread": 0,
                    "cpuCount": 0,
                    "cpuSpeed": "",
                    "cpuType": "",
                    "diskSpace": "",
                    "ram": "",
                    "cpuManufacturer": "",
                    "virtualMachine": {
                        "id": 43413,
                        "esxHost": "",
                        "esxCluster": ""
                    }
                },
                "networkConfig": {
                    "id": 0,
                    "type": null,
                    "atmPort": null,
                    "atmSwitching": null,
                    "bridge": null,
                    "elan": null,
                    "interfaceIndex": null,
                    "ioChassis": null,
                    "ipFirewall": null,
                    "ipSubnet": null,
                    "tcpIpPort": null,
                    "vlan": null,
                    "slotNumber": null,
                    "transportType": null,
                    "circuit": null
                },
                "softwares": [
                    {
                        "id": 6590,
                        "type": "Operating System",
                        "application": "Linux 7SERVER-X86_64",
                        "servicePack": "",
                        "version": "",
                        "addressWidth": "",
                        "licenceOwnership": ""
                    }
                ],
                "ciInstances": [
                    {
                        "id": 485266,
                        "sourceId": "36417226",
                        "sourceSystem": "Vantive",
                        "sourceCreatedDate": "2019-09-03 00:00:00",
                        "sourceCreatedBy": "khaliqh",
                        "sourceUpdatedDate": "2021-07-23 00:00:00",
                        "sourceUpdatedBy": "headd",
                        "attributes": [
                            {
                                "name": "Function",
                                "value": "Infrastructure"
                            }
                        ],
                        "primary": true
                    }
                ],
                "ciInterfaces": [
                    {
                        "id": 9912540,
                        "type": "Primary",
                        "ipAddressV4": "167.215.232.49",
                        "ipAddressV6": null,
                        "macAddress": null,
                        "subnet": null
                    }
                ],
                "relationships": [
                    {
                        "ciId": 8209228,
                        "sourceId": "36417223",
                        "name": "36417223.00000",
                        "ciClass": "Server",
                        "ciSubClass": "Chassis",
                        "type": "Parent of",
                        "reverseType": "Child of"
                    }
                ],
                "audit": {
                    "createdDate": "2021-06-29 14:25:58.169",
                    "createdBy": "CSAMService",
                    "updatedDate": "2022-04-04 15:56:57.631",
                    "updatedBy": "DQSyncService"
                }
            }

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

    # This method can be removed once we migrate to CMS
    def parse_cmdb_records(self, records):
        """Extracts required data from CMDB records and transforms it in to a
        tuple containing hosts and groups.

        Sample record format:
            {
                "name": "S639527DC3VL101",
                "status": [
                    {
                        "source": "EDGE",
                        "status": "Active"
                    }
                ]
                "ipAddresses": [
                    {
                        "id": 1117511,
                        "value": "10.102.65.30",
                        "primary": true
                    }
                ],
                "site": [
                    {
                        "logicalName": "S639527",
                        "type": "OWNER"
                    },
                    {
                        "logicalName": "ZZDC3",
                        "type": "PHYSICAL"
                    }
                ]
            }

        Args:
            records (TYPE): Description

        Returns:
            TYPE: Description
        """
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

            for index, record in enumerate(records, start=1):
                if record:
                    try:
                        record_num = index + 1

                        # Retrieve the device hostname from CMDB record
                        inventory_hostname = self.get_device_hostname_from_cmdb_record(
                            record
                        )

                        if not inventory_hostname or len(inventory_hostname) < 5:
                            self.display.warning(
                                "Record {n}: invalid name '{name}' found (skipping {name})"
                                " record: {record_text}".format(
                                    n=record_num,
                                    name=inventory_hostname,
                                    record_text=to_text(record),
                                )
                            )
                            continue

                        self.display.verbose(
                            msg=to_text(
                                "Record {n}: processing '{inventory_hostname}'".format(
                                    n=record_num, inventory_hostname=inventory_hostname
                                )
                            )
                        )

                        # Retrieve the device primary IP Address from CMDB record
                        ansible_host = self.get_device_ip_address_from_cmdb_record(
                            record
                        )

                        if not ansible_host:
                            self.display.warning(
                                "Record {n}: No primary IP address found (skipping"
                                " {inventory_hostname})".format(
                                    n=record_num, inventory_hostname=inventory_hostname
                                )
                            )
                            continue

                        # If inventory_hostname not in hosts add hostname and ipaddress to hosts. Perform check in case of duplicate records.
                        if not hosts.get(inventory_hostname, {}).get(
                            "ansible_host", ""
                        ):
                            hosts.setdefault(inventory_hostname, {})[
                                "ansible_host"
                            ] = ansible_host
                            hosts.setdefault(inventory_hostname, {})["cmdb_status"] = ""

                        # CMDB component status
                        cmdb_status = self.get_device_cmdb_status_from_cmdb_record(
                            record
                        )

                        if cmdb_status:
                            hosts.setdefault(inventory_hostname, {})[
                                "cmdb_status"
                            ] = cmdb_status

                        # Ownership Vantive siteID: Create groups & add hosts if data is present
                        group_names = self.get_device_sites_from_cmdb_record(record)
                        [
                            groups.setdefault(
                                self._get_valid_group_name(group_name), set()
                            ).add(inventory_hostname)
                            for group_name in group_names
                        ]
                    except:
                        self.display.warning(
                            "Exception while trying to process record_num: {} record: {}"
                            " exception: {}".format(
                                record_num,
                                to_text(record),
                                to_text(traceback.format_exc()),
                            )
                        )

            # Remove any hosts that have a cmdb_status and not an IP/ansible_host
            hosts = {k: v for (k, v) in hosts.items() if "ansible_host" in v.keys()}

            # Create a unique list of groups for valid host names and convert the hosts set array to list
            all_hosts = hosts.keys()
            groups = {
                k: list(v.intersection(all_hosts))
                for (k, v) in groups.items()
                if k and v and v.intersection(all_hosts)
            }

            return (hosts, groups)
        except:
            self.display.error(to_text(traceback.format_exc()))

    def get_cms_records_thread_worker(self, location):
        """Pulls CMS records from URLs/files listed in the locations option.

        Returns:
            TYPE: Description

        Args:
            location (TYPE): Description

        No Longer Raises:
            AnsibleParserError: Description
        """
        try:
            records = []
            data = []
            locations_has_http = False
            if location and str(location).strip().lower().startswith("http"):
                locations_has_http = True

            if locations_has_http is True:
                if self.cms_auth_token and (
                    not hasattr(thread_local, "requests_session")
                    or self.cms_auth_token
                    != thread_local.requests_session.headers.get("accesstoken", "")
                ):
                    self.display.verbose(
                        "cms_auth_token: {} cms_auth_token_expires_in: {} cms_url_auth: {}".format(
                            self.cms_auth_token,
                            self.cms_auth_token_expires_in,
                            self.cms_url_auth,
                        )
                    )

                    # Create CMS API data pull session
                    headers = {
                        "content-type": "application/json",
                        "accept": "application/json",
                        "applicationkey": "cms",
                        "accesstoken": self.cms_auth_token,
                    }

                    thread_local.requests_session = self.get_requests_session(
                        headers,
                        self.skip_cert_validation,
                        self.ca_cert_path,
                        self.cmdb_request_timeout,
                    )

                if self.cms_auth_token and (
                    hasattr(thread_local, "requests_session")
                    and self.cms_auth_token
                    == thread_local.requests_session.headers.get("accesstoken", "")
                ):
                    parsed = urlparse(location)
                    # Retrieve CMS CI data using provided data location URL
                    data = self.get_cms_records_data(
                        parsed, thread_local.requests_session
                    )
                else:
                    self.display.error(
                        msg=to_text(
                            "Invalid request session for CMS API data ... failed processing location: {}".format(
                                location
                            )
                        )
                    )
            else:
                data = self.get_records_from_file(location) or []

            if data and isinstance(data, list):
                records += data
            elif data and isinstance(data, str):
                records.append(data)

            return records
        except:
            self.display.error(to_text(traceback.format_exc()))

    def get_cms_records_thread_pool(self):
        """Pulls CMS records from URLs/files listed in the locations option.

        Returns:
            TYPE: Description
        """
        try:
            cms_auth_token = None
            cms_auth_token_expires_in = 0
            locations = self.get_option("locations")
            self.exclude_devices_with_cmdb_status = self.get_option("exclude_devices_with_cmdb_status")
            locations_has_http = False
            thread_records = []

            for location in locations:
                if location and str(location).strip().lower().startswith("http"):
                    locations_has_http = True
                    break

            if locations_has_http is True:
                self.ca_cert_path = self.get_option("ca_cert_path")
                self.cms_number_of_threads = self.get_option("cms_number_of_threads")
                if (
                    self.cms_number_of_threads
                    and str(self.cms_number_of_threads).isdigit()
                ):
                    self.cms_number_of_threads = int(self.cms_number_of_threads)
                else:
                    self.cms_number_of_threads = 4
                self.cms_username = self.get_option("cms_username")
                self.cms_password = self.get_option("cms_password")
                if not (self.cms_username and self.cms_password):
                    get_cms_credentials_from_ansible_vault()
                self.cmdb_request_timeout = self.get_option("cmdb_request_timeout")
                self.cms_url_auth = self.get_option("cms_url_auth")
                self.cms_vault_encrypted_file = self.get_option(
                    "cms_vault_encrypted_file"
                )
                self.iag_vault_password_file = self.get_option(
                    "iag_vault_password_file"
                )
                self.skip_cert_validation = self.get_option("skip_cert_validation")

                # If processing CMS location URLs get CMS API auth token and CMS API data session
                (cms_auth_token, cms_auth_token_expires_in,) = self.get_cms_auth_token(
                    urlparse(self.cms_url_auth),
                    self.cms_username,
                    self.cms_password,
                    skip_cert_validation=self.skip_cert_validation,
                    timeout=self.cmdb_request_timeout,
                )

            self.cms_auth_token = cms_auth_token
            self.cms_auth_token_expires_in = cms_auth_token_expires_in
            self.cms_url_auth = cms_url_auth

            # # ThreadPool to retrieve results (sync threads)
            # cms_data_pool = ThreadPool(self.cms_number_of_threads)
            # thread_records = cms_data_pool.map(
            #     self.get_cms_records_thread_worker, locations
            # )
            # cms_data_pool.close()
            # cms_data_pool.join()

            # ThreadPoolExecutor to return/handle future promises (async threads)
            futures = []
            with concurrent.futures.ThreadPoolExecutor(
                self.cms_number_of_threads
            ) as executor:
                futures = {
                    executor.submit(
                        self.get_cms_records_thread_worker, location
                    ): location
                    for location in locations
                }

                for future in concurrent.futures.as_completed(futures):
                    # thread_records.append({futures[future]: future.result()})
                    thread_records.append(future.result())

            return thread_records
        except:
            self.display.error(to_text(traceback.format_exc()))

    def get_cms_records_multithreaded(self):
        """Pulls CMS records from URLs/files listed in the locations option.

        Returns:
            TYPE: Description

        No Longer Raises:
            AnsibleParserError: Description
        """
        try:
            pool_records = self.get_cms_records_thread_pool() or [[]]

            pool_records = [
                record
                for thread_records in pool_records or []
                for record in thread_records or []
            ]

            return pool_records
        except:
            self.display.error(to_text(traceback.format_exc()))

    def get_cms_credentials_from_ansible_vault(self):
        """Get and decrypt CMS credentials from ansible vault.

        No Longer Raises:
            AnsibleParserError: Description

        No Longer Returned:
            TYPE: Description
        """
        try:
            decrypted_data = ""
            encrypted_data = ""
            vault_password = ""

            with open(self.cms_vault_encrypted_file, "r") as f:
                encrypted_data = f.read()

            with open(self.iag_vault_password_file, "r") as f:
                vault_password = f.read()

            vault_ref = vault.VaultLib(
                [("default", VaultSecret(_bytes=to_bytes(vault_password.strip())))]
            )

            if vault.is_encrypted(encrypted_data):
                decrypted_data = vault_ref.decrypt(encrypted_data.strip())
                self.cms_username = decrypted_data.split()[1]
                self.cms_password = decrypted_data.split()[3]
            else:
                self.display.warning(
                    msg=to_text("Check if the CMS credentials file is encrypted.")
                )
        except:
            self.display.error(to_text(traceback.format_exc()))
