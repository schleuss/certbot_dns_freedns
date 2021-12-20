"""DNS Authenticator for FreeDNS."""
import json
import logging
import time

import re
import requests
import zope.interface

from bs4 import BeautifulSoup
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for FreeDNS

    This Authenticator uses the FreeDNS Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using FreeDNS for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="FreeDNS credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using FreeDNS."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "FreeDNS credentials INI file",
            {
                "username": "Username for FreeDNS Remote API.",
                "password": "Password for FreeDNS Remote API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_freedns_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_freedns_client().del_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _get_freedns_client(self):
        return _FreeDNSClient(
            self.credentials.conf("username"),
            self.credentials.conf("password"),
        )


class _FreeDNSClient(object):
    """
    Encapsulates all communication with the FreeDNS.
    """

    def __init__(self, username, password):
        logger.debug("creating freedns client")
        self.endpoint = "https://freedns.afraid.org"
        self.username = username
        self.password = password
        self.domains_data = {}
        self.domains = None
        self.session = None

    def _login(self):
        if self.session is not None:
            return

        self.session = requests.Session()
        logger.debug("logging in")
        logindata = {'action': 'auth', 'submit': 'Login', 'username': self.username, 'password': self.password}
        response = self.session.post(self._get_url('/zc.php?step=2'), params=logindata)

        if response.status_code == 200:
            return True
        return False

    def _get_url(self, path):
        return "{0}{1}".format(self.endpoint, path)

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        self._login()
        zone_id, zone_name = self._find_managed_zone_id(domain)
        if zone_id is None:
            raise errors.PluginError("Domain not known")
        logger.debug("domain found: %s with id: %s", zone_name, zone_id)

        o_record_name = record_name
        record_name = record_name.replace(zone_name, "")[:-1]
        logger.debug(
            "using record_name: %s from original: %s", record_name, o_record_name
        )
        
        record = self.get_existing_txt(zone_id, record_name, record_content)
        
        if record is not None:
            if record["data"] == record_content:
                logger.info("already there, id {0}".format(record["id"]))
                return
            else:
                logger.info("update {0}".format(record["id"]))
                self._update_txt_record(
                    zone_id, record["id"], record_name, record_content, record_ttl
                )
        else:
            logger.info("insert new txt record")
            self._insert_txt_record(zone_id, record_name, record_content, record_ttl)

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        self._login()
        zone_id, zone_name = self._find_managed_zone_id(domain)
        
        if zone_id is None:
            raise errors.PluginError("Domain not known")

        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        o_record_name = record_name
        record_name = record_name.replace(zone_name, "")[:-1]
        
        logger.debug(
            "using record_name: %s from original: %s", record_name, o_record_name
        )
        
        record = self.get_existing_txt(zone_id, record_name, record_content)
        if record is not None and 'id' in record:
            self._del_txt_record(record['id'])


    def _del_txt_record(self, record_id):
        if record_id is not None:
            response = self.session.post("{}/subdomain/delete2.php?data_id%5B%5D={}&submit=delete+selected".format(self.endpoint, record_id))
            if response.status_code == 200:
                    return True
        return False

    def _insert_txt_record(self, zone_id, record_name, record_content, record_ttl):
        logger.debug("insert with data: %s", (zone_id, record_name, record_content, record_ttl))
        return self._edit_txt_record(zone_id, None, record_name, record_content, record_ttl)

    def _update_txt_record(self, zone_id, primary_id, record_name, record_content, record_ttl):
        logger.debug("update with data: %s", (zone_id, primary_id, record_name, record_content, record_ttl))
        return self._edit_txt_record(zone_id, primary_id, record_name, record_content, record_ttl)

    def _edit_txt_record(self, zone_id, primary_id, record_name, record_content, record_ttl):
        # Valid types: A, AAAA, CNAME, CAA, NS, MX, TXT, SPF, LOC, HINFO, RP, SRV, SSHFP, 
        txt_data = '"{}"'.format(record_content)
        params = {"type": "TXT", 
                "subdomain": record_name, 
                "domain_id": zone_id,
                "address": txt_data, 
                "send": "Save%21"}

        if primary_id is not None:
            params["data_id"] = primary_id
    
        if record_ttl is not None:
            params["ttl"] = record_ttl    

        response = self.session.post(self.endpoint+"/subdomain/save.php?step=2", data=params)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.find("title")
            if "Problems" not in title.text:
                return True
        return False

    def get_existing_txt(self, zone_id, record_name, record_content):
        self._login()
        
        zone_data = self._load_domain_data(zone_id, record_name)
        if zone_data is not None:
            for entry in zone_data:
                if (
                    entry["subdomain"] == record_name
                    and entry["type"] == "TXT"
                    and entry["data"] == record_content
                ):
                    return entry
        return None

    def _find_managed_zone_id(self, domain):
        zone_data = self._load_domains()
        if domain in zone_data:
            return zone_data[domain]['id'], zone_data[domain]['domain'] 
        else:
            for entry in zone_data:
                if entry in domain:
                    return zone_data[entry]['id'], zone_data[entry]['domain'] 
        return None, None

    def _load_domains(self):
        
        if self.domains is not None:
            return self.domains

        search_pattern = re.compile(r'\/subdomain\/edit\.php\?edit_domain_id=([0-9]+)', re.MULTILINE)
        response = self.session.post(self._get_url('/subdomain/'))
        if response.status_code == 200:

            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all('a', text=re.compile("\[\s+add\s+\]"))

            self.domains = {}
            for link in links:
                
                if link.parent is not None:
                    prev = link.parent.find_previous_sibling('td')

                    if prev is not None:
                        domain = prev.text.strip()
                        domain_url = link['href'].strip()
                        domain_id=None

                        mat = search_pattern.match(domain_url)
                        if mat is not None:
                            domain_id = mat.group(1).strip()
                            self.domains[domain] = {'id': domain_id, 'domain': domain }

        return self.domains

    def _load_domain_data(self, domain_id, record_name):

        if domain_id in self.domains_data:
            return self.domains_data[domain_id]
        
        response = self.session.post("{}/subdomain/?limit={}".format(self.endpoint, domain_id))
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            form = soup.find("form", action="delete2.php")
            if form is not None:
                table = form.find("table")
                if table is not None:
                    trs = table.find_all("tr")
                    for tr in trs:
                        tds = tr.find_all("td")
                        if len(tds) == 4:
                            f_input = tds[0].find("input")
                            if f_input is not None:
                                if domain_id not in self.domains_data:
                                    self.domains_data[domain_id] = list()

                                freedns_record_id = tds[0].find("input").get("value")
                                freedns_record_domain = tds[1].find("a").text.strip()
                                freedns_record_type = tds[2].text.strip()
                            
                                if record_name in freedns_record_domain:
                                    full_data = self._load_txt_record(domain_id, freedns_record_id, freedns_record_type)
                                    if full_data is not None:
                                        self.domains_data[domain_id].append(full_data)

        if domain_id in self.domains_data:
            return self.domains_data[domain_id]
        return None

    def _load_txt_record(self, freedns_domain_id, freedns_record_id, freedns_record_type):
        record_data = None

        response = self.session.get("{}/subdomain/edit.php?data_id={}".format(self.endpoint, freedns_record_id))
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            form = soup.find("form", action="save.php?step=2")

            if form is not None:
                input_wildcard = soup.find("input", recursive=True, attrs={"name": "wildcard"}).get("value")
                input_ttl = soup.find("input", recursive=True, attrs={"name": "ttl"}).get("value")
                input_address = soup.find("input", recursive=True, attrs={"name": "address"}).get("value")
                input_subdomain = soup.find("input", recursive=True, attrs={"name": "subdomain"}).get("value")

                record_data = {}
                record_data["id"] = freedns_record_id
                record_data["domain_id"] = freedns_domain_id
                record_data["wildcard"] = input_wildcard
                record_data["data"] = input_address.replace('"', '')
                record_data["subdomain"] = input_subdomain
                record_data["type"] = freedns_record_type

        return record_data 

