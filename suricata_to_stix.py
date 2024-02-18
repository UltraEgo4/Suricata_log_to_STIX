#!/usr/bin/env python
# coding: utf-8

# In[155]:


import json
import socket
import binascii
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from stix2 import  File,CustomExtension,properties,registry,Relationship,Incident, Indicator,IPv4Address,DomainName, NetworkTraffic, HTTPRequestExt, X509Certificate


# #######ELASTIC CONNECTION#######

# In[156]:


#Elastic Connection
client = Elasticsearch(hosts=["http://192.168.1.235:9200"])

client.info
client.indices.refresh()


# #######PARSING#######

# In[157]:


#JSON parsing
json_path ='/home/spacepirate/Programing/projects/SuricataToStix/alerts/http_and_flow.json'
with open(json_path,'r') as file:
    suricata_log = json.load(file)

#global datetime variable, when the script runs the timestap of the stix object creation will be this
created_time = datetime.utcnow()

#list storing stix objects, defined just for clarity
stix_objects = [] 

#timedelta for checking if indicator in incident range
time_range = timedelta(minutes=30)


# #######RELATIONSHIP FUNCTION#######
# 

# In[158]:


#Function to create relationships between 2 stix objects
def create_relationship(stix_obj1,stix_obj2,rel_type):
    relationship= Relationship(
        type="relationship",
        spec_version="2.1",
        created=created_time,
        modified=created_time,
        relationship_type = rel_type,
        source_ref =stix_obj1["id"],
        target_ref =stix_obj2["id"],
    )
    return relationship


# #######DOMAIN-IP CHECK FUNCTION#######

# In[159]:


#Domain lookup
def check_ip_to_domain(ip_addr):
    try:
        hostnames, _, _ = socket.gethostbyaddr(ip_addr)
        return hostnames
    except socket.herror:
        return None

#Reverse dns lookup
def reverse_dns_lookup(hostname):
    try:
        ip_addresses = socket.gethostbyname_ex(hostname)[2]
        return ip_addresses
    except socket.herror:
        return None



# #######CUSTOM EXTENSIONS#######
# 

# In[160]:


#Custom Extensions

#when you create a CustomExtension you have to check ifs not registered twice, for this querry the registered extensions
EXT_MAP = registry.STIX2_OBJ_MAPS['2.1']['extensions']

#DNS CustomExtension
if 'x-dns-ext' not in EXT_MAP:
    @CustomExtension('x-dns-ext', [
        ('type', properties.StringProperty()),
        ('id', properties.StringProperty()),
        ('version', properties.StringProperty()),
        ('flags', properties.StringProperty()),
        ('qr', properties.BooleanProperty()),
        ('aa', properties.BooleanProperty()),
        ('tc', properties.BooleanProperty()),
        ('rd', properties.BooleanProperty()),
        ('ra', properties.BooleanProperty()),
        ('z', properties.BooleanProperty()),
        ('rcode', properties.StringProperty()),
        ('rrname', properties.StringProperty()),
        ('rrtype', properties.StringProperty()),
        ('rdata', properties.StringProperty()),
        ('ttl', properties.IntegerProperty()),
    ])
    class DNSExtension():
        pass


#FTP CustomExtension
if 'x-ftp-ext' not in EXT_MAP:
    @CustomExtension('x-ftp-ext', [
        ('command', properties.StringProperty()),
        ('command_data', properties.StringProperty()),
        ('reply', properties.ListProperty(properties.StringProperty())),
        ('completion_code', properties.ListProperty(properties.StringProperty())),
        ('dynamic_port', properties.StringProperty()),
        ('mode', properties.StringProperty()),
        ('reply_received', properties.BooleanProperty()),
    ])
    class FTPExtension():
        pass

#FTP_DATA CustomExtension
if 'x-ftp-data-ext' not in EXT_MAP:
    @CustomExtension('x-ftp-data-ext', [
        ('command', properties.StringProperty()),
        ('filename', properties.StringProperty()),
    ])
    class FTPDataExtension():
        pass

#TFTP CustomExtension
if 'x-tftp-ext' not in EXT_MAP:
    @CustomExtension('x-tftp-ext', [
        ('packet', properties.StringProperty()),
        ('file', properties.StringProperty()),
        ('mode', properties.StringProperty()),
    ])
    class TFTPExtension():
        pass



#SSH CustomExtension
if 'x-ssh-ext' not in EXT_MAP:
    @CustomExtension('x-ssh-ext', [
        ('client', properties.DictionaryProperty({
            'proto_version': properties.StringProperty(),
            'software_version': properties.StringProperty(),
            'hassh': properties.DictionaryProperty({
                'hash': properties.StringProperty(),
                'string': properties.StringProperty(),
            }),
        })),
        ('server', properties.DictionaryProperty({
            'proto_version': properties.StringProperty(),
            'software_version': properties.StringProperty(),
            'hassh': properties.DictionaryProperty({
                'hash': properties.StringProperty(),
                'string': properties.StringProperty(),
            }),
        })),
    ])
    class SSHExtension():
        pass









# #######INDICATOR#######

# In[161]:


#Create indicator object
alert_timestamp = datetime.strptime(suricata_log["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z") #timestamp of the alert

indicator = Indicator(
        type="indicator",
        spec_version="2.1",
        created=alert_timestamp,
        modified=alert_timestamp,
        name=suricata_log["alert"]["signature"],
        description=suricata_log["alert"]["category"],
        indicator_types="malicious-activity",
        pattern=suricata_log["alert"]["rule"],
        pattern_type="suricata",
        valid_from=created_time,
        custom_properties={"severity": suricata_log["alert"]["severity"]}
    )
#Append object to stix object list
stix_objects.append(indicator)




# #######INCIDENT#######

# In[162]:


#Time difference calculation, acceptable range
ext_incident_time = alert_timestamp + time_range

#asumming there could only be one incident at a time where it matches the time frame
#since if an indicator in the timeframe of the first incident-indicator generation
#the next alerts in the timeframe until it reaches 30minute will be assigned to the same incident

#Elastic querry to check incidents with time range
query_incident_timestamp = {
    "query": {
        "bool": {
            "must": [
                {"match": {"type": "incident"}},
                {"range": {"created": {"lte": ext_incident_time.isoformat()}}},
                {"range": {"created": {"gte": alert_timestamp.isoformat()}}},
            ]
        }
    }
}

#Querry response
resp_query_incident_timestamp = client.search(index="test_index", body=query_incident_timestamp)
#Number of querry responses, if 0 no matching if !=0 match
total_hits_incident_timestamp = resp_query_incident_timestamp['hits']['total']['value']

#Create Incident object
if(total_hits_incident_timestamp ==0):
    incident = Incident(
        type="incident",
        spec_version="2.1",
        created=alert_timestamp,
        modified=alert_timestamp,
        name=suricata_log["alert"]["signature"]
    )
    stix_objects.append(incident)


# #######RELATIONSHIP INDICATOR-INCIDENT#######

# In[163]:


#Relationship between indicator and incident, ALWAYS PRESENT
#Check if theres an incident with timeframe, if querry total hits == 0, no matches
if(total_hits_incident_timestamp ==0):
    inc_ind_rel = create_relationship(indicator,incident,"related-to")
    stix_objects.append(inc_ind_rel)
else:
    inc_ind_rel= create_relationship(indicator,resp_query_incident_timestamp['hits']['hits'][0]["_source"],"related-to")
    stix_objects.append(inc_ind_rel)
    


# #######IPV4#######  
# -SRC  
# -DEST

# In[164]:


#Query if src IP exits in Elastic
query_src_ip = {
    "query": {
        "bool": {
            "must": [
                {"match": {"type": "ipv4"}},
                {"match": {"value": suricata_log["src_ip"]}}
            ]
        }
    }
}
#Query responses and number of responses
resp_query_src_ip=client.search(index="test_index", body=query_src_ip)
total_hits_src_ip = resp_query_src_ip['hits']['total']['value']
#If no ip in elastic create src ip object
if(total_hits_src_ip == 0 ):
    src_ipv4addr = IPv4Address(
        type="ipv4-addr",
        spec_version="2.1",
        value=suricata_log["src_ip"]
    )
    stix_objects.append(src_ipv4addr)



#Querry if dest IP exits in Elastic
query_dest_ip = {
    "query": {
        "bool": {
            "must": [
                {"match": {"type": "ipv4"}},
                {"match": {"value": suricata_log["dest_ip"]}}
            ]
        }
    }
}

resp_query_dest_ip=client.search(index="test_index", body=query_dest_ip)

total_hits_dest_ip = resp_query_dest_ip['hits']['total']['value']

#If no ip in elastic create dest ip object
if(total_hits_dest_ip == 0 ):
    dest_ipv4addr = IPv4Address(
        type="ipv4-addr",
        spec_version="2.1",
        value=suricata_log["dest_ip"]
    )
    stix_objects.append(dest_ipv4addr)


# #######NETWORK-TRAFFICE OBJ#######  
# -FLOW  
# -HTTP
# -DNS
# -FTP
# -FTP_DATA
# -TLS
# -TFTP
# -SSH

# In[165]:


#Set protocols order matters, refer to stix documentation
network_traffic_protocols= ["ipv4",suricata_log["proto"]]

#Check in log if theres any app proto field
if "app_proto" in suricata_log:
    network_traffic_protocols.append(suricata_log["app_proto"])

if "src_port" in suricata_log:
    src_port_checked = suricata_log["src_port"]
else:
    src_port_checked = None

if "dest_port" in suricata_log:
    dest_port_checked = suricata_log["dest_port"]
else:
    dest_port_checked = None

#Formating flow timestamp, timestamp of the alert
flow_timestamp = datetime.strptime(suricata_log["flow"]["start"], "%Y-%m-%dT%H:%M:%S.%f%z") 

#Checking possible network extension fields
network_extension = {} #extension dictonary intialization

#Check if there will be an extension
if any(field in suricata_log for field in ["http", "dns", "ftp", "ftp_data", "tftp", "ssh"]):
    #Http_request predefined extension
    if "http" in suricata_log:
        if "http_method" in suricata_log["http"] and "url" in suricata_log["http"]:
            
            http_request_method = suricata_log["http"]["http_method"]
            http_request_value = suricata_log["http"]["url"]
            
            if("protocol" in suricata_log["http"]):
                http_request_version = suricata_log["http"]["protocol"]
                #http_extension["http-request-ext"]["request_version"] = suricata_log["http"]["protocol"]
            else:
                http_request_version = None

            headerFlag = False
            if("http_user_agent" in suricata_log["http"]):
                http_request_header={}
                headerFlag = True
                http_request_header["User-Agent"]= suricata_log["http"]["http_user_agent"]
            
            #print(suricata_log["http"]["hostname"])
            if("hostname" in suricata_log["http"]):
                if(headerFlag == False):
                    http_request_header={}
                    headerFlag = True
                http_request_header["Hostname"]=suricata_log["http"]["hostname"]
                
            if(headerFlag == False):
                http_request_header = None
            

            if("length" in suricata_log["http"]):
                http_message_body_length = suricata_log["http"]["length"]
            else:
                http_message_body_length = None


            network_extension["http-request-ext"] = HTTPRequestExt(
                request_method=http_request_method,
                request_value=http_request_value,
                request_version =http_request_version,
                request_header = http_request_header,
                message_body_length = http_message_body_length
            )

    #Custom extensions
    if "dns" in suricata_log:
        if "type" in suricata_log["dns"]:
            dns_type = suricata_log["dns"]["type"]
        else:
            dns_type = None

        if "id" in suricata_log["dns"]:
            dns_id = suricata_log["dns"]["id"]
        else:
            dns_id = None

        if "version" in suricata_log["dns"]:
            dns_version = suricata_log["dns"]["version"]
        else:
            dns_version = None

        if "flags" in suricata_log["dns"]:
            dns_flags = suricata_log["dns"]["flags"]
        else:
            dns_flags = None

        if "qr" in suricata_log["dns"]:
            dns_qr = suricata_log["dns"]["qr"]
        else:
            dns_qr = None

        if "aa" in suricata_log["dns"]:
            dns_aa = suricata_log["dns"]["aa"]
        else:
            dns_aa = None

        if "tc" in suricata_log["dns"]:
            dns_tc = suricata_log["dns"]["tc"]
        else:
            dns_tc = None

        if "rd" in suricata_log["dns"]:
            dns_rd = suricata_log["dns"]["rd"]
        else:
            dns_rd = None

        if "ra" in suricata_log["dns"]:
            dns_ra = suricata_log["dns"]["ra"]
        else:
            dns_ra = None

        if "z" in suricata_log["dns"]:
            dns_z = suricata_log["dns"]["z"]
        else:
            dns_z = None

        if "rcode" in suricata_log["dns"]:
            dns_rcode = suricata_log["dns"]["rcode"]
        else:
            dns_rcode = None

        if "rrname" in suricata_log["dns"]:
            dns_rrname = suricata_log["dns"]["rrname"]
        else:
            dns_rrname = None

        if "rrtype" in suricata_log["dns"]:
            dns_rrtype = suricata_log["dns"]["rrtype"]
        else:
            dns_rrtype = None

        if "rdata" in suricata_log["dns"]:
            dns_rdata = suricata_log["dns"]["rdata"]
        else:
            dns_rdata = None

        if "ttl" in suricata_log["dns"]:
            dns_ttl = suricata_log["dns"]["ttl"]
        else:
            dns_ttl = None

        network_extension["x-dns-ext"] = DNSExtension(
                type= dns_type,
                id = dns_id,
                version =dns_version,
                flags = dns_flags,
                qr = dns_qr,
                aa = dns_aa,
                tc = dns_tc,
                rd = dns_rd,
                ra = dns_ra,
                z = dns_z,
                rcode = dns_rcode,
                rrname = dns_rrname,
                rrtype = dns_rrtype,
                rdata = dns_rdata,
                ttl = dns_ttl
        )

    if "ftp" in suricata_log:
        if "command" in suricata_log["ftp"]:
            ftp_command = suricata_log["ftp"]["command"]
        else:
            ftp_command = None

        if "command_data" in suricata_log["ftp"]:
            ftp_command_data = suricata_log["ftp"]["command_data"]
        else:
            ftp_command_data = None

        if "reply" in suricata_log["ftp"]:
            ftp_reply = suricata_log["ftp"]["reply"]
        else:
            ftp_reply = None

        if "completion_code" in suricata_log["ftp"]:
            ftp_completion_code = suricata_log["ftp"]["completion_code"]
        else:
            ftp_completion_code = None

        if "dynamic_port" in suricata_log["ftp"]:
            ftp_dynamic_port = suricata_log["ftp"]["dynamic_port"]
        else:
            ftp_dynamic_port = None

        if "mode" in suricata_log["ftp"]:
            ftp_mode = suricata_log["ftp"]["mode"]
        else:
            ftp_mode = None

        if "reply_received" in suricata_log["ftp"]:
            ftp_reply_received = suricata_log["ftp"]["reply_received"]
            ftp_reply_received = True
        else:
            ftp_reply_received = None

        network_extension["x-ftp-ext"] = FTPExtension(
                command= ftp_command,
                command_data = ftp_command_data,
                reply =ftp_reply,
                completion_code = ftp_completion_code,
                dynamic_port = ftp_dynamic_port,
                mode = ftp_mode,
                reply_received = ftp_reply_received,
        )

    if "ftp_data" in suricata_log:
        if "command" in suricata_log["ftp_data"]:
            ftp_data_command = suricata_log["ftp_data"]["command"]
        else:
            ftp_data_command = None

        if "filename" in suricata_log["ftp_data"]:
            ftp_data_filename = suricata_log["ftp_data"]["filename"]
        else:
            ftp_data_filename = None

        network_extension["x-ftp-data-ext"] = FTPDataExtension(
                command= ftp_data_command,
                filename = ftp_data_filename,      
        )

    if "tftp" in suricata_log:
        if "packet" in suricata_log["tftp"]:
            tftp_packet = suricata_log["tftp"]["packet"]
        else:
            tftp_packet = None
        
        if "file" in suricata_log["tftp"]:
            tftp_file = suricata_log["tftp"]["file"]
        else:
            tftp_file = None

        if "mode" in suricata_log["tftp"]:
            tftp_mode = suricata_log["tftp"]["mode"]
        else:
            tftp_mode = None

        network_extension["x-tftp-ext"] = TFTPExtension(
                packet= tftp_packet,
                file = tftp_file,
                mode =tftp_mode,       
        )

    if "ssh" in suricata_log:
        if "client" in suricata_log["ssh"]:
            ssh_client={}       
            if "proto_version" in suricata_log["ssh"]["client"]:
                ssh_client["client_proto_version"] = suricata_log["ssh"]["client"]["proto_version"]
            else:
                ssh_client["client_proto_version"] = None

            if "software_version" in suricata_log["ssh"]["client"]:
                ssh_client["client_software_version"] = suricata_log["ssh"]["client"]["software_version"]
            else:
                ssh_client["client_software_version"] = None

            if "hassh" in suricata_log["ssh"]["client"]:
                ssh_client["client_hassh"] = {}
                if "hash" in suricata_log["ssh"]["client"]["hassh"]:
                    ssh_client["client_hassh"]["hash"] = suricata_log["ssh"]["client"]["hassh"]["hash"]
                else:
                    ssh_client["client_hassh"]["hash"] = None

                if "string" in suricata_log["ssh"]["client"]["hassh"]:
                    ssh_client["client_hassh"]["string"]= suricata_log["ssh"]["client"]["hassh"]["string"]
                else:
                    ssh_client["client_hassh"]["string"]= None
            
        else:
            ssh_client = None


        if "server" in suricata_log["ssh"]:
            ssh_server = {}
            if "proto_version" in suricata_log["ssh"]["server"]:
                ssh_server["server_proto_version"] = suricata_log["ssh"]["server"]["proto_version"]
            else:
                ssh_server["server_proto_version"]= None

            if "software_version" in suricata_log["ssh"]["server"]:
                ssh_server["server_software_version"] = suricata_log["ssh"]["server"]["software_version"]
            else: 
                ssh_server["server_software_version"] = None


            if "hassh" in suricata_log["ssh"]["server"]:
                ssh_server["server_hassh"] = {}
                if "hash" in suricata_log["ssh"]["server"]["hassh"]:
                    ssh_server["server_hassh"]["hash"] = suricata_log["ssh"]["server"]["hassh"]["hash"]
                else:
                    ssh_server["server_hassh"]["hash"] = None

                if "string" in suricata_log["ssh"]["server"]["hassh"]:
                    ssh_server["server_hassh"]["string"]= suricata_log["ssh"]["server"]["hassh"]["string"]
                else:
                    ssh_server["server_hassh"]["string"]= None
        else:
            ssh_server = None

        network_extension["x-ssh-ext"] = SSHExtension(
                client= ssh_client,
                server = ssh_server
        )
            
else:
    network_extension = None

#Check if network traffice src&dest ref already in Elastic or not
if(total_hits_src_ip == 0 ):
    ip_src_id = src_ipv4addr["id"]
else:
    ip_src_id = resp_query_src_ip['hits']['hits'][0]['_id']

print(total_hits_dest_ip)
if(total_hits_dest_ip == 0 ):
    ip_dest_id = dest_ipv4addr["id"]
else:
    ip_dest_id = resp_query_dest_ip['hits']['hits'][0]['_id']


#Create NetworkTraffic stix object
network_traffic = NetworkTraffic(
    type="network-traffic",
    spec_version="2.1",
    start=flow_timestamp,
    src_ref=ip_src_id,
    dst_ref=ip_dest_id,
    src_port=suricata_log["src_port"],
    dst_port=suricata_log["dest_port"],
    protocols=network_traffic_protocols,
    src_byte_count = suricata_log["flow"]["bytes_toserver"],
    dst_byte_count= suricata_log["flow"]["bytes_toclient"],
    src_packets = suricata_log["flow"]["pkts_toserver"],
    dst_packets = suricata_log["flow"]["pkts_toclient"],
    extensions= network_extension
    
)
#Append network_traffice object to stix objects
stix_objects.append(network_traffic)


# #######RELATIONSHIPS NETWORK-TRAFFIC - INDICATOR#######
# 

# In[166]:


#Create relationship between indicator and network traffic ALWAYS PRESENT
ind_network_traffic_rel= create_relationship(network_traffic,indicator,"related-to")
stix_objects.append(ind_network_traffic_rel)


# #######RELATIONSHIPS NETWORK-TRAFFIC - SRC&DEST#######
# 

# In[167]:


#Create relationship between network traffic and IPS, check if IP exists in Elastic or not
if(total_hits_src_ip == 0 ):
    src_network_traffic_rel= create_relationship(src_ipv4addr,network_traffic,"related-to")
    stix_objects.append(src_network_traffic_rel)
else:
    src_network_traffic_rel= create_relationship(resp_query_src_ip['hits']['hits'][0]["_source"],network_traffic,"related-to")
    stix_objects.append(src_network_traffic_rel)

if(total_hits_dest_ip == 0 ):
    dest_network_traffic_rel= create_relationship(dest_ipv4addr,network_traffic,"related-to")
    stix_objects.append(dest_network_traffic_rel)
else:
    src_network_traffic_rel= create_relationship(resp_query_dest_ip['hits']['hits'][0]["_source"],network_traffic,"related-to")
    stix_objects.append(src_network_traffic_rel)




# #######FILE OBJ#######  

# In[168]:


#Cant be ftp_data and tftp in the same Suricata log
#dont have to do checks for that

if "ftp_data" in suricata_log:
    if "filename" in suricata_log["ftp_data"]:

#Query if theres file obj in Elastic
        query_ftp_data_file = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"type": "file"}},
                        {"match": {"value": suricata_log["ftp_data"]["filename"]}}
                    ]
                }
            }
        }
        print(query_ftp_data_file)
        #Query responses and number of responses
        resp_query_ftp_data_file=client.search(index="test_index", body=query_ftp_data_file)
        print(resp_query_ftp_data_file)
        total_hits_ftp_data_file = resp_query_ftp_data_file['hits']['total']['value']

        if (total_hits_ftp_data_file == 0):
            ftp_data_file =File(
                type = "file",
                spec_version="2.1",
                name = suricata_log["ftp_data"]["filename"]
            )
            stix_objects.append(ftp_data_file)
            


if "tftp" in suricata_log:
    if "file" in suricata_log["tftp"]:

        query_tftp_file = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"type": "file"}},
                        {"match": {"value": suricata_log["tftp"]["file"]}}
                    ]
                }
            }
        }
        #Query responses and number of responses
        resp_query_tftp_file=client.search(index="test_index", body=query_tftp_file)
        total_hits_tftp_file = resp_query_tftp_file['hits']['total']['value']

        if (total_hits_tftp_file == 0):
            tftp_file =File(
                type = "file",
                spec_version="2.1",
                name = suricata_log["tftp"]["file"]
            )
            stix_objects.append(tftp_file)

        


# #######RELATIONSHIP NETWORK_TRAFFIC - FILE #######  

# In[169]:


#Create relationship between network traffic and IPS, check if IP existed in Elastic or not
if "ftp_data" in suricata_log:
    if "filename" in suricata_log["ftp_data"]:
        if(total_hits_ftp_data_file == 0 ):
            file_network_traffic_rel= create_relationship(ftp_data_file,network_traffic,"related-to")
            stix_objects.append(file_network_traffic_rel)
        else:
            file_network_traffic_rel= create_relationship(resp_query_ftp_data_file['hits']['hits'][0]["_source"],network_traffic,"related-to")
            stix_objects.append(file_network_traffic_rel)
    
if "tftp" in suricata_log:
    if "file" in suricata_log["tftp"]:
        if(total_hits_tftp_file == 0 ):
            total_hits_tftp_file= create_relationship(tftp_file,network_traffic,"related-to")
            stix_objects.append(total_hits_tftp_file)
        else:
            total_hits_tftp_file= create_relationship(resp_query_tftp_file['hits']['hits'][0]["_source"],network_traffic,"related-to")
            stix_objects.append(total_hits_tftp_file)


# #######X.509 CERTIFICATE OBJ#######  
# -TLS

# In[170]:


#Create X.509 cert Obj if "tls" field in suricata log then..
if ("tls" in suricata_log):

    if("subject" in suricata_log["tls"]):
        tls_subject = suricata_log["tls"]["subject"]
    else:
        tls_subject = None

    if("issuerdn" in suricata_log["tls"]):
        tls_issuer = suricata_log["tls"]["issuerdn"]
    else:
        tls_issuer = None

    if("serial" in suricata_log["tls"]):
        tls_serial = suricata_log["tls"]["serial"]
    else:
        tls_serial= None

    if("fingerprint" in suricata_log["tls"]):
        tls_hash = {
            "SHA-1": binascii.unhexlify(suricata_log["tls"]["fingerprint"].replace(":", "")).hex()
        }    
    else:
        tls_hash = None

    if("version" in suricata_log["tls"]):
        tls_version = suricata_log["tls"]["version"]
    else:
        tls_version = None

    if("notbefore" in suricata_log["tls"]):

        not_before_str = suricata_log["tls"]["notbefore"]

        if "." in not_before_str and "Z" in not_before_str:
            # Timestamp with milliseconds and timezone
            tls_not_before = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        elif "." in not_before_str:
            # Timestamp with milliseconds
            tls_not_before = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S.%f")
        elif "Z" in not_before_str:
            # Timestamp with timezone
            tls_not_before = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S%z")
        else:
            # Timestamp without milliseconds and timezone
            tls_not_before = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S")
    else:
        tls_not_before = None



    if("notafter" in suricata_log["tls"]):

        not_after_str = suricata_log["tls"]["notafter"]

        if "." in not_after_str and "Z" in not_after_str:
            # Timestamp with milliseconds and timezone
            tls_not_after = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        elif "." in not_after_str:
            # Timestamp with milliseconds
            tls_not_after = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S.%f")
        elif "Z" in not_after_str:
            # Timestamp with timezone
            tls_not_after = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S%z")
        else:
            # Timestamp without milliseconds and timezone
            tls_not_after = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S")
    else:
        tls_not_after = None

    if("subject" in suricata_log["tls"]):
        tls_subject = suricata_log["tls"]["subject"]
    else:
        tls_subject = None

#Create the object
  
    tls = X509Certificate(
        type="x509-certificate",
        spec_version="2.1",
        hashes=tls_hash,
        version=tls_version,
        serial_number=tls_serial,
        issuer=tls_issuer,
        validity_not_before=tls_not_before,
        validity_not_after=tls_not_after,
        subject=tls_subject
    )
    stix_objects.append(tls)


# #######RELATIONSHIPS NETWORK-TRAFFIC - X509 CERT#######
# 

# In[171]:


#Relationship between network traffic and cert
if ("tls" in suricata_log):
    tls_network_traffic_rel= create_relationship(tls,network_traffic,"related-to")
    stix_objects.append(tls_network_traffic_rel)


# #######DOMAIN NAME OBJ#######  

# In[172]:


#Check if theres a http field in suricata log
#also Check if theres a hostname field and check if that exits in Elastic or not
if("http" in suricata_log):
    if( "hostname" in suricata_log["http"]):
        query_domain = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"type": "domain-name"}},
                        {"match": {"value": suricata_log["http"]["hostname"]}}
                    ]
                }
            }
        }
        #query responses and number of responses
        resp_query_domain =client.search(index="test_index", body=query_domain)
        total_hits_domain = resp_query_domain['hits']['total']['value']

        #if domain dosent exits create it
        if(total_hits_domain == 0):
            domain = DomainName(
                type="domain-name",
                spec_version="2.1",
                value=suricata_log["http"]["hostname"]
            )
            stix_objects.append(domain)

if("dns" in suricata_log):
    if( "rrname" in suricata_log["dns"]):
        query_domain = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"type": "domain-name"}},
                        {"match": {"value": suricata_log["dns"]["rrname"]}}
                    ]
                }
            }
        }
        resp_query_domain =client.search(index="test_index", body=query_domain)
        total_hits_domain = resp_query_domain['hits']['total']['value']

        #if domain dosent exits create it
        if(total_hits_domain == 0):
            domain = DomainName(
                type="domain-name",
                spec_version="2.1",
                value=suricata_log["dns"]["rrname"]
            )
            stix_objects.append(domain)
        


# #######RELATIONSHIP DOMAIN-DEST_IP#######

# In[173]:


#Create relationship between domain and one of the IPS
#Check if the ips are local or in Elastic
#and do dns lookups if any of the Ips match the Domain Name
#dns lookup functions are using your local configured DNS server

httpFlag = "http" in suricata_log
dnsFlag = "dns" in suricata_log

if( httpFlag and "hostname" in suricata_log["http"] or dnsFlag and "rrname" in suricata_log["dns"]):

    local_dest_ip = False
    ext_dest_ip = False
    local_src_ip = False
    ext_src_ip = False

    #cant be http and dns fields in one suricata log at the same time

    if("http" in suricata_log):
        if( "hostname" in suricata_log["http"]):
            for hit in reverse_dns_lookup(suricata_log["http"]["hostname"]):
                    if (hit == suricata_log["dest_ip"]):
                        local_dest_ip = True
                        break
                    if (hit == resp_query_dest_ip):
                        ext_dest_ip = True
                        break
                    if (hit == suricata_log["src_ip"]):
                        local_src_ip = True
                        break
                    if (hit == resp_query_src_ip):
                        ext_src_ip = True
                        break
    
    if("dns" in suricata_log):
        if( "rrname" in suricata_log["dns"]):
            for hit in reverse_dns_lookup(suricata_log["dns"]["rrname"]):
                    if (hit == suricata_log["dest_ip"]):
                        local_dest_ip = True
                        break
                    if (hit == resp_query_dest_ip):
                        ext_dest_ip = True
                        break
                    if (hit == suricata_log["src_ip"]):
                        local_src_ip = True
                        break
                    if (hit == resp_query_src_ip):
                        ext_src_ip = True
                        break

    if(total_hits_domain == 0 and total_hits_dest_ip == 0 and local_dest_ip == True): ##id dest_ip - domain relationship dosent exits
        domain_destip_rel = create_relationship(domain,dest_ipv4addr,"resolves-to")
        stix_objects.append(domain_destip_rel)

    #if destinatip_ip exists and domain dosent exits
    if(total_hits_dest_ip !=0 and total_hits_domain ==0 and ext_dest_ip == True):
        domain_destip_rel = create_relationship(domain,resp_query_dest_ip['hits']['hits'][0]["_source"],"resolves-to")
        stix_objects.append(domain_destip_rel)


    ################################################


    if(total_hits_domain == 0 and total_hits_src_ip == 0  and local_src_ip == True): ##id dest_ip - domain relationship dosent exits
        domain_destip_rel = create_relationship(domain,src_ipv4addr,"resolves-to")
        stix_objects.append(domain_destip_rel)


    #if destinatip_ip exists and domain dosent exits
    if(total_hits_dest_ip !=0 and total_hits_src_ip ==0 and ext_src_ip == True):
        domain_destip_rel = create_relationship(domain,resp_query_src_ip['hits']['hits'][0]["_source"],"resolves-to")
        stix_objects.append(domain_destip_rel)

    #if dest_ip domain exits there has to be a relationship between them


# #######STIX OBJECT SERIALIZATION#######

# In[174]:


#Write all the stix objects serialized into a JSON output file

output_file_path = '/home/spacepirate/Programing/projects/SuricataToStix/alerts/output.json'

with open(output_file_path, "w") as output_file:
    output_file.write("[\n")
    for i, obj in enumerate(stix_objects):
        serialized_obj = obj.serialize(pretty=True)
        output_file.write(serialized_obj)
        if i < len(stix_objects) - 1:
            output_file.write(",\n")
    output_file.write("\n]\n")

    

