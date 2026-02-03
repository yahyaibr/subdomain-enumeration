
import requests
import json

print(r"""
╔════════════════════════════════════════╗
║                                        ║
║     WELCOME TO THE SUBDOMAIN TOOL      ║
║                                        ║
║     CREATED BY: Yahyaibr               ║
║     CYBER SECURITY STUDENT & RESEARCHER║
║                                        ║
║           LET'S GET STARTED!           ║
║                                        ║
╚════════════════════════════════════════╝
""")



print("Please enter a domain:")
domain = input("> ")

 

print ("[+] Checking subdomains activity...")

def GET_FROM_crt_sh_source(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    return response.json()


def GET_FROM_OTX_source(domain):
    url =f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"  
    headers = {
        'X-OTX-API-KEY' : 'YOUR_API_KEY'
    }
    response = requests.get(url, headers=headers)
    return response.json()

def GET_FROM_virus_total_source(domain):
    url =f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"  
    headers = {
        'x-apikey' : 'YOUR_API_KEY'
    }
    response = requests.get(url, headers=headers)
    return response.json()

def GET_FROM_security_trails_source(domain):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "APIKEY":"YOUR_API_KEY"
    }
    response = requests.get(url,headers=headers)
    return response.json()
    
    
def GET_FROM_TLS_BufferOver(domain):
    url = f"https://tls.bufferover.run/dns?q=.{domain}"
    headers = {
        "x-api-key": "YOUR_API_KEY"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        return data.get("Results", [])
    except:
        return []

    
    
    
    
def GET_FROM_ThreatCrowd(domain):
   url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
   try:
       response = requests.get(url,timeout=10)
       data5 = response.json()
       if data5.get("response_code") == "1":
           return data5.get("subdomains",[])
       else:
           return []
        
   except Exception as e :
       return []
   

data1 = GET_FROM_crt_sh_source(domain)
data2 = GET_FROM_OTX_source(domain)
data3 = GET_FROM_virus_total_source(domain)
data4 = GET_FROM_security_trails_source(domain)
data5 = GET_FROM_ThreatCrowd(domain)
data6 = GET_FROM_TLS_BufferOver(domain)


subdomain = set()

for item in data1: 
    if "name_value" in item : 
        for value in item["name_value"].split('\n'):
            value = value.strip().lower()
            if value:
                subdomain.add(value)
        
for record in data2.get("passive_dns", []):
    hostname = record.get("hostname", "").strip().lower()
    if hostname:
        subdomain.add(hostname)

                

for third in data3.get("data", []):
    sub = third.get("id", "").strip().lower()
    if sub:
        subdomain.add(sub)
        
 

for fth in data4.get("subdomains", []): 
    subd = f"{fth}.{domain}"
    if subd:
        subdomain.add(subd)
        
for sub in GET_FROM_TLS_BufferOver(domain):
    sub = sub.strip().lower()
    if sub.endswith(domain):
        subdomain.add(sub)

    
for fith in data5:
    subdomain.add(fith.strip().lower())


print('\n[+] Subdomains found: ')
for sub in sorted(subdomain):
    print(" └─", sub)





