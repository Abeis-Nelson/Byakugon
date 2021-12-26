from libraries.get_input import *  
from libraries.col import *			 
from dotenv import load_dotenv
import json
import requests
import os
import subprocess

load_dotenv()
report_flag = 0


VT_API_Key =  os.getenv('VT_API_Key') 
X_Rapid_API_KEY = os.getenv('X_Rapid_API_KEY') 

def api_check():
    if VT_API_Key is None and X_Rapid_API_KEY is None:
        print("Please create an account in Virustotal.com and check-mail.org in order to get your free API key")
        api_configure()
        exit()
    else:
        pass
            
def api_configure():
    if VT_API_Key != None and X_Rapid_API_KEY != None:
        print("API Key's are already configured successfully do u want to reconfigure it?\n")
        print("Press Y for yes and N for no\n")
        c = input()
        if c == 'Y' or c =='yes' or c =='y':
            with open (".env", 'r+' ) as f:
                I_VT_API_Key = input("enter your API KEY for Virustotal\n")
                I_X_Rapid_API_KEY = input("enter your API KEY for check-mail.org\n")
                f.write(f"\nX_Rapid_API_KEY={I_X_Rapid_API_KEY}\n")
                f.write(f"\nVT_API_Key={I_VT_API_Key}\n")
                f.close()
            print("\nAPI key's are successfully stored on your system securely\n")
            exit()
        elif c == 'N' or c =='no' or c =='n':
            print("\nConfiguration's not changed\n")
    else:
        with open (".env", 'a+' ) as f:
                I_VT_API_Key = input("enter your API KEY for Virustotal\n")
                I_X_Rapid_API_KEY = input("enter your API KEY for check-mail.org\n")
                f.write(f"X_Rapid_API_KEY={I_X_Rapid_API_KEY}\n")
                f.write(f"\nVT_API_Key={I_VT_API_Key}\n")
                f.close()
        print("API key's are successfully stored on your system securely\n")
        exit()
        
            
        

def disposable_check(i):
        
    if report_flag == 1:
        disposable_domain_check(i)
    else:
        for i in user_inputs:
            disposable_domain_check(i)


def Domain_Validation_Report():
    api_check()
    for i in user_inputs:
        print(f"{colors.HIGHLIGHT}Domain Validation Result for {i.strip()}{colors.HIGHTLIGHT_RESET}\n")
        who_is(i)
        VT_Domain_Validation(i)
        global report_flag
        report_flag = 1
        disposable_check(i)
        report_flag = 0


def VT_Domain_Validation(i):
    print("\n---------------------------------------------------")
    print(f"{colors.RED}VirusTotal Results for {i.strip()}{colors.RESET}" )
    print("---------------------------------------------------")
    url = f"https://www.virustotal.com/api/v3/domains/{i}"
    headers = {'x-apikey': VT_API_Key}
    response = requests.get(url, headers=headers)
    results = response.json()
    print(f"\n{colors.GREEN}Scan Results of {i.strip()}{colors.RESET}\n")
    scan_results = results['data']['attributes']['last_analysis_results']
    for x,y in scan_results.items():
        r = y['result']
        if r == 'clean':
            print(f"{x.capitalize()}: {colors.GREEN}{r}{colors.RESET}") 
        elif r == 'harmful' or 'phishing' or 'spam':
            print(f"{x.capitalize()}: {colors.RED}{r}{colors.RESET}")
        elif r == 'unrated':
            print(f"{x.capitalize()}: {colors.WHITE}{r}{colors.RESET}")
    print('\n')
    
    Output = results['data']['attributes']['last_analysis_stats']
    votes = results['data']['attributes']['total_votes']
    for x,y in Output.items():
        print(f"{colors.YELLOW}{x.capitalize()}{colors.RESET} \t{y}")
    print(f"{colors.YELLOW}Reputation{colors.RESET}\t{results['data']['attributes']['reputation']}")
    print(f"\n{colors.GREEN}Community Votes{colors.RESET}\n")
    for a,b in votes.items():
        print(f"{colors.YELLOW}{a.capitalize()}{colors.RESET} \t{b}")
    try:
        subdomains = results['data']['attributes']['last_https_certificate']['extensions']['subject_alternative_name']
        print(f"\n{colors.GREEN}Subdomain list{colors.RESET}\n")
        for subdomain in subdomains:
            print(subdomain)
        print("\n")
    except:
        print(f"\n{colors.GREEN}Subdomain list{colors.RESET}\n")
        print(f"{colors.RED}No subdomain has been found for this Domain :( {colors.RESET}\n")

def IP_Validation():

    api_check()    
    for i in user_inputs:
        who_is(i)
        print(f"\n{colors.HIGHLIGHT}IP Validation Report for {i}{colors.HIGHTLIGHT_RESET}\n")
        print("\n---------------------------------------------------")
        print(f"{colors.RED}VirusTotal Results for {i.strip()}{colors.RESET}" )
        print("---------------------------------------------------")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{i}"
        headers = {'x-apikey': VT_API_Key}
        response = requests.get(url, headers=headers)
        results = response.json()
        print(f"\n{colors.GREEN}Scan Results of {i.strip()}{colors.RESET}\n")
        scan_results = results['data']['attributes']['last_analysis_results']
        for x,y in scan_results.items():
            r = y['result']
            if r == 'clean':
                print(f"{x.capitalize()}: {colors.GREEN}{r}{colors.RESET}") 
            elif r == 'harmful' or 'phishing' or 'spam':
                print(f"{x.capitalize()}: {colors.RED}{r}{colors.RESET}")
            elif r == 'unrated':
                print(f"{x.capitalize()}: {colors.WHITE}{r}{colors.RESET}")
        print('\n')

        Output = results['data']['attributes']['last_analysis_stats']
        votes = results['data']['attributes']['total_votes']
        for x,y in Output.items():
            print(f"{colors.YELLOW}{x.capitalize()}{colors.RESET} \t{y}")
        print(f"{colors.YELLOW}Reputation{colors.RESET}\t{results['data']['attributes']['reputation']}")
        print(f"\n{colors.GREEN}Community Votes{colors.RESET}\n")
        for a,b in votes.items():
            print(f"{colors.YELLOW}{a.capitalize()}{colors.RESET} \t{b}")
        try:
            subdomains = results['data']['attributes']['last_https_certificate']['extensions']['subject_alternative_name']
            print(f"\n{colors.GREEN}Subdomain list{colors.RESET}\n")
            for subdomain in subdomains:
                print(subdomain)
            print("\n")
        except:
            print(f"\n{colors.GREEN}Subdomain list{colors.RESET}\n")
            print(f"{colors.RED}No subdomain has been found :( {colors.RESET}\n")

                
                
def URL_Validation():

    api_check() 
    for i in user_inputs:
        print("\n---------------------------------------------------")
        print(f"{colors.RED}VirusTotal URL Report for {i.strip()}{colors.RESET}" )
        print("---------------------------------------------------")
        p_url = "https://www.virustotal.com/api/v3/urls"
        headers_p = {'x-apikey': VT_API_Key}
        form = {'url': f'{i}'}
        response_p = requests.post(p_url, headers=headers_p, data=form)
        results_p = response_p.json()
        analytics_id = results_p['data']['id']
        g_url = f"https://www.virustotal.com/api/v3/analyses/{analytics_id}"
        headers_g = {'x-apikey': VT_API_Key}
        response_g = requests.get(g_url, headers=headers_g)
        results = response_g.json()
        scan_results = results['data']['attributes']['results']
        for x,y in scan_results.items():
            r = y['result']
            if r == 'clean':
                print(f"{x.capitalize()}: {colors.GREEN}{r}{colors.RESET}") 
            elif r == 'harmful' or 'phishing' or 'spam':
                print(f"{x.capitalize()}: {colors.RED}{r}{colors.RESET}")
            elif r == 'unrated':
                print(f"{x.capitalize()}: {colors.WHITE}{r}{colors.RESET}")
        Output = results['data']['attributes']['stats']
        for x,y in Output.items():
            print(f"{colors.YELLOW}{x.capitalize()}{colors.RESET} \t{y}")
        print("\n")



def disposable_domain_check(i):

    api_check()
    print("\n---------------------------------------------------")
    print(f"{colors.GREEN}Disposable Domain check for {i.strip()}{colors.RESET}" )
    print("---------------------------------------------------")
    url = "https://mailcheck.p.rapidapi.com/"
    querystring ={"domain":f'{i}'}
    headers = {
        'x-rapidapi-host': "mailcheck.p.rapidapi.com",
        'x-rapidapi-key': X_Rapid_API_KEY
    }
    response = requests.get(url, headers=headers, params=querystring)
    results = json.loads(response.text)
    disposable = str(results['disposable'])
    if disposable == 'True':
        print(f"\n{colors.HIGHLIGHT_RED}{i} is a disposable Domain {colors.HIGHTLIGHT_RESET}\n")
    else:
        print(f"\n{colors.HIGHLIGHT}{i} is not a disposable Domain {colors.HIGHTLIGHT_RESET}\n")
    print(f"Result : \t" + str(results['text']))
    print(f"Reason : \t" + str(results['reason']))
    print(f"Risk : \t\t" + str(results['risk']))
    print(f"MX_host : \t" + str(results['mx_host']))
    print(f"MX_info : \t" + str(results['mx_info']))
    print(f"MX_IP : \t" + str(results['mx_ip']))
    print(f"Last Changed : \t" + str(results['last_changed_at']))
    print('\n')




def who_is(i):
    keyword_list=['Domain Name:','Registrar:','Creation Date:','Organization:','Country:','country','created:',
	'domain:','org:','registrar:','organisation','remarks:','netname:','Domain Status:','Updated Date:','Name Server:','Domain Status:','inetnum:',
    'descr:','source:','irt:','e-mail:','mnt-by:','address:','phone:','route:','origin:']
    print(f"{colors.GREEN}WHOIS Data of {i.strip()}{colors.RESET}" )
    print("---------------------------------------------------")
    with subprocess.Popen(['whois',i], stdout=subprocess.PIPE) as pr:
        out, err = pr.communicate()
        try:
            f_output = str(out.decode('utf-8')).strip()
        except:
            print(f"Error: {err}\n")
    with open('.whois_data','+w') as fw:
        for l in f_output:
            fw.write(l)
    with open('.whois_data','r') as fr:
        for line in fr:
            for keys in keyword_list:
                if keys in line:
                    print(line.strip())



