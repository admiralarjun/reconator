from distutils.file_util import write_file
from colorama import Fore, Back, Style
import os
import io
import urllib.request
from tld import get_tld

ROOT_DIR = 'targets'

# create directory based onthe host name
def createDir(host):
    if not os.path.exists(host):
        os.makedirs(host)
    print("[+] Project Directory Created")    

# create file to store result
def createFile(path,data):
    f = open(path,'w')
    f.write(data)
    f.close
    print(Fore.GREEN+"[+] Report File generated")
    
# extract TLD from user input
def getDomain(host):
    domain_name = get_tld(host)
    return domain_name 




def getIP(host):
    command = "host "+host # syntax of host command - host domain
    process = os.popen(command) 
    result = str(process.read())
    ip = result.find("has address")+12
    print(Fore.GREEN+"[+] IP Address Identified")
    return (result[ip:].splitlines()[0])
    

def getNmap(option,host):
    command = "nmap "+ option +" "+ host
    process = os.popen(command)
    result = str(process.read())
    print(Fore.GREEN+"[+] NMAP Scan completed")
    return result

def getRobots(host):
    if host.endswith("/"):
        path = "https://" + host
    else:
        path = "https://"+ host + "/"
    try:
        req = urllib.request.urlopen(path+"robots.txt",data= None)
        data = io.TextIOWrapper(req, encoding="utf-8")
        return data.read()
    except:
        print(Fore.RED+"[-] Failed to fetch robots.txt")
        return "Robots failed"
    

def getWhois(host):
    command = "whois "+host
    process = os.popen(command)
    result = str(process.read())    
    print(Fore.GREEN+"[+] WHOIS Scan completed")
    return result

def genReport(name,domain,ip,NMAP,ROBOTS,WHOIS):
    projectdir = ROOT_DIR + "/" + name
    createDir(projectdir)
    createFile(projectdir + "/report.txt",name)
    file = open(projectdir + "/report.txt","a")
    file.write("\n[+]Domain name = "+domain+"\n")
    file.write("\n[+]Domain IP = "+ip+"\n")
    file.write("\n[+]NMAP SCAN RESULTS\n"+NMAP+"\n")
    file.write("\n[+]ROBOTS.txt\n"+ROBOTS+"\n")
    file.write("\n[+]WHOIS Information\n"+WHOIS+"\n")
    print(Fore.GREEN+"[+] Scan report generated")


def drive(name,host):
    ip = getIP(host)
    NMAP = getNmap('-F',host)
    ROBOTS = getRobots(host)
    WHOIS = getWhois(host)
    genReport(name,host,ip,NMAP,ROBOTS,WHOIS)


NAME = input("[=> Enter name of project: ")
HOST = input("[=> Enter host without [http/https] - [eg: admiralarjun.com]:")
drive(NAME,HOST)