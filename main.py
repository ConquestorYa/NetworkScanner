import scapy.all as scapy
from optparse import OptionParser
import re, platform
from rich.console import Console
from os import system
from random import choice
console = Console()

banner1 = """
░▒█▄░▒█░█▀▀░▀█▀░█░░░█░▄▀▀▄░█▀▀▄░█░▄░▒█▀▀▀█░█▀▄░█▀▀▄░█▀▀▄░█▀▀▄░█▀▀░█▀▀▄
░▒█▒█▒█░█▀▀░░█░░▀▄█▄▀░█░░█░█▄▄▀░█▀▄░░▀▀▀▄▄░█░░░█▄▄█░█░▒█░█░▒█░█▀▀░█▄▄▀
░▒█░░▀█░▀▀▀░░▀░░░▀░▀░░░▀▀░░▀░▀▀░▀░▀░▒█▄▄▄█░▀▀▀░▀░░▀░▀░░▀░▀░░▀░▀▀▀░▀░▀▀
"""
banner2 = r"""                     __                 
|\ | _ |_     _  _| (_  _  _  _  _  _  _  
| \|(-`|_\/\/(_)| |<__)(_ (_|| )| )(-`|  
"""
banner3 = r"""
    ||||| ----> New Years Eve at the computer...
   ||O O|`____.
  |||\-/|| \ __\
  |.--:--|  .   :
  /( ):( |_.-~~_.
 (~m  : /  | oo:|
 ~~~~~~~~~~~~~~~~~

"""

def get_ip_range():

    console.print(f'[bold dodger_blue1]{choice([banner1, banner2])}')
    console.print(f'[bold green]{banner3}')
    parser = OptionParser()
    parser.add_option("-r", "--range", dest="ip_range",
                  help="ip range you want to scan")
    (user_input, args) = parser.parse_args()
        
    if not user_input.ip_range:
        while True:

            try:
                console.print('[bold blue]Enter ip range you want to scan:', end=" ")
                user_input.ip_range = input()
            except KeyboardInterrupt:
                console.print("[bold purple] \nAborting...")
                exit()

            if not user_input.ip_range:
                continue
            elif user_input.ip_range == 'clear':
                system('cls') if platform.system() == 'Windows' else system('clear')
                continue
            else:
                validate_result = validate_ip_range(user_input.ip_range)
                
                if validate_result == 'pattern_1':
                    validate_ip(user_input.ip_range, 1)
                    break
                elif validate_result == 'pattern_2':
                    validate_ip(user_input.ip_range, 2)
                    break
                else:
                    message()
                    continue
                    
    else:
        
        validate_result = validate_ip_range(user_input.ip_range)
        
        
        if validate_result == False:
            
            message()
            exit()
        elif validate_result == 'pattern_1':
            
            validate_ip(user_input.ip_range, 1)
        else:
            validate_ip(user_input.ip_range, 2)
           

    


def validate_ip_range(ip):
    try:
        pattern_1 = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/(0|[1-9]\d?|1[0-9]|2[0-9]|3[0-2])$'
        pattern_2 = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\b\d{1,3}\b$"
        if re.match(pattern_1, ip):
            
            return 'pattern_1'
        elif re.match(pattern_2, ip):
            
            return 'pattern_2'
        else:
            return False
        
    except KeyboardInterrupts:
        console.print("[bold purple] \nAborting...")
        exit()

def validate_ip(ip_address, pattern_type):
    
    
    
    if pattern_type == 1:
        octets = ip_address.split('.')
        subnetmask = octets[3].split('/')
        octets.pop()
        octets.append(subnetmask[0])
        del subnetmask[0]

        
        for i in range(4):
            
            if int(octets[i]) > 255:
                
                message()

                exit()
        
        start_network_scanning(ip_address, start=9999, end=9999)
    else:
        octets = ip_address.split('.')
        range_ = octets[3].split('-')
        octets.pop()
        octets.append(range_[0])
        del range_[0]

        for i in range(4):
            
            if int(octets[i]) > 255:
                message()
                exit()

        if int(octets[-1]) > int(range_[0]):
            message()
            exit()
        
        usr_input = ''
        for i in range(3):
            usr_input += (str(octets[i]))
            if i != 2:
                usr_input += '.'

        
        start_network_scanning(usr_input, start=str(octets[-1]), end=str(range_[0]))

def message():
    console.print("[bold red]\nYour IP range is not valid\nExample [192.168.1.105/24]\n        [192.168.1.105-120]\nPlease try again\n")


def start_network_scanning(ip_addr, start, end):

    if start == 9999:
        arp_request = scapy.ARP(pdst=ip_addr)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp = broadcast/arp_request
        

        try:    
                
                answered=scapy.srp(arp, timeout=1,verbose=False)[0]
                number = 0

                for element in answered:

                    number +=1
                    console.print(f'[deep_pink4]Device {str(number)}')
                    console.print(f"[sea_green2]Ip address:[cyan2] {element[1].psrc}")
                    console.print(f"[sea_green1]Mac address:[cyan2] {element[1].hwsrc}\n")
                    

                
        except KeyboardInterrupt:
            console.print("[bold purple] \nAborting...")
            exit()
        except PermissionError:
            console.print("[bold red]You must be root to perform this action")
            exit()
    else:
        try:
            console.print('[bold red]NOTE:[bold purple] This type of scan can be slow!\nIf you want more faster try /24 or other subnetmasks\n')
            for i in range(int(start), int(end)+1):
                target_ip = f"{ip_addr}.{i}"
                
                arp = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(op=1, pdst=target_ip)
                
                answered=scapy.srp(arp, timeout=0.5,verbose=False)[0]
                number = 0 

                for element in answered:
                    number +=1
                    console.print(f'[deep_pink4]Device {str(number)}')
                    console.print(f"[sea_green2]Ip address:[cyan2] {element[1].psrc}")
                    console.print(f"[sea_green1]Mac address:[cyan2] {element[1].hwsrc}\n")
                    
        except PermissionError:
            console.print("[bold red]You must be root to perform this action")
            exit()

get_ip_range()


