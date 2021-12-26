#!/usr/bin/env python3

from libraries.validation import *
from libraries.get_input import *
from libraries.col import colors
import webbrowser
import os 

 

def banner():
	print(f"""\n{colors.GREEN}
	██████╗ ██╗   ██╗ █████╗ ██╗  ██╗██╗   ██╗ ██████╗  ██████╗ ███╗   ██╗
	██╔══██╗╚██╗ ██╔╝██╔══██╗██║ ██╔╝██║   ██║██╔════╝ ██╔═══██╗████╗  ██║
	██████╔╝ ╚████╔╝ ███████║█████╔╝ ██║   ██║██║  ███╗██║   ██║██╔██╗ ██║
	██╔══██╗  ╚██╔╝  ██╔══██║██╔═██╗ ██║   ██║██║   ██║██║   ██║██║╚██╗██║
	██████╔╝   ██║   ██║  ██║██║  ██╗╚██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║
	╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝v1.1
    \t\t\t\t\t\t\t\t{colors.RESET}Coded by Abeis_Nelson""")

def main():

	while True:
	
		print(f"\n{colors.RED}Choose your Option{colors.RESET}\n")

		print(f"{colors.GREEN}[1] {colors.WHITE}Disposable Domain Check{colors.RESET}\n")
		print(f"{colors.GREEN}[2] {colors.WHITE}Domain validation{colors.RESET}\n")
		print(f"{colors.GREEN}[3] {colors.WHITE}URL validation{colors.RESET}\n")
		print(f"{colors.GREEN}[4] {colors.WHITE}IP validation{colors.RESET}\n")
		print(f"{colors.GREEN}[5] {colors.WHITE}Configure your API Keys{colors.RESET}\n")
		print(f"{colors.GREEN}[6] {colors.WHITE}Exit {colors.RESET}\n")

		c = int(input(f"{colors.YELLOW}Option > "))

		if c == 1:
			print(f"\n{colors.WHITE}Enter the Domain details:{colors.RESET} ")
			getting_input()
			i = 1
			disposable_check(i)
			user_inputs.clear()


		if c == 2:
			print(f"\n{colors.WHITE}Enter the Domain details:{colors.RESET} ")
			getting_input()
			Domain_Validation_Report()
			user_inputs.clear()

		if c == 3:
			print(f"\n{colors.WHITE}Enter the full url: (ex: 'https://www.google.co.in/') {colors.RESET}")
			getting_input()
			URL_Validation()
			user_inputs.clear()


		if c == 4:
			print(f"\n{colors.WHITE}Enter the IP Details: {colors.RESET}")
			getting_input()
			IP_Validation()
			user_inputs.clear()
		
		if c == 5:
			api_configure()
			break

		if c == 6:
			print(f"\n{colors.YELLOW}Thank u for using me! have a nice day....bye{colors.RESET}\n")
			break
		if c == 7:
			getting_input()
			who_is()
			user_inputs.clear()

		if c <= 0 or c == 0 or c >=8:
			print(f"\n{colors.RED}Please enter a valid option {colors.RESET}\n")
			break
		
if __name__ =="__main__":
	banner()
	main()
	





