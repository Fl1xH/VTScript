#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: Fl1x
# Version: 0.1
#
# References:
# https://support.virustotal.com/hc/en-us/articles/360006819798-API-Scripts-and-client-libraries
# https://developers.virustotal.com/reference/overview#files
# https://brain-upd.com/programming/how-to-use-virustotal-api-with-python/

import json
import vt

API_client = vt.Client("YOUR_API_KEY_HERE")	# Personal API key

def existing_file_vt():
	file = API_client.get_object("/files/" + input("\n\x1b[94m[-]\033[0m SHA256 of the file: "))  # SHA256 search through API
	print("\x1b[92m[+]\033[0m Recovering VT data in progress ...")
	result_file = file.to_dict()	# Dictionary method all infos from file
	result_file_scanned = json.dumps(result_file, sort_keys=False, indent=4)
	result_fs_format = json.loads(result_file_scanned)
	
	#### JSON Parsing output results ####
	print('\n Status: completed' )  # Status
	print(' Stats: \n   Type description:',result_fs_format['attributes']['type_description'])  # Stats Harmless (Clean)
	print('   Size:',result_fs_format['attributes']['size'],'Bytes')  # Stats size file
	print('   File type: \n     ',result_fs_format['attributes']['trid'][0]['file_type'])  # Stats trid file type
	print('      Probability:',result_fs_format['attributes']['trid'][0]['probability']) # Stats trid probability
	print('   Times submitted:',result_fs_format['attributes']['times_submitted']) # Stats times submitted
	print('   Names associated: \n     ',result_fs_format['attributes']['names']) # Stats names associated
	print('   Analysis stats: \n      Clean:',result_fs_format['attributes']['last_analysis_stats']['harmless'])  # Stats clean file
	print('      Malicious:',result_fs_format['attributes']['last_analysis_stats']['malicious']) # Stats malicious file
	print('      Suspicious:',result_fs_format['attributes']['last_analysis_stats']['suspicious']) # Stats suspicious file
	print('      Undetected:',result_fs_format['attributes']['last_analysis_stats']['undetected']) # Stats undetected file
	print('   Magic:',result_fs_format['attributes']['magic']) # Stats magic
	print('   Tags:',result_fs_format['attributes']['tags'])  # Stats tags

	# Close API connection
	API_client.close()

def url_scan_vt():
 	analysis = API_client.scan_url(input("\n\x1b[94m[-]\033[0m What URL do you want to scan? : "), wait_for_completion=True)
 	print("\x1b[92m[+]\033[0m Analysis in progress ...")
 	result_url_scan = analysis.to_dict()
 	result_url_scan_formatted = json.dumps(result_url_scan, sort_keys=False, indent=4)
 	result_dict = json.loads(result_url_scan_formatted)   # convert JSON string to a dictionary
 	
 	#### JSON Parsing output results ####
 	print('\n Status:',result_dict['attributes']['status'])  # Status
 	print(' Stats: \n   Clean:',result_dict['attributes']['stats']['harmless'])  # Stats Harmless (Clean)
 	print('   Malicious:',result_dict['attributes']['stats']['malicious'])  # Stats Malicious
 	print('   Suspicious:',result_dict['attributes']['stats']['suspicious'])  # Stats Suspicious
 	print('   Undetected:',result_dict['attributes']['stats']['undetected'])  # Stats Undetected

 	#### ADD result analysis behavior, or more informations link url to gui WEB #### 

 	# Close API connection
 	API_client.close()
 	# https://github.com/VirusTotal/vt-py/issues/47

def file_scan_vt():
	print("\n\x1b[94m[-]\033[0m What file do you want to scan?")
	with open(input("\x1b[94m[-]\033[0m Provide the absolute path (/home/user/Documents/file): "), "rb") as f:
		print("\x1b[92m[+]\033[0m Uploading the file and run the analysis ...")
		analysis = API_client.scan_file(f, wait_for_completion=True)
		result_analysis = analysis.to_dict()
		result_analysis_formatted = json.dumps(result_analysis, sort_keys=False, indent=4)
		result_dict = json.loads(result_analysis_formatted)

	#### JSON Parsing output results ####
	print('\n Status:',result_dict['attributes']['status'])  # Status
	print(' Stats: \n   Undetected:',result_dict['attributes']['stats']['undetected'])  # Stats Undetected
	print('   Type-unsupported:',result_dict['attributes']['stats']['type-unsupported'])  # Stats Type-unsupported
	print('   Malicious:',result_dict['attributes']['stats']['malicious'])  # Stats Malicious
	print('   Suspicious:',result_dict['attributes']['stats']['suspicious'])  # Stats Suspicious
	print('   Failure:',result_dict['attributes']['stats']['failure'])  # Stats Failure

	# Close API connection
	API_client.close()

def print_menu():
    for key in menu_options.keys():
        print (key, '--', menu_options[key])

def print_banner():
    banner = """
 __     _______ ____            _       _    
 \ \   / /_   _/ ___|  ___ _ __(_)_ __ | |_  
  \ \ / /  | | \___ \ / __| '__| | '_ \| __| 
   \ V /   | |  ___) | (__| |  | | |_) | |_  
    \_/    |_| |____/ \___|_|  |_| .__/ \__|
                                 |_|         
  Made by Fl1x				v0.1
"""
    print(banner)

menu_options = {
    1: 'File scan from hash',
    2: 'File scan upload',
    3: 'Url scan',
    4: 'Exit',
}

if __name__=='__main__':
    while(True):
    	print_banner()
    	print_menu()
    	option = ''
    	try:
    		option = int(input('\nEnter your choice: '))
    	except:
    		print('Wrong input. Please enter a number ...')

    	if option == 1:
    		existing_file_vt()
    	elif option == 2:
        	file_scan_vt()
    	elif option == 3:
        	url_scan_vt()
    	elif option == 4:
        	print('Bye bye')
        	exit()
    	else:
        	print('Invalid option. Please enter a number between 1 and 4.')
