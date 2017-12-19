#!/usr/bin/python
import os
import sys
from datetime import date, timedelta
import re
import shodan
foldername=date.today().strftime('%d%m%Y')
if not os.path.exists("/root/results/%s" % foldername):
	os.mkdir("/root/results/%s" % foldername)
def gendiff(line):
	result_set=line.split(",")
	if result_set[0]=="null":
		subdomain=result_set[1]
	else:
		subdomain=result_set[0]
	port=result_set[2:]
	for i in port:
		if int(i) in [8080,8081,8008]:
			return "http://%s:%s" % (subdomain,i)
		if int(i) == 80:
			return "http://%s" % (subdomain)
		if int(i) == 443:
			return "https://%s" % (subdomain)

def main():
	resultset=0
	SHODAN_API_KEY = ""
	pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
	api = shodan.Shodan(SHODAN_API_KEY)
	
	ytd=(date.today()- timedelta(1)).strftime('%d/%m/%Y')

	if len(sys.argv) == 1:
		print 'Usage: %s targetlist DictList vendor filetype' % sys.argv[0]
		sys.exit(1)
	host=sys.argv[1]
	print host,ytd
	os.system("shodan download /root/results/%s/output hostname:%s port:80,8080,8081,443,8008 after:%s  --limit 3000" % (foldername,host,ytd))
	os.system("shodan parse --fields hostnames,ip_str,port --separator , /root/results/%s/output.json.gz > /root/results/%s/output.txt" % (foldername,foldername))
	with open("/root/results/%s/output.txt" % foldername,'r') as f1:
		file1=[line.rstrip() for line in f1.readlines()]
	f2=open("/root/results/%s/targetlist" % foldername,'wb+')
	resultset=0
	for line in file1:
		if ":" not in line:
			resultset=resultset+1
			target=gendiff(line)
			f2.write("%s\n" % target)
	f2.close()

if __name__ == '__main__':
	main()
