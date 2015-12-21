#***************application (content distribution) client*************************

from os import fork
from time import sleep
import httplib, urllib
from os import path
from subprocess import Popen, check_output
from Crypto.PublicKey import RSA
from Crypto import Random
import json

class App1():		
	t=3	#time to get new policy
	dt=0	#set in getPolicy()
	bw=0 	#set in getPolicy()
	uid=""	#extract from auth.txt, get from server
	pwd=""	#extract from auth.txt, get from server
	ip=""	#extract from server.txt
	wd=""
	uname=""
	loc=""

	def __init__(self):	
		#get server information
		server=open("server.txt", "r")
		line=server.readline()
		server.close()	
		trash, self.ip=line.split(":", 1)

		#get working directory
		self.wd=check_output("pwd")
		
		#get parameters of client 
		params=["", ""]
		info=open("info.txt", "r")	
		for line in info:
			key, val=line.split(":", 1)
			if key=="uname":
				params[0]=val
			elif key=="loc":
				params[1]=val
		info.close()
		self.uname=params[0]
		self.loc=params[1]


	def getPolicy(self):		
		#1
		#http request response get jason obj or something else
		#write code
		policy=open("policy.txt", "r+")
		policy.seek(0, 2)
		line="bw:"+self.bw
		policy.write(line)
		line="dt:"+self.dt
		policy.write(line)
		policy.close()

	def initialize(self):
		
		#login
		if path.isfile("auth.txt"): 
			auth=open("auth.txt", "r")
			line=auth.read()
			auth.close()
			j=json.loads(line)	
			print j			
			#self.uid=line
			#print self.uid
			#self.pwd=line['pwd']
			
			# encryption to send pwd to server
			file=open("../../appServer/keys_server.txt","r")
			public_str=file.read()
			file.close()
			public_key=RSA.importKey(public_str)
			enc_data=public_key.encrypt(self.pwd, 32)			


			params = urllib.urlencode({self.uid:enc_data})
			params = urllib.urlencode({self.uid:self.pwd})
			headers = {"Content-type": "appication/x-www-form-urlencoded", "Accept": "text/plain"}
			conn = httplib.HTTPConnection(self.ip, 8080)
			conn.request("POST","/login",params ,headers)
			response=conn.getresponse()
			
			print response.status, response.reason
			s1=response.read()
			print s1 
			s2="1"
			if(s1==s2):
				return 1
			else :
				return 0
		else:

		#registration	
			#encryption: generate keys
			random_num=Random.new().read
			keys=RSA.generate(1024,random_num)
			public_key=keys.publickey()

			file=open("keys_client.txt","w+")
			file.write(public_key.exportKey())
			file.close()

		#registration		
			params = urllib.urlencode({self.uid: self.loc})
			headers = {"Content-type": "appication/x-www-form-urlencoded", "Accept": "text/plain"}
			conn = httplib.HTTPConnection(self.ip, 8080)
			conn.request("POST", "/newNode", params, headers)
			response = conn.getresponse()
			print response.status, response.reason
			enc_data=response.read()
			dec_data=keys.decrypt(enc_data)
			zero="0"
			if dec_data==zero:
				return 0
			print dec_data
			json_obj=json.loads(dec_data)
			auth=open("auth.txt", "w")
			auth.write(json_obj)
			auth.close()
			return 1

	def run(self):
		#sync content			

		rsync="rsync"+"-rtv"+self.uname+"@"+self.ip+"::"+self.uname+"/data/"+self.wd+"/data/"
		str=self.pwd+"\n"
		run(rsync, events={'(?i)password': str})				
		self.getPolicy()

		hr=timedelta(hours=self.dt)
		days_1=timedelta(days=1)
		temp=datetime.now()
		temp+=days_1
		t=datetime(temp.year, temp.month, temp.day, 3, 0, 0)

		pid=fork()
		if pid==0:
			while(1):
				while(datetime.now()-t<hr):
					if(get_bw<self.bw):

						#sync content			
						rsync="rsync"+"-rtv"+self.uname+"@"+self.ip+"::"+self.uname+"/data/"+self.wd+"/data/"
						str=self.pwd+"\n"
						run(rsync, events={'(?i)password': str})				
		
						#get parameters from new policy
						self.getPolicy()
						hr.hours=self.dt	

						break
					sleep(15)
				temp=datetime.now()-self.t
				self.t=self.t+days_1-temp
				time.sleep((days_1-temp).total_seconds())	
				

client=App1()
ok=client.initialize()
if ok:
	client.run()
else:
	#7
	#print appropriate error from the server.
	print "error in login, registration"
