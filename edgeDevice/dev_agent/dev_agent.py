#********service client************#
# REMAINING- 1)msg too large error
#		2) reading json ob from file
#this is the administrative daemon communicating with the service server
#1. initializes comm with the server(login or registration)
#2. maintain policy, app list as variables
#3. run listed apps
#4. in func run: update policy, run new apps
#5. repeat 4 acc. to policy

import base64
from os import fork
from time import sleep
import httplib, urllib
from os import path
import json
from Crypto.PublicKey import RSA
from Crypto import Random
from subprocess import Popen, check_output


class Admin():

	t=0	# time to get new policy
	uid=""	#extract from auth.txt, get from server
	pwd=""	#extract from auth.txt, get from server
	apps=[]	#list of apps, appid:serverip
	ip=""	#extract from server.txt
	app_handle=[]	#just in case
	i=0;		#counter
	uname=""
	loc=""
	wd=""

	def __init__(self):

		
		#get server information
		server=open("server.txt", "r")
		line=server.readline()
		server.close()	
		trash, self.ip=line.split(":", 1)
		print self.ip

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

	def setParams(self,params):
		return

	def getPolicy(self):
		print "...................IN GETPOLICY........................."
		params = urllib.urlencode({self.uid: self.pwd})
		print params
		headers = {"Content-type": "appication/x-www-form-urlencoded", "Accept": "text/plain"}
		conn = httplib.HTTPConnection("localhost", 8080)
		conn.request("POST","/getPolicy",params ,headers)
		response=conn.getresponse()
		print "...................AFTER TAKING RESPONCE........................."
		print response.status, response.reason
		st=response.read()
		policy=open("policy.txt", "w")
		policy.write(st)
		policy.close()
		policy=open("policy.txt","r")
		line=policy.read();
		json_obj = json.loads(line)
		print(json_obj['t'])
		#why notst['t']

	def getApps(self):
		print "...................IN GETAPPS................................"
		params = urllib.urlencode({self.uid: self.pwd})
		headers = {"Content-type": "appication/x-www-form-urlencoded", "Accept": "text/plain"}
		conn = httplib.HTTPConnection("localhost", 8080)
		conn.request("POST","/getApps",params ,headers)
		response=conn.getresponse()
			
		print response.status, response.reason
		st=response.read()
		print st
		if st!="0":
			app_list=open("app_list.txt", "w")
			app_list.write(st)
			app_list.close()
			app_list=open("app_list.txt","r")
			line=app_list.read();
			json_obj = json.loads(line)
			print("appid: "+json_obj['appid']+" server location: "+json_obj['server_loc'])
			
		else:
			print "No apps available"	

	def initialize(self):
		
		#login
		if path.isfile("auth.txt"): 
			# read json object form auth-> kshitish
			#auth=open("auth.txt", "r")
			#line=auth.read()	
			#self.uid=line['uid']
			#self.pwd=line['pwd']
			


			#self.uid=120
			#self.pwd="pwdcocomum"
					



			# add encryption to send pwd to server
			file=open("../../serviceServer/keys_server.txt","r")
			public_str=file.read()
			file.close()
			public_key=RSA.importKey(public_str)
			enc_data=public_key.encrypt(self.pwd, 32)

			params = urllib.urlencode({self.uid:enc_data})
			print params
			headers = {"Content-type": "appication/x-www-form-urlencoded", "Accept": "text/plain"}
			conn = httplib.HTTPConnection(self.ip, 8080)
			conn.request("POST","/login",params ,headers)
			response=conn.getresponse()
			
			print response.status, response.reason
			s1=response.read()
			print s1 

			if(s1=="1"):
				return 1
			else :
				return 0
		else:
		#registration
			print ".......................IN REG.........................."
			random_num=Random.new().read
			keys=RSA.generate(1024,random_num)
			public_key=keys.publickey()
	

			file=open("keys_client.txt","w+")
			file.write(public_key.exportKey())
			file.close()
			print "check"
			name=self.uname.strip()
			print name
			location= self.loc.strip()
			
			params = urllib.urlencode({name: location})
			headers = {"Content-type": "appication/x-www-form-urlencoded", "Accept": "text/plain"}
			conn = httplib.HTTPConnection("localhost", 8080)

			conn.request("POST", "/newNode", params, headers)
			response = conn.getresponse()
			print response.status, response.reason
			enc_data=response.read()

			print enc_data
			dec_data=keys.decrypt(enc_data)
			zero="0"
			if dec_data==zero:
				return 0
			print dec_data
			json_obj=json.loads(dec_data)
			
			with open("auth.txt", "w") as auth:
				json.dump(json_obj,auth)
			auth.close()
			
			self.uid=json_obj['uid']
			self.pwd=json_obj['pwd']
			
			print "self.pwd: "+self.pwd
			print self.uid	
			return 1
	def startApp(self):
		# download appid.service file in correct location
		# download other files in the predefined location
		# how?
		# 5
		for app in apps:
			service="App"+app[0]+".service"
			trash=Popen("systemctl", "enable", service)
			app_handle[i]=Popen("systemctl", "start", service)
			i=i+1
		
	def startApp(self,app):
		service=app[0]+".service"
		trash=Popen("systemctl", "enable", service)
		app_handle[i]=Popen("systemctl", "start", service)
		i=i+1

	def run(self):

		self.getPolicy()
		apps=self.getApps()
		self.startApp()
		pid=fork()
		if pid==0:
			while True:
				self.getPolicy()
				new_apps=self.getApps()
				#6
				#code considers addition of new apps
				#do we need to consider removal of already running apps
				for app in new_apps:
					flag=0
					for app_old in self.apps:
						if app[0]==app_old[0]:
							flag=1
							break
					if not flag:
						apps.append(app)
						self.startApp(app)
				sleep(t)
					
admin=Admin()
ok=admin.initialize()

if ok:
	admin.run()
else:
	#7
	#print appropriate error from the server.
	print "error in login, registration"
