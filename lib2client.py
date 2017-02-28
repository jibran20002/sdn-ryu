#!/usr/bin/python
import socket   #for sockets
import sys  #for exit
 
# create dgram udp socket
def crt_udp_sock(hname,hport,ev):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error:
		print 'Failed to create UDP socket'
		sys.exit()

	host = str(hname);
	port = int(hport);
	msg = str(ev);
	
	try :
		#Set the whole string
		s.sendto(msg, (host,port))
	except socket.error, msg:
		print 'Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
		sys.exit()

	if 'exit' in msg.lower():
		#break
		sys.exit()

	D = s.recvfrom(1024)
	recvData = D[0]
	addr = D[1]
	print 'Data received from server :', recvData
	return recvData

# create stream tcp socket
def crt_tcp_sock(hname,hport):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error:
		print 'Failed to create TCP socket'
		#sys.exit()

	host = str(hname);
	port = int(hport);
	
	try :
		s.connect((host,port))
	except socket.error, msg:
		print 'Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
		#sys.exit()

	return s

# TCP Send message
def snd_tcp_msg(s, ev):
	msg = str(ev);
	s.send(msg)
	
	if 'exit' in msg.lower():
		s.close()
		sys.exit()

	recvData = s.recv(1024)
	print 'Data received from server: ', recvData
	return recvData


if __name__ == '__main__':
	typec = raw_input('Enter connection type: ').lower()
	if typec == 'udp' :
		while(1) :
			msg = raw_input('Enter message to send : ')
			conn = crt_udp_sock('localhost',8888,msg)
	elif typec == 'tcp' :
		conn = crt_tcp_sock('localhost',8888)
		while(1) :
			msg = raw_input('Enter message to send : ')
			ah = snd_tcp_msg(conn,msg)
	else :
		print 'Invalid connection type. Exitting...'
		sys.exit()

