#!/usr/bin/python
import socket   #for sockets
import sys  #for exit
 
# create dgram udp socket
def crt_sock(ev):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error:
		print 'Failed to create socket'
		sys.exit()

	host = 'localhost';
	port = 8888;

	#while(1) :
	#msg = raw_input('Enter message to send : ')

	msg = ev
	
	try :
		#Set the whole string
		s.sendto(msg, (host, port))
	except socket.error, msg:
		print 'Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
		sys.exit()

	if msg.strip() == 'exit':
		#break
		sys.exit()

if __name__ == '__main__':
	while(1) :
		msg = raw_input('Enter message to send : ')
		crt_sock(msg)
