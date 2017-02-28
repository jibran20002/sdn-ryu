#!/usr/bin/python
import socket
import sys
 
ServHost = ''   # Symbolic name meaning all available interfaces
ServPort = 8888 # Arbitrary non-privileged port
 

def server_udp():
    #Datagram (udp) socket
    try :
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print 'UDP Socket created'
    except socket.error, msg :
        print 'Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    # Bind socket to local host and port
    try:
        s.bind((ServHost, ServPort))
    except socket.error , msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    print 'UDP Socket bind complete'

    return s

def server_tcp():
    #Datastream (tcp) socket
    try :
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'TCP Socket created'
    except socket.error, msg :
        print 'Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    # Bind socket to local host and port
    try:
        s.bind((ServHost, ServPort))
        s.listen(1)
    except socket.error , msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    print 'TCP Socket bind complete and listening..'
    conn, addr = s.accept()
    return conn, addr

def recv_udp(sock):
    
    # receive data from client (data, addr)
    d = sock.recvfrom(1024)
    data = d[0]
    addr = d[1]

    s.sendto('received', addr)

    return data, addr

def recv_tcp(conn, addr):

    data = conn.recv(1024)

    conn.send('received')

    return data



if __name__ == '__main__':

    typec = raw_input('Enter connection type: ').lower()
    if typec == 'udp' :
        s = server_udp()
    elif typec == 'tcp' :
        conn, addr = server_tcp()
    else:
        print 'Invalid Connection type. Quitting..'
        sys.exit()
    
    print 'Creating output file'
    text_file = open("Output_file1.txt", "w")
    while(1) :
        if typec == 'udp' :
            data, addr = recv_udp(s)
        if typec == 'tcp' :
            data = recv_tcp(conn, addr)

        if 'exit' in data.lower():
            print 'Exit received. Quitting...'
            break 

        text_file.write("data: %s \n" % str(data))
        text_file.write("addr: %s \n" % str(addr))

    if typec == 'tcp' :
        conn.close()

    text_file.close()
    print 'File closed! Closing socket'
    s.close()