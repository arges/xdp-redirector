import socket
import random
import os
import sys
import multiprocessing
 
def send(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        sock.sendto(os.urandom(random.randint(0,1200)), ("10.0.1.2", port))
 
def main():
    if len(sys.argv) > 1:
        for i in range(1,int(sys.argv[1])):
            print(f"process for {65500+i}")
            p = multiprocessing.Process(target=send, args=(65500+i,))
            p.start()
 
    send(65500)
 
if __name__ == "__main__":
    main()
