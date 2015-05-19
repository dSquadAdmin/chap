#!/usr/bin/env python

import hashlib
import socket
import struct
import random
import time
import sys

header_len = 4  # Code (1 octect) + Identifier (1 octect ) + Length (2 octects )

# Constants used in the protocol fields
AUTH_REQUEST_CODE = 0x00
CHALLENGE_CODE = 0x01
RESPONSE_CODE = 0x02
SUCCESS_CODE = 0x03
FAILURE_CODE = 0x04

class ConfigException(Exception):
	pass

def get_config_values(type):
	config = {}
	try:
		if (type == 'peer'):
			config['authenticator'] = raw_input("Enter the IP of the authenticator: ")
			config['port'] = raw_input("Enter the port to connect to: ")
			config['identity'] = raw_input("Enter the identity you want to authenticate with: ")
			config['secret'] = raw_input("Enter the secret you want to authenticate with: ")
			config['localname'] = raw_input("Enter the name of the local (peer) system: ")
	
		elif (type == 'authenticator'):
			config['port'] = raw_input("Enter the port to listen to: ")
			config['localname'] = raw_input("Enter the name of the local (authenticator) system: ")
		else:
			raise ConfigException("Invalid config type: must be either 'peer' or 'authenticator'. Exiting...")
	
		for setting in config:
			if (config[setting] == ''):
				raise ConfigException('Cannot continue: One or more settings are empty. Exiting...')
	except Exception as e:
		if (isinstance(e, ConfigException)):
			print e
		elif (isinstance(e, EOFError)):
			print "\nCannot continue: End of File detected. Exiting..."
		else:
			raise e

		sys.exit()

	return config

def connect(config):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((config['authenticator'], int(config['port'])))
	return sock

def listen(config):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind(('', int(config['port'])))  # Host == '' means any local IP address
	print "Waiting for incoming authentication requests..."
	sock.listen(1)
	(conn, addr) = sock.accept()
	return conn

def send_packet(sock, packet):
	totalsent = 0
	while totalsent < len(packet):
		sent = sock.send(packet[totalsent:])
		if sent == 0:
			raise RuntimeError("socket connection broken")
		totalsent = totalsent + sent

def receive_packet(sock):
	header = sock.recv(header_len)
	if header == '':
		raise RuntimeError("socket connection broken")

	(code, identifier, length) = struct.unpack('!BBH', header)
	packet = header

	while len(packet) < length:
		chunk = sock.recv(length - len(packet))
		if chunk == '':
			raise RuntimeError("socket connection broken")
		packet = packet + chunk

	(code, identifier, length, data) = struct.unpack('!BBH' + str(length - header_len) + 's', packet)
	return {'code' : code,
		'identifier' : identifier,
		'length' : length,
		'data' : data }

def create_protocol_packet(code, identifier, data):
	data_len = len(data)
	packet_len = header_len + data_len

	# Packing format:
	#    ! ==> use network byte order
	#    B ==> encode as a C unsigned char (8 bit character == octect)
	#    s ==> encode as a string character (in particular NNs => encode NN characters)
	#     
	pack_format = '!BBH' + str(data_len) + 's'

	packet = struct.pack(pack_format, code, identifier, packet_len, data)

	return packet

def create_authentication_request(config):
	print "Creating authentication request for identity:", config['identity']
	return create_protocol_packet(AUTH_REQUEST_CODE, 0x00, config['identity'])

def process_authentication_request(auth_request_packet):
	identity = auth_request_packet['data']
	print "Processing authentication request for identity:", identity
	return {'identifier' : auth_request_packet['identifier'],
		'identity' : identity}

def create_challenge(config, auth_request_data):
	identifier = random.randint(0, 255)
	# Create some random challenge, using the hash of a string
	# composed of 60 random integer number in the range
	# [1,100000000]
	hash = hashlib.sha1(''.join(str(random.sample(xrange(10000000), 60))))
	challenge_value = hash.digest()
	challenge_value_size = struct.pack('!B', len(challenge_value))
	name = config['localname']
	data = challenge_value_size + challenge_value + name
	print "Creating challenge with identifier:", identifier
	packet = create_protocol_packet(CHALLENGE_CODE, identifier, data)
	return (packet, identifier, challenge_value)

def process_challenge(challenge_packet):
	challenge_len = struct.unpack('!B', challenge_packet['data'][0])[0]
	challenge = challenge_packet['data'][1:challenge_len+1]
	name =  challenge_packet['data'][challenge_len+1:]
	print "Processing challenge with identifier:", challenge_packet['identifier'], "name:", name
	return {'identifier' : challenge_packet['identifier'],
		'challenge' : challenge,
		'name' : name }

def create_response(config, challenge):
	hash = hashlib.sha1(chr(challenge['identifier']) + config['secret'] + challenge['challenge'])
	response_value = hash.digest()
	response_value_size = struct.pack('!B', len(response_value))
	name = config['localname']
	data = response_value_size + response_value + name
	print "Creating response with identifier:", challenge['identifier']
	return create_protocol_packet(RESPONSE_CODE, challenge['identifier'], data)

def process_response(response_packet):
	response_len = struct.unpack('!B', response_packet['data'][0])[0]
	response = response_packet['data'][1:response_len+1]
	name =  response_packet['data'][response_len+1:]
	print "Processing response with identifier:", response_packet['identifier'], "name:", name
	return {'identifier' : response_packet['identifier'],
		'response' : response,
		'name' : name }

def verify_response(response_data, identity, identifier, challenge):
	print "Verifying response for identifier:", identifier

	# This is the list of valid identities and associated secrets
	identities = {}
	identities['iarenaza'] = 'secret1';
	identities['gsagardui'] = 'secret2';
	identities['mereno'] = 'secret3';

	if (identity in identities):
		secret = identities[identity]
		hash = hashlib.sha1(chr(identifier) + secret + challenge)
		our_value = hash.digest()
		if (our_value == response_data['response']):
			return 1
		else:
			return 0
	else:
		return 0

def peer(config):
	sock = connect(config)
	packet = create_authentication_request(config)
	send_packet(sock, packet)
	packet = receive_packet(sock)
	if (packet['code'] == CHALLENGE_CODE):
		challenge_data = process_challenge(packet)
		packet = create_response(config, challenge_data)
		send_packet(sock, packet)
		packet = receive_packet(sock)
		if (packet['identifier'] == challenge_data['identifier']):
			if (packet['code'] == SUCCESS_CODE):
				print "Successfully authenticated!"
			elif ((packet['code'] == FAILURE_CODE)):
				print "Could not authenticate. Reason from the authenticator:", packet['data']

			else:
				print "Protocol error"				
		else:
			print "Discarding mismatched response packet..."
	else:
		print "Protocol error"

	sock.close()

def authenticator(config):
	sock = listen(config)
	packet = receive_packet(sock)
	if (packet['code'] == AUTH_REQUEST_CODE):
		auth_request_data = process_authentication_request(packet)
		(packet, challenge_identifier, challenge) = create_challenge(config, auth_request_data)
		send_packet(sock, packet)
		packet = receive_packet(sock)
		if (packet['code'] == RESPONSE_CODE):
			if (packet['identifier'] == challenge_identifier):
				response_data = process_response(packet)
				if (verify_response(response_data, auth_request_data['identity'], challenge_identifier, challenge)):
					code = SUCCESS_CODE
					data = ''
				else:
					code = FAILURE_CODE
					data = 'Identity or secret is incorrect'
				packet = create_protocol_packet(code, packet['identifier'], data)
				send_packet(sock, packet)
			else:
				print "Discarding mismatched response packet..."
		else:
			print "Protocol error"
	else:
		print "Protocol error"

	time.sleep(1)
	sock.close()

if __name__ == "__main__":
	try:
		type = raw_input("Run as a peer or as an authenticator [peer|authenticator]: ")
		if (type == 'peer'):
			config = get_config_values('peer')
			print "============ Starting authentication process as peer ================"
			peer(config)
		elif (type == 'authenticator'):
			config = get_config_values('authenticator')
			print "============ Starting authentication process as authenticator ================"
			authenticator(config)
		else:
			print "Invalid config type: must be either 'peer' or 'authenticator'. Exiting..."
	except EOFError:
		print "\nCannot continue: End of File detected. Exiting..."
		sys.exit()

#
# Local Variables:
# mode: python
# c-basic-offset: 8
# python-indent: 8
# tab-width: 8
# indent-tabs-mode: (quote t)
# End:
