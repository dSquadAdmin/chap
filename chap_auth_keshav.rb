#!/usr/bin/env ruby

require "socket"
require "digest/sha1"
require "securerandom"
$header_len = 4
$AUTH =0x00
$CHALLENGE =0x01
$RESPONSE = 0x02
$AUTHR = 0x03
$FAIL = 0x04

def configure(id )   #configure the program mode {Server or Client}
	config = Hash.new
	if( id == 0)
		printf("\n Enter ID [NAME]of the system: ")
		config["name"] = gets.chomp
		printf("\n Enter the port To listen on: ")
		config["port"] =gets.chomp
	elsif(id == 1)
		printf("\n Enter IP of the Server: ")
		config["server"] = gets.chomp
		printf("\n Enter Port Number: ")
		config["port"] = gets.chomp
		printf("\n Enter Your Identity: ")
		config["identity"] =gets.chomp
		printf("\n Enter your Password: ")
		config["pass"] = gets.chomp
		printf("\n Enter the name: ")
		config["name"] = gets.chomp
	else
		printf("\n\n Invalid choice, Exiting..................")
		exit 1
	end 
	return config
end

### Configure the sockets for Client and Server
## Client
def conect(config)
	con = TCPSocket.new(config["server"],config["port"])
	return con
end

##server
def serv(config)
	serv = TCPServer.new("", config["port"])
	con =serv.accept
	return con
end

## Sending Data
def send_data(sock, data)
	printf("\nSending Data....................................................")
	total =0
	len = data.size
	printf("\n[Data Size: %d]", len)
	while total < len do
		transmit = sock.send data[total..len], 0
		if (transmit==0)
			printf("\n Socket Connection Broken\n")
			exit
		end
		total = total+transmit
		printf(" [Sent bytes =%d]", total)
	end
end

## Receive Data
def receive(sock)
	printf("\nReceiving Packet................................................")
	data = Hash.new
	header = sock.recv $header_len
	if(header==nil)
		printf("\n Error! Broken link: Header couldnot be fetched, aborting\n")
		exit
	end
#	printf("\n[HEADER: %s ]", header) 
	code, identifier, length = header.unpack("CCn")
#	printf("\n[CODE: %d]\n[IDENTIFIER: %d]\n[Packet length: %d]",code,identifier, length)
	packet = header
	while packet.size < length do
		len = length - packet.size
		part = sock.recv len
		if (part == nil) 
			printf("\n Broken Connection .............................\n")
			break
        end
		packet = packet + part
	end
	printf("\n[Packet Lenght: %d]", packet.size)
	unpacklen = packet.size-$header_len
	format_unpack = "CCnA"+unpacklen.to_s
	code, identifier, length, data = packet.unpack(format_unpack)
	data = {"code"=>code, "identifier"=>identifier, "length"=>length,"data"=>data}
	return data
end

## Create packet
def cook_packet(code, identifier, data)
	printf("\nCooking Packet..................................................")
	data_len = data.size
	pack_len = $header_len+data.size
	pack_form = "CCnA"+data_len.to_s
	packet = [code, identifier, pack_len, data].pack(pack_form)
	return packet
end

## Authentication Request Packet
def request_auth(config) #client
	printf("\nRequest Authentication Packet...................................")
	printf("\n==============================\n Creating Authentication: %s\n", config["name"]) 
	printf(" [Request Code: %d]", $AUTH)
	packet =cook_packet($AUTH, 0, config["identity"])
	return packet
end

## Process Auntication Request
def process_auth(packet)
	printf("\nAuthentication packet Process...................................")
	authData = Hash.new
	identity = packet["data"]
	authData = {"identifier"=> packet["identifier"], "identity"=>identity}
	return authData
end

## Create Challenge Server
def create_challenge(config)               
	printf("\nChallenge packet Cook...........................................")
	chal_data = Hash.new
	identifier = rand(0..255)
	temp = SecureRandom.hex
	challenge_data = Digest::SHA1.digest temp
	str1 = challenge_data + config["name"]
	len = challenge_data.size
	packform = "CA"+(str1.size).to_s
	data = [len, str1].pack(packform)
#	printf("\n[CHALLENGE CODE: %d IDENTIFIER: %d Length: %d]", $CHALLENGE, identifier, len)
	packet = cook_packet($CHALLENGE, identifier, data)	
	chal_data = {"identifier"=>identifier, "challenge"=>challenge_data}
	return packet, chal_data
end

## Process Challenge
def challenge_proc(packet)
	printf("\nChallenge packet Process........................................")      
	pack =Hash.new
	data = packet["data"]
	lenc= data[0]
	length = data.size

	length_c = lenc.unpack("C")[0]

	challenge = data[1..length_c]

	length_c = length_c + 1

	name = data[length_c..length]
	
	printf("\nChallenge for Server [NAME:  %s] is being Processed",name)
#	printf("\nCHALLENGE:\n[Length: %d, Value: %s]",length_c, challenge )
	pack = {"identifier"=> packet["identifier"], "challenge"=> challenge, "name"=> name}
	return pack
end

### Creating response Packet
def cook_resp(config, challenge)
	printf("\nResponse packet Cook............................................")
	str1 = config["pass"] + challenge["challenge"]
	packform ="CA"+(str1.size).to_s
	str = [challenge["identifier"], str1].pack(packform)
	response = Digest::SHA1.digest str
	len = response.size
	length = [len].pack("C")
	data = length+response+config["name"]
	packet = cook_packet($RESPONSE, challenge["identifier"], data)
	return packet
end

## Unpack Response Packet
def response_proc(packet)
	printf("\nResponse packet Processing......................................")
	pro = Hash.new
        data = packet["data"]
	lenc= data[0]
	length = data.size
	length_c = lenc.unpack("C")[0]
	response = data[1..length_c]
	length_c = length_c + 1
	name = data[length_c..length]
#	printf("\nResponse for peer [ %s ] with id [ %d ] is being Processed",name, packet["identifier"])
	pro = {"identifier"=>packet["identifier"], "response"=>response, "name"=>name}
	return pro
end


## Verify Response
def ifExists(resp, challenge, user)

	validUser = Hash.new
	validUser = {"userx"=>"passwordx","usery"=>"passwordy","usery"=>"passwordy"}
	identifier = challenge["identifier"]
	response = resp["response"]
	printf("\n\n[AUTHENTICATING: %s USERID: %s]\n\n",resp["name"], user)
	#Read User and Passwords from hash
	message = "Invalid user information"
	validUser.each do |key, value|
		if (key <=> user)==0 then
			message = "Password Mismatch"
			str1 = value+challenge["challenge"]
			length = str1.size
			packform = "CA"+length.to_s

			expected = [identifier, str1].pack(packform)

			expectedhash = Digest::SHA1.digest expected
			if(expectedhash == response) then
				message = "Authorization Granted!"
				return true, message
				break
			end
		else
			message = "Identity not found in Database"
		end
	end

	return false, message
end

def server()
	printf("\n=======================SERVER=========================")
	config = configure(0)
	printf("\n Waiting for Incomming Connection for authentication   ")
	sock = serv(config)
	packet = receive(sock)
	
	if packet["code"] == $AUTH then
		printf("\nAuthentication Request Received.......")
		authdata = process_auth(packet)
		packet, challenge = create_challenge(config)
		send_data(sock, packet)
		packet = receive(sock)
		resp = response_proc(packet)
		if  packet["code"] == $RESPONSE then
			if packet["identifier"] == challenge["identifier"] then
				result, message = ifExists(resp, challenge, authdata["identity"])
				if result==true then
					printf("\nAccess Granted ...... ")
					packet = cook_packet($AUTHR, challenge["identifier"], message)
					send_data(sock, packet)
				else
					printf("\nAuthorization Faliure ")
					packet = cook_packet($FAIL, challenge["identifier"], message)
					send_data(sock, packet)
				end
			else
				printf("\nPeer not verified ")
			end
 		else
			printf("\nDiscarding Packet")
		end
	else
		printf("\n Handshake Protocol Breached, Closing Connection")
	end
	sock.close()
end

def client()
	printf("\n=======================PEER=========================")
	config = configure(1)
	sock = conect(config)
	packet = request_auth(config)
	send_data(sock, packet)
	packet = receive(sock)
	if packet["code"]==$CHALLENGE then
		challenge_data = challenge_proc(packet)
		packet = cook_resp(config, challenge_data)
		send_data(sock, packet)
		packet = receive(sock)
		if packet["identifier"]==challenge_data["identifier"] then
			printf("\n\n[CODE: %d]", packet["code"])
			if packet["code"]==$AUTHR then
				printf("\nVerified\nResponse: %s", packet["data"])
			elsif packet["code"]== $FAIL
				printf("\nAccess Denied\nReason: %s",packet["data"]) 
			else 
				printf("\nPacket not Recognized")
			end
		end
	else
		printf("\nDiscarding Packet..") 
	end
	sock.close()
end


def chap_info()
	File.open("rfc1994.txt", "r") do |f|
		f.each_line do |line|
			puts line
		end
	end
	printf("\n------ Challenge Handshake Authentication Protocol - CHAP ------")
	printf("\n------------------------- RFC- 1994 ----------------------------")
	printf("\n[0 : Server       ]\n[1 : Client       ]\n[2 : CHAP DETAILS ]\nSelect an Option: ")
	option = gets.chomp
	case option
	when "0"
		server()
	when "1"
		client()
	when "2"
		chap_info()
	else
		printf("\n ERROR! Invalid Input, Aborting......\n")
		exit 0
	end
end

if __FILE__ ==$0
	printf("\n------ Challenge Handshake Authentication Protocol - CHAP ------")
	printf("\n------------------------- RFC- 1994 ----------------------------")
	printf("\n--        http://tools.ietf.org/html/rfc1994                  --")
	printf("\n----------------------------------------------------------------")
	printf("\n-- Programmer : Keshav Bist                                   --")
	printf("\n-- Email      : keshav.bist@alumni.mondragon.edu              --")
	printf("\n-- web        : http://keshavbist.com.np                      --")
	printf("\n----------------------------------------------------------------")
	printf("\n--Note: This Program is implimented in ruby for simuating CHAP--")
	printf("\n----------------------------------------------------------------\n")
	
	printf("\n[0 : Server       ]\n[1 : Client       ]\n[2 : CHAP DETAILS ]\nSelect an Option: ")
	option = gets.chomp
	case option
	when "0"
		server()
	when "1"
		client()
	when "2"
		chap_info()
	else
		printf("\n ERROR! Invalid Input, Aborting......\n")
		exit 0
	end
		printf("\n")
end
