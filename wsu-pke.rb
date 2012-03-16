#!/usr/bin/env ruby

BLOCK_SIZE = 32

def print_usage
	print "Usage: wsu-pke [OPTION]... [-k|-e|-d] FILE1 FILE2\n"
	print "Encrypt or Decrypt FILE2 with a key of FILE1 to standard output"
	print "\n\tDefault method is encryption"
	print "\n\n\t-e\tEncrypt FILE1 with key FILE2"
	print "\n\t-d\tDecrypt FILE1 with key FILE2"
	print "\n\t-h\t\t\tOutput text to hexidecimal representations"
	print "\n\t--debug\tDisplay debug text to stdout"
	print "\n\t--help\t\t\tDisplay this help and exit"
	print "\n\t--version\t\tOutput version information end exit"
	print "\n\nExamples:\n\twsu-pke --debug -e keyfile plaintextfile"
	print "\n\twsu-pke -d keyfile cipherfile"
	print "\n\nReport bugs to skylarhiebert@computer.org\n"
	exit
end

# Pulled from Wikipedia
# http://en.wikipedia.org/wiki/Exponentiation_by_squaring
def power(x,n)
	result = 1
	while n.nonzero?
		if n[0].nonzero?
			result *= x
			n -= 1
		end
		x *= x
		n /= 2
	end
	return result
end

# http://snippets.dzone.com/posts/show/4636
# From: http://en.wikipedia.org/wiki/Miller-Rabin_primality_test
# Miller-Rabin test for primality
class Integer
	def prime?
		n = self.abs()
		return true if n == 2
		return false if n == 1 || n & 1 == 0

		# cf. http://betterexplained.com/articles/another-look-at-prime-numbers/ and
		# http://everything2.com/index.pl?node_id=1176369
		#
		return false if n > 3 && n % 6 != 1 && n % 6 != 5     # added

		d = n-1
		d >>= 1 while d & 1 == 0
		20.times do                               # 20 = k from above
			a = rand(n-2) + 1
			t = d
			y = ModMath.pow(a,t,n)                  # implemented below
			while t != n-1 && y != 1 && y != n-1
				y = (y * y) % n
				t <<= 1
			end
			return false if y != n-1 && t & 1 == 0
		end
		return true
	end
end

# Used this implementation as it benchmarked much 
# faster than my own implementation
# Implementation for Square-Multiply
# http://snippets.dzone.com/posts/show/4636
module ModMath
	def ModMath.pow(base, power, mod)
		result = 1
		while power > 0
			result = (result * base) % mod if power & 1 == 1
			base = (base * base) % mod
			power >>= 1;
		end
		result
	end
end

# Generate a safe prime, see RFC 4419
def generate_safe_prime(generator=2)
	p = 0
	# Create a 33 bit prime number for modulo
	# This allows us to work with 32-bit block sizes
	until p.prime? and p.to_s(2).length > BLOCK_SIZE do
		q = 0
		# 4294967296 = 2^32 
		q = rand(2**BLOCK_SIZE) until q.to_i.prime? and q % 12 == 5 
		p = generator * q + 1
	end
	return p
end

# Generate a public/private key pair
def generate_key_pair
	g = 2
	p = generate_safe_prime(g)
	d = rand(p)
	e2 = ModMath.pow(g, d, p)

	public_key = [p, g, e2]
	private_key = [p, g, d]

	return public_key, private_key
end

def get_random_seed
	seed = 0
	until seed > 0 do
		puts "Please enter a number"
		seed = STDIN.gets.to_i
	end
	srand(seed)
end

# Encrypts a block and returns integer values for
# C1 and C2
def encrypt_block(block, key) 
	# key[0] = p, key[1] = g, key[2] = e2
	k = rand(key[0] - 1)
	c1 = ModMath.pow(key[1], k, key[0])
	# c2 = ((e2^k % p) * (m % p)) % p
	c2 = (ModMath.pow(key[2], k, key[0]) * ModMath.pow(block, 1, key[0])) % key[0]
	return c1, c2
end

# Decrypts C1 and C2 into a binary block
def decrypt_block(c1, c2, key)
	# key[0] = p, key[1] = g, key[2] = d
	# Exponent = p - 1 - d
	exp = key[0] - key[2] - 1
	# m = (c1^exp * c2) % p
	# m = ((c1^exp % p ) * (c2 % p) % p
	blk = (ModMath.pow(c1, exp, key[0]) * ModMath.pow(c2, 1, key[0])) % key[0]
	blk = blk.to_s(2)
	# Prepend 0's until the block is appropriately sized
	blk.insert(0, '0') until blk.size == BLOCK_SIZE
	return blk
end

$debug = false
encrypt = false
keygen = true
pt_file = nil
key_file = nil
hex_output = false

# Parse Command Line Parameters
if ARGV.size < 1
	if ARGV[0] == "--version" or ARGV[0] == "-version"
		puts "wsu-pke 1.0.0 (2012-11-03) [Skylar Hiebert]"
		exit
	end
	print_usage # Too few arguments or --help defined
end

ARGV.size.times do |i|
	key_file = ARGV[i] if i+1 == ARGV.size - 1
	pt_file = ARGV[i] if i+1 == ARGV.size
	if ARGV[i] == "-k"
		# Seed RNG
		encrypt = false
		keygen = true
	elsif ARGV[i] == "-e"
		encrypt = true
		keygen = false
	elsif ARGV[i] == "-d"
		encrypt = false
		keygen = false
	end
	hex_output = true if encrypt and (ARGV[i] == "-h" or ARGV[i] == "-x")
	$debug = true if ARGV[i] == "--debug"
end

# Read input file text

if keygen
	get_random_seed
	keys = generate_key_pair
	File.open("pubkey.txt", 'w') {|f| f.write("#{keys[0][0]} #{keys[0][1]} #{keys[0][2]}")}
	File.open("prikey.txt", 'w') {|f| f.write("#{keys[1][0]} #{keys[1][1]} #{keys[1][2]}")}
	exit
end

keys = File.open(key_file, 'rb') { |f| f.read.split }	

# Convert keys from string to integers
0.upto(keys.length) { |i| keys[i] = keys[i].to_i }

if encrypt
	puts "Encrypt" 
	plaintext = File.open(pt_file, 'rb') { |f| f.read.unpack('B*')[0] } 
	cipher = ""
	0.upto(plaintext.size / BLOCK_SIZE) do |i|
		blk = plaintext[i*BLOCK_SIZE, BLOCK_SIZE] unless plaintext[i*BLOCK_SIZE].nil?
		unless blk.nil?
			blk << '0' until blk.size == BLOCK_SIZE
			cblk = encrypt_block(blk.to_i(2), keys)
			cipher += "#{cblk[0]} #{cblk[1]} "
		end
	end
	puts cipher
	File.open("ctext.txt", 'w') { |f| f.write(cipher) }
else
	puts "Decrypt"
	ciphertext = File.open(pt_file, 'rb') { |f| f.read.split }
	plaintext = Array.new
	plaintext[0] = ""
	0.upto(ciphertext.size / 2) do |i|
		index = i * 2
		blk = decrypt_block(ciphertext[index].to_i, ciphertext[index+1].to_i, keys)
		plaintext[0] << blk
	end
	
	puts plaintext.pack('B*')
	File.open("dtext.txt", 'w') { |f| f.write(plaintext.pack('B*')) }
end

