#!/usr/bin/env ruby

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
	print "\n\nExamples:\n\twsu-crypt --debug -e keyfile plaintextfile"
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
	until p.prime? and p.to_s(2).length >= 32 do
		q = 0
		# 4294967298 = 2^32
		q = rand(4294967296) until q.to_i.prime? and q % 12 == 5 
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
else
	plaintext = File.open(pt_file, 'rb') { |f| f.read.unpack('B*')[0] } 
	keytext = File.open(key_file, 'rb') { |f| f.read.unpack('B64')[0] } 
end
	srand(Time.now.to_i)
puts "Keygen" if keygen
puts "Encrypt" if encrypt and !keygen
puts "Decrypt" if !encrypt and !keygen
t = Time.now
puts "#{power(1234, 4856) % 124} ran in #{Time.now - t} seconds"
t = Time.now
puts "#{ModMath.pow(1234, 4856, 124)} ran in #{Time.now - t} seconds"
puts 13.prime?
puts rand(1000000)
p = generate_safe_prime
puts "p: #{p} : num_bits = #{p.to_s(2).length}"
puts generate_key_pair
