#!/usr/bin/env ruby
#author zywu@bamboofox
#mail w.zongyu@gmail.com

require 'openssl'
require 'base64'
require 'optparse'

class SanityCheck
  def initialize(n, p, q, e, d)
    @n = n
    @p = p
    @q = q
    @e = e
    @d = d
    exit if !chkpq if !@p.zero? && !@q.zero?
    exit if !chked if !@e.zero? && !@d.zero? && !@p.zero? && !@q.zero?
  end

  def chked
    if (@e*@d) % ((@p-1)*(@q-1)) != 1
      puts "e and d is wrong"
      return false
    end
    return true
  end

  def chkpq
    if !@n.zero? && @n != @p*@q
      puts "n not equal to p*q"
      return false
    end
  
    if !OpenSSL::BN.new(@p.to_s).prime?
      puts "p is not prime" 
      return false 
    end

    if !OpenSSL::BN.new(@q.to_s).prime? 
      puts "q is not prime"
      return false 
    end
    return true
  end
end

class Given_d_find_pnq
  #Ref: http://cacr.uwaterloo.ca/hac/about/chap8.pdf
  def initialize(d, n, e)
    @d = d
    @n = n
    @e = e
    @p, @q = findpq
  end

  def p
    @p
  end

  def q
    @q
  end

  def findst(t)
    s = 0
    until t%2 != 0 do
      t /= 2
      s += 1
    end
    return s, t
  end

  def findpq
    s, t = findst(@e*@d-1)
    loop do
      begin
        w = Random.new.rand(1..@n-1)
      end until w.gcd(@n) == 1

      (1..s).each do |i|
        con1 = w.to_bn.mod_exp((2**i)*t, @n).to_i
        con2 = w.to_bn.mod_exp((2**(i-1))*t, @n).to_i
        return (con2-1).gcd(@n), @n/((con2-1).gcd(@n)) if con1 ==1 && con2 != 1 && con2 != (-1 % @n)
      end
    end
  end
end

class RSAtool
  def initialize(p,q,e=65537)
    p,q = q,p if q>p
    @v = 0
    @p = p
    @q = q
    @n = @p*@q
    @e = e
    @d = invmod(@e, ((@p-1)*(@q-1)))
    @exp1 = @d % (@p-1)
    @exp2 = @d % (@q-1)
    @coef = invmod(@q, @p)
    version = OpenSSL::ASN1::Integer.new(@v)
    modulus = OpenSSL::ASN1::Integer.new(@n)
    publicExponent = OpenSSL::ASN1::Integer.new(@e)
    privateExponent = OpenSSL::ASN1::Integer.new(@d)
    prime1 = OpenSSL::ASN1::Integer.new(@p)
    prime2 = OpenSSL::ASN1::Integer.new(@q)
    exponent1 = OpenSSL::ASN1::Integer.new( @d % (@p-1))
    exponent2 = OpenSSL::ASN1::Integer.new( @d % (@q-1))
    coefficient = OpenSSL::ASN1::Integer.new( invmod(@q, @p) )
    @seq = OpenSSL::ASN1::Sequence.new( [version, modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient] )
  end

  def to_der
    @seq.to_der
  end

  def to_pem
    header = "-----BEGIN RSA PRIVATE KEY-----\n" 
    tail = "-----END RSA PRIVATE KEY-----\n"
    return "#{header}#{Base64.encode64(@seq.to_der)}#{tail}"
  end

  def extended_gcd(a, b)
    last_remainder, remainder = a.abs, b.abs
    x, last_x, y, last_y = 0, 1, 1, 0
    while remainder != 0
      last_remainder, (quotient, remainder) = remainder, last_remainder.divmod(remainder)
      x, last_x = last_x - quotient*x, x
      y, last_y = last_y - quotient*y, y
    end
    return last_remainder, last_x * (a < 0 ? -1 : 1)
  end

  def invmod(e, et)
    g, x = extended_gcd(e, et)
    if g != 1
      raise 'Teh maths are broken!'
    end
    x % et
  end

  def output(outfile, format)
    case format
    when /(pem|PEM)/
      if outfile.nil?
        puts to_pem
      else
        File.open(outfile, 'w') { |f| f.write( to_pem ) }
      end
    when /(der|DER)/
      if outfile.nil?
        puts to_der
      else
        File.open(outfile, 'w') { |f| f.write( to_der ) }
      end
    else
      puts "Unsupported file format"
    end
  end
end

options = {format: "PEM"}
OptionParser.new do |opts|
  opts.banner = "Usage: rsatool.rb [options]"
  
  opts.on("-p P", "First prime number") do |v|
    options[:p] = v
  end

  opts.on("-q Q", "Second prime number") do |v|
    options[:q] = v
  end

  opts.on("-e E", "Public exponent") do |v|
    options[:e] = v
  end

  opts.on("-d D", "Private exponent") do |v|
    options[:d] = v
  end

  opts.on("-n N", "Modulus") do |v|
    options[:n] = v
  end

  opts.on("-o OUTFILE", "Output to file") do |v|
    options[:outfile] = v
  end

  opts.on("-f FORMAT", "Ouput format(PEM/DER)") do |v|
    options[:format] = v
  end
end.parse!

options[:e] = 65537 if options[:e].nil? #default e = 0x10001 = 65537
if options[:p].nil? || options[:q].nil? #does not provide p or q
  if options[:p].nil? && options[:q].nil?  # p = q = nil
    if options[:d].nil?
      puts "If you does not have p and q. I need e and d"
      exit
    end

    if options[:n].nil?
      puts "If you does not have p and q. I need n"
      exit
    end
    d = Given_d_find_pnq.new(options[:d].to_i, options[:n].to_i, options[:e].to_i)
    options[:p], options[:q] = d.p, d.q
  else # given n and ( p or q)
    if options[:n].nil?
      puts "If you only have p or q. I need n"
      exit
    end
    options[:q] = options[:n].to_i / options[:p].to_i if options[:q].nil?
    options[:p] = options[:n].to_i / options[:q].to_i if options[:p].nil?
  end
end

SanityCheck.new(options[:n].to_i, options[:p].to_i, options[:q].to_i, options[:e].to_i, options[:d].to_i)
r = RSAtool.new(options[:p].to_i, options[:q].to_i, options[:e].to_i)
r.output(options[:outfile], options[:format])

