#!/usr/bin/env ruby
#author zywu@bamboofox
#mail w.zongyu@gmail.com

require 'openssl'
require 'base64'
require 'optparse'

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
end


options = {} 
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
end.parse!


options[:e] = 65537 if options[:e].nil?
r = RSAtool.new(options[:p].to_i, options[:q].to_i, options[:e].to_i)
puts r.to_pem
