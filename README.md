#rsatoolrb  
This tool can construct the private key by give (p, q, e) or (N, e, d).  
The output format can also be der or pem.  
The tool provide the same functionailiy as rsatool wirtten in python [here](https://github.com/ius/rsatool). The advantage of this tool is we using ruby bulit in library. And it is in ruby!

**Usage**

  * If you have the (p, q, e) pair
```ruby
ruby ./rsatool.rb -p P -q Q -e E #By default E is 0x10001 (65537)
```  
  * If you have (N, d, e) pair
```ruby
ruby ./rsatool.rb -n N -d D -e E #By default E is 0x10001 (65537)
```  
  * Output format
```ruby
ruby ./rsatool.rb -f (DER|PEM) -p P -q Q -e E
```  
  * Output to file not stdout
```ruby
ruby ./rsatool.rb -o filepath -f (DER|PEM) -p P -q Q -e E
```  
  * Decrypt cipheretext by given rsa parameter  
```ruby
ruby ./rsatool.rb (some rsa parameter) -c ciphertext_file
```
 
