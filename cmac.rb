require 'openssl'

module Digest
  class CMAC
    BLOCK_SIZE = 16
    
    # Constant defined in the RFC for 16-byte block sizes
    RB = "\0" * (BLOCK_SIZE - 1) + "\x87"
    
    # For testing purposes
    attr_accessor :l, :lu, :lu2
    
    # Constructs an object to calculate CMACs for data
    def initialize(cipher, key)
      raise "Cipher block size must be #{BLOCK_SIZE}" unless cipher.block_size == BLOCK_SIZE
      
      @cipher = cipher
      @cipher.encrypt
      @cipher.key = @key = key
      
      generate_subkeys
      reset
    end
    
    def reset
      @data = ''
      @tag = "\0" * BLOCK_SIZE
    end
    
    def update(data)
      @data += data
      complete_block_count = (@data.length / BLOCK_SIZE).floor
      
      if @data.length > BLOCK_SIZE
        0.upto(complete_block_count-1) do |i|
          break if @data.length == BLOCK_SIZE
          block = @data[0..(BLOCK_SIZE-1)]
          @data = @data[BLOCK_SIZE..@data.length]
          raise 'Bad block length' if block.length != BLOCK_SIZE
          @tag = xor(@tag, block)
          @tag = encrypt_block(@tag)
        end
      end
    end
    
    def digest
      raise 'Bad data length' if @data.length > BLOCK_SIZE
      
      if @data.length == BLOCK_SIZE
        @data = xor(@data, @lu)
      else
        @data << "\200" + ("\000" * (BLOCK_SIZE - @data.length - 1))
        @data = xor(@data, @lu2)
      end
      
      @tag = xor(@tag, @data)
      @tag = encrypt_block(@tag)
    end
    
    
    private
    
    def encrypt_block(block)
      @cipher.reset
      @cipher.update(block)
    end
    
    def generate_subkeys
      @l = encrypt_block("\0" * BLOCK_SIZE)
      @lu = subkey_shift(@l)
      @lu2 = subkey_shift(@lu)
    end
    
    def subkey_shift(subkey)
      msb, tail = subkey.unpack('B*').first.unpack('a a*')
      left_shift = [tail, '0'].pack('B*')
      msb == '1' ? xor(left_shift, RB) : left_shift
    end
    
    def xor(a, b)
      a.bytes.zip(b.bytes).map { |x,y| (x^y).chr }.join
    end
  end
end
