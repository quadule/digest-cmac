require 'openssl'

module Digest
  class CMAC
    @@RB = 0x87 #constant defined in the RFC for 16-byte block sizes
    
    # for testing purposes
    attr_accessor :lu, :lu2
    
    # Constructs an object to calculate CMACs for data
    def initialize(cipher, key)
      @cipher = cipher
      @cipher.encrypt
      @block_size = @cipher.block_size
      reset(key)
    end
    
    def reset(key = @key)
      @data = ''
      @tag = "\000"*@block_size
      
      # subkey generation
      if key != @key
        @key = key
        @cipher.key = @key
        bits = @block_size*8
        @l = encrypt_block("\000"*@block_size)
        l = @l.unpack('H*')[0].hex
        
        limit_mask = (2**bits)-1
        msb_mask = 2**(bits-1)
        
        @lu = l << 1
        @lu &= limit_mask
        @lu ^= @@RB unless (l & msb_mask)
        
        @lu2 = @lu << 1
        @lu2 &= limit_mask
        
        # the spec says to do this, but it doesn't work. why?
        # @lu2 ^= @@RB unless (@lu & msb_mask)
        # this is wrong according to the spec, but seems to work correctly
        @lu2 ^= @@RB if (@lu & msb_mask)
        
        @lu = @lu.to_s(16).rjust(@block_size*2, '0').hex_to_raw
        @lu2 = @lu2.to_s(16).rjust(@block_size*2, '0').hex_to_raw
      end
    end
    
    def encrypt_block(block)
      @cipher.reset
      @cipher.update(block)
    end
    
    # TODO: this should be made to work on an IO object too
    def update(data)
      @data += data
      complete_block_count = (@data.length / @block_size).floor

      if @data.length > @block_size
        0.upto(complete_block_count-1) do |i|
          break if @data.length == @block_size
          block = @data[0..(@block_size-1)]
          @data = @data[@block_size..@data.length]
          throw 'bad block length' if block.length != @block_size
          @tag = @tag.xor(block)
          @tag = encrypt_block(@tag)
        end
      end
    end
    
    def digest
      throw 'bad data length' if @data.length > @block_size
      
      if @data.length == @block_size
        @data = @data.xor(@lu)
      else
        @data << "\200" + ("\000" * (@block_size - @data.length - 1))
        @data = @data.xor(@lu2)
      end
      
      @tag = @tag.xor(@data)
      @tag = encrypt_block(@tag)
    end
  end
end

class String
  # Converts a hex string to a string of raw bytes.
  def hex_to_raw
    scan(/../).map { |h| h.hex.chr }.join.rjust(length/2, "\000")
  end
  
  # XORs each byte of the string with that of another
  def xor(str)
    result = str.rjust(length, "\000")
    unpack('C*').each_with_index do |c, i|
      result[i] ^= c
    end
    result
  end
end
