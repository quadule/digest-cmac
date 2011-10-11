require File.join(File.dirname(__FILE__), '..', 'cmac')
require 'test/unit'

class CMACTest < Test::Unit::TestCase
  def setup
    @cipher = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
    @cmac = Digest::CMAC.new(@cipher, ['2b7e151628aed2a6abf7158809cf4f3c'].pack('H*'))
  end
  
  def test_subkey_l
    assert_equal @cmac.l.unpack('H*')[0], '7df76b0c1ab899b33e42f047b91b546f'
  end
  
  def test_subkey_lu
    assert_equal @cmac.lu.unpack('H*')[0], 'fbeed618357133667c85e08f7236a8de'
  end
  
  def test_subkey_lu2
    assert_equal @cmac.lu2.unpack('H*')[0], 'f7ddac306ae266ccf90bc11ee46d513b'
  end
  
  def test_empty_string
    @cmac.update("")
    assert_equal @cmac.digest.unpack('H*')[0], 'bb1d6929e95937287fa37d129b756746'
  end
  
  def test_16_bytes
    @cmac.update(['6bc1bee22e409f96e93d7e117393172a'].pack('H*'))
    assert_equal @cmac.digest.unpack('H*')[0], '070a16b46b4d4144f79bdd9dd04a287c'
  end
  
  def test_32_bytes_chunked
    @cmac.update(['6bc1be'].pack('H*'))
    @cmac.update(['e22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e'].pack('H*'))
    @cmac.update(['51'].pack('H*'))
    assert_equal @cmac.digest.unpack('H*')[0], 'ce0cbf1738f4df6428b1d93bf12081c9'
  end
  
  def test_40_bytes
    @cmac.update(['6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'].pack('H*'))
    assert_equal @cmac.digest.unpack('H*')[0], 'dfa66747de9ae63030ca32611497c827'
  end
  
  def test_64_bytes
    @cmac.update(['6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'].pack('H*'))
    assert_equal @cmac.digest.unpack('H*')[0], '51f0bebf7e3b9d92fc49741779363cfe'
  end
end