pragma solidity ^0.4.0;

/*************************************
*
* ZEROPASS team (project TOKEN REGISTRY)
*
*************************************/

contract TokenRegistry {
  
  /*
    Storage structure of signature. 
  */
  struct SignatureSHA1 {
    bytes m_signature;
    uint256 m_timestamp; //block.timestamp
    bool m_isValid;
  }
  
  /*
    Map of all successed (passed the 'check signature' and  'check certificate' tests) addresses with their signatures
  */
  mapping(address => SignatureSHA1) signatures;
  
  /*
   This is one of main functions.
   This function detect few things before it write to map of successed signatures.
        -detection/validation of correct signature
        -validation of certificate of signer (passport ceritiface validation)
        -deteciton if signature already exists in map
        -timestamping (block)
    params: ethereum address, hashed address(future fork: remove this because of custom SHA1 implementation in Solidity), signature, exponent for RSA encryption 
    return: true if success, false if address already exists or one of validation failed
  */
  
  //future work: delete address from parameters, because later we will get address from basic data 'sender' implemented in Solidity
  
  //IMPORTANT: to work properly you need to put arguments in ASCII coding for HEX bytes 
  function checkAndSaveSignature(address currentAddress, bytes hashedAddress, bytes signDevicePublicKey, bytes signToCheck, bytes exponent) public returns (bool)
  {
    if(!isExists(currentAddress))
    {
        return false;   
    }
    //future work: remove hashed address - we should implement SHA1
    //future work: impementing certificate validation of sign device(passport certificate validation)
    
    if (RSAVerify(hashedAddress, signToCheck, exponent, signDevicePublicKey) != 0)
    {
        // verification failed - return false
        return false;   
    }
    SignatureSHA1 sign = signatures[currentAddress];
    sign.m_signature = signToCheck;
    sign.m_timestamp = block.timestamp;
    sign.m_isValid = true;
    return true;
  }
  
  /*
   This is one of main functions.
   This function returns true if address is signed by passport, otherwise returns false
   params: ethereum address
   return: true if address exists, otherwise false
  */
  function checkAddress(address currentAddress) public returns (bool)
  {
    return isExists(currentAddress);
  }
  
  /*
   Is current address already signed by passport
  */
  function isExists(address currentAddress) private returns (bool)
  {
      SignatureSHA1 sign = signatures[currentAddress];
      return (sign.m_isValid == true);
  }
        
  function memcpy(uint dest, uint src, uint len) private {
    // Copy word-length chunks while possible
    for(; len >= 32; len -= 32) {
        assembly {
            mstore(dest, mload(src))
        }
        dest += 32;
        src += 32;
    }

    // Copy remaining bytes
    uint mask = 256 ** (32 - len) - 1;
    assembly {
        let srcpart := and(mload(src), not(mask))
        let destpart := and(mload(dest), mask)
        mstore(dest, or(destpart, srcpart))
    }
    }


    uint8[]  SHA1PREFIX = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    ];
    
    /*
     Join array of bytes with usage of ethereum vm
    */
    function join(bytes s, bytes e, bytes m) internal returns (bytes) {
        uint input_len = 0x60+s.length+e.length+m.length;
        
        uint s_len = s.length;
        uint e_len = e.length;
        uint m_len = m.length;
        uint s_ptr;
        uint e_ptr;
        uint m_ptr;
        uint input_ptr;
        
        bytes memory input = new bytes(input_len);
        assembly {
            s_ptr := add(s,0x20)
            e_ptr := add(e,0x20)
            m_ptr := add(m,0x20)
            mstore(add(input,0x20),s_len)
            mstore(add(input,0x40),e_len)
            mstore(add(input,0x60),m_len)
            input_ptr := add(input,0x20)
        }
        memcpy(input_ptr+0x60,s_ptr,s.length);        
        memcpy(input_ptr+0x60+s.length,e_ptr,e.length);        
        memcpy(input_ptr+0x60+s.length+e.length,m_ptr,m.length);

        return input;
    }
    /*
    * Main funtcion to verify RSA signature
    */
    function RSAVerify(bytes hash, bytes s, bytes e, bytes m) returns (int){
        uint i;
        
      	require(m.length >= SHA1PREFIX.length+hash.length+11);

        /// decipher
        bytes memory input = join(s,e,m);
        uint input_len = input.length;

        uint decipherlen = m.length;
        bytes memory decipher=new bytes(decipherlen);
        bool success;
		assembly {
			success := call(sub(gas, 2000), 5, 0, add(input,0x20), input_len, add(decipher,0x20), decipherlen)
			switch success case 0 { invalid }
		}
        uint paddingLen = decipherlen - 3 - SHA1PREFIX.length - 32;

        for(i =0; i < hash.length; i++)
        {
            uint indexDeciper = (decipher.length - 1)/*last byte*/ - i;
            uint indexHash = (hash.length -1)/*last byte*/ - i;
            if (decipher[indexDeciper]!=hash[indexHash]) {
                return 1;
            }
        }
        return 0;
    }

    /*
    Transfering from array of integers to HEX value
    */
    function uints2bytes(uint[4] memory v) returns (bytes) {
        bytes memory b = new bytes(4*32);
        uint v_ptr;
        uint b_ptr;
        assembly {
            v_ptr := v
            b_ptr := add(b,0x20)
        }
         memcpy(b_ptr,v_ptr,b.length); 
         return b;
    }
    
    /*
    Transfering from array of integers to HEX value
    */
    function uints2bytes(uint[1] memory v) returns (bytes) {
        bytes memory b = new bytes(32);
        uint v_ptr;
        uint b_ptr;
        assembly {
            v_ptr := v
            b_ptr := add(b,0x20)
        }
        memcpy(b_ptr,v_ptr,b.length); 
        return b;
    }
}