pragma solidity ^0.4.15;


contract SolRsaVerify {

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


    uint8[]  SHA256PREFIX = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    ];
    
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
    
    function printData() returns (bytes){
        uint[4] memory s = [
            0x5f49d8dc4519d9520d6542eca08cafb2d99cdb97c5a8685df2476b40505a2f9e,
            0x8d63d76516b83481e2d961a7e8dc5f9f46887e394776711b0f85e4303065c06d,
            0x362456bc219fc6eb343ede6733f779f75853533bc9ab876188da8ad98f9ea2f3,
            0x35d2ceec34ef9cb2782bb0f79cad309608ddc222e00ebcff9d14f6e6ed39638b
        ];
        bytes memory sb = uints2bytes(s);
        return sb;
    }
    
    function test_fips_sha256_success() returns (/*bool*/ bytes) {
        
        uint[4] memory s = [
            0x5f49d8dc4519d9520d6542eca08cafb2d99cdb97c5a8685df2476b40505a2f9e,
            0x8d63d76516b83481e2d961a7e8dc5f9f46887e394776711b0f85e4303065c06d,
            0x362456bc219fc6eb343ede6733f779f75853533bc9ab876188da8ad98f9ea2f3,
            0x35d2ceec34ef9cb2782bb0f79cad309608ddc222e00ebcff9d14f6e6ed39638b
        ];
        
        uint[1] memory e = [
            uint(0x10001)
        ];
        
        uint[4] memory m = [
            0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
            0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
            0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
            0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
        ];
        
        uint[4] memory data = [
            0xf56379c42e3ba856585ca28f7fb768f65d273a5fc546156142857b0afb7c72d2,
            0xd97ecfceec71b4260bdc58c9bb42065f53af69805d9006233ec70a591aff463b,
            0xf23d78200fb8cc14a4eba286afe8924120efad9e3d3f06f7452c725e53728b8f,
            0x86c9fb245fbaf7086ab0092e215213830d1091212efc1ec59ddc3a83707d4ab8
        ];
        
        //bytes memory sb = hex"5f49d8dc4519d9520d6542eca08cafb2d99cdb97c5a8685df2476b40505a2f9e8d63d76516b83481e2d961a7e8dc5f9f46887e394776711b0f85e4303065c06d362456bc219fc6eb343ede6733f779f75853533bc9ab876188da8ad98f9ea2f335d2ceec34ef9cb2782bb0f79cad309608ddc222e00ebcff9d14f6e6ed39638b";
        //bytes memory eb = hex"010001";
        //bytes memory mb = hex"a8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802aafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080ede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941ada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5";
        //bytes memory datab = hex"f56379c42e3ba856585ca28f7fb768f65d273a5fc546156142857b0afb7c72d2d97ecfceec71b4260bdc58c9bb42065f53af69805d9006233ec70a591aff463bf23d78200fb8cc14a4eba286afe8924120efad9e3d3f06f7452c725e53728b8f86c9fb245fbaf7086ab0092e215213830d1091212efc1ec59ddc3a83707d4ab8";
        
        bytes memory sb = hex"1da1a80268ebcbb3e513ee4cef86387f1a0b5f8a77515bc430edd42cb798ce0f65de4a6a4a0f9de149205c51b3888b96f3fcd6b96e70c6271b29136e737e6ef7d54cbf53dc845953cd402cbfc0aac2dcfb0ec5177c09b117045a5c5cdbfff2e8abe92d8291d9be98fdd5e026bdc4e1dcda64a84c91d6f62f37cbcab9082f7bb1";
        bytes memory eb = hex"010001";
        bytes memory mb = hex"d94d889e88853dd89769a18015a0a2e6bf82bf356fe14f251fb4f5e2df0d9f9a94a68a30c428b39e3362fb3779a497eceaea37100f264d7fb9fb1a97fbf621133de55fdcb9b1ad0d7a31b379216d79252f5c527b9bc63d83d4ecf4d1d45cbf843e8474babc655e9bb6799cba77a47eafa838296474afc24beb9c825b73ebf549";
        bytes memory datab = hex"6b";
        
        bytes memory neki = pkcs1Sha256Verify(sha256(datab),sb,eb,mb);
        return neki;
        //return (pkcs1Sha256Verify(sha256(datab),sb,eb,mb)==0);
        

    }

    function pkcs1Sha256Verify(bytes32 hash, bytes s, bytes e, bytes m) returns (bytes){
        uint i;
        
      	require(m.length >= SHA256PREFIX.length+hash.length+11);

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
        return decipher;
        
        /// 0x00 || 0x01 || PS || 0x00 || DigestInfo
        /// PS is padding filled with 0xff
        //  DigestInfo ::= SEQUENCE {
        //     digestAlgorithm AlgorithmIdentifier,
        //     digest OCTET STRING
        //  }
        
        uint paddingLen = decipherlen - 3 - SHA256PREFIX.length - 32;
        
        /*if (decipher[0] != 0 || decipher[1] != 1) {
            return 1;
        }
        for (i=2;i<2+paddingLen;i++) {
            if (decipher[i] != 0xff) {
                return 2;
            }
        }
        if (decipher[2+paddingLen] != 0) {
            return 3;
        }
        for (i=0;i<SHA256PREFIX.length;i++) {
            if (uint8(decipher[3+paddingLen+i])!=SHA256PREFIX[i]) {
                return 4;
            }
        }
        for (i=0;i<hash.length;i++) {
            if (decipher[3+paddingLen+SHA256PREFIX.length+i]!=hash[i]) {
                return 5;
            }
        }

        return 0;*/
    }

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