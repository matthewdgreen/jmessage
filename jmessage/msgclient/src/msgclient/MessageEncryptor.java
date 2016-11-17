// MessageEncryptor.java
//
// Copyright (c) 2016 Matthew Green
// Part of the JMessage messaging client, used for Practical Cryptographic
// Systems at JHU. 
// 
// Note that the J could stand for "Janky". This is demonstration code
// that contains deliberate vulnerabilities included for students to find.
// You're free to use it, but it is not safe to use it for anything
// you care about. 
// 
// TL;DR: if you deploy it in production I will laugh at you. 
// 
// Distributed under the MIT License. See https://opensource.org/licenses/MIT.

package msgclient;

import javax.crypto.*;
import java.security.*;
import java.util.zip.CRC32;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;

public class MessageEncryptor {

	static final String CIPHERTEXT_DELIMITER = " ";
	static final String SENDERID_DELIMITER = ":";
	static int AES_BLOCKSIZE = 16;
	
	MsgKeyPair mOurKeys;
	String mSenderID;
	
	public MessageEncryptor(String senderID) throws Exception {
		// This constructor generates a brand new keypair
		mOurKeys = new MsgKeyPair();
		mOurKeys.generateKeyPair();
		
		mSenderID = senderID;
	}
	
	public MessageEncryptor(String senderID, String secretKeyFile) {
		mOurKeys = new MsgKeyPair();
		mOurKeys.loadKeysFromFile(secretKeyFile);
		
		mSenderID = senderID;
	}
	
	public void regenerateKeys() throws Exception {
		mOurKeys.generateKeyPair();
	}
	
	// Encrypt a given message under the recipient key
	// Steps are:
	// 1. Concatenate sender ID : message string, encode as UTF-8
	// 2. Encrypt with random 128-bit AES key K to get C2
	// 3. Encrypt K with RSA under sender's key to get C1
	// 4. Encode C1, C2 as Base64, compute C' = B64(C1) || " " || B64(C2)
	// 5. Compute a DSA signature S on concatenation C'
	// 6. Output C1 || " " || C2 || " " || S
	
	public String encryptMessage(String message, MsgKeyPair recipientKey) {
		byte[] rsaCiphertext;
		byte[] aesCiphertext;
		byte[] dsaSignature;
		
		// Make sure sure that the recipient's key is valid, and so is ours
		if (recipientKey.isValidForSending() == false || mOurKeys == null)  {
			System.out.println("Error: invalid keys");
			return null;
		}
		
		// Prepend the sender ID to the message
		message = mSenderID + SENDERID_DELIMITER + message;
		
		// Generate a 128-bit AES key and export it to a byte array
		KeyGenerator kgen;
		try {
			kgen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			return null; 
		}
		
	    kgen.init(128);
	    SecretKey aesKey = kgen.generateKey();
	    byte[] rawAESkey = aesKey.getEncoded();
	    
	    // Now encrypt the AES key using the sender's RSA key
	    Cipher rsaCipher;
	    try {
	    	rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		    rsaCipher.init(Cipher.ENCRYPT_MODE, recipientKey.getRSAPublicKey(), new SecureRandom());
		    rsaCiphertext = rsaCipher.doFinal(rawAESkey);
	    } catch (Exception e) {
			return null; 
		}
	   
	    // Configure an AES instance with CTR mode and no padding
	    // then encrypt the message string || CRC32 with it
	    Cipher aesCipher;
	    try {
	    	// Initialize AES with the key
	    	aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
	        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	        IvParameterSpec ivspec = new IvParameterSpec(iv);
	    	aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivspec);
	    	
	    	// Encode message to UTF-8 byte array
	    	ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();
	    	byte[] encodedMessage = message.getBytes("UTF-8");
	    	plaintextStream.write(encodedMessage);
	    	
	    	// Calculate CRC32 on plaintext message
	    	CRC32 crc = new CRC32();
	    	crc.update(encodedMessage);
	    	long crcVal = crc.getValue();
	        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	        buffer.putLong(crcVal);
	        plaintextStream.write(Arrays.copyOfRange(buffer.array(), 4, buffer.array().length));
	        
	        // Manually add padding
	        int paddingLen = AES_BLOCKSIZE - (plaintextStream.size() % AES_BLOCKSIZE);
	        for (int i = 0; i < paddingLen; i++) {
	        	plaintextStream.write(paddingLen);
	        }
	        
	        // AES encrypt the resulting buffer
	        byte[] aesCiphertextWithoutIV = aesCipher.doFinal(plaintextStream.toByteArray());
	        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	        outputStream.write( iv );
	        outputStream.write( aesCiphertextWithoutIV );

	        aesCiphertext = outputStream.toByteArray();
	    } catch (Exception e) {
			return null; 
		}
	    
	    // Encode the RSA and AES ciphertexts as two separate 
	    // Base64 strings, and butt-splice them together
	    String rsaBase64 = Base64.getEncoder().encodeToString(rsaCiphertext);
	    String aesBase64 = Base64.getEncoder().encodeToString(aesCiphertext);
	    String concatenated = rsaBase64 + CIPHERTEXT_DELIMITER + aesBase64;
		
	    // Sign the result using DSA
	    try {
	    	Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
	    	dsa.initSign(mOurKeys.getDSAPrivateKey());
	    	dsa.update(concatenated.getBytes("UTF-8"));
	    	dsaSignature = dsa.sign();
	    } catch (Exception e) {
			return null; 
		}
	    
	    // Encode the signature and output all three base64 strings
	    // concatenated together
	    String dsaBase64 = Base64.getEncoder().encodeToString(dsaSignature);
        concatenated = rsaBase64 + CIPHERTEXT_DELIMITER + aesBase64 + CIPHERTEXT_DELIMITER + dsaBase64;
	    
		return concatenated;
	}
	
	// Decrypt a given ciphertext using our secret key
	public String decryptMessage(String ciphertext, String senderId, MsgKeyPair senderKey) {
		byte[] aesKey;
		byte[] aesPlaintext;
		
		// Make sure sure that the sender's key is valid, and so is ours
		if (senderKey.isValidForSending() == false || mOurKeys == null)  {
			System.out.println("Error: invalid keys");
			return null;
		}

		// First, parse the input ciphertext into three substrings
		// (RSA Ciphertext, AES ciphertext, Signature)
		String[] parsedString = ciphertext.trim().split(CIPHERTEXT_DELIMITER);
		if (parsedString.length != 3) {
			return null;
		}

		// Decode the signature and verify it against the first
		// two encoded strings
	    try {
	    	// Initialize DSA verifier (with SHA1)
			byte[] decodedSignature = Base64.getDecoder().decode(parsedString[2]);
	    	Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
	    	sig.initVerify(senderKey.getDSAPublicKey());
	    	
	    	// Concatenate RSA ciphertext + delimiter + AES ciphertext
	    	// Feed raw bytes into signature verifier
		    String concatenated = parsedString[0] + CIPHERTEXT_DELIMITER + parsedString[1];
	    	sig.update(concatenated.getBytes("UTF-8"));
	    	
	    	// Verify the signature
	    	if (sig.verify(decodedSignature) == false) {
	    		// Verification failed.
	    		return null;
	    	}
	    } catch (Exception e) {
	    	return null;
	    }
	    
		// Instantiate an RSA cipher to decrypt the first component
	    // Now encrypt the AES key using the sender's RSA key
	    Cipher rsaCipher;
	    try {
	    	rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		    rsaCipher.init(Cipher.DECRYPT_MODE, mOurKeys.getRSAPrivateKey());
			byte[] decodedRSACiphertext = Base64.getDecoder().decode(parsedString[0]);
		    aesKey = rsaCipher.doFinal(decodedRSACiphertext);
		    
		    // Check that decryption produced a 16-byte key
		    if (aesKey.length != 16) {
		    	return null;
		    }
	    } catch (Exception e) {
			return null; 
		}

	    // Use the resulting AES key to instantiate an AES cipher
	    // and decrypt the payload
	    Cipher aesCipher;
	    try {
	    	// Decode AES ciphertext
			byte[] decodedAESCiphertext = Base64.getDecoder().decode(parsedString[1]);
			
	    	// Initialize AES with the key
	    	SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
	        byte[] iv = Arrays.copyOfRange(decodedAESCiphertext, 0, 16);
	        byte[] actualCiphertext = Arrays.copyOfRange(decodedAESCiphertext, 16, decodedAESCiphertext.length);
	        IvParameterSpec ivspec = new IvParameterSpec(iv);
	    	aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
	    	aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivspec);
	    	
	        // AES decrypt the ciphertext buffer
	        aesPlaintext = aesCipher.doFinal(actualCiphertext);   
	        
	        // Remove the PKCS7 padding
	        if (aesPlaintext.length >= AES_BLOCKSIZE) {
	        	int paddingLen = aesPlaintext[aesPlaintext.length - 1];
	        	if (paddingLen < 0 || paddingLen > AES_BLOCKSIZE) {
	        		return null;
	        	}
	        	
	        	for (int i = 0; i < paddingLen; i++) {
	        		if (aesPlaintext[(aesPlaintext.length - 1) - i] != paddingLen) {
	        			// Bad padding
	        			return null;
	        		}
	        	}
	        	
	        	// Padding checks out -- remove it
	        	aesPlaintext = Arrays.copyOfRange(aesPlaintext, 0, (aesPlaintext.length) - paddingLen);
	        } else {
	        	// Error: plaintext too small
	        	return null;
	        }
	    } catch (Exception e) {
			return null; 
		}
	
    	// Calculate CRC32 on decrypted message, compare to last four bytes
    	CRC32 crc = new CRC32();
    	crc.update(aesPlaintext, 0, aesPlaintext.length - 4);
    	long crcVal = crc.getValue();
    	byte[] crcBytes = {0, 0, 0, 0, 0, 0, 0, 0};
    	System.arraycopy(aesPlaintext, aesPlaintext.length - 4, crcBytes, 4, 4);
    	if (crcVal != bytesToLong(crcBytes)) {
    		// Invalid CRC
    		return null;
    	}
    	
    	// Strip off the CRC and recover the plaintext to a string
    	String messagePlaintext = new String(Arrays.copyOfRange(aesPlaintext, 0, aesPlaintext.length - 4));
    	
    	// Break the decrypted string into <senderID>:<message>, and check
    	// that <senderID> matches the expected sender
    	int delimiterLoc = messagePlaintext.indexOf(SENDERID_DELIMITER);
    	if (delimiterLoc < 1) {
    		return null;
    	}
    	if (messagePlaintext.substring(0, delimiterLoc).equals(senderId) == false) {
    		return null;
    	}
    	
    	// Finally, trim off the sender ID portion and return the 
    	// message itself
    	return messagePlaintext.substring(delimiterLoc + 1);
	}
	
	public long bytesToLong(byte[] bytes) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.put(bytes);
	    buffer.flip(); // needed to handle byte order issues 
	    return buffer.getLong();
	}
	
	public String getEncodedPublicKeys() {
		if (mOurKeys == null) {
			return null;
		}
		
		return mOurKeys.getEncodedPubKey();
	}
	
	public String getKeyFingerprint() {
		return MessageEncryptor.computeFingerprint(getEncodedPublicKeys());
	}
	
	static public String computeFingerprint(String encodedPublicKey) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (Exception e) {
			return "";
		}
		byte[] hash = digest.digest(encodedPublicKey.getBytes(StandardCharsets.UTF_8));
		
		StringBuilder sb = new StringBuilder();
	    for (byte b : hash) {
	        sb.append(String.format("%02X ", b));
	    }
	    
	    return sb.toString();
	}
}
