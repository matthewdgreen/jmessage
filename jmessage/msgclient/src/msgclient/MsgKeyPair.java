// MsgKeyPair.java
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

import java.security.*;
import java.security.spec.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class MsgKeyPair {

	static final String PUBKEY_DELIMITER = "%";
	
	PublicKey mRSAPublicKey = null;
	PublicKey mDSAPublicKey = null;
	KeyPair mRSAKeys = null;
	KeyPair mDSAKeys = null;
	boolean mHasPrivate = false;
	
	public MsgKeyPair() {
	}
	
	public MsgKeyPair(String encodedPubKey) throws Exception {
		setPublicKey(encodedPubKey);
	}
	
	public void setPublicKey(String encodedPubKey) throws Exception {
		// Parse the key as RSA || DELIMITER CHAR || DSA
		String[] parsedKeys = encodedPubKey.trim().split(PUBKEY_DELIMITER);
		if (parsedKeys.length != 2 || parsedKeys[0].length() < 50 || parsedKeys[1].length() < 50) {
			throw new Exception();
		}
		
		// Decode the RSA public key
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");
		byte[] decodedRSAPubKey = Base64.getDecoder().decode(parsedKeys[0]);
        EncodedKeySpec publicKeySpecRSA = new X509EncodedKeySpec(decodedRSAPubKey);
        mRSAPublicKey = keyFactoryRSA.generatePublic(publicKeySpecRSA);
		
        // Decode the DSA public key
		KeyFactory keyFactoryDSA = KeyFactory.getInstance("DSA");
		byte[] decodedDSAPubKey = Base64.getDecoder().decode(parsedKeys[1]);
        EncodedKeySpec publicKeySpecDSA = new X509EncodedKeySpec(decodedDSAPubKey);
        mDSAPublicKey = keyFactoryDSA.generatePublic(publicKeySpecDSA);
        
        mHasPrivate = false;
	}
	
	public void generateKeyPair() throws Exception {
		// Generate a 1024-bit RSA keypair
		KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA");
		keyGenRSA.initialize(1024);
		
		// Store the resulting RSA keypair
		mRSAKeys = keyGenRSA.genKeyPair();
		mRSAPublicKey = mRSAKeys.getPublic();

        // Generate a 1024-bit DSA keypair
        KeyPairGenerator keyGenDSA = KeyPairGenerator.getInstance("DSA");
        keyGenDSA.initialize(1024);
        
        // Store the resulting DSA keypair
        mDSAKeys = keyGenDSA.genKeyPair();
        mDSAPublicKey = mDSAKeys.getPublic();
        
        mHasPrivate = true;
        
        // Print the encoded public key out as a test
        //System.out.print("Public key is: ");
        //System.out.println(getEncodedPubKey());
	}
	
	// Returns the two public keys encoded as a single string
	public String getEncodedPubKey() {
        StringBuffer hexPublicKey = new StringBuffer();

		// Get the RSA public key and encode into hex. Add to hexPublicKey.
        byte[] rsaPublicKey = mRSAPublicKey.getEncoded();
        hexPublicKey.append(Base64.getEncoder().encodeToString(rsaPublicKey));
        
        // Add a (non-hex) delimiter between the two public keys
        hexPublicKey.append(PUBKEY_DELIMITER);
        
		// Get the DSA public key and encode into hex. Add to hexPublicKey.
        byte[] dsaPublicKey = mDSAPublicKey.getEncoded();
        hexPublicKey.append(Base64.getEncoder().encodeToString(dsaPublicKey));
        
        return hexPublicKey.toString();
	}
	
	// Get the RSA public key if there is one
	public PublicKey getRSAPublicKey() {
		return mRSAPublicKey;
	}
	
	// Get the DSA private key if there is one
	public PrivateKey getDSAPrivateKey() {
		if (mDSAKeys == null) {
			return null;
		}
		
		return mDSAKeys.getPrivate();
	}
	
	// Get the DSA public key if there is one
	public PublicKey getDSAPublicKey() {
		return mDSAPublicKey;
	}
	
	// Get the RSA private key if there is one
	public PrivateKey getRSAPrivateKey() {
		if (mRSAKeys == null) {
			return null;
		}
		
		return mRSAKeys.getPrivate();
	}
	
	// Check that this class contains valid public keys
	public boolean isValidForSending() {
		if (mRSAPublicKey != null && mDSAPublicKey != null) {
			return true;
		} else { 
			return false;
		}
	}
	
	public void loadKeysFromFile(String secretKeyFile) {
		// TODO. Not implemented yet
	}
	
}
