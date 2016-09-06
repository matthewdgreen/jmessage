package msgclient;

public class TestEncryption {
	static boolean testEncryption(String message) throws Exception {
		
		MessageEncryptor senderEncryptor = new MessageEncryptor("senderTestID");
		MessageEncryptor receiverEncryptor = new MessageEncryptor("receiverTestID");
		
		String encodedReceiverPubKey = receiverEncryptor.getEncodedPublicKeys();
		String encodedSenderPubKey = senderEncryptor.getEncodedPublicKeys();
		MsgKeyPair receiverKeyPair = new MsgKeyPair(encodedReceiverPubKey);
		MsgKeyPair senderKeyPair = new MsgKeyPair(encodedSenderPubKey);
				
		// Encrypt the message
		String encryptedMsg = senderEncryptor.encryptMessage(message, receiverKeyPair);
		if (encryptedMsg == null) {
			System.out.println("Failed to encrypt message.");
			return false;
		}
		
		// Decrypt the resulting ciphertext
		String decryptedMsg = receiverEncryptor.decryptMessage(encryptedMsg, senderEncryptor.mSenderID, senderKeyPair);
		if (decryptedMsg == null) {
			System.out.println("Failed to decrypt message.");
			return false;
		}	

		// Compare the decrypted message to the original
		if (message.equals(decryptedMsg) == true) {
			return true;
		} else {
			return false;
		}
	}
}
