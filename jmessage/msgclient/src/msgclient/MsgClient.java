// MsgClient.java
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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Scanner;
import org.apache.commons.cli.*;

public class MsgClient {
	
	static final int DEFAULT_PORT = 8000;
	static final String DEFAULT_PASSWORD = "";
	static final String READRECEIPT_MESSAGE = ">>>READMESSAGE";
	
	String	serverName;
	int		serverPort;
	String	serverUsername;
	String	serverPassword;
	String  mPeerIdentifier;
	MessageEncryptor mEncryptor;
	ServerConnection mServerConnection;
	ArrayList<Message> mPendingMessages;
	Thread 	mCheckerThread = null;
	long	mCurrentMessageID = 0;
	
	Scanner scanner;
	
	public MsgClient() {
		mPendingMessages = new ArrayList<Message>();
	}
	
	public void parseArguments(String[] args) throws Exception {
    	// Parse command line arguments
    	Options options = new Options();

        Option server = new Option("s", "server", true, "server name");
        server.setRequired(true);
        options.addOption(server);

        Option port = new Option("p", "port", true, "server port (default 8000)");
        port.setRequired(false);
        options.addOption(port);
        
        Option uname = new Option("u", "username", true, "username");
        uname.setRequired(true);
        options.addOption(uname);
        
        Option password = new Option("w", "password", false, "password (default is none)");
        password.setRequired(false);
        options.addOption(password);
        
        Option peerIdentifier = new Option("m", "peer identifier", true, "peer identifier (default is none)");
        peerIdentifier.setRequired(false);
        options.addOption(peerIdentifier);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("msgclient", options);

            System.exit(1);
            return;
        }
        
        // Optional arguments
        if (cmd.hasOption("p") == true) {
        	serverPort = Integer.parseInt(cmd.getOptionValue("p"));
        } else {
        	serverPort = DEFAULT_PORT;
        }
        
        if (cmd.hasOption("w") == true) {
        	serverPassword = cmd.getOptionValue("w");
        } else {
        	serverPassword = "";
        }
        
        if (cmd.hasOption("m") == true) {
        	mPeerIdentifier = cmd.getOptionValue("m");
        } else {
        	mPeerIdentifier = "";
        }
        
        // Required arguments
        serverName = cmd.getOptionValue("s");
        serverUsername = cmd.getOptionValue("u");
	}
	
	public void printHelp() {
		System.out.println("Available commands:");
		System.out.println("   get (or empty line)  - check for new messages");
		System.out.println("   c(ompose) <user>     - compose a message to <user>");
		System.out.println("   f(ingerprint) <user> - return the key fingerprint of <user>");
		System.out.println("   l(ist)               - lists all the users in the system");
		System.out.println("   genkeys              - generates and registers a fresh keypair");
		System.out.println("   h(elp)               - prints this listing");
		System.out.println("   q(uit)               - exits");
	}
	
	public boolean isReadReceipt(String messageText) {
		if (messageText.startsWith(READRECEIPT_MESSAGE) == true) {
			return true;
		} else {
			return false;
		}
	}
	
	public void sendReadReceipt(String receiverID, long msgID) {
		// First look up the recipient's public key on the server
		MsgKeyPair recipientKey = mServerConnection.lookupKey(receiverID);
		if (recipientKey == null) {
			return;
		}
		
		String readMessage = READRECEIPT_MESSAGE + " " + msgID;
		String encryptedMessage = mEncryptor.encryptMessage(readMessage, recipientKey);
		
		if (encryptedMessage == null) {
			System.out.println("Error sending read receipt.");
		} else {
			// Send the encrypted message
			mServerConnection.sendEncryptedMessage(receiverID, mCurrentMessageID++, encryptedMessage);
		}
	}
	
	public void printMessage(Message message) {
		java.util.Date time = new java.util.Date(message.getSentTime() * 1000);
		
		System.out.println("");
		System.out.println("Message ID: " + message.getMessageID());
		System.out.println("From: " + message.getSenderID());
		System.out.println("Time: " + time);
		System.out.println(message.getMessageText());
	}
	
	// Print pending messages
	public void printMessages() throws Exception {	
		synchronized(mPendingMessages) {
			if (mPendingMessages.isEmpty()) {
				System.out.println("No new messages.");
			} else {
				Iterator<Message> iterator = mPendingMessages.iterator();
		
				while (iterator.hasNext()) {
					Message nextMessage = iterator.next();
				
					printMessage(nextMessage);
				}
		
				// Clear the array
				mPendingMessages.clear();
			}
		}
	}
	
	// Get messages from the server, store them in mPendingMessages
	public void getMessages() throws Exception {		
		// Call the server to get recent mail
		ArrayList<EncryptedMessage> messages = mServerConnection.lookupMessages();
		
		if (messages == null) {
			System.out.println("Invalid response from server");
			return;
		}
		
		// Decrypt and process each message
		if (messages == null || messages.isEmpty()) {
			//System.out.println("No new messages.");
		} else {
			Iterator<EncryptedMessage> iterator = messages.iterator();
			while (iterator.hasNext()) {
				EncryptedMessage nextMessage = iterator.next();
				
				//System.out.println("Received an encrypted message");
				
				// We need to get the sender's public key
				MsgKeyPair senderKey = mServerConnection.lookupKey(nextMessage.getSenderID());
				if (senderKey != null) {
					String decryptedText = mEncryptor.decryptMessage(nextMessage.getMessageText(), 
						nextMessage.getSenderID(), senderKey);
					
					if (decryptedText != null) {
						if (isReadReceipt(decryptedText) == false) {
							// Add the decrypted message to our pending messages list
							Message newMessage = new Message(nextMessage.getSenderID(), 
									nextMessage.getReceiverID(), decryptedText,
									nextMessage.getSentTime(), nextMessage.getMessageID());
							
							// Make sure we don't mess with the object thread locks,
							// since the mPendingMessages member can be accessed by
							// a different thread.
							synchronized (mPendingMessages) {
								mPendingMessages.add(newMessage);
								//System.out.println("Got a message!");
							}

							sendReadReceipt(nextMessage.getSenderID(), nextMessage.getMessageID());
						}
					}
				} else {				
					//System.out.println("Could not get keys for " + nextMessage.getSenderID());
				}
			}
			
		}
	}

	// List existing users in the server
	public void listUsers() throws Exception {
		System.out.println("Getting list of user IDs from server...");

		ArrayList<String> users = mServerConnection.lookupUsers();
		if (users == null) {
			System.out.println("Could not reach the server");
			return;
		} else if (users.isEmpty()) {
			System.out.println("No users yet");
			return;
		}

		// Display the list of users
		for(int i = 0; i < users.size(); i++) {
			System.out.println(i + ":" + users.get(i));
		}
		System.out.println("");
		return;
	}
	
	// Send a new message without UI interaction
	public boolean transmitMessage(String recipient, String message) throws Exception {
		
		// First look up the recipient's public key on the server
		MsgKeyPair recipientKey = mServerConnection.lookupKey(recipient);
		if (recipientKey == null) {
			System.out.println("Could not find a key for user " + recipient);
			return false;
		}
		
		String encryptedMessage = mEncryptor.encryptMessage(message, recipientKey);
		if (encryptedMessage == null) {
			System.out.println("Error encrypting message.");
			return false;
		} else {
			// Send the encrypted message
			boolean result = mServerConnection.sendEncryptedMessage(recipient, mCurrentMessageID++, encryptedMessage);
				
			if (result) {
				System.out.println("Message sent.");
			} else {
				System.out.println("Failed to send.");
			}
			
			return result;
		} 
	}
	
	// Compose a new message
	public void composeMessage(String recipient) throws Exception {
		
		// First look up the recipient's public key on the server
		MsgKeyPair recipientKey = mServerConnection.lookupKey(recipient);
		if (recipientKey == null) {
			System.out.println("Could not find a key for user " + recipient);
			return;
		}
		
		// Read in a message
		System.out.println("Enter your message and hit return (empty line cancels message):");
		String message = scanner.nextLine().trim();
		
		if (message.isEmpty() == true) {
			System.out.println("Message canceled.");
		} else {
			// Encrypt the message to the recipient
			String encryptedMessage = mEncryptor.encryptMessage(message, recipientKey);
			if (encryptedMessage == null) {
				System.out.println("Error encrypting message.");
			} else {
				// Send the encrypted message
				boolean result = mServerConnection.sendEncryptedMessage(recipient, mCurrentMessageID++, encryptedMessage);
				
				if (result) {
					System.out.println("Message sent.");
				} else {
					System.out.println("Failed to send.");
				}
			}
		} 
	}
	
	// Print the key fingerprint of a user
	public void printFingerprint(String recipient) throws Exception {
		MsgKeyPair recipientKey = null;
		
		if (recipient.isEmpty() == false) {
			// First look up the recipient's public key on the server
			recipientKey = mServerConnection.lookupKey(recipient);
			if (recipientKey == null) {
				System.out.println("Could not find a key for user " + recipient);
				return;
			}
		}
		
		// Print our fingerprint and the user's fingerprint
		System.out.println("Your key fingerprint: ");
		System.out.println(mEncryptor.getKeyFingerprint());
		
		if (recipientKey != null) {
			System.out.println("Fingerprint for user " + recipient + ":");
			System.out.println(MessageEncryptor.computeFingerprint(recipientKey.getEncodedPubKey()));
		}
	}
	
	// Generates a MsgKeyPair, registers it with server
	public boolean registerKeys(boolean regenerate) {
		boolean success = false;
		
		try {
			// Regenerate our key pair if we're asked to
			if (regenerate == true) {
				System.out.println("Generating a new keypair...");
				mEncryptor.regenerateKeys();
			}
		
			// Send the public keys to the server
			success = mServerConnection.registerKey(mEncryptor.getEncodedPublicKeys());
		} catch (Exception e) {
			System.out.println("Register keys, failed with: " + e);
			return false;
		}
		
		return success;
	}
	
	public String constructMessage(String peerIdentifier) {
		return "Hey " + peerIdentifier + ", what do you think about 09 F9 11 02 9D 74 E3 5B D8 41 56 C5 63 56 88 C0?";
	}
	
	public void automaticLoop() throws Exception {
		boolean running = true;

		while (running) {
			Thread.sleep(20000);
			transmitMessage(mPeerIdentifier, constructMessage(mPeerIdentifier));	
		}
	}
	
	public void mainLoop() throws Exception {
		boolean running = true;
		scanner = new Scanner(System.in);
		
		while (running == true) {
			// Print a command prompt and wait for user input
			System.out.print("enter command> ");
			String command = scanner.nextLine().trim();
		
			// Parse input into tokens
			String[] parsedString = command.split("[ ]+");
			
			// Check input
			if (command.isEmpty() || parsedString[0].equals("get")) {
				printMessages();
			}
			else if (parsedString[0].startsWith("c")) {
				if (parsedString.length > 1) {
					composeMessage(parsedString[1]);
				} else {
					System.out.println("Usage: compose <username>");
				}
			} else if (parsedString[0].startsWith("f")) {
				if (parsedString.length > 1) {
					printFingerprint(parsedString[1]);
				} else {
					printFingerprint("");
				}
			} else if (parsedString[0].startsWith("l")) {
				listUsers();
			} else if (parsedString[0].startsWith("h") || parsedString[0].startsWith("?")) {
				printHelp();
			} else if (parsedString[0].startsWith("q")) {
				running = false;
			} else if (parsedString[0].startsWith("genkeys")) {
				if (registerKeys(true) == false) {
					System.out.println("Error: could not register new keypair");
				}
			}
			
			//System.out.println(command);
		}
		
		scanner.close();
	}
	
	public void runClient() throws Exception {
		
		// Create an encryption class and a server connection class
		mEncryptor = new MessageEncryptor(serverUsername);
		try {
			mServerConnection = new ServerConnection(serverName, serverPort, serverUsername, serverPassword);
			mServerConnection.connectToServer();
		} catch (Exception e) {
			System.out.println("Could not connect to server.");
			System.exit(1);
		}
		
		// Run an encryption test
		if (TestEncryption.testEncryption("Test message") == false) {
			System.out.println("Encryption self-test failed.");
		}
		
		// JAA: this seems to register a new key every time the client is launched.
		// Register our public keys
		if (registerKeys(false) == false) {
			// Key registration failed
			System.out.println("Could not contact server to register keys. Exiting.");
			System.exit(1);
		}
		
		// All tests and registration complete
		System.out.println("Server connection successful. Type (h)elp for commands.");
		
		// With a server connection, launch the background message checking thread
		MessageChecker checkerRunnable = new MessageChecker(this);
		mCheckerThread = new Thread(checkerRunnable);
		mCheckerThread.setDaemon(true);
		mCheckerThread.start();
		   
		// Start the main "UI" command entry loop
		if (mPeerIdentifier == null || mPeerIdentifier.isEmpty()) {
			mainLoop();
		} else {
			automaticLoop();
		}
		// Shut down the messaging checking thread
    	if (mCheckerThread != null) {
    		checkerRunnable.terminate();
    		mCheckerThread.join();
    	}
    	
		// Shut down the connection to the server
		mServerConnection.shutDown();
	}
	
    public static void main(String[] args) throws Exception {
    	
    	// Create a client and parse command line arguments
    	MsgClient msgClient = new MsgClient();
    	msgClient.parseArguments(args);
    	
    	// Run the client
    	msgClient.runClient();
    	
    	// We're done
        System.out.println("Shutting down...");
    }
    
}
