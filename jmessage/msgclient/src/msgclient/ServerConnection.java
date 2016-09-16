// ServerConnection.java
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

import org.apache.http.impl.client.*;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.commons.io.IOUtils;
import java.net.URI;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import java.util.*;

public class ServerConnection {

	static final String PROTOCOL_TYPE = "http";
	static final String USERLOOKUP_PATH = "/lookupUsers";
	static final String KEYLOOKUP_PATH = "/lookupKey";
	static final String MESSAGELOOKUP_PATH = "/getMessages";
	static final String KEYREGISTER_PATH = "/registerKey";
	static final String SENDMESSAGE_PATH = "/sendMessage";
	static final String RESPONSE_KEYDATA = "keyData";	

	String mServerName;
	String mUsername;
	String mPassword;
	int mPort;
	
	public ServerConnection(String serverName, int port, String username, String password) {
		mServerName = serverName;
		mUsername = username;
		mPassword = password;
		mPort = port;
	}
	
	public void connectToServer() {
		// TODO
	}
	
	public JSONObject makeGetToServer(String path) {
		CloseableHttpResponse response;
		JSONObject jsonObject = null;
		
		// Send a GET request to the server
		try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
			// Create a URI	         
			URI uri = new URIBuilder()
			        .setScheme(PROTOCOL_TYPE)
			        .setHost(mServerName + ":" + mPort)
			        .setPath(path)
			        .build();
	        HttpGet httpget = new HttpGet(uri);
	        httpget.addHeader("accept", "application/json");
	        //System.out.println(httpget.getURI());

	        response = httpClient.execute(httpget);
            if (response.getStatusLine().getStatusCode() == 200) {           
            	String jsonData = IOUtils.toString(response.getEntity().getContent());
            	JSONParser parser = new JSONParser();
            	Object obj = parser.parse(jsonData);
            	jsonObject = (JSONObject) obj;
            } else {
            	System.out.println("Received status code " + response.getStatusLine().getStatusCode() + " from server");
            }
            
	        response.close();
	        httpClient.close();
		} catch (Exception e) {
			System.out.println(e);
			return null;
		} 
		
		return jsonObject;
	}
	
	public JSONObject makePostToServer(String path, String json_data) {
		CloseableHttpResponse response;
		JSONObject jsonObject = null;
		
		// Send a POST request to the server
		try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
			// Create a URI	         
			URI uri = new URIBuilder()
			        .setScheme(PROTOCOL_TYPE)
			        .setHost(mServerName + ":" + mPort)
			        .setPath(path)
			        .build();
			HttpPost httppost = new HttpPost(uri);
	        //System.out.println(httppost.getURI());
	        StringEntity entity = new StringEntity(json_data, ContentType.create("plain/text", "UTF-8"));
	        entity.setContentType("application/json");
	        httppost.setEntity(entity);
	        
	        response = httpClient.execute(httppost);
            if (response.getStatusLine().getStatusCode() == 200) {           
            	String jsonData = IOUtils.toString(response.getEntity().getContent());
            	JSONParser parser = new JSONParser();
            	Object obj = parser.parse(jsonData);
            	jsonObject = (JSONObject) obj;
            } else {
            	System.out.println("Received status code " + response.getStatusLine().getStatusCode() + " from server");
            }
            
	        response.close();
	        httpClient.close();
		} catch (Exception e) {
			System.out.println(e);
			return null;
		} 
		
		return jsonObject;
	}
	
	public ArrayList<String> lookupUsers() {
		ArrayList<String> result = new ArrayList<String>();

		JSONObject jsonObject = makeGetToServer(USERLOOKUP_PATH);
		if (jsonObject == null) {
			return null;
		}

		try {
			long numUsers = (long) jsonObject.get("numUsers");
			if (numUsers <= 0) {
				return result;
			}

			JSONArray users = (JSONArray) jsonObject.get("users");
			Iterator<String> iterator = users.iterator();
			while (iterator.hasNext()) {
				String nextUser = iterator.next();
				result.add(nextUser);
			}
		} catch (Exception e) {
			// Some kind of problem
			return null;
		}

		return result;
	}
	
	public MsgKeyPair lookupKey(String recipient) {
		MsgKeyPair result = null;
		
		JSONObject jsonObject = makeGetToServer(KEYLOOKUP_PATH + "/" + recipient);
        String keyData = (String) jsonObject.get("keyData");
        keyData = keyData.trim();
        //System.out.println(keyData);
                
        // Attempt to parse the key blob back into a MsgKeyPair
        try {
        	if (keyData != null && keyData.isEmpty() == false) {
        		result = new MsgKeyPair(keyData);
        	} else {
        		System.out.println("Did not receive a key from the server");
        	}
        } catch (Exception e) {
        	// Unable to parse the key data
        	System.out.println("Encountered a malformed key");
        	result = null;
        }
		
		// Finally, return the key if it was found
		return result;
	}
	
	public ArrayList<EncryptedMessage> lookupMessages() {
		ArrayList<EncryptedMessage> result = new ArrayList<EncryptedMessage>();
		
		JSONObject jsonObject = makeGetToServer(MESSAGELOOKUP_PATH + "/" + mUsername);
		if (jsonObject == null) {
			return null;
		}
		
		try {
			long numMessages = (long) jsonObject.get("numMessages");
			if (numMessages <= 0) {
				return result;
			}

			JSONArray msg = (JSONArray) jsonObject.get("messages");
			Iterator<JSONObject> iterator = msg.iterator();
			while (iterator.hasNext()) {
				JSONObject nextMessage = iterator.next();
				long sentTime = (long) nextMessage.get("sentTime");
				long messageID = (long) nextMessage.get("messageID");
				String encryptedMessage = (String) nextMessage.get("message");
				String fromID = (String) nextMessage.get("senderID");
			
				if (encryptedMessage != null) {
					if (encryptedMessage.trim().isEmpty() == false) {
						EncryptedMessage eMsg = new EncryptedMessage(fromID.trim(), mUsername.trim(), 
								encryptedMessage.trim(), sentTime, messageID);
						result.add(eMsg);
					}
				}
			}
		} catch (Exception e) {
			// Some kind of problem
			return null;
		}
        
		// Return the resulting list
		return result;
	}
	
	public boolean registerKey(String encodedKey) {		
		// build up post data for key registration
		boolean result = false;
		String keyData = "{\"keyData\": \"" + encodedKey + "\"}";
		JSONObject jsonObject = makePostToServer(KEYREGISTER_PATH + "/" + mUsername, keyData);
        if (jsonObject == null) {
        	System.out.println("Key registration failed.");
        } else {
	        result = (boolean) jsonObject.get("result");
	        
	        if (result) {
	        	System.out.println("Successfully registered a public key for '" + mUsername + "'.");
	        }
        }
        return result;
	}
	
	public boolean sendEncryptedMessage(String recipient, long messageID, String encryptedMessage) {
		String messageDetails = "{\"recipient\": \"" + recipient + "\", \"messageID\": \"" + messageID + "\", \"message\": \"" + encryptedMessage + "\"}";		
		JSONObject jsonObject = makePostToServer(SENDMESSAGE_PATH + "/" + mUsername, messageDetails);
		if (jsonObject == null) {
			System.out.println("Failed to send encrypted message.");
		}
		
		return true;
	}
	
	public void shutDown() {
	}
}
