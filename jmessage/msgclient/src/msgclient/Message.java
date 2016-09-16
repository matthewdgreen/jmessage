package msgclient;

public class Message {
	String 	mSenderID;
	String 	mReceiverID;
	String 	mMessageText;
	long	mSentTime;
	long	mMessageID;
	
	public Message(String senderID, String receiverID, String messageText, 
			long sentTime, long messageID) {
		this.mSenderID = senderID;
		this.mReceiverID = receiverID;
		this.mMessageText = messageText;
		this.mSentTime = sentTime;
		this.mMessageID = messageID;
	}
	
	public String getSenderID() {
		return mSenderID;
	}
	
	public String getReceiverID() {
		return mReceiverID;
	}
	
	public String getMessageText() {
		return mMessageText;
	}
	
	public long getSentTime() {
		return mSentTime;
	}
	
	public long getMessageID() {
		return mMessageID;
	}
	
}
