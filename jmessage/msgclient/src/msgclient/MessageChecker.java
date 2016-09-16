package msgclient;

public class MessageChecker implements Runnable {

	MsgClient mMsgClient;
	boolean	  mRunning = true;
	
	MessageChecker(MsgClient msgClient) {
		mMsgClient = msgClient;
	}
	
	public void terminate() {
		mRunning = false;
	}
	
	// Message checking loop. Runs in the background as long as
	// the program is running.
    public void run() {
    	while (mRunning == true) {
    		try {
    			Thread.sleep(5000);
        		mMsgClient.getMessages();

    		} catch (Exception e) {
    			System.out.println("Caught an exception in MessageChecker" + e);
    		}
    	}
    }
}
