
/*--------------------------------------------------------

1. Erik P 08/18/18


2. Java version used: 1.8

3. Command-line instructions:

	:javac Blockchain.java
	:java Blockchain
	or
	:all.bat 

4. Instructions to run this program:

	:javac Blockchain.java
	:java Blockchain //or// :all.bat
	
	
5. List of files needed for running the program:
	Technically only need the Blockchain.java and BlockInput0.txt
	a)Blockchain.java
	b)BlockInput0.txt
	c)BlockInput1.txt
	d)BlockInput2.txt
	e)all.bat
	f)BlockchainLedger.xml

5. Notes:
	all.bat will spawn off the three servers in three terminal windows
	I don't reassign the combined verification hash and the sha256 and sign it the second time before adding it to the blockchain
	It does make a sha256 and sign it before it sends to the Unverified Server and it does "verify" in the queue
	This only has bare bones functionality, no console commands or verifying the entire chain
	
6. Special Thanks to the following websites
	Thanks: http://www.javacodex.com/Concurrency/PriorityBlockingQueue-Example
	http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
	https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
	https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
	https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom	
	https://www.mkyong.com/java/java-sha-hashing-example/
	https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
	https://stackoverflow.com/questions/9755057/converting-strings-to-encryption-keys-and-vice-versa-java

----------------------------------------------------------*/

import java.util.*;

import java.io.*;
import java.net.*;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.*;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;



//this is the custom class that takes the process number and a string of the PublicKey
//will be xml marshalled and sent to the other servers and saved in a hashmap for access to later
@XmlRootElement
class ProcessBlock{
  Integer processID;
  String pubKey;
public int getProcessID() {
	return processID;
}
@XmlElement
public void setProcessID(int processID) {
	this.processID = processID;
}
public String getPubKey() {
	return pubKey;
}
@XmlElement
public void setPubKey(String pubKey) {
	this.pubKey = pubKey;
}
  }

//the major block in all of this
//holds the medical/personal data as well as necessary info for sending and verifying the blocks
@XmlRootElement
class HealthRecord{
	String SHA256String;
	String SignedSHA256;
	String hashSolution;
	String BlockUUID;
	String BlockNumber;
	String VerificationProcessID;
	String CreatorProcessID;
	String TimeStamp;
	String PreviousHash;
	String Fname;
	String Lname;
	String Bday;
	String SSN;
	String Diagnosis;
	String wellnessRec;
	String drugRec;
	
	
	public String gethashSolution() {
		return hashSolution;
	}
	@XmlElement
	public void sethashSolution(String hashsol) {
		hashSolution = hashsol;
	}
	public String getBlockNumber() {
		return BlockNumber;
	}
	@XmlElement
	public void setBlockNumber(String blocknum) {
		BlockNumber = blocknum;
	}
	
	public String getCreatorProcessID() {
		return CreatorProcessID;
	}
	@XmlElement
	public void setCreatorProcessID(String id) {
		CreatorProcessID = id;
	}
	public String getVerificationProcessID() {
		return VerificationProcessID;
	}
	@XmlElement
	public void setVerificationProcessID(String verificationId) {
		VerificationProcessID = verificationId;
	}
	public String getSHA256String() {
		return SHA256String;
	}
	@XmlElement
	public void setSHA256String(String sHA256String) {
		SHA256String = sHA256String;
	}
	public String getSignedSHA256() {
		return SignedSHA256;
	}
	@XmlElement
	public void setSignedSHA256(String signedSHA256) {
		SignedSHA256 = signedSHA256;
	}
	public String getBlockUUID() {
		return BlockUUID;
	}
	@XmlElement
	public void setBlockUUID(String blockUUID) {
		BlockUUID = blockUUID;
	}
	public String getTimeStamp() {
		return TimeStamp;
	}
	@XmlElement
	public void setTimeStamp(String timeStamp) {
		TimeStamp = timeStamp;
	}
	public String getPreviousHash() {
		return PreviousHash;
	}
	@XmlElement
	public void setPreviousHash(String previousHash) {
		PreviousHash = previousHash;
	}
	public String getFname() {
		return Fname;
	}
	@XmlElement
	public void setFname(String fname) {
		Fname = fname;
	}
	public String getLname() {
		return Lname;
	}
	@XmlElement
	public void setLname(String lname) {
		Lname = lname;
	}
	public String getBday() {
		return Bday;
	}
	@XmlElement
	public void setBday(String bday) {
		Bday = bday;
	}
	public String getSSN() {
		return SSN;
	}
	@XmlElement
	public void setSSN(String sSN) {
		SSN = sSN;
	}
	public String getDiagnosis() {
		return Diagnosis;
	}
	@XmlElement
	public void setDiagnosis(String diagnosis) {
		Diagnosis = diagnosis;
	}
	public String getWellnessRec() {
		return wellnessRec;
	}
	@XmlElement
	public void setWellnessRec(String wellnessRec) {
		this.wellnessRec = wellnessRec;
	}
	public String getDrugRec() {
		return drugRec;
	}
	@XmlElement
	public void setDrugRec(String drugRec) {
		this.drugRec = drugRec;
	}
}
// Ports will incremented by 1 based on it's PID
class Ports{
	public static int PublicKeyPortBase = 4710;
	public static int UnverifiedPortBase = 4820;
	public static int BCPortBase = 4930;

	public static int PublicKeyPort;
	public static int UnverifiedPort;
	public static int BCPort;

	public void setPorts(){
		PublicKeyPort = PublicKeyPortBase + Blockchain.PID;
		UnverifiedPort = UnverifiedPortBase + Blockchain.PID;
		BCPort = BCPortBase + Blockchain.PID;
		}
}



//cookiecutter code for implementing all 3 listener ports

//will initialize the port and listen for incoming public keys
class PublicKeyWorker extends Thread {
	Socket sock;
	PublicKeyWorker (Socket s) {sock = s;}
	public void run(){
		try{
			//basic connection strategy
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			//gonna concatenate everything that's coming in
			StringBuilder everything = new StringBuilder();
			String data;
			while((data = in.readLine()) != null) {
				everything.append(data);
			}
			
			//now that we have everything, we're gonna unmarshall it back into the process class
			String erthing = everything.toString();
			JAXBContext jaxbContext = JAXBContext.newInstance(ProcessBlock.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			StringReader reader = new StringReader(erthing);
			ProcessBlock pb2 = (ProcessBlock)jaxbUnmarshaller.unmarshal(reader);
			//finally we will add it to the hashmap for later use
			Blockchain.zed.put(pb2.getProcessID(), pb2);
			System.out.println("Got from PID: " + pb2.getProcessID() + "\nWith Key: " + pb2.getPubKey());
			sock.close();
			}catch (IOException x){x.printStackTrace();} catch (JAXBException e) {e.printStackTrace();}
		}
	}
//starts listening
class PublicKeyServer implements Runnable{
	public void run(){
		int q_len = 6;
		Socket sock;
		System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.PublicKeyPort));
		try{
			
			ServerSocket servsock = new ServerSocket(Ports.PublicKeyPort, q_len);
			while(true){
				sock = servsock.accept();
				new PublicKeyWorker(sock).start(); 
				}
			}catch(IOException ioe){System.out.println(ioe);}
		}
	}

//will receive unverified blocks of data(entirely user medical data)
class UnverifiedBlockServer implements Runnable {
	//our priority queue is gonna take type HealthRecord
	BlockingQueue<HealthRecord> queue;
	UnverifiedBlockServer(BlockingQueue<HealthRecord> queue){
		this.queue = queue; 
		}

	class UnverifiedBlockWorker extends Thread {
		Socket sock;
		UnverifiedBlockWorker (Socket s) {sock = s;} 
		public void run(){
			try{
				//same as before, gonna read everything into a big string
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				StringBuilder tempBuild = new StringBuilder();
				String data;
				while((data = in.readLine()) != null) {
					tempBuild.append(data);
    				}
				String finalBlock = tempBuild.toString();
				//this is where we will reconstruct the object
				//we give the context for reconstructing the object which is a HealthRecord type
				JAXBContext jaxbContext = JAXBContext.newInstance(HealthRecord.class);
				Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
				StringReader readerForHealth = new StringReader(finalBlock);
				HealthRecord queueHealthRecord = (HealthRecord)jaxbUnmarshaller.unmarshal(readerForHealth);
				//finally we add it to the queue
				queue.put(queueHealthRecord);
				sock.close(); 
    			}catch(Exception e){e.printStackTrace();}
    		}
    	}
public void run(){
	int q_len = 6;
    Socket sock;
    System.out.println("Starting the Unverified Block Server input thread using " + Integer.toString(Ports.UnverifiedPort));
    try{
    	ServerSocket servsock = new ServerSocket(Ports.UnverifiedPort, q_len);
    	//continually listening for new connecctions for incoming blocks
    	while(true){
    		sock = servsock.accept();
    		new UnverifiedBlockWorker(sock).start();
    		}
    	}catch(IOException ioe){System.out.println(ioe);}
    }
}

//Generally: Gonna Pull from the queue do some work, verify it and ship it off to the blockchain worker to 
//be added to the chain
class UnverifiedBlockConsumer implements Runnable {
  BlockingQueue<HealthRecord> queue;
  UnverifiedBlockConsumer(BlockingQueue<HealthRecord> queue){
    this.queue = queue; 
  }

  public void run(){
    HealthRecord data;
    PrintStream toServer;
    Socket sock;

    System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
    try{
    	//continually reads from the queue and is blocked waiting if it's empty
    	while(true){
    		//is a queue of HealthRecord type
    		data = queue.take();
    		//need to check if block is in chain already so we grab it's uuid
    		String uuid = data.getBlockUUID();
    		//if it's there we "continue" by going to the next element in the queue
    		if(Blockchain.blockchain.contains(uuid)) continue;
    		//we obtain it's 256 hash and it's signed 256 hash
    		String unsignedString = data.getSHA256String();
    		String signedString = data.getSignedSHA256();
    		byte[] uS = unsignedString.getBytes();
    		byte[] sS = Base64.getDecoder().decode(signedString);
    		
    		//using the hashmap array of PublicKey's we find the key by attached processId from the HealthRecord
    		Integer processId = Integer.parseInt(data.getCreatorProcessID());
    		ProcessBlock pb = Blockchain.zed.get(processId);
    		String publicKey = pb.getPubKey();
    	    
    		//we convert the String key into a PublicKey type
    		PublicKey pubbb = Blockchain.loadAPublicKey(publicKey);
    		//use the verification method
    		boolean verified = Blockchain.verifySig(uS, pubbb, sS);
    		//if it can't be verified we go to the next object in the queue
    		if(!verified) break;
    		
    		//this is the major work section
    		String random = null;
    		String concantenatedString;
    		String output;
    		Integer amtOfWork;
    		String verification = null;
    		try{
    			//attempt to create a hash with the data that results in first four digits of our hash being less than 20000
    			int j = 0;
    			for(int i=1; i<200; i++){
    				//grabs a random number
    				random = Blockchain.randomAN(8); 
    				concantenatedString = data + random; 
    				//digest with sha256
    				MessageDigest MD = MessageDigest.getInstance("SHA-256");
    				byte[] bytesHash = MD.digest(concantenatedString.getBytes("UTF-8"));
    				output = DatatypeConverter.printHexBinary(bytesHash);
    				//then check to see if we have won
    				amtOfWork = Integer.parseInt(output.substring(0,4),16);
    				if (amtOfWork < 20000){
    					verification = random;
    				  break;
    				}
    				//j is used as a counter to see if another process has solved the problem yet
    				if(j>3) {
    					if(Blockchain.blockchain.contains(uuid)) continue;
    				}
    		  }
    	} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
    		e.printStackTrace();
    	}
    		//if we were able to solve the problem we insert the varification code into the HealthRecord
    		if(verification != null) data.sethashSolution(verification);
    		//if it didn't work we go to the next object
    		else continue;
    		
    		
    		//set which id solved it
    		//and add which block number it is
    		data.setVerificationProcessID(Integer.toString(Blockchain.PID));
    		data.setBlockNumber(Integer.toString(Blockchain.blockNumber));
    		//set previous hash, if none exists it sets to default
    		data.setPreviousHash(Blockchain.previousHash);
    		Blockchain.previousHash = data.getSignedSHA256();
    		Blockchain.blockNumber += 1;
    		
    		
    		//marshall everything to xml to be shipped out to the other processes
    		JAXBContext jaxbContext = JAXBContext.newInstance(HealthRecord.class);
    		Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
    		StringWriter sWriter = new StringWriter();
    		jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
    		jaxbMarshaller.marshal(data, sWriter);
    		String completeBlock = sWriter.toString();
    		//then send info to everybody
    		String overloaded = completeBlock + "\n" + Blockchain.blockchain;
    		for(int i = 0; i<Blockchain.numProcesses; i++){
    			sock = new Socket(Blockchain.serverName, Ports.BCPortBase + i);
    			toServer = new PrintStream(sock.getOutputStream());
    			toServer.println(overloaded); 
    			toServer.flush();
    			sock.close();
    			}
    		//liberal sleep statement
    		Thread.sleep(1500);}
    }catch (Exception e) {System.out.println(e);}
  }
}

//starts the blockchain worker that "doesn't" check against the updated one, always assumes is being updated
class BlockchainWorker extends Thread {
	Socket sock;
	BlockchainWorker (Socket s) {sock = s;}
	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String data;
			//read in all the data again
			StringBuilder fullBlock = new StringBuilder();
			while((data = in.readLine()) != null){
				fullBlock.append(data);
				fullBlock.append("\n");
				}
			Blockchain.blockchain = fullBlock.toString();
			sock.close();
			//if this is process 0 it will write the entire blockchain to the ledger
			if(Blockchain.PID == 0) {
				BufferedWriter writer = new BufferedWriter(new FileWriter("BlockchainLedger.xml"));
				writer.write(Blockchain.blockchain);
				writer.close();
				System.out.println("BlockchainLedger.xml has been updated");
      }
    } catch (IOException x){x.printStackTrace();}
  }
}

class BlockchainServer implements Runnable{
	public void run(){
		int q_len = 6;
		Socket sock;
		System.out.println("Starting the blockchain server:  " + Integer.toString(Ports.BCPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.BCPort, q_len);
			//gonna listen and spawn off more BlockchainWorker threads to update the blockchain and ledger if process 0
			while (true) {
				sock = servsock.accept();
				new BlockchainWorker (sock).start();
				}
			}catch (IOException ioe) {System.out.println(ioe);}
		}
	}

//main class for Blockchain
public class Blockchain{
	//starts up the global vars, always gonna be on a localhost
	static String serverName = "localhost";
	static String previousHash = "First Block/no hash";
	static Integer blockNumber = 0;
	static String blockchain = "[First block]";
	//num of processes is static at 3
	static int numProcesses = 3;
	//declared PID which will be changed depending on which process
	static int PID = 0;
	//is gonna hold all of our public keys and use the process number as the identifier
	static HashMap<Integer, ProcessBlock> zed = new HashMap<Integer, ProcessBlock>();
	//our secret key
	static PrivateKey privateKey;
	//from Elliott's work function, still needed, did not want to mess with it at this point
	private static final String ALPHA_NUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  
	//same as Prof Elliott's work generator, makes a random number
	public static String randomAN(int c) {
	    StringBuilder sb = new StringBuilder();
	    while(c-- != 0) {
	      int aCharacter = (int)(Math.random()*ALPHA_NUMERIC.length());
	      sb.append(ALPHA_NUMERIC.charAt(aCharacter));
	    }
	    return sb.toString();
	  }
	
	//used to signdata and verify the signiture, taken from Prof Elliott's ulitilies
	public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
	    Signature sig = Signature.getInstance("SHA1withRSA");
	    sig.initSign(key);
	    sig.update(data);
	    return (sig.sign());
	  }
	//used to verify the signiture
	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
	    Signature sign = Signature.getInstance("SHA1withRSA");
	    sign.initVerify(key);
	    sign.update(data);
	    return (sign.verify(sig));
	  }
	public static String saveAPublicKey(PublicKey publicKey) throws GeneralSecurityException {
	    KeyFactory factory = KeyFactory.getInstance("RSA");
	    X509EncodedKeySpec xSpec = factory.getKeySpec(publicKey, X509EncodedKeySpec.class);
	    return Base64.getEncoder().encodeToString(xSpec.getEncoded());
	}
	public static PublicKey loadAPublicKey(String storedPublic) throws GeneralSecurityException {
	    byte[] bArray = Base64.getDecoder().decode(storedPublic);
	    X509EncodedKeySpec xSpec = new X509EncodedKeySpec(bArray);
	    KeyFactory factory = KeyFactory.getInstance("RSA");
	    return factory.generatePublic(xSpec);
	}
  
	public void MultiSend(){ // Multicast some data to each of the processes.
    Socket sock;
    PrintStream toServer;
    try{
    	//generate keypair and base64 encode
    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keypair = keyGen.genKeyPair();
        //stores the private key used to sign the sha256
        Blockchain.privateKey = keypair.getPrivate();
        
        //converting the public key to string and creating a ProcessBlock
        ProcessBlock pb = new ProcessBlock();
    	String keyAsString = saveAPublicKey(keypair.getPublic());
    	pb.setProcessID(Blockchain.PID);
    	pb.setPubKey(keyAsString);
    	
    	//cookie cutter marshalling
    	JAXBContext jaxbContext = JAXBContext.newInstance(ProcessBlock.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sweet = new StringWriter();
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        jaxbMarshaller.marshal(pb, sweet);
        String stringXML = sweet.toString();
    	
        //send out that marshalled processblock to all the process so they know your public key and can
        //verify blocks that you send them
        for(int i=0; i< numProcesses; i++){// Send our key to all servers.
        	sock = new Socket(serverName, Ports.PublicKeyPortBase + i);
        	toServer = new PrintStream(sock.getOutputStream());
        	toServer.println(stringXML); toServer.flush();
        	sock.close();
      }
        Thread.sleep(1000);
        }catch (Exception x) {x.printStackTrace ();
        }
    }
	//this method is gonna read from the input file auto specified by the processId
	public void MultiDataReadAndSend(){ // Multicast some data to each of the processes.
	    Socket sock;
	    PrintStream toServer;
	    try{
	    	//gets this processes PID, concatenates a string to make the filename
	        String tempPID = Integer.toString(Blockchain.PID);
	        String filename = "BlockInput"+ tempPID + ".txt";
	        BufferedReader br = new BufferedReader(new FileReader(filename));
	        String record;
	        //start reading from the file, line by line
	        while((record =br.readLine()) != null) {
	        	//each line is gonna be tokenized and will assign the appropriate tokens to HealthRecord fields
	        	StringTokenizer st = new StringTokenizer(record);
				HealthRecord block = new HealthRecord();
				block.setFname(st.nextToken());
				block.setLname(st.nextToken());
				block.setBday(st.nextToken());
				block.setSSN(st.nextToken());
				block.setDiagnosis(st.nextToken());
				block.setWellnessRec(st.nextToken());
				block.setDrugRec(st.nextToken());
				
				//make a random uuid for the block
				String Uuid = UUID.randomUUID().toString();
				block.setCreatorProcessID(tempPID);
				block.setBlockUUID(Uuid);
				Date date = new Date();
			    String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
			    String TimeStampString = T1 + "." + Blockchain.PID + "\n";
			    block.setTimeStamp(TimeStampString);
			    
			    //these fields will be set later on
			    block.setSHA256String("To be Set Later");
			    block.setSignedSHA256("To be Set Later");
			    block.setPreviousHash("Will be set prior to appending on chain");
			    block.setVerificationProcessID("will be set later);");
			    
			    //again cookie cutter marshilling that we will send each record to all processes
			    JAXBContext jaxbContextForHealthBlock = JAXBContext.newInstance(HealthRecord.class);
			    Marshaller jaxbMarshallerHealthBlock = jaxbContextForHealthBlock.createMarshaller();
			    StringWriter sweaty = new StringWriter();
			    jaxbMarshallerHealthBlock.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			    jaxbMarshallerHealthBlock.marshal(block, sweaty);
			    String stringXMLHealthBlock = sweaty.toString();
			    String holdBlock= stringXMLHealthBlock;
			    
			    //creating the sha256 digest of the block so far
			    MessageDigest md = MessageDigest.getInstance("SHA-256");
			    md.update (holdBlock.getBytes());
			    byte byteData[] = md.digest();
			      
			    StringBuffer stringBuff = new StringBuffer();
			    for(int i = 0; i<byteData.length; i++) {
			    	stringBuff.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
			      }
			    //sets the 256 unsigned and signed versions
			    String sha256String = stringBuff.toString();
			    block.setSHA256String(sha256String);
			    byte[] digitalSignature = signData( sha256String.getBytes(), Blockchain.privateKey);
			    String signed = Base64.getEncoder().encodeToString(digitalSignature);
			    block.setSignedSHA256(signed); 
			    StringWriter stringWriteFinal = new StringWriter();
			    
			    //then marshall the whole thing again to be sent over the network
			    jaxbMarshallerHealthBlock.marshal(block, stringWriteFinal);
			    String fullBlock = stringWriteFinal.toString();
			    for(int i = 0; i< numProcesses; i++) {
			    	sock = new Socket(serverName, Ports.UnverifiedPortBase+i);
			    	toServer = new PrintStream(sock.getOutputStream());
			    	toServer.println(fullBlock);
			    	toServer.flush();
			    	sock.close();
			    }
			    //liberal sleep so queues don't overflow
			    try{Thread.sleep(1000);}catch(Exception e){}
			}
	    }catch (Exception x) {x.printStackTrace ();}
	  }
  
  public static void main(String args[]){
    int q_len = 6; /* Number of requests for OpSys to queue. Not interesting. <-lol*/
    PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // Process ID
    
    System.out.println("Erik Pugesek's Blockchain for Healthcare, control-c to quit.\n");
    System.out.println("ProcessID " + PID + "\n");
    
    //sets up the priority queue with our custom comparator to properly compare times
    final BlockingQueue<HealthRecord> queue = new PriorityBlockingQueue<HealthRecord>(1000, new Comparator<HealthRecord>() {
    	public int compare(HealthRecord a, HealthRecord b) {
    		String time1 = a.getTimeStamp();
    		String time2 = a.getTimeStamp();
    		return time1.compareTo(time2);
    	}
    });
    //sets the proper port numbers  ie port + PID
    new Ports().setPorts();
    
    //starts all of our servers to start listening
    new Thread(new PublicKeyServer()).start(); // process for incoming Public Keys
    new Thread(new UnverifiedBlockServer(queue)).start(); //where each block data is gonna get sent
    new Thread(new BlockchainServer()).start(); //is gonna update and write the blockchain ledger
    try{Thread.sleep(1000);}catch(Exception e){} //liberal waiting for everything to get settled
    
    new Blockchain().MultiSend(); //gonna send all the Public Keys to all processes
    new Blockchain().MultiDataReadAndSend(); //is gonna read from the files and send to the unverified block servers
    try{Thread.sleep(1000);}catch(Exception e){} //Probably unecessary sleep but hey whatevs as long as it works

    new Thread(new UnverifiedBlockConsumer(queue)).start(); //once the queue is settled we start popping elements
  }
}