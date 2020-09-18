package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.DataUtill;
import util.GzipUtil;
import util.KeystoreReader;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	public static void main(String[] args) throws Exception {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        Security.addProvider(new BouncyCastleProvider());
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	    
        //TODO: Decrypt a message and decompress it. The private key is stored in a file.
		Cipher rsaCipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		MailBody mailBody=new MailBody(MailHelper.getText(chosenMessage));
		String encMsg = mailBody.getEncMessage();
		byte[] encKey = mailBody.getEncKeyBytes();
		
		KeystoreReader keyReader=new KeystoreReader();
		KeyStore keyStoreUserB = keyReader.readKeyStore("./data/KeyStores/userb.jks", "123".toCharArray());
		PrivateKey privateKeyBEnc=keyReader.getPrivateKeyFromKeyStore(keyStoreUserB, "userb", "123".toCharArray());
		
		
		rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKeyBEnc);
		byte[] sk = rsaCipherDec.doFinal(encKey);
		
		SecretKey secretKey = new SecretKeySpec(sk, "RSA");
		byte[]iv11=mailBody.getIV1Bytes();
		byte[]iv22=mailBody.getIV2Bytes();
		
		
		byte[] iv1 = JavaUtils.getBytesFromFile(IV1_FILE);
		IvParameterSpec ivParameterSpec1 = new IvParameterSpec(iv1);
		rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKeyBEnc);
		
		String str = mailBody.getEncMessage();
		byte[] bodyEnc = Base64.decode(str);
		
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
		
		String receivedBodyTxt = new String(aesCipherDec.doFinal(bodyEnc));
		String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
		System.out.println("Body text: " + decompressedBodyText);
		
		
		byte[] iv2 = JavaUtils.getBytesFromFile(IV2_FILE);
		IvParameterSpec ivParameterSpec2 = new IvParameterSpec(iv2);
		//inicijalizacija za dekriptovanje
		aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
		
		//dekompresovanje i dekriptovanje subject-a
		String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
		System.out.println("Subject text: " + new String(decompressedSubjectTxt));
		
		byte[] byteSignature = Base64.decode(mailBody.getSignature());
		
		Document doc = DataUtill.toXml(byteSignature);
		
		Element rootElement = doc.getDocumentElement();
		
		X509Certificate certA =keyReader.getXCertificateFromKeyStore(keyStoreUserB, "usera");
		System.out.println("Mail se poklapa sa signature-om: " + DataUtill.verify(doc, certA));
		System.out.println("Izmena delova maila...");
		rootElement.setAttribute("subject", "Pogresan string");
		System.out.println("Mail se poklapa sa signature-om: " + DataUtill.verify(doc, certA));
	}
}
