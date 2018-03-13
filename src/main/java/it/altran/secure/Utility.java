package it.altran.secure;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Utility {
	
	/**
	  * 
	  * 
	  * 
	  * @param secureResource
	  * @throws Exception
	  */
	 public static void signatureVerification(PrivateKey chiaveprivata,PublicKey provaKey, SecureResource secureResource) throws Exception{
		 
		 System.out.println(">>>>>>>>>>>TEST SIGNATURE----------------------------------------");
		 //chiaveprivata=secureResource.readKeyFromKeystore(Cipher.PRIVATE_KEY);
		 String test= "SAVERIOLETTERESE2017";
		 System.out.println("testo in chiaro:"+test);
			
		 String testSigned=secureResource.signMessage(test, chiaveprivata);
	     System.out.println("testsigned:"+testSigned);
		   
	     //PublicKey provaKey =secureResource.readRSAPublicKey2();
	     boolean result = 	secureResource.verifyMessage(test, testSigned, provaKey);	
	     System.out.println("Verify signature:"+result);
	  
	 }
	 
	 public static void cryptingDecriptingVerification(PrivateKey chiaveprivata, PublicKey provaKey, SecureResource secureResource) throws Exception{
		 
		 //-----------------------------------------------
		 System.out.println("TEST CRYPTING------------------------------------------");
		 
		 String test= "ANTONIOLETTERESE1968";
		 System.out.println("test:"+test);
		 
		 String testEncrypted = secureResource.encryptMessage(test, provaKey);
	     System.out.println("testEncrypted:"+testEncrypted);
	     
	     String testDecrypted = secureResource.decryptMessage(testEncrypted,chiaveprivata);
		   
	     System.out.println("test decrypted:"+testDecrypted);
	    
	 }
	
	 
	 public static void cryptingSignatureVerification(PrivateKey chiaveprivata,PublicKey provaKey,SecureResource secureResource) throws Exception{
		
		 System.out.println("-- TEST CRYPTING SIGNED -------------------------------------------------");
		 
		 
		 String test= "ANTONIOLETTERESE1968";
		 System.out.println("test:"+test);
		 String testEncrypted = secureResource.encryptMessage(test, provaKey);
		 System.out.println("testEncrypted:"+testEncrypted);
		 
		 
		 String testEncryptedSigned=secureResource.signMessage(testEncrypted, chiaveprivata);
	     System.out.println("testEncryptedSigned:"+testEncryptedSigned);
		 

	     boolean result = 	secureResource.verifyMessage(testEncrypted, testEncryptedSigned, provaKey);	
	     System.out.println("Verify signature:"+result);
	     
	     
	     //-------------------------------------------------------------
	 }



}
