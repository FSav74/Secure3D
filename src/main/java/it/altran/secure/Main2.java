package it.altran.secure;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

/**
 * 
 * Come la classe Main: solo con una diversa configurazione di jks e certificati (uso quelli del cashManagement
 * 
 * le chiave vengono tutte recuyperate sdal keystore configurato
 * 
 * @author Admin
 *
 */
public class Main2 {
	public static void main(String[] args) throws IOException {
		 
		 try{
			 SecureResource secureResource = new SecureResource();
			 configure(secureResource);
			 
			//----------------------------------------------------------
			 // Recupero chiave pubblica (certificato pubblico) per criptare
			 // Recupero chiave privata per firmare SHA2
			 //----------------------------------------------------------
			 PrivateKey chiavePrivata =(PrivateKey)secureResource.readKeyFromKeystore2(Cipher.PRIVATE_KEY);
			 PublicKey chiavePubblica =(PublicKey)secureResource.readKeyFromKeystore2(Cipher.PUBLIC_KEY);
			 
			 //-------------------------------------------
			 // 1)Con la mia chiave provata firmo (sign) un testo: 
			 //   operazione di solito eseguita dal proprietario del certificato provato  
			 //
			 // 2)Con la mia chiave pubblica, prendo la stringaOriginale e
			 // la stringa firnamta e verifico la firma:
			 // questa operazione viene effettuata dal possessore del certificato pubblico, che 
			 // in questo modo verifica che il testo proviene proprio dal possessore della chiave privat
			 //-------------------------------------------
			 //Utility.signatureVerification(chiavePrivata, chiavePubblica, secureResource);
			 
			 
			 //----------------------------------------------------------
			 // 1)Semplice metodo che crypta con chiave pubblica
			 // 
			 // 2) decrypta con chaive privata
			 //----------------------------------------------------------
			 Utility.cryptingDecriptingVerification(chiavePrivata, chiavePubblica, secureResource);
			 
			 //----------------------------------------------------------
			 // Simile al metodo signatureVerification
			 // ma il testo viene prima criptato e poi firmato
			 // e la verifica della firma viene fatta con 
			 // la stringa criptata e la stringa criptata e firmata
			 //----------------------------------------------------------
			 //Utility.cryptingSignatureVerification(chiavePrivata, chiavePubblica, secureResource);
		 }catch(Exception e){
				
				System.out.println( "TEST Error: " + e.getMessage() );
				e.printStackTrace();
		 }
		        
	}
		 
		 
	 public static void configure(SecureResource secureResource){
		 //---------------------------------------------------------
		 //path al keyStore dove è contenuta la mia chiave privata
		 //---------------------------------------------------------
		 secureResource.setKeyStorePath("C:\\PROGETTI\\ICBPI-DOC\\NEW_SVIL\\keyStoreCollaudo135\\riscarico\\icbpi-ibk-cashmanagement.jks");
		 
		 secureResource.setPrivateKeyAlias("ibk_cm");
		 secureResource.setPublicKeyAlias("icbpi");
		 secureResource.setKeyStorePassword("change_cm");  //<<<<<<<<<<password del keystore
		 
		 secureResource.setKeyPassword("icbpiibkcm");      //<<<<<<<<<<password della chiave
		 //---------------------------------------------------------
		 //Path al mio certificato pubblico
		 //---------------------------------------------------------
		 secureResource.setMyPublicNameCert("C:\\server\\apache-tomcat-7.0.37\\shared\\3DSECURE\\IBK.cer");
	 }

}
