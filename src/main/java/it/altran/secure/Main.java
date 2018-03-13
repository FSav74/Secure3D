package it.altran.secure;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Locale;

import javax.crypto.Cipher;

public class Main {
	 
	 public static void main(String[] args) throws IOException {
		 
		 try{
			 
			 BigDecimal bigdecimal = new BigDecimal("10.00");
			 System.out.println(bigdecimal);
			 String numero ="10,00";
			 DecimalFormat df = new DecimalFormat("#,##0.00");
		    System.out.println(df.format(bigdecimal));
			 
		    bigdecimal = bigdecimal.setScale(0, RoundingMode.CEILING);
		    System.out.println(">>>>>>>"+bigdecimal);
			 
			 DecimalFormat df2 = new DecimalFormat("##0.00");
			 System.out.println(df2.format(bigdecimal));
			 
			 System.out.println("---------------");
			 Locale locale  = new Locale("en", "UK");
			 //Locale locale  = new Locale("it", "IT");
			 String pattern = "###.##";

			 DecimalFormat decimalFormat = (DecimalFormat)
			         NumberFormat.getNumberInstance(locale);
			 decimalFormat.applyPattern(pattern);

			 String format = decimalFormat.format(100.00);
			 System.out.println(format);
			 System.out.println("---------------");
			 
			 
			 
			 SecureResource secureResource = new SecureResource();
			 /* configuration */
			 /*
			
			 1.	Verificare che a STRINGA1 non sia applicato alcun tipo di encoding (UTF-8), se non fosse cosi eseguire la decode (UTF-8).
              2.	Cifrare STRINGA1 in RSA con la chiave pubblica di CartaSì
              3.	Effettuare l’encoding BASE64 su STRINGA1

              4.	Valorizzare STRINGA2 con la firma di STRINGA1 precedentemente codificata in BASE64.
                    La firma deve essere eseguita con algoritmo SHA2 (SHA-256) con la chiave privata della BANCA.

				5.	Effettuare l’encoding BASE64 su STRINGA2
				
				6.	Valorizzare STRINGA3 con l’ABI in chiaro della banca
				
				7.	Eseguire l’ENCODING UTF-8 a STRINGA1 e STRINGA2 per il passaggio in post

			 */
			 
			 configure(secureResource);
			 
			
			 
			 //----------------------------------------------------------
			 // Recupero chiave pubblica (certificato pubblico) per criptare
			 // Recupero chiave privata per firmare SHA2
			 //----------------------------------------------------------
			 PrivateKey chiavePrivata=(PrivateKey)secureResource.readKeyFromKeystore(Cipher.PRIVATE_KEY);
			 PublicKey chiavePubblica =secureResource.readRSAPublicKey2();
			 
			 
			 //-------------------------------------------
			 // 1)Con la mia chiave provata firmo (sign) un testo: 
			 //   operazione di solito eseguita dal proprietario del certificato provato  
			 //
			 // 2)Con la mia chiave pubblica, prendo la stringaOriginale e
			 // la stringa firnamta e verifico la firma:
			 // questa operazione viene effettuata dal possessore del certificato pubblico, che 
			 // in questo modo verifica che il testo proviene proprio dal possessore della chiave privat
			 //-------------------------------------------
			 Utility.signatureVerification(chiavePrivata, chiavePubblica, secureResource);
			 
			 
			 //----------------------------------------------------------
			 // 1)Semplice metodo che crypta con chiave pubblica
			 // 
			 // 2) decrypta con chaive privata
			 //----------------------------------------------------------
			 //Utility.cryptingDecriptingVerification(chiavePrivata, chiavePubblica, secureResource);
			 
			 //----------------------------------------------------------
			 // Simile al metodo signatureVerification
			 // ma il testo viene prima criptato e poi firmato
			 // e la verifica della firma viene fatta con 
			 // la stringa criptata e la stringa criptata e firmata
			 //----------------------------------------------------------
			 Utility.cryptingSignatureVerification(chiavePrivata, chiavePubblica, secureResource);
			 
			 //----------------------------------------------------------
			 // L'ultimo metodo è quello piu' vicino alla realtà.
			 // L'unica differenza e che dovrei avere oltre al mio certificato privato 
			 // con cui firmo, il certificato pubblico del mio interlocutore:
			 //
			 // 1) cripto con il certificato pubblico del mio interlocutore (STRINGA1)
			 // 2) firmo con la mia chiave privata (STRINGA2)
			 // 3) invio al mio interlocutore le due stringhe
			 //
			 // interlocutore:
			 // 1) verifica la firma con STRINGA1 e STRINGA2
			 // 2) decripta la STRINGA1 con la dua chiave privata
			 //----------------------------------------------------------
			 
		     
		}catch(Exception e){
			
			System.out.println( "TEST Error: " + e.getMessage() );
			e.printStackTrace();
		}
	        
	 }
	 
	 public static void configureOLD(SecureResource secureResource){
		 //---------------------------------------------------------
		 //path al keyStore dove è contenuta la mia chiave privata
		 //---------------------------------------------------------
		 secureResource.setKeyStorePath("C:\\server\\apache-tomcat-7.0.37\\shared\\3DSECURE\\ibk_3ds.jsk");
		 secureResource.setPrivateKeyAlias("ibk");
		 secureResource.setKeyStorePassword("ibk2017"); //<<--- password del keystore
		                                                //ho usata la stessa per la password della chiave privata
		 
		 //---------------------------------------------------------
		 //Path al mio certificato pubblico
		 //---------------------------------------------------------
		 secureResource.setMyPublicNameCert("C:\\server\\apache-tomcat-7.0.37\\shared\\3DSECURE\\IBK.cer");
	 }
	 
	 public static void configure(SecureResource secureResource){
		 //---------------------------------------------------------
		 //path al keyStore dove è contenuta la mia chiave privata
		 //---------------------------------------------------------
		 secureResource.setKeyStorePath("C:\\PROGETTI\\ICBPI-DOC\\NEW_SVIL\\UFFICIALI\\NUOVO3\\ibanking.pfx.pfx");
		 secureResource.setPrivateKeyAlias("ibanking");
		 secureResource.setKeyStorePassword("ibanking"); //<<--- password del keystore
		                                                //ho usata la stessa per la password della chiave privata
		 
		 //---------------------------------------------------------
		 //Path al mio certificato pubblico
		 //---------------------------------------------------------
		 secureResource.setMyPublicNameCert("C:\\PROGETTI\\ICBPI-DOC\\NEW_SVIL\\UFFICIALI\\NUOVO3\\ICBPI_NQ.cer");
		 
		 
		 

		 
	 }

	 
}
