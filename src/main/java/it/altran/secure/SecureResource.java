package it.altran.secure;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class SecureResource {

	 private String privateKeyAlias;
	 private String keyStorePath;
	 private String keyStorePassword;   //password del keystore
     private String myPublicNameCert;
     
     private String publicKeyAlias; //main2
     private String keyPassword; //main2 password della chiave privata (se messa diversa)
	    
	 public Key readKeyFromKeystore(int keyType ) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
				UnrecoverableKeyException {
			
		//int keyType=Cipher.PRIVATE_KEY;

		//KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		KeyStore keyStore=null;
		try {
			keyStore = KeyStore.getInstance("pkcs12", "SunJSSE");
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		FileInputStream keyStoreFile = new FileInputStream(keyStorePath);
		System.out.println("Caricamento store " + keyStorePath);
		keyStore.load(keyStoreFile, keyStorePassword.toCharArray());

		Key key = null;
		switch (keyType) {
		case Cipher.PUBLIC_KEY:
			Certificate certificate = keyStore.getCertificate(privateKeyAlias);   //la chiave pubblica: prende il certificato privato e 
			                                                                      // chiede la public key: cioè è il corrispondente certificato pubblico del
																				  // mio certioficato privato	
			System.out.println("Estrazione chiave pubblica " + privateKeyAlias);
			key = certificate.getPublicKey();
			break;
		case Cipher.PRIVATE_KEY:
			System.out.println("Estrazione chiave privata " + privateKeyAlias);
			key = keyStore.getKey(privateKeyAlias, keyStorePassword.toCharArray());    //attenzione: qui va la password della chiave (richiesta in fase di creazione) 
																					   //nel mio caso è uguale a quella del keystore
			break;
		default:
			System.out.println("Tipologia chiave non supportata");
		}

		return key;
	}
	 
	 
	 public Key readKeyFromKeystore2(int keyType ) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
		UnrecoverableKeyException {
	
		//int keyType=Cipher.PRIVATE_KEY;
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		FileInputStream keyStoreFile = new FileInputStream(keyStorePath);
		System.out.println("Caricamento store " + keyStorePath);
		keyStore.load(keyStoreFile, keyStorePassword.toCharArray());
		
		Key key = null;
		switch (keyType) {
		case Cipher.PUBLIC_KEY:
			Certificate certificate = keyStore.getCertificate(publicKeyAlias);    // la chiave pubblica: prendo il certificato publico 
																				  // che è già nel mio keystore: 
			System.out.println("Estrazione chiave pubblica " + publicKeyAlias);
			key = certificate.getPublicKey();
			break;
		case Cipher.PRIVATE_KEY:
			System.out.println("Estrazione chiave privata " + privateKeyAlias);
			key = keyStore.getKey(privateKeyAlias, keyPassword.toCharArray());    //password della chiave diversa da quella del keystore
			break;
		default:
			System.out.println("Tipologia chiave non supportata");
		}
		
		return key;
}
	 
	 
	 
	 public String signMessageOLD(String message, Key privatekey) throws Exception {
			
			String algorithm="SHA256withRSA";//privatekey.getAlgorithm();

			Signature signature = Signature.getInstance(algorithm);

			signature.initSign((PrivateKey)privatekey);
			signature.update(message.getBytes("UTF-8"));

			System.out.println("Firma con algoritmo " + algorithm);
					
			String signedMessage =  new String(Base64.encodeBase64(signature.sign()), "UTF-8");
			
			return signedMessage;
	 }
	 
	 public String signMessage(String message, PrivateKey privatekey) throws Exception {
			
			String algorithm="SHA256withRSA";//privatekey.getAlgorithm();
		 
			Signature signature = Signature.getInstance(algorithm);

			signature.initSign(privatekey);
			signature.update(message.getBytes());

			System.out.println("Firma con algoritmo " + algorithm);
					
			String signedMessage =  new String(Base64.encodeBase64(signature.sign()));
			
			return signedMessage;
	 }
	 
	 /**
	  * Il messaggio e il messaggio segnato e verifica con la chiave pubblica.
	  * 
	  * @param message
	  * @param signedMessage
	  * @param publicKey
	  * @return
	  * @throws Exception
	  */
	 public boolean verifyMessage(String message, String signedMessage, PublicKey publicKey) throws Exception{
		 
		 //String algorithm=publicKey.getAlgorithm();
		 String algorithm="SHA256withRSA";

		 Signature signature = Signature.getInstance(algorithm);
    
		 signature.initVerify(publicKey);
		 //signature.update(message.getBytes());
		 //return signature.verify(signedMessage.getBytes());
		 
		 signature.update(message.getBytes("UTF-8"));
	     return signature.verify(Base64.decodeBase64(signedMessage.getBytes("UTF-8")));
		 
	 }
	 
	/* public static String encrypt(String rawText, PublicKey publicKey) throws Exception {
	        Cipher cipher = Cipher.getInstance("RSA");
	        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
	    }*/
	 
	 public String encryptMessage(String message, PublicKey key) throws Exception {
			
			String transformation = "RSA/ECB/PKCS1Padding";
			Provider provider = new BouncyCastleProvider();
		 
			Cipher cipher = Cipher.getInstance(transformation,provider);
			cipher.init(Cipher.ENCRYPT_MODE, key);

			System.out.println(">>>Cifratura con algoritmo :" + transformation);
			//3.	Effettuare lâ€™encoding BASE64 su STRINGA1
			String encryptedMessage = Base64.encodeBase64String(cipher.doFinal(message.getBytes()));
			System.out.println("Messaggio criptato: " + encryptedMessage);

			return encryptedMessage;
		}
	 public  String decryptMessage(String cipherText, PrivateKey privateKey) throws Exception {
		 	String transformation = "RSA/ECB/PKCS1Padding";
		 	Provider provider = new BouncyCastleProvider();

			Cipher cipher = Cipher.getInstance(transformation,provider);
	        cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), "UTF-8");
	    }
	 
	 //recupera chiave publica da certificato
	 public PublicKey readRSAPublicKey2() throws Exception {
			PublicKey pubKey = null;
			try {
				InputStream fis = new FileInputStream(myPublicNameCert);
				
				
				CertificateFactory cf =  CertificateFactory.getInstance("X.509");
				X509Certificate x509cert = (X509Certificate) cf.generateCertificate(fis);
				
				System.out.println("certificato per test!");
				System.out.println("\nInformazioni nInformazioni reperite dal certificato: reperite dal certificato: " +x509cert);
				System.out.println("tipo = " + x509cert.getType());
				System.out.println("versione = " + x509cert.getVersion()); 
				System.out.println("soggetto = " + x509cert.getSubjectDN().getName());
				System.out.println("inizio validit inizio validitÃ  = " + x509cert.getNotBefore());
				System.out.println("fine validit fine validitÃ  = " + x509cert.getNotAfter()); 
				System.out.println("numero di serie = " + x509cert.getSerialNumber().toString(16));
				System.out.println("emettitore = " + x509cert.getIssuerDN().getName());
				System.out.println("algoritmo di firma = " + x509cert.getSigAlgName());
				System.out.println("algoritmo per la chiave pubblica = " + x509cert.getPublicKey().getAlgorithm());
				
				return x509cert.getPublicKey();
				
				
				
				
			} catch (Exception e) {
				throw new Exception("Errore nella lettura chiave pubblica.", e);
			}
		}

	public String getPrivateKeyAlias() {
		return privateKeyAlias;
	}

	public void setPrivateKeyAlias(String privateKeyAlias) {
		this.privateKeyAlias = privateKeyAlias;
	}

	public String getKeyStorePath() {
		return keyStorePath;
	}

	public void setKeyStorePath(String keyStorePath) {
		this.keyStorePath = keyStorePath;
	}

	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	public String getMyPublicNameCert() {
		return myPublicNameCert;
	}

	public void setMyPublicNameCert(String myPublicNameCert) {
		this.myPublicNameCert = myPublicNameCert;
	}


	public String getPublicKeyAlias() {
		return publicKeyAlias;
	}


	public void setPublicKeyAlias(String publicKeyAlias) {
		this.publicKeyAlias = publicKeyAlias;
	}


	public String getKeyPassword() {
		return keyPassword;
	}


	public void setKeyPassword(String keyPassword) {
		this.keyPassword = keyPassword;
	}
	
	
	    
	 
	/*public static String sign(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initSign(privateKey);
        sign.update(message.getBytes("UTF-8"));
        return new String(Base64.encodeBase64(sign.sign()), "UTF-8");
    }
    
 
    public static boolean verify(PublicKey publicKey, String message, String signature) throws SignatureException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        Signature sign = Signature.getInstance("SHA1withRSA");
        sign.initVerify(publicKey);
        sign.update(message.getBytes("UTF-8"));
        return sign.verify(Base64.decodeBase64(signature.getBytes("UTF-8")));
    }*/
	
	
	/*
	 * public static String encrypt(String rawText, PublicKey publicKey) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
    }
    
   
    public static String decrypt(String cipherText, PrivateKey privateKey) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), "UTF-8");
    }

	 */
	
	    
}
