package at.diwh.cryptoTools.engine.RSA;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import at.diwh.cryptoTools.b64.Base64;
import at.diwh.cryptoTools.engine.ICryptoEngine;
import at.diwh.cryptoTools.exception.CryptoException;
import at.diwh.cryptoTools.token.EngineToken;

/**
 * Benötigt zwingend mindestens einen Schlüssel (privat, öffentlich, auch beide), eine Blocksize und natürlich Daten.
 * Für das Signieren bzw. die Signaturprüfung müssen die Daten im Token als Zusatzdaten mitgegeben werden:
 * <br/>TOKEN_B64ENCSTRING_RSA = "b64EncString"; "b64EncString" = das verschlüsselte Byte-Array, das als base64-String vorliegt
 * <br/>TOKEN_B64SIGNATURSTRING_RSA = "b64SignaturString"; "b64SignaturString" = die Signatur als base64-String
 * 
 * @author 246J
 *
 */
public class RSAImpl implements ICryptoEngine {

	private static final String ALGORITHM = "RSA";
	private String pubKeyBase64;
	private String privKeyBase64;
	private PublicKey pubkey = null;
	private PrivateKey privKey = null;
	private int BLOCKSIZE;
	private byte[] data = null;
	// Zusätzliche Daten:
	private static final String TOKEN_B64ENCSTRING_RSA = "b64EncString";// "b64EncString" = das verschlüsselte Byte-Array, das als base64-String vorliegt
	private static final String TOKEN_B64SIGNATURSTRING_RSA = "b64SignaturString";// "b64SignaturString" = die Signatur als base64-String
	private Map<String,Object> additionalInformation = new HashMap<String, Object>();
	
	/**
	 * <b>KONSTRUKTOR</b>
	 * @param eToken
	 */
	public RSAImpl(EngineToken eToken) throws CryptoException {
		super();
		if (!RSAImpl.checkToken(eToken)) {
			throw new CryptoException("Fehlerhafter Engine Token. Pflichtfelder sind mind. ein Key, Data und Blocksize");
		}
		// erzeugen neuen Token, damit Änderungen am originalen Token nicht durchschlagen und wir hier einfach mit "=" zuweisen können
		EngineToken e = new EngineToken(eToken.getSymetricKey(), eToken.getPrivateKey(), 
				eToken.getPublicKey(), eToken.getData(), eToken.getAdditionalInformation(), eToken.getBlocksize());
		this.BLOCKSIZE = e.getBlocksize().intValue();
		int allowedMax = 0;
		int schluesselLaenge = 0;
		if (e.getPublicKey() != null) {
			this.pubKeyBase64 = Base64.toString(e.getPublicKey());
			this.pubkey = convertPublic64toPublicKey(pubKeyBase64);
			schluesselLaenge = e.getPublicKey().length;
			allowedMax = - schluesselLaenge/8 - (2*(256/8)) -2; // RSA with SHA256
			
		}
		if (e.getPrivateKey() != null) {
			this.privKeyBase64 = Base64.toString(e.getPrivateKey());
			this.privKey = convertPrivate64toPrivateKey(privKeyBase64);
			schluesselLaenge = e.getPrivateKey().length;
			allowedMax = schluesselLaenge/8 - (2*(256/8)) -2; // RSA with SHA256
		}
		if (allowedMax > this.BLOCKSIZE) {
			throw new CryptoException("Fehler: Die maximale Blockgröße bei einer Schlüssellänge von " + schluesselLaenge + 
					" ist " + allowedMax + " aber die übergebene Schlüssellänge ist " + this.BLOCKSIZE);	
		}
		this.data = e.getData();
		this.additionalInformation = e.getAdditionalInformation();
	}
	
	private static boolean checkToken(EngineToken eToken) {
		if (	// komplexere Prüfung. Weil wir dürfen z.B. nur mit einem PubKey verschlüsseln, dazu braucht es keinen PrivKey
				(eToken.getPrivateKey() == null && eToken.getPublicKey() == null) // beide(!) RSA-Schlüssel sind null
				|| ((eToken.getBlocksize() == null || eToken.getData() == null)) // _oder_ ein anderer notwendiger Wert ist null
			) {
			return false;
		}
		return true;
	}
	

	public byte[] decrypt() throws CryptoException {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus",e);
		} catch (NoSuchPaddingException e) {
			throw new CryptoException("Ungültiges Padding",e);
		}
        try {
			cipher.init(Cipher.DECRYPT_MODE, this.privKey);
		} catch (InvalidKeyException e) {
			throw new CryptoException("Ungültiger Schlüssel",e);
		}
        byte[] decryptedBytes;
		try {
			decryptedBytes = cipher.doFinal(this.data);
		} catch (IllegalBlockSizeException e) {
			throw new CryptoException("Ungültige Blockgröße "+this.data.length + " !",e);
		} catch (BadPaddingException e) {
			throw new CryptoException("Ungültiges Padding",e);
		}
        return decryptedBytes;
	}

	public byte[] encrypt() throws CryptoException {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus",e);
		} catch (NoSuchPaddingException e) {
			throw new CryptoException("Ungültiges Padding",e);
		}
        try {
			cipher.init(Cipher.ENCRYPT_MODE, this.pubkey);
		} catch (InvalidKeyException e) {
			throw new CryptoException("Ungültiger Schlüssel",e);
		}
        byte[] encryptedBytes;
		try {
			encryptedBytes = cipher.doFinal(this.data);
		} catch (IllegalBlockSizeException e) {
			throw new CryptoException("Ungültige Blockgröße",e);
		} catch (BadPaddingException e) {
			throw new CryptoException("Ungültiges Padding",e);
		}
        return encryptedBytes;
	}
	
	public byte[] sign() throws CryptoException {
		// in den zus. Daten muss mit dem Schlüssel "b64EncString" der base64-String drinnen sein; dafür hat der CryptoHID zu sorgen
		String b64EncData = (String) additionalInformation.get(TOKEN_B64ENCSTRING_RSA); 
		if (b64EncData == null) {
			throw new CryptoException("Fehler! Keine Daten zum Signieren im EngineToken! Signieren abgebrochen!");
		}
		Signature privateSignature;
		Scanner is = null;
		try {
			privateSignature = Signature.getInstance("SHA256withRSA");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus",e);
		}
	    try {
			privateSignature.initSign(privKey);
		} catch (InvalidKeyException e) {
			throw new CryptoException("Ungültiger Schlüssel",e);
		}
	    is = new Scanner(b64EncData);
	    try {
	        while ((is.hasNextLine())) { // Solange da noch eine Zeile ist...
	        	String zeile = is.nextLine(); // ... lesen ...
	    	    privateSignature.update(zeile.getBytes("UTF-8"));
		       
	        }
	    } catch (SignatureException e) {
	    	throw new CryptoException("Ausnahme bei Signaturerstellung: ",e);
		} catch (UnsupportedEncodingException e) {
			throw new CryptoException("Ungültiges Encoding (UTF-8)",e);
		} finally {
	        if (is != null) {
	        	is.close();
	        }
	    }
		try {
			return  privateSignature.sign();
		} catch (SignatureException e) {
			throw new CryptoException("Ausnahme bei Signaturerstellung: ",e);
		}
	}

	public boolean checkSignature() throws CryptoException {
		// in den zus. Daten muss mit dem Schlüssel "b64EncString" der base64-String drinnen sein; dafür hat der CryptoHID zu sorgen
		String b64EncData = (String) additionalInformation.get(TOKEN_B64ENCSTRING_RSA); 
		if (b64EncData == null) {
			throw new CryptoException("Fehler! Keine Daten zum Prüfen im EngineToken! Prüfung abgebrochen!");
		}
		// in den zus. Daten muss mit dem Schlüssel "b64SignaturString" der Signaturstring drinnen sein; dafür hat der CryptoHID zu sorgen
		String b64SigString = (String) additionalInformation.get(TOKEN_B64SIGNATURSTRING_RSA);
		if (b64SigString == null) {
			throw new CryptoException("Fehler! Keine Signatur zum Prüfen im EngineToken! Prüfung abgebrochen!");
		}
		Scanner is = null;
		Signature publicSignature;
		try {
			publicSignature = Signature.getInstance("SHA256withRSA");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus",e);
		}
	    try {
			publicSignature.initVerify(pubkey);
		} catch (InvalidKeyException e) {
			throw new CryptoException("Ungültiger Schlüssel",e);
		}
	    is = new Scanner(b64EncData);
	    try {
	        while ((is.hasNextLine())) { // Solange da noch eine Zeile ist...
	        	String zeile = is.nextLine(); // ... lesen ...
	    	    publicSignature.update(zeile.getBytes("UTF-8"));
		       
	        }
	    } catch (SignatureException e) {
	    	throw new CryptoException("Ausnahme bei Signaturprüfung: ",e);
		} catch (UnsupportedEncodingException e) {
			throw new CryptoException("Ungültiges Encoding (UTF-8)",e);
		} finally {
	        if (is != null) {
	        	is.close();
	        }
	    }

	    byte[] signaturInBytes = Base64.toBytes(b64SigString);
	    try {
			return publicSignature.verify(signaturInBytes);
		} catch (SignatureException e) {
			throw new CryptoException("Ausnahme bei Signaturprüfung: ",e);
		}
	}
	
    /**
     * Erzeugt einen RSA-Public Key (PublicKey-Objekt) aus einem öffentlichen Schlüssel, der als base64-String vorliegt. 
     * @param pubKey (Base64 String)
     * @return PublicKey
     * @throws CryptoException 
     * @see java.security.PublicKey
     */
    private static PublicKey convertPublic64toPublicKey(String pubKey) throws CryptoException {
    	PublicKey key = null;
    	try {
			key = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(Base64.toBytes(pubKey)));
		} catch (InvalidKeySpecException e) {
			throw new CryptoException("Ungültige Schlüsselspezifikation",e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus",e);
		}
        return key;
    }
    
    /**
     * Erzeugt einen RSA-Private Key (PrivateKey-Objekt) aus einem privaten Schlüssel, der als base64-String vorliegt.
     * @param privKey (Base64 String)
     * @return PrivateKey
     * @throws CryptoException 
     * @see java.security.PrivateKey
     */
    private static PrivateKey convertPrivate64toPrivateKey(String privKey) throws CryptoException {
    	PrivateKey key = null;
    	byte[] privateKey = Base64.toBytes(privKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = null;
        try {
			keyFactory = KeyFactory.getInstance(ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus",e);
		}
        try {
			key = keyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			throw new CryptoException("Ungültige Schlüsselspezifikation",e);
		}
        return key;
    }

	
	

}
