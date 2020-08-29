package at.diwh.cryptoTools.engine.AES;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import at.diwh.cryptoTools.engine.ICryptoEngine;
import at.diwh.cryptoTools.exception.CryptoException;
import at.diwh.cryptoTools.token.EngineToken;

public class AESImpl implements ICryptoEngine {
	
	private int BLOCKSIZE;
	private SecretKeySpec secretKey = null;
	private byte[] key = null;
	private Cipher cipherEnc = null;
	private Cipher cipherDec = null;
	private byte[] data = null;
	
	/**
	 * <b>KONSTRUKTOR</b>
	 * @param eToken
	 */
	public AESImpl(EngineToken eToken) throws CryptoException {
		super();
		if (!AESImpl.checkToken(eToken)) {
			throw new CryptoException("Fehlerhafter Engine Token. Pflichtfelder sind SymetricKey, Data und Blocksize");
		}
		// erzeugen neuen Token, damit Änderungen am originalen Token nicht durchschlagen und wir hier einfach mit "=" zuweisen können
		EngineToken e = new EngineToken(eToken.getSymetricKey(), eToken.getPrivateKey(), 
				eToken.getPublicKey(), eToken.getData(), eToken.getAdditionalInformation(), eToken.getBlocksize());
		this.BLOCKSIZE = e.getBlocksize().intValue();
		setKey(e.getSymetricKey());
		this.data = e.getData();
	}
	
	private static boolean checkToken(EngineToken eToken) {
		if (eToken.getBlocksize() == null || eToken.getSymetricKey() == null || eToken.getData() == null) {
			return false;
		}
		return true;
	}
	
	private void setKey(byte[] myKey) throws CryptoException {
		MessageDigest sha = null;
	    try {
	       	this.key = myKey;
	        sha = MessageDigest.getInstance("SHA-256");
	        key = sha.digest(key);
	        int len = (this.key.length <=16 ? this.key.length : 16);
	        byte[] keyFinal = new byte[16];
	        for (int i=0; i<len; i++) {
	        	keyFinal[i] = this.key[i];
	        } // all das weil es key = Arrays.copyOf(key, 16); nicht gibt
	        this.secretKey = new SecretKeySpec(keyFinal, "AES");
	    }
	    catch (NoSuchAlgorithmException e) {
	        e.printStackTrace();
	    }
	    try {
	    	this.cipherEnc = Cipher.getInstance("AES/ECB/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus", e);
		} catch (NoSuchPaddingException e) {
			throw new CryptoException("Ungültiges Padding", e);
		}
	    try {
			this.cipherEnc.init(Cipher.ENCRYPT_MODE, this.secretKey);
		} catch (InvalidKeyException e) {
			throw new CryptoException("Ungültiger Schlüssel", e);
		}
	    try {
			this.cipherDec = Cipher.getInstance("AES/ECB/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus", e);
		} catch (NoSuchPaddingException e) {
			throw new CryptoException("Ungültiges Padding", e);
		}
	    try {
			this.cipherDec.init(Cipher.DECRYPT_MODE, this.secretKey);
		} catch (InvalidKeyException e) {
			throw new CryptoException("Ungültiger Schlüssel", e);
		}
	}
	
	public int getBlocksize() {
		return this.BLOCKSIZE;
	}

	public byte[] decrypt() throws CryptoException {
		try {
			return this.cipherDec.doFinal(this.data);
		} catch (IllegalBlockSizeException e) {
			throw new CryptoException("Decrypt: IllegalBlockSizeException", e);
		} catch (BadPaddingException e) {
			throw new CryptoException("Decrypt: BadPaddingException", e);
		}
	}

	public byte[] encrypt() throws CryptoException {
		try {
			return cipherEnc.doFinal(this.data);
		} catch (IllegalBlockSizeException e) {
			throw new CryptoException("Encrypt: IllegalBlockSizeException", e);
		} catch (BadPaddingException e) {
			throw new CryptoException("Encrypt: BadPaddingException", e);
		}
	}

	
	public boolean checkSignature() throws CryptoException {
		throw new CryptoException("AES kann keine Signatur prüfen." + DONOTUSETHISCLASS);
	}

	public byte[] sign() throws CryptoException {
		throw new CryptoException("AES kann nicht signieren." + DONOTUSETHISCLASS);
	}
}
