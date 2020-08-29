package at.diwh.cryptoTools.engine.AES;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import at.diwh.cryptoTools.b64.Base64;
import at.diwh.cryptoTools.engine.ICryptoEngine;
import at.diwh.cryptoTools.exception.CryptoException;
import at.diwh.cryptoTools.token.EngineToken;

/**
 * Die Implementierung der 256-Bit Encryption erfolgt mittels "Bouncy Castle"
 * <pre>{@code
<dependency>
 <groupId>org.bouncycastle</groupId>
 <artifactId>bcprov-jdk15on</artifactId>
 <version>1.60</version>
</dependency>
 * </pre>}
 * Inspiriert von https://artofcode.wordpress.com/2017/01/10/aes-256-without-jce-unlimited-strength-jurisdiction-policy-files/
 * @author 246J
 *
 */
public class AES256Impl  implements ICryptoEngine {
	private int BLOCKSIZE;
	private byte[] key = null;
	private PaddedBufferedBlockCipher cipherEnc = null;
	private PaddedBufferedBlockCipher cipherDec = null;
	private byte[] data = null;
	
	private static final String TOKEN_B64SIGNATURSTRING_AES256 = "b64SignaturString";// "b64SignaturString" = die Signatur als base64-String
	private static final String TOKEN_IV_AES256 = "ivAES256";// der Initialisation Vector für AES256; Wert: byte[]
	private Map<String,Object> additionalInformation = new HashMap<String, Object>();
	/**
	 * <b>KONSTRUKTOR</b>
	 * @param eToken
	 */
	public AES256Impl(EngineToken eToken) throws CryptoException {
		super();
		if (!AES256Impl.checkToken(eToken)) {
			throw new CryptoException("Fehlerhafter Engine Token. Pflichtfelder sind SymetricKey, Data und Blocksize");
		}
		// erzeugen neuen Token, damit Änderungen am originalen Token nicht durchschlagen und wir hier einfach mit "=" zuweisen können
		EngineToken e = new EngineToken(eToken.getSymetricKey(), eToken.getPrivateKey(), 
				eToken.getPublicKey(), eToken.getData(), eToken.getAdditionalInformation(), eToken.getBlocksize());
		this.BLOCKSIZE = e.getBlocksize().intValue();
		this.data = e.getData();
		this.additionalInformation = e.getAdditionalInformation();
		setKey(e.getSymetricKey());
	}
	
	private static boolean checkToken(EngineToken eToken) {
		if (eToken.getBlocksize() == null || eToken.getSymetricKey() == null || eToken.getData() == null) {
			return false;
		}
		return true;
	}

	public byte[] decrypt() throws CryptoException {
		byte[] ivAES256 = (byte[]) additionalInformation.get(TOKEN_IV_AES256);
		if (ivAES256 == null) {
			throw new CryptoException("Fehler! Kein IV im EngineToken! Decryption abgebrochen!");
		}
	    byte[] output = new byte[cipherDec.getOutputSize(this.data.length)];
	    int len = cipherDec.processBytes(this.data, 0, this.data.length, output, 0);
	    try {
			len += cipherDec.doFinal(output, len);
		} catch (DataLengthException e) {
			throw new CryptoException("Decrypt: Datenlänge passt nicht ", e);
		} catch (IllegalStateException e) {
			throw new CryptoException("Decrypt: Zustand passt nicht ", e);
		} catch (InvalidCipherTextException e) {
			throw new CryptoException("Decrypt: Cipher passt nicht ", e);
		}
	    return output;
	}

	public byte[] encrypt() throws CryptoException {
		byte[] ivAES256 = (byte[]) additionalInformation.get(TOKEN_IV_AES256);
		if (ivAES256 == null) {
			throw new CryptoException("Fehler! Kein IV im EngineToken! Encryption abgebrochen!");
		}
        byte[] output = new byte[cipherEnc.getOutputSize(this.data.length)];
        int len = cipherEnc.processBytes(this.data, 0, this.data.length, output, 0);
        try {
			len += cipherEnc.doFinal(output, len);
        } catch (DataLengthException e) {
			throw new CryptoException("Encrypt: Datenlänge passt nicht ", e);
		} catch (IllegalStateException e) {
			throw new CryptoException("Encrypt: Zustand passt nicht ", e);
		} catch (InvalidCipherTextException e) {
			throw new CryptoException("Encrypt: Cipher passt nicht ", e);
		}
        return output;
	}
	

	private void setKey(byte[] myKey) throws CryptoException {
		int MAXKEYSIZE = 32;
		Security.addProvider(new BouncyCastleProvider());
		MessageDigest sha = null;
		try {
			sha = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("setKey: Kein solcher Algorythmus ", e);
		}
		byte[] iv = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }; // der IV ist immer 16 Byte
		// Achtung: Der IV muss bei Ver- und Entschlüsseln gleich sein
		// iv = SecureRandom.getSeed(16); // überschreibt das Array oben
		if (this.additionalInformation != null && this.additionalInformation.get(TOKEN_IV_AES256) != null) {
			iv =(byte[]) this.additionalInformation.get(TOKEN_IV_AES256);
		}
		
//	    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // Java 8 required
//	    sha = MessageDigest.getInstance("SHA-256");
		
		this.key = sha.digest(myKey);
	    int len = (this.key.length <= MAXKEYSIZE ? this.key.length : MAXKEYSIZE);
	    byte[] keyFinal = new byte[MAXKEYSIZE];
	    for (int i=0; i<len; i++) {
	    	keyFinal[i] = this.key[i];
	    } // all das weil es key = Arrays.copyOf(key, ...); nicht gibt
	    
	    this.key = keyFinal;
	    
	    CipherParameters params = new ParametersWithIV(new KeyParameter(this.key), iv);
        cipherEnc = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        cipherEnc.init(true, params);
        cipherDec = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
        cipherDec.init(false, params);
	}
	
	public int getBlocksize() {
		return this.BLOCKSIZE;
	}
	
	public boolean checkSignature() throws CryptoException {
		String b64SigString = (String) additionalInformation.get(TOKEN_B64SIGNATURSTRING_AES256);
		if (b64SigString == null) {
			throw new CryptoException("Fehler! Keine Signatur zum Prüfen im EngineToken! Prüfung abgebrochen!");
		}
		byte[] signaturInBytes = Base64.toBytes(b64SigString);
		byte[] tmpHashB64 = this.sign();
		return Arrays.equals(tmpHashB64,signaturInBytes);
		
		// throw new CryptoException("AES kann keine Signatur prüfen." + DONOTUSETHISCLASS);
	}
	
	public byte[] sign() throws CryptoException {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Ungültiger Algorithmus",e);
		}
		byte[] hash = digest.digest(this.data);
		return hash;
		// throw new CryptoException("AES kann nicht signieren." + DONOTUSETHISCLASS);
	}
}
