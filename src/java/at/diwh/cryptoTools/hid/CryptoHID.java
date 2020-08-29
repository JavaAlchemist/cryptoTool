package at.diwh.cryptoTools.hid;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import at.diwh.cryptoTools.b64.Base64;
import at.diwh.cryptoTools.engine.ICryptoEngine;
import at.diwh.cryptoTools.engine.AES.AES256Impl;
import at.diwh.cryptoTools.engine.AES.AESImpl;
import at.diwh.cryptoTools.engine.RSA.RSAImpl;
import at.diwh.cryptoTools.exception.CryptoException;
import at.diwh.cryptoTools.token.EngineToken;
import at.diwh.utils.array.ArrayFunction;
import at.diwh.utils.file.tools.RABinDateiIO;

/**
 * Crypto<b>HID</b> - <b>H</b>uman <b>I</b>nterface <b>D</b>evice<br/>
 * Sinn dieser Klasse ist es, die Schnittstelle zu bieten zwischen einzelnen Implementierungen und dem
 * Anwender der Kryptografie. So sollte sich der Aufrufer möglichst nicht um das <i>EngineToken</i> kümmern müssen.<br/>
 * Zum Beispiel AES: Ein Anwender ist gewohnt, einen String als Passphrase zu übergeben und z.B. ein File. Dann will er ein File zurück bekommen.
 * Damit der Aufrufer nicht ein <i>EngineToken</i> befüllen muss, nimmt er das CryptoHID.<br/>
 * Auch soll der CryptoHID Methoden zum Umgang mit Schlüsseln bereit stellen. Das ist bei AES nicht so wesentlich, bei RSA aber kann das
 * schon ermüdend sein.<br/>
 * Das HID kümmert sich auch um das Encoding, wo es nötig ist. Dazu werden <br>
 * &nbsp &nbsp setEncodingForInput(String encoding)<br/>
 * &nbsp &nbsp setEncodingForOutput(String encoding)<br/>
 * &nbsp &nbsp getEncodingForInput()<br/>
 * &nbsp &nbsp getEncodingForOutput()<br/>
 * geboten. Default ist immer "UTF-8".
 * 
 * @author 246J
 *
 */
public class CryptoHID {
	// Für AES
	private static final int BUFFERSIZE_AES = 2048;
	
	// Für RSA
	private static final String ALGORITHM_RSA = "RSA";
	private static final String ALGORITHM_SHA1PRNG = "SHA1PRNG";
	private static final String PROVIDER_SUN = "SUN";
	private static final int BUFFERSIZE_RSA = 256; // aka "Blocksize"
	private static final int KEYSIZE_RSA = 4096;
	private static final String TOKEN_B64ENCSTRING_RSA = "b64EncString";// "b64EncString" = das verschlüsselte Byte-Array, das als base64-String vorliegt
	private static final String TOKEN_B64SIGNATURSTRING_RSA = "b64SignaturString";// "b64SignaturString" = die Signatur als base64-String
	private static final String TOKEN_B64SIGNATURSTRING_AES256 = "b64SignaturString";// "b64SignaturString" = die Signatur als base64-String
	private static final String TOKEN_IV_AES256 = "ivAES256";// der Initialisation Vector für AES256, Wert: byte[]

	// Allgemein
	private static final Integer BUFFERSIZE = 2048; // allgemeine Buffer-Size (z.B. beim FileRead)
	private String encodingForInput = "UTF-8"; // defaults UTF-8
	private String encodingForOutput = "UTF-8"; // defaults UTF-8
	private final double MINVERSION = 1.1D;
	
/*
 * AES-basierte Methoden	
 */
	/**
	 * <H1>AES</H1>
	 *
	 * Generalistische Methode, ein Engine-Token für AES (egal welches) zu erzeugen.
	 */
	private EngineToken engineTokenForAES(String passphrase, byte[] data) throws CryptoException {
		byte[] key = null;
		try {
			key = passphrase.getBytes(getEncodingForInput());
		} catch (UnsupportedEncodingException e) {
			throw new CryptoException("Input Encoding " +getEncodingForInput() + " not supported ", e);
		}
		return new EngineToken(key, null, null, data, null, BUFFERSIZE_AES);
	}
	
	/**
	 * <H1>AES</H1>
	 * Entschlüsselt das Byte-Array per AES. Benötigt dazu eine Passphrase (String). Berücksichtigt die im
	 * CryptoHID gesetzte Instanzvariable des Character-Encodings für Input (<i>setEncodingForInput()</i>),
	 * weil die Passphrase ja ein <b>Input</b> ist. Default ist UTF-8.
	 * @param passphrase als String (benutzerfreundlich!)
	 * @param data - als Byte-Array
	 * @return das entschlüsselte Byte-Array
	 * @throws CryptoException
	 */
	public byte[] aes_decrypt(String passphrase, byte[] data) throws CryptoException {
		EngineToken et = engineTokenForAES(passphrase, data);
		ICryptoEngine engine;
		engine = new AESImpl(et);
		return decrypt(engine);
	}
	
	/**
	 * <H1>AES</H1>
	 * Wie {@link CryptoHID#aes_decrypt(String, byte[])} nur mit AES256
	 * Im Unterschied zur AES (128) Implementierung verwendet die AES256-Version aber
	 * <br/>1. einen sich immer ändernden Initialisation Vector (IV), und
	 * <br/>2. einen Header, der die originale Datei-Länge und den IV beinhaltet
	 * <br/>D.h. ein verschlüsselter Satz besteht aus
	 * <br/>[4 Byte] Integer-Wert + [16 Byte] IV + [n Byte] verschlüsselte Daten
	 * <br/>Dem Anwendungsprogramm kann das eigentlich egal sein, solange es die Methoden des Crypto HID
	 * benutzt, ist die Verwaltung der Metadaten darin automatisch.
	 * @param passphrase als String (benutzerfreundlich!)
	 * @param data - als Byte-Array
	 * @return das entschlüsselte Byte-Array
	 * @throws CryptoException
	 */
	public byte[] aes256_decrypt(String passphrase, byte[] data) throws CryptoException {
		if (extractJavaVersion() < MINVERSION) {
			throw new CryptoException("Java Version kleiner 1.8 - AES256 wegen fehlendem PBKDF2WithHmacSHA256 nicht unterstützt! ");
		}
		// konstruiere Input
		ByteBuffer bBuffer = ByteBuffer.wrap(data);
		int fileLaenge = bBuffer.getInt(); // die ersten 4 Byte sind ein Integer-Wert
		byte[] iv = new byte[16]; // Init.Vektor
		bBuffer.get(iv);
		byte[] encData = new byte[bBuffer.remaining()]; // der Rest ist Cypertext
		bBuffer.get(encData);
		
		// EngineToken et = engineTokenForAES(passphrase, encData); // kann wegen des IV nicht mehr verwendet werden
		
		Map<String,Object> paraMap = new HashMap<String, Object>();
		paraMap.put(TOKEN_IV_AES256, (byte[]) iv);
		EngineToken et;
		try {
			et = new EngineToken(passphrase.getBytes("UTF-8"), null, null, encData, paraMap, BUFFERSIZE_AES);
		} catch (UnsupportedEncodingException e) {
			throw new CryptoException("Ich konnte die Passphrase nicht in ein Byte Array umwandeln!", e);
		}

		ICryptoEngine engine;
		engine = new AES256Impl(et);
		
		byte[] decData = decrypt(engine);
		
		// kürze Output
		bBuffer = ByteBuffer.wrap(decData);
		byte[] returnDecData = new byte[fileLaenge];
		bBuffer.get(returnDecData);
		
		return returnDecData;
	}
	
	/**
	 * <H1>AES</H1>
	 * Verschlüsselt das Byte-Array per AES. Benötigt dazu eine Passphrase (String). Berücksichtigt die im
	 * CryptoHID gesetzte Instanzvariable des Character-Encodings für Input (<i>setEncodingForInput()</i>),
	 * weil die Passphrase ja ein <b>Input</b> ist. Default ist UTF-8.
	 * @param passphrase - als benutzerfreundlicher String
	 * @param data - als Byte-Array
	 * @return das verschlüsselte Byte-Array
	 * @throws CryptoException
	 */
	public byte[] aes_encrypt(String passphrase, byte[] data) throws CryptoException {
		EngineToken et = engineTokenForAES(passphrase, data);
		ICryptoEngine engine;
		engine = new AESImpl(et);
		return encrypt(engine);
	}
	
	/**
	 * <H1>AES</H1>
	 * Wie {@link CryptoHID#aes_encrypt(String, byte[])} nur mit AES256
	 * Im Unterschied zur AES (128) Implementierung verwendet die AES256-Version aber
	 * <br/>1. einen sich immer ändernden Initialisation Vector (IV), und
	 * <br/>2. einen Header, der die originale Datei-Länge und den IV beinhaltet
	 * <br/>D.h. ein verschlüsselter Satz besteht aus
	 * <br/>[4 Byte] Integer-Wert + [16 Byte] IV + [n Byte] verschlüsselte Daten
	 * <br/>Dem Anwendungsprogramm kann das eigentlich egal sein, solange es die Methoden des Crypto HID
	 * benutzt, ist die Verwaltung der Metadaten darin automatisch.
	 * @param passphrase - als benutzerfreundlicher String
	 * @param data - als Byte-Array
	 * @return das verschlüsselte Byte-Array
	 * @throws CryptoException
	 */
	public byte[] aes256_encrypt(String passphrase, byte[] data) throws CryptoException {
		if (extractJavaVersion() < MINVERSION) {
			throw new CryptoException("Java Version kleiner 1.8 - AES256 wegen fehlendem PBKDF2WithHmacSHA256 nicht unterstützt! ");
		}
		//EngineToken et = engineTokenForAES(passphrase, data); // vereinfachter Konstruktor kann nicht mehr eingesetzt werden für AES256 Impl.
		
		byte[] iv = new byte[16];
		iv = SecureRandom.getSeed(16); 
		Map<String,Object> paraMap = new HashMap<String, Object>();
		paraMap.put(TOKEN_IV_AES256, (byte[]) iv);
		EngineToken et;
		try {
			et = new EngineToken(passphrase.getBytes("UTF-8"), null, null, data, paraMap, BUFFERSIZE_AES);
		} catch (UnsupportedEncodingException e) {
			throw new CryptoException("Ich konnte die Passphrase nicht in ein Byte Array umwandeln!", e);
		}
		
		ICryptoEngine engine;
		engine = new AES256Impl(et);
		byte[] encData = encrypt(engine);

		// konstruiere Output
		ByteBuffer bBuffer = ByteBuffer.allocate(4 + 16 + encData.length); // 4 für die File-Länge, 16 für den IV
		bBuffer.putInt(data.length);
		bBuffer.put(iv);
		bBuffer.put(encData);
		
		return bBuffer.array();
	}
	
	/**
	 * Erzeugt aus den übergebenen Daten einen SHA256-Hashcode
	 * @param data
	 * @return den Hashcode als Byte-Array
	 * @throws CryptoException
	 */
	public byte[] aes256_generateHashcode(byte[] data) throws CryptoException {
//		byte[] dummyBar = "DASISTEINDUMMY".getBytes();
//		EngineToken et = new EngineToken(dummyBar, null, null, data, null, BUFFERSIZE_AES);
		EngineToken et = engineTokenForAES("DASISTEINDUMMY", data);
		ICryptoEngine engine;
		engine = new AES256Impl(et);
		return engine.sign();
	}
	
	/**
	 * Prüft den übergebenen Hashcode gegen das File, das als Byte-Array vorliegen muss.
	 * @param data
	 * @param hashCodeB64 - bequem als Base64-String
	 * @return true, wenn der Hashcode passt, false wenn nicht
	 * @throws CryptoException
	 */
	public boolean aes256_checkHashcode(byte[] data, String hashCodeB64) throws CryptoException {
		byte[] dummyBar = "DASISTEINDUMMY".getBytes();
		Map<String,Object> paraMap = new HashMap<String, Object>();
		paraMap.put(TOKEN_B64SIGNATURSTRING_AES256, (String) hashCodeB64);
		EngineToken et = new EngineToken(dummyBar, null, null, data, paraMap, BUFFERSIZE_AES);
		ICryptoEngine engine;
		engine = new AES256Impl(et);
		return engine.checkSignature();
	}
	

	/**
	 * Wie {@link CryptoHID#aes256_checkHashcode(byte[], String)}
	 * @param data 
	 * @param hashCode - als Byte-Array
	 * @return true, wenn der Hashcode stimmt, false wenn nicht.
	 * @throws CryptoException
	 */
	public boolean aes256_checkHashcode(byte[] data, byte[] hashCode) throws CryptoException {
		return this.aes256_checkHashcode(data, Base64.toString(hashCode));
	}

	
	/*
	 * RSA-basierte Methoden	
	 */
	
	/**
	 * <H1>RSA</H1>
	 * Verschlüsselt das übergebene Byte-Array per RSA. Nimmt dazu den übergebenen öffentlichen Schlüssel.
	 * <br/><b>ACHTUNG</b> Das klappt nur bei sehr kleinen Byte-Arrays (ca. 500 Byte).
	 * @param publicKeyReceiver - öfentlicher Schlüssel als Byte-Array
	 * @param data - Daten als Byte-Array
	 * @return die verschlüsselten Daten als Byte-Array
	 * @throws CryptoException
	 */
	public byte[] rsa_encryptSmallData(byte[] publicKeyReceiver, byte[] data) throws CryptoException {
		EngineToken et = new EngineToken(null, null, publicKeyReceiver, data, null, BUFFERSIZE_RSA);
		ICryptoEngine engine;
		engine = new RSAImpl(et);
		return encrypt(engine);
	}
	
	/**
	 * <H1>RSA</H1>
	 * Entschlüsselt das übergebene Byte-Array per RSA. Nimmt dazu den übergebenen privaten Schlüssel.
	 * <br/><b>ACHTUNG</b> Das klappt nur bei sehr kleinen Byte-Arrays (ca. 500 Byte).
	 * @param privateKey - privater Schlüssel als Byte-Array
	 * @param data - verschlüsselte Daten als Byte-Array
	 * @return die entschlüsselten Daten als Byte-Array
	 * @throws CryptoException
	 */
	public byte[] rsa_decryptSmallData(byte[] privateKey, byte[] data) throws CryptoException {
		EngineToken et = new EngineToken(null, privateKey, null, data, null, BUFFERSIZE_RSA);
		ICryptoEngine engine;
		engine = new RSAImpl(et);
		return decrypt(engine);
	}
	
	/**
	 * <H1>RSA</H1>
	 * Diese Methode verschlüsselt ein beliebig großes Byte-Array per RSA. RSA verschlüsselt Byte-Arrays normalerweise nur in sehr
	 * geringer Größe, abhängig vom Schlüssel. Noch dazu "padded" es. Jedenfalls arbeiten wir mit Blöcken  d.h. man müsste sich zu jeder
	 * Datei die verwendete Blockgröße merken, denn es kommen ggf. unterschiedlich lange Blöcke verschlüsselt raus. Würde man
	 * die wieder zusammen setzen, könnte man ohne die Information, wie lange jeder Block war/ist, diese nie mehr entschlüsseln. D.h. zu einem
	 * derart verschlüsselten Byyte-Array müsste immer noch eine Datenstruktur als Metadaten mit Blockgrößen beigefügt werden. Das ist sehr
	 * unpraktisch. Deswegen verlagert diese Methode diese Aufgabe an base64-Strings. Die eingehenden Binärdaten werden in Blöcke zerlegt,
	 * die RSA sicher verschlüsseln kann. Die verschlüsselten Blöcke samt Padding (also in variabler Größe) werden dann jedweils mit
	 * einem LineSeparator beendet und so ist das Block-Ende klar. Diese Blöcke werden zusammengehängt und am Ende kommt dadurch
	 * ein fertig RSA-verschlüsselter String im base64-Format raus.
	 * <br/>Diese Methode ist logischerweise das Pendant zu <i>rsa_decrypt(byte[] privateKey, String data)</i>.
	 * <br/>D.h. FileXY -> byte[] -> rsa_encrypt(...) -> base64-String -> rsa_decrypt(...) -> byte[] -FileXY
	 * <br/> Also letzlich eine vollständige Kette perfekter Ver- und Entschlüsselung. Siehe auch @see {@link #rsa_decrypt(byte[], String)}
	 * @param publicKeyReceiver
	 * @param data - das Byte-Array
	 * @param lineSeparator - kann <i>null</i> sein, dann wird der vom <i>System.getProperty("line.separator");</i> genommen
	 * @return die verschlüsselten Daten als base64-String in Blöcke per lineSeparator (default: vom System) zerteilt
	 * @throws CryptoException
	 */
	public String rsa_encrypt(byte[] publicKeyReceiver, byte[] data, String lineSeparator) throws CryptoException {
		ByteArrayInputStream bArrIs = null;
		String zeilenumbruch = System.getProperty("line.separator");
		if (lineSeparator != null) {
			zeilenumbruch = new String(lineSeparator);
		}
		StringBuffer sb = new StringBuffer();
		// die erste Zeile ist die Metainformation
		String datenLaenge = String.valueOf(data.length);
		sb.append(datenLaenge);
		sb.append(zeilenumbruch);
		
		try {
		   	bArrIs = new ByteArrayInputStream(data);
		    byte[] buffer = new byte[BUFFERSIZE_RSA];
		    while ((bArrIs.read(buffer)) > 0) {
		    	sb.append(Base64.toString(rsa_encryptSmallData(publicKeyReceiver, buffer)));
		        sb.append(zeilenumbruch);
		    }
		} catch (IOException e) {
			throw new CryptoException("I/O ging schief beim RSA encrypt", e);
		} finally {
		   	try {
				if (bArrIs != null) {
					bArrIs.close();
				}
			} catch (IOException e) {
				throw new CryptoException("I/O Fehler beim Schließen des Byte Array Input Streams", e);
			}
		}
		
		return sb.toString();
	}
	
	/**
	 * <H1>RSA</H1>
	 * Diese Methode entschlüsselt einen beliebig langen base64-String per RSA.
	 * <br/>Hintergrund ist wie beim Verschlüsseln: RSA geht nur mit sehr kleinen Byte-Arrays, die dann <u>ein</u> Block 
	 * sind und diser Block wird dann "gepadded". Mehrere Blöcke gehen, aber würde man nun alles in EIN Byte-Array zusammen pferchen, 
	 * müsste man sich die verwendete Blocksize merken, die kann ja unterschiedlich lange sein pro Verschlüsselungsdurchgang.
	 * Ich will aber unabhängig von Meta-Informationen arbeiten, die verschlüsselte Datei soll alles sein, was man braucht. (Und Schlüssel, klar.) 
	 * <br/>Fazit, kurz: Alle Blöcke zusammengesetzt in ein byte[] taugt nicht wirklich.
	 * <br/>Um das zu umgehen, wurde beim Verschlüsseln eben auf base64-Strings gesetzt, die durch eben ein Zeilenende die
	 * Blockgrenzen markieren. Dadurch kann der Entschlüsselungsalgorithmus die verschieden langen Blöcke richtig verarbeiten.  
	 * <br/>Genauere Info über @see {@link #rsa_encrypt(byte[], byte[], String)} 
	 * @param privateKey - privater Schlüssel
	 * @param data - verschlüsselte Daten als base64-String
	 * @return - entschlüsselte Daten wieder als normale Binärdaten, also Byte-Array
	 * @throws CryptoException
	 */
	public byte[] rsa_decrypt(byte[] privateKey, String data) throws CryptoException {
		Scanner is = new Scanner(data); // Strings lechzen förmlich nach Scanner
	    ByteArrayOutputStream os = null;
	    int zielLaenge = 0;
	    try {
	    	boolean firstLine = true;
	        os = new ByteArrayOutputStream();
	        while ((is.hasNextLine())) { // Solange da noch eine Zeile ist...
	        	String zeile = is.nextLine(); // ... lesen ...
	        	if (firstLine) {
	        		firstLine = false;
	        		zielLaenge = Integer.valueOf(zeile);
	        	} else {
		        	// System.out.println("Debug: Decodiere Zeile: " + zeile);
			        byte[] buffer = Base64.toBytes(zeile); // ... in ein Byte Array konvertieren ...
		            os.write(rsa_decryptSmallData(privateKey, buffer)); // ... und schreiben.
		        }
	        }
	    } catch (IOException e) {
	    	throw new CryptoException("I/O ging schief beim RSA decrypt", e);
		} finally {
	        is.close();
	        try {
				if (os != null) {
					os.flush();
			        os.close();
				}
			} catch (IOException e) {
				throw new CryptoException("I/O Fehler beim Schließen des Byte Array Output Streams", e);
			}

	    }
		
		// kürze Output
		ByteBuffer bBuffer = ByteBuffer.wrap(os.toByteArray());
		byte[] returnDecData = new byte[zielLaenge];
		bBuffer.get(returnDecData);
		return returnDecData;
	}
		
	/**
	 * <H1>RSA</H1>
	 * Signiert Daten, die als base64-String vorliegen, mit dem privaten Schlüssel (üblicherweise
	 * der des sog. "Senders"). Normaler Einsatz ist gedacht für den klassischen Ablauf: 
	 * <br/>Sender X verschlüsselt Daten für Emfänger Y mit dessen öffentlichem Schlüssel (Y.publicKey) und signiert dann mit dem eigenen
	 * privaten Schlüssel (X.privateKey) diese Daten.
	 * <br/>Y empfängt die Daten und die Signatur und prüft dann mit dem öffentlichen Schlüssel des Senders (X.publicKey) die Signatur.
	 * Wenn diese Prüfung OK ist, kann er gefahrlos die Authentiizität annehmen. Er wird dann mit seinem privaten Schlüssel (Y.privateKey)
	 * die Daten entschlüsseln und verwenden.
	 * @param base64CryptedData - String im base64-Format
	 * @param privateKey - privater Schlüssel als Byte-Array
	 * @return einen Schlüssel als base64-String
	 * @throws CryptoException
	 */
	public String rsa_sign(String base64CryptedData, byte[] privateKey) throws CryptoException {
		byte[] dummyBar = "DASISTEINDUMMY".getBytes();
		Map<String,Object> paraMap = new HashMap<String, Object>();
		paraMap.put(TOKEN_B64ENCSTRING_RSA, (String) base64CryptedData);
		EngineToken et = new EngineToken(null, privateKey, null, dummyBar, paraMap, BUFFERSIZE_RSA);
		ICryptoEngine engine;
		engine = new RSAImpl(et);
		return Base64.toString(engine.sign());
	}
	
	/**
	 * <H1>RSA</H1>
	 * Stub-Methode, um sofort ein beliebiges Byte-Array zu signieren.
	 * @see #rsa_sign(String, byte[])
	 * @param data - die Daten als Byte-Array
	 * @param privateKey - der private Schlüssel des Signierenden
	 * @return die Signatur als base64-String
	 * @throws CryptoException
	 */
	public String rsa_sign(byte[] data, byte[] privateKey) throws CryptoException {
		String base64CryptedData = Base64.toString(data);
		return rsa_sign(base64CryptedData, privateKey);
	}
	
	/**
	 * <H1>RSA</H1>
	 * Prüft eine Signatur gegen Daten. Typ. Ablauf siehe @see {@link #rsa_sign(String, byte[])}
	 * @param base64CryptedData - die Daten, zu der die Signatur angeblich gehört
	 * @param publicKey - der öffentliche Schlüssel, des Signierenden als Byte-Array
	 * @param signatur - die Signatur als base64-String
	 * @return true, wenn die Signatur zu den Daten passt, sonst false.
	 * @throws CryptoException
	 */
	public boolean rsa_checkSignature(String base64CryptedData, byte[] publicKey, String signatur) throws CryptoException {
		byte[] dummyBar = "DASISTEINDUMMY".getBytes();
		Map<String,Object> paraMap = new HashMap<String, Object>();
		paraMap.put(TOKEN_B64ENCSTRING_RSA, (String) base64CryptedData);
		paraMap.put(TOKEN_B64SIGNATURSTRING_RSA, (String) signatur);
		EngineToken et = new EngineToken(null, null, publicKey, dummyBar, paraMap, BUFFERSIZE_RSA);
		ICryptoEngine engine;
		engine = new RSAImpl(et);
		return engine.checkSignature();
	}
	
	/**
	 * <H1>RSA</H1>
	 * Stub-Methode, um die Signatur direkt von einem Byte-Array (Binärdaten) zu prüfen.
	 * @see #rsa_checkSignature(String, byte[], String)
	 * @param data - die Daten, zu denen die Signatur passen sollte als Byte-Array
	 * @param publicKey - der öffentliche Schlüssel des Signierenden als Byte-Array
	 * @param signatur - die Signatur, die zu den Daten passen soll, als base64-String
	 * @return true, wenn die Signatur passt, sonst false
	 * @throws CryptoException
	 */
	public boolean rsa_checkSignature(byte[] data, byte[] publicKey, String signatur) throws CryptoException {
		String base64CryptedData = Base64.toString(data);
		return rsa_checkSignature(base64CryptedData, publicKey, signatur);
	}

	/**
	 * <H1>RSA</H1>
	 * Speichert einen Key in ein File.
	 * Als Komfort gibt die Methode den Key als base64-String zurück.
	 * @param anyRSAKey - egal ob privater oder öffentlicher Schlüssel, als Byte-Array
	 * @param file - Zielfile
	 * @return den soeben gespeicherten Key als base64-String (wenn man das braucht, ist das nützlich)
	 * @throws CryptoException
	 */
	public String rsa_saveKey(byte[] anyRSAKey, File file) throws CryptoException {
		String b64S = Base64.toString(anyRSAKey);
		writeBase64ToFile(file, b64S);
		return b64S;
	}
	
	/**
	 * <H1>RSA</H1>
	 * Liest einen Key aus einem File
	 * @param file - Quell-File
	 * @return den Schlüssel als Byte-Array
	 * @throws CryptoException
	 */
	public byte[] rsa_loadKey(File file) throws CryptoException {
		String b64S = readBase64FromFile(file, false);
		return Base64.toBytes(b64S);
	}
	
	/**
	 * <H1>RSA</H1>
	 * Generiere einan RSA Keypai
	 * @param keySize - wird auf internen Default gesetzt wenn <i>null</i>
	 * @return das RSA-KeyPair-Objekt
	 * @throws CryptoException
	 */
    public KeyPair rsa_generateKeyPair(Integer keySize) throws CryptoException {
    	int RSA_KEYSIZE = KEYSIZE_RSA;
    	if (keySize != null) {
    		RSA_KEYSIZE = keySize.intValue();
    	}
        KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance(ALGORITHM_RSA);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Kein solcher Algorithmus", e);
		}
        SecureRandom random;
		try {
			random = SecureRandom.getInstance(ALGORITHM_SHA1PRNG, PROVIDER_SUN);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException("Kein solcher Algorithmus", e);
		} catch (NoSuchProviderException e) {
			throw new CryptoException("Kein solcher Provider", e);
		}
        keyGen.initialize(RSA_KEYSIZE, random);
        KeyPair generateKeyPair = keyGen.generateKeyPair();
        return generateKeyPair;
    }
    
    /**
     * <H1>RSA</H1>
     * Extrahiere den Private Key als Byte-Array aus einem KeyPair-Objekt 
     * @param kp (KeyPair)
     * @return byte[]
     */
    public byte[] rsa_extractPrivateKey(KeyPair kp) {
    	return kp.getPrivate().getEncoded();
    }
	
    /**
     * <H1>RSA</H1>
     * Extrahiere den Public Key als Byte Array aus einem KeyPair-Objekt 
     * @param kp (KeyPair)
     * @return byte[]
     */
    public byte[] rsa_extractPublicKey(KeyPair kp) {
    	return kp.getPublic().getEncoded();
    }
/*
 * ALLGEMEINE Methoden rund um's Verschlüsseln; nützliche Helfer
 */
	/**<H1>Allgemeine Methode</H1>
	 * Einfachste Methode, um aus einem Byte-Array einen base64-String zu machen.
	 * Im Normalfall die zu bevorzugende Methode.
	 * @param bArr - das Byte-Array, das umgewandelt werden soll
	 * @return den base64-String
	 */
	public String transformByteArrayToBase64(byte[] bArr) {
		return Base64.toString(bArr);
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Komplexere Methode, ein Byte-Array in einen base64-String umzuwandeln.
	 * <br/>Man kann hier den zu verwendenden Zeilenumbruch-String angeben und auch, wie lange die
	 * Zeilen sein sollen. Setzt man den Zeilenumbruch <i>null</i> wird wie ohne Parameter gehandelt, also
	 * der vom System genommen, setzt man die Zeilenlänge auf <i>null</i>, wird ebenso der default genommen
	 * (also alles ist eine Zeile).
	 * @param bArr - Byte-Array
	 * @param zeilenSeparator - darf <i>null</i> sein
	 * @param zeilenLaenge - Integer Objekt, darf <i>null</i> sein
	 * @return den base64-String
	 */
	public String transformByteArrayToBase64(byte[] bArr, String zeilenSeparator, Integer zeilenLaenge) {
		Base64 b64 = new Base64();
		if (zeilenSeparator != null) {
			b64.setLineSeparator(zeilenSeparator);
		}
		if (zeilenLaenge != null) {
			b64.setLineLength(zeilenLaenge.intValue());
		}
		return b64.encode(bArr);
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Einfachste Methode, um aus einem base64-String wieder ein Byte-Array zu machen.
	 * Sollte für die Standardfälle genügen und die bevorzugte Methode sein. 
	 * @param b64S - der base64-String
	 * @return das Byte-Array
	 */
	public byte[] transformBase64StringToByteArray(String b64S) {
		return Base64.toBytes(b64S);
	}

	/**
	 * <H1>Allgemeine Methode</H1>
	 * Komplexere Methode, einen base64-String in ein Byte-Array umzuwandeln.
	 * <br/>Man kann hier den zu verwendenden Zeilenumbruch-String angeben und auch, wie lange die
	 * Zeilen sein sollen. Setzt man den Zeilenumbruch <i>null</i> wird wie ohne Parameter gehandelt, also
	 * der vom System genommen, setzt man die Zeilenlänge auf <i>null</i>, wird ebenso der default genommen
	 * (also alles ist eine Zeile).
	 * @param b64S - der zu wandelnde String
	 * @param zeilenSeparator - darf <i>null</i> sein
	 * @param zeilenLaenge - Integer Objekt, darf <i>null</i> sein
	 * @return
	 */
	public byte[] transformBase64StringToByteArray(String b64S, String zeilenSeparator, Integer zeilenLaenge) {
		Base64 b64 = new Base64();
		if (zeilenSeparator != null) {
			b64.setLineSeparator(zeilenSeparator);
		}
		if (zeilenLaenge != null) {
			b64.setLineLength(zeilenLaenge.intValue());
		}
		return b64.decode(b64S);
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Wandelt einen String in ein Byte-Array um. Berücksichtigt das Encoding, das per <i>setEncodingFor<b>Input</b>(String)</i> in
	 * der Instanz des CryptoHID gesetzt wurde.
	 * @param s - der umzuwandelnde String
	 * @return das Byte-Array
	 * @throws UnsupportedEncodingException
	 */
	public byte[] transformStringObjectToByteArray(String s) throws UnsupportedEncodingException {
		return s.getBytes(this.encodingForInput);
	}
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Wandelt ein Byte-Array in einen String um. Berücksichtigt das Encoding, das per <i>setEncodingFor<b>Output</b>(String)</i> in
	 * der Instanz des CryptoHID gesetzt wurde.
	 * @param b - das umzuwandelnde Byte-Array
	 * @return den String
	 * @throws UnsupportedEncodingException
	 */
	public String transformByteArrayToStringObject(byte[] b) throws UnsupportedEncodingException {
		return new String(b,encodingForOutput);
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Einfache Methode, die ganz schnell eine beliebige Datei in ein großes Byte-Array einliest.
	 * Verwendet im Hintergrund die Klasse RABinDateiIO.
	 * @param inFile - zu lesende Datei als File-Objekt
	 * @return die Datei als Byte-Array
	 * @throws CryptoException
	 */
	public byte[] binaryReadWholeFile(File inFile) throws CryptoException {
		// ALTERNATIVES LESEN
//		if (inFile == null) {
//			throw new CryptoException("Fehler: Datei ist _null_. Kann man nicht gut von lesen.");
//		}
//		OutputStream bos = new ByteArrayOutputStream();
//		InputStream is = null;
//		try {
//			is = new FileInputStream(inFile);
//		} catch (FileNotFoundException e) {
//			if (inFile == null) {
//				throw new CryptoException("Fehler: Datei scheint nicht zu existieren. Kann man nicht gut von lesen.");
//			}
//		}
//		int i;
//		try {
//			while ((i=is.read()) != -1) {
//				bos.write(i);
//			}
//		} catch (IOException e1) {
//			throw new CryptoException("I/O Fehler beim binären Lesen einer Datei.");
//		} finally {
//			try {
//				if (is != null) {
//					is.close();
//				}
//			} catch (IOException e) {
//				throw new CryptoException("Fehler beim Schließen des Input-Streams.");
//			}
//			try {
//				bos.close();
//			} catch (IOException e) {
//				throw new CryptoException("Fehler beim Schließen des Byte-Output-Streams. Sehr seltsam!");
//			}
//		}
//		return ((ByteArrayOutputStream) bos).toByteArray();

		if (inFile == null) {
			throw new CryptoException("Fehler: Datei ist _null_. Kann man nicht gut von lesen.");
		}
		RABinDateiIO rabin = new RABinDateiIO();
		try {
			rabin.openFile(inFile, true);
		} catch (IOException e) {
			throw new CryptoException("Fehler beim Öffnen der Datei " + inFile.getAbsolutePath(), e);
		}
		try {
			List<byte[]> gelesenesArray = rabin.leseGanzeDatei(BUFFERSIZE);
			return ArrayFunction.combineByteArrays(gelesenesArray);
		} catch (IOException e) {
			throw new CryptoException("Fehler beim Lesen der Datei " + inFile.getAbsolutePath(), e);
		} finally {
			try {
				rabin.closeFile();
			} catch (IOException e) {
				throw new CryptoException("Fehler beim Schließen der Datei " + inFile.getAbsolutePath(), e);
			}
		}
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Einfache Methode, die ein byte[] als Datei abspeichert. <b>Achtung:</b> Die Zieldatei wird gnadenlos <u>überschrieben</u>,
	 * falls es sie schon gibt. Verwendet im Hintergrund die Klasse RABinDateiIO.
	 * <br/><b>WARNUNG</b> Die Methode ist <u>nutzlos</u> bei AES-Byte-Arrays, da hier das Schreiben das Padding zerstört. 
	 * <br/> Man sollte beim Umgang mit verschlüsselten Dateien besser immer base64 schreiben! <br/>
	 * @see {@link #writeBase64ToFile(File, String)
	 * @param outFile - zu schreibende Datei
	 * @param data - die zu schreibenden Daten als Byte-Array
	 * @throws CryptoException
	 */
	public void binaryWriteWholeFile(File outFile, byte[] data) throws CryptoException {
		// ALTERNATIVES SCHREIBEN
//		if (outFile == null) {
//			throw new CryptoException("Fehler: Datei ist _null_. Kann man nicht gut rein schreiben.");
//		}
//		
//		OutputStream fos = null;
//		try {
//			fos = new FileOutputStream(outFile);
//		} catch (FileNotFoundException e) {
//			throw new CryptoException("Fehler. Detei nicht gefunden (bei der AUSGABE? WTF?)", e);		}
//		for (int i=0; i<data.length; i++) {
//			try {
//				fos.write(data[i]);
//			} catch (IOException e) {
//				throw new CryptoException("Fehler beim Öffnen der Datei " + outFile.getAbsolutePath(), e);
//			}
//		}
//		try {
//			if (fos != null) {
//				fos.close();
//			}
//		} catch (IOException e) {
//			throw new CryptoException("Fehler beim Schließen der Datei " + outFile.getAbsolutePath(), e);
//		}
		
		if (outFile == null) {
			throw new CryptoException("Fehler: Datei ist _null_. Kann man nicht gut rein schreiben.");
		}
		RABinDateiIO rabin = new RABinDateiIO();
		try {
			rabin.openFile(outFile, false);
		} catch (IOException e) {
			throw new CryptoException("Fehler beim Öffnen der Datei " + outFile.getAbsolutePath(), e);
		}
		try {
			rabin.speichereDatensatz(data);
		} catch (IOException e) {
			throw new CryptoException("Fehler beim Schreiben der Datei " + outFile.getAbsolutePath(), e);
		} finally {
			try {
				rabin.closeFile();
			} catch (IOException e) {
				throw new CryptoException("Fehler beim Schließen der Datei " + outFile.getAbsolutePath(), e);
			}
		}
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Schreibt einen base64-String auf ein File. Diese Methode sollte bevorzugt werden, wenn man mit verschlüsselten Daten hantiert. 
	 * @param outFile - Zielfile
	 * @param b64S - der base64-String
	 * @throws CryptoException
	 */
	public void writeBase64ToFile(File outFile, String b64S) throws CryptoException {
		FileOutputStream fos = null;
		BufferedWriter bw = null;
		try {
			fos = new FileOutputStream(outFile);
			bw = new BufferedWriter(new OutputStreamWriter(fos));
			bw.write(b64S);
		} catch (FileNotFoundException e) {
			throw new CryptoException("Fehler beim Öffnen der Datei " + outFile.getAbsolutePath(), e);
		} catch (IOException e) {
			throw new CryptoException("Fehler beim Schreiben des Strings", e);
		} finally {
			if (bw!=null) {
				try {
					bw.close();
				} catch (IOException e) {
					throw new CryptoException("Fehler beim Schließen des Buffers der Datei " + outFile.getAbsolutePath(), e);
				}
			}
			if (fos != null) {
				try {
					fos.close();
				} catch (IOException e) {
					throw new CryptoException("Fehler beim Schließen der Datei " + outFile.getAbsolutePath(), e);
				}
			}
		}
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Dies ist nur ein 1:1 Alias für {@link CryptoHID#writeBase64ToFile(File, String)}
	 * <br/>Warum also die Methode? Wenn man im Code schon durch den Aufruf sichtbar / lesbar machen will,
	 * dass es sich um einen base64-String handelt, dann sollte man die <i>writeBase64ToFile(File, String)</i>
	 * verwenden. Für alle anderen Strings oder wenn einem die Lesbarkeit wurscht ist, dann diese.
	 * @param outFile - zu schreibendes File als File-Objekt
	 * @param str - der zu schreibende String
	 * @throws CryptoException
	 */
	public void writeAnyStringToFile(File outFile, String str) throws CryptoException {
		writeBase64ToFile(outFile, str);
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Liest eine Datei, in der sich Daten im base64-Format befinden und gibt diese als einen String zurück.
	 * <br/>Die Methode liefert den String INKLUSIVE der Zeilenumbrüche, weil das ja die Blockgrenzen bestimmt.
	 * wenn man <i>insertLineSeparator</i> true setzt. Das ist nötig, wenn man mit RSA arbeitet oder anderen
	 * Engines, die die "padded blocks" erzeugt habenm deren Rrepräsentation dann die einzelnen Strings im base64 sind.
	 * @param inFile - Quelle
	 * @param insertLineSeparator - wahr, wenn man die Strings durch einen Lineseparator trennen will
	 * @return einen base64-String
	 * @throws CryptoException
	 */
	private String readBase64FromFile(File inFile, boolean insertLineSeparator) throws CryptoException {
		FileInputStream fis = null;
		BufferedReader br = null;
		StringBuffer sb = new StringBuffer();
		String zeilenumbruch = System.getProperty("line.separator");
		try {
			fis = new FileInputStream(inFile);
			br = new BufferedReader(new InputStreamReader(fis));
			String s = null;;
			try {
				while ((s=br.readLine())!= null) {
					sb.append(s);
					if (insertLineSeparator) {
						sb.append(zeilenumbruch);
					}
					
				}
			} catch (IOException e) {
				throw new CryptoException("Fehler beim Lesen einer Zeile in der Datei " + inFile.getAbsolutePath(), e);
			}
			
		} catch (FileNotFoundException e) {
			throw new CryptoException("Fehler beim Öffnen der Datei " + inFile.getAbsolutePath(), e);
		} finally {
			if (br!=null) {
				try {
					br.close();
				} catch (IOException e) {
					throw new CryptoException("Fehler beim Schließen des Buffers der Datei " + inFile.getAbsolutePath(), e);
				}
			}
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					throw new CryptoException("Fehler beim Schließen der Datei " + inFile.getAbsolutePath(), e);
				}
			}
		}
		return sb.toString();
	}

	/**
	 * <H1>Allgemeine Methode</H1>
	 * Dies ist nur ein Alias für {@link CryptoHID#readBase64FromFile(File, boolean)}
	 * <br/>Warum also die Methode? Wenn man im Code schon durch den Aufruf sichtbar / lesbar machen will,
	 * dass es sich um einen base64-String handelt, dann sollte man die {@link CryptoHID#readBase64FromFile(File)}
	 * verwenden. Für alle anderen Strings oder wenn einem die Code-Lesbarkeit wurscht ist, dann diese.
	 * <br/><b>Achtung:</b> Diese Stub liest den Inhalt wirklich als EINEN String, LineSeparatoren sind ihr egal. 
	 * <br/>Also wie <i>readBase64FromFile(inFile, <b>false</b>);</i>
	 * @param inFile - zu lesendes File als File-Objekt
	 * @param preserveLineSeparator - true, wenn man den LineSeparator behalten will
	 * @return den gelesenen String
	 * @throws CryptoException
	 */
	public String readAnyStringFromFile(File inFile) throws CryptoException {
		return readBase64FromFile(inFile, false);
	}
	
	/**
	 * <H1>Allgemeine Methode</H1>
	 * Standard-Lese-Methode für in Blöcken verschlüsselte base64-Dateien.
	 * @see CryptoHID#readBase64FromFile(File, boolean)
	 * @param inFile
	 * @return den Inhalt als base64-String mit aktiven Zeilenumbrüchen
	 * @throws CryptoException
	 */
	public String readBase64FromFile(File inFile) throws CryptoException {
		return readBase64FromFile(inFile, true);
	}
/*
 * PRIVATE Methoden, INTERN
 */
	/**
	 * INTERN<br/>
	 * Generalistischer Verschlüsselungsaufruf gegen die Engine.
	 * <br/>Das EngineToken wurde bereits befüllt und die Engine damit instanziiert.
	 * <br/>Deswegen benötigt man nur noch die Engine-Instanz als Parameter.
	 * @param engine - Implementierung von ICryptoEngine
	 * @return verschlüsseltes Byte-Array
	 * @throws CryptoException
	 */
	private byte[] encrypt(ICryptoEngine engine) throws CryptoException {
		return engine.encrypt();
	}
	/**
	 * INTERN<br/>
	 * Generalistischer Entschlüsselungsaufruf gegen die Engine.
	 * <br/>Das EngineToken wurde bereits befüllt und die Engine damit instanziiert.
	 * <br/>Deswegen benötigt man nur noch die Engine-Instanz als Parameter.
	 * @param engine - Implementierung von ICryptoEngine
	 * @return entschlüsseltes Byte-Array
	 * @throws CryptoException
	 */
	private byte[] decrypt(ICryptoEngine engine) throws CryptoException {
		return engine.decrypt();
	}
	
	private double extractJavaVersion () {
	    String version = System.getProperty("java.version");
	    int pos = version.indexOf('.');
	    pos = version.indexOf('.', pos+1);
	    return Double.parseDouble (version.substring (0, pos));
	}
/*
 * GETTER UND SETTER Methoden 
 */
	/**
	 * <H1>Getter-Methode</H1>
	 */
	public String getEncodingForInput() {
		return encodingForInput;
	}
	
	/**
	 * <H1>Setter-Methode</H1>
	 * Setter für das Encoding, mit dem Input-Strings/Bytes versehen sind.<br>
	 * Default ist "UTF-8"
	 * @param encodingForInput
	 */
	public void setEncodingForInput(String encodingForInput) {
		this.encodingForInput = encodingForInput;
	}

	/**
	 * <H1>Getter-Methode</H1>
	 * @return
	 */
	public String getEncodingForOutput() {
		return encodingForOutput;
	}
	/**
	 * <H1>Setter-Methode</H1>
	 * Setter für das Encoding, mit dem Output-Strings/Bytes versehen werden sollen.<br>
	 * Default ist "UTF-8"
	 * @param encodingForInput
	 */
	public void setEncodingForOutput(String encodingForOutput) {
		this.encodingForOutput = encodingForOutput;
	}
	
	/**
	 * <H1>Besondere Informationsmethode</H1>
	 * Diese Methode retourniert alle <i>final</i> deklarierten Konstanten in dieser Klasse und gibt sie
	 * als "Name :: Wert"-Paare in einer Map zurück.
	 * <br/> Ausgeben/Verarbeiten am besten mittels:
	 * <pre>
	 * {@code
Map<String, String> konstantenMap = CryptoHID.getAllConstants();
Set<String> keyset = konstantenMap.keySet();
for (String element : keyset) {
	System.out.println("Konstante: " + element + " Wert: " + konstantenMap.get(element));
}
	 * }
	 * </pre> Manche Konstanten sind Default-Werte, die sich mit Parametern in Methoden überstimmen lassen.
	 * @return
	 * @throws CryptoException
	 */
	public static Map<String, String> getAllConstants() throws CryptoException {
		CryptoHID meinK = new CryptoHID();
		Class<? extends CryptoHID> k = meinK.getClass();
		Map<String, String> reMap = new HashMap<String, String>();
		
		Field[] f = k.getDeclaredFields();
		for (int i=0; i<f.length; i++) {
			if (f[i].toString().contains("final ")){
				try {
					reMap.put(f[i].getName(), f[i].get(meinK).toString());
				} catch (IllegalArgumentException e) {
					throw new CryptoException("Fehler Abruf der Konstanten: ", e);
				} catch (IllegalAccessException e) {
					throw new CryptoException("Fehler Abruf der Konstanten: ", e);
				}
			}
		}
		return reMap;
	}
}
