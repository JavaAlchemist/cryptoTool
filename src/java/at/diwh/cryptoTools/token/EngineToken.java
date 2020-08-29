package at.diwh.cryptoTools.token;

import java.util.Map;

/**
 * Diese Klasse stellt den Crypto-Token zur Verfügung. Dieser Token ist der einzige Parameter für alle
 * Implementierungen vom Interface <i>ICryptoEngine</i>. Der Token ist <u>sicher</u> implementiert. D.h.
 * jeder Setter und jeder Getter setzt bzw. liefert eine Kopie des Objekts zurück. Auch der Konstruktor entkoppelt die
 * Parameter-Objekte von den dann tatsächlichen Instanz-Variablenwerten.
 * <br/><b>AUßER</b> bei der Map für die zusätzlichen Informationen. Damit kann man somit nachträglich Daten 
 * in die Engine "injizieren". Beispiel: Die RSA-verschlüsselten Daten zum Signieren.
 * <br/>Für bisher nicht vorgesehene Fälle enthält der Token auch eine Map<String, Object> <i>additionalInformation</i>. Da
 * hinein kann der CryptoHID dann diverse Property::Werte-Paare hinein geben, wenn es mal eine Implementierung verlangt.
 * @see #EngineToken(byte[], byte[], byte[], byte[], Map, Integer)
 * @author 246J 
 */
public class EngineToken {
	private byte[] symetricKey;
	private byte[] privateKey;
	private byte[] publicKey;
	private byte[] data;
	private Map<String, Object> additionalInformation;
	private Integer blocksize;
	
	/**
	 * <b>KONSTRUKTOR</b>
	 * Default Konstruktor. Darf benutzt werden, 
	 * <br/>aber besser: @see {@link #EngineToken(byte[], byte[], byte[], byte[], Map, Integer)}
	 */ 
	public EngineToken() {
		super();
	}
	/**
	 * <b>KONSTRUKTOR</b>
	 * <br/>Erzeuge einen <i>EngineToken</i> mit den ensprechenden Werten. Parameter, die die Engine-Implementierung
	 * nicht benötigt, können <i>null</i> gesetzt werden.
	 * @param symetricKey - z.B. für AES256-Implementierungen
	 * @param privateKey - z.B. der private Schlüssel bei RSA
	 * @param publicKey - z.B. der öffentliche Schlüssel bei RSA
	 * @param data - die zu verschlüsselnden / entschlüsselnden Daten
	 * @param additionalInformation - Map<String, Object> falls die Engine-Implementierung noch was braucht, was man irgendwie übergeben muss
	 * @param blocksize - Blocksize als Integer-Objekt
	 */
	public EngineToken(byte[] symetricKey, byte[] privateKey, byte[] publicKey,
			byte[] data, Map<String, Object> additionalInformation, Integer blocksize) {
		super();
		setSymetricKey(symetricKey);
		setPrivateKey(privateKey);
		setPublicKey(publicKey);
		setData(data);
		setAdditionalInformation(additionalInformation);
		setBlocksize(blocksize);
	}
	
	public byte[] getSymetricKey() {
		if (this.symetricKey == null) { return null; }
		byte[] returnArray = new byte[this.symetricKey.length];
		System.arraycopy(this.symetricKey, 0, returnArray, 0, this.symetricKey.length);
		return returnArray;
	}
	public void setSymetricKey(byte[] symetricKey) {
		if (symetricKey == null) { this.symetricKey = null; return;}
		byte[] returnArray = new byte[symetricKey.length];
		System.arraycopy(symetricKey, 0, returnArray, 0, symetricKey.length);
		this.symetricKey = returnArray;
	}
	public byte[] getPrivateKey() {
		if (this.privateKey == null) { return null; }
		byte[] returnArray = new byte[this.privateKey.length];
		System.arraycopy(this.privateKey, 0, returnArray, 0, this.privateKey.length);
		return returnArray;
	}
	public void setPrivateKey(byte[] privateKey) {
		if (privateKey == null) { this.privateKey = null; return;}
		byte[] returnArray = new byte[privateKey.length];
		System.arraycopy(privateKey, 0, returnArray, 0, privateKey.length);
		this.privateKey = returnArray;
	}
	public byte[] getPublicKey() {
		if (this.publicKey == null) { return null; }
		byte[] returnArray = new byte[this.publicKey.length];
		System.arraycopy(this.publicKey, 0, returnArray, 0, this.publicKey.length);
		return returnArray;
	}
	public void setPublicKey(byte[] publicKey) {
		if (publicKey == null) { this.publicKey = null; return;}
		byte[] returnArray = new byte[publicKey.length];
		System.arraycopy(publicKey, 0, returnArray, 0, publicKey.length);
		this.publicKey = returnArray;
	}
	public byte[] getData() {
		if (this.data == null) { return null; }
		byte[] returnArray = new byte[this.data.length];
		System.arraycopy(this.data, 0, returnArray, 0, this.data.length);
		return returnArray;
	}
	public void setData(byte[] data) {
		if (data == null) { this.data = null; return;}
		byte[] returnArray = new byte[data.length];
		System.arraycopy(data, 0, returnArray, 0, data.length);
		this.data = returnArray;
	}
	public Map<String, Object> getAdditionalInformation() {
		// absichtlich NICHT entkoppelt
//		if (this.additionalInformation == null) { return null; }
//		return new HashMap<String, Object>(this.additionalInformation);
		return this.additionalInformation;
	}
	public void setAdditionalInformation(Map<String, Object> additionalInformation) {
		// absichtlich NICHT entkoppelt
//		if (additionalInformation == null) { this.additionalInformation = null; return;}
//		this.additionalInformation = new HashMap<String, Object>(additionalInformation);
		this.additionalInformation = additionalInformation;
	}
	public Integer getBlocksize() {
		if (this.blocksize == null) { return null; }
		return new Integer(blocksize.intValue());
	}
	public void setBlocksize(Integer blocksize) {
		if (blocksize == null) { this.blocksize = null; return;}
		this.blocksize = new Integer(blocksize.intValue());
	}

	
}
