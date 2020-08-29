package at.diwh.cryptoTools.engine;

import at.diwh.cryptoTools.exception.CryptoException;

/**
 * Interface zur Erzeugung von Crypto-Engine-Klassen.<br/>
 * Man kann leider über das Interface keinen <b>Konstruktor</b> erzwingen. Fakt ist aber, dass der CryptoHID und somit das ganze
 * Konzept darauf beruhen, dass es einen Konstruktor der Engine gibt, der mit einem EngineToken arbeitet:
 * <br/>Es ist daher <b>notwendig</b>, so einen Konstruktor zu erzeugen (hier am Beispiel der Referenzimplementierung für AES):
 * <pre>{@code
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
 * }</pre>
 * Was man <b>auch</b> sieht: <i>if (!AESImpl.<b>checkToken(eToken)</b>) {...</i><br/>
 * Das ist eine <b>Prüfroutine</b>, die gleich im Konstruktor checken sollte, ob im EngineToken auch alles,
 * was die Implementierung braucht, vorhanden ist, hier als Beispiel aus der Referenzimplementierung für AES:
 * <pre>{@code
 	private static boolean checkToken(EngineToken eToken) {
	if (eToken.getBlocksize() == null || eToken.getSymetricKey() == null || eToken.getData() == null) {
		return false;
	}
	return true;
	}
 * }</pre>
 * Diese <b>Prüfroutine</b> ist nicht zwingend. Sie ist aber <u>empfohlen</u> und sie sollte <i>private</i> und <i>static</i> sein, was auch der Grund ist,
 * warum sie im Interface nicht erzwungen wird. Warum <i>static</i>? Weil sie natürlich ohne Instanz aufgerufen werden muss, da eine Instanz einer 
 * Engine nur <u>mit</u> validem Token erzeugt werden kann.
 * @author 246J
 *
 */
public interface ICryptoEngine {
	public byte[] encrypt() throws CryptoException;
	public byte[] decrypt() throws CryptoException;
	public byte[] sign() throws CryptoException;
	public boolean checkSignature() throws CryptoException;
	// An die entsprechende Fehlermeldung anhängen, wenn's passt:
	public final String DONOTUSETHISCLASS = " ! Benutze diese Methode nicht. Benutze diese Klasse nicht. Verwende CryptoHID ! ";
}
