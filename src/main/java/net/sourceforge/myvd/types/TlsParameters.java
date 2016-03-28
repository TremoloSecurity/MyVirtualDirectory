package net.sourceforge.myvd.types;

import javax.security.cert.X509Certificate;

public class TlsParameters {
	X509Certificate[] clientChain;
	String cipherSuite;
	
	
	public TlsParameters(String cipherSuite,X509Certificate[] x509Certificates) {
		this.cipherSuite = cipherSuite;
		this.clientChain = x509Certificates;
	}


	public X509Certificate[] getClientChain() {
		return clientChain;
	}


	public String getCipherSuite() {
		return cipherSuite;
	}
	
	
}
