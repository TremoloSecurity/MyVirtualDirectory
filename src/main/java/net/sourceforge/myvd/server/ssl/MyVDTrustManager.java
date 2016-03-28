package net.sourceforge.myvd.server.ssl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;

public class MyVDTrustManager implements X509TrustManager {
	static Logger logger = Logger.getLogger(MyVDTrustManager.class.getName());
	
	X509Certificate[] issuers;
	KeyStore ks;
	
	public MyVDTrustManager(KeyStore ks,List<String> issuers) {
		this.ks = ks;
		ArrayList<X509Certificate> issuerList = new ArrayList<X509Certificate>();
		for (String alias : issuers) {
			try {
				issuerList.add((X509Certificate) ks.getCertificate(alias));
			} catch (KeyStoreException e) {
				logger.warn("Could not add alias : '" + alias + "'",e);
			}
		}
		
		this.issuers = new X509Certificate[issuerList.size()];
		for (int i=0;i<this.issuers.length;i++) {
			this.issuers[i] = issuerList.get(i);
		}
		
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		boolean trusted = false;
		for (X509Certificate cert : chain) {
			try {
				String alias = ks.getCertificateAlias(cert);
				if (alias != null) {
					trusted = true;
					break;
				}
			} catch (KeyStoreException e) {
				e.printStackTrace();
				throw new CertificateException(e);
			}
			
		}
		
		if (! trusted) {
			
			X509Certificate last = chain[chain.length-1];
			if (last.getIssuerX500Principal().equals(last.getSubjectX500Principal())) {
				//self signed, no point in continuing
				throw new CertificateException("Could not validated certificate chain");
			}
			
			try {
				Enumeration<String> aliases = ks.aliases();
				while (aliases.hasMoreElements()) {
					String alias = aliases.nextElement();
					java.security.cert.Certificate cert = ks.getCertificate(alias);
					
					if (cert instanceof X509Certificate) {
						X509Certificate ca = (X509Certificate) cert;
						if (ca.getSubjectX500Principal().equals(last.getIssuerX500Principal())) {
							try {
								last.verify(ca.getPublicKey());
								trusted = true;
								
								
								
								
								
								break;
							} catch (Throwable t) {
								t.printStackTrace();
								if (logger.isDebugEnabled()) {
									logger.debug("Could not verify " + last.getSubjectX500Principal() + " using alias " + alias);
								}
							}
						}
					}
				}
			} catch (KeyStoreException e) {
				throw new CertificateException("Could not validated certificate chain",e);
			}
			
			
			if (! trusted) {
				throw new CertificateException("Could not validated certificate chain");
			}
		}
		
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		this.checkClientTrusted(chain, authType);
		
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return this.issuers;
	}

}
