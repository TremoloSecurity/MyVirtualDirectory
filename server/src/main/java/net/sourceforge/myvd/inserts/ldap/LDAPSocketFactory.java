package net.sourceforge.myvd.inserts.ldap;

import javax.net.ssl.SSLSocketFactory;

public interface LDAPSocketFactory {
	SSLSocketFactory getSSLSocketFactory();
}
