package net.sourceforge.myvd.test.Server;

import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Assert;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSearchResults;

import net.sourceforge.myvd.test.util.StartMyVD;
import junit.framework.TestCase;

public class TestClientAuth extends TestCase {

	private StartMyVD server;

	protected void setUp() throws Exception {
		super.setUp();

		this.server = new StartMyVD();
		this.server.startServer(System.getenv("PROJ_DIR")
				+ "/test/TlsServer/conf/myvd.conf", 10983);

	}

	public void testStartup() {
		// do nothing
		System.out.print("");
	}

	public void testConnectSuccess() throws Exception {
		KeyStore tks = KeyStore.getInstance(KeyStore.getDefaultType());
		tks.load(new FileInputStream(System.getenv("PROJ_DIR")
				+ "/test/TlsServer/conf/server.jks"), "start123".toCharArray());
		TrustManagerFactory tmf = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(tks);

		KeyStore iks = KeyStore.getInstance(KeyStore.getDefaultType());
		iks.load(new FileInputStream(System.getenv("PROJ_DIR")
				+ "/test/TlsServer/conf/client.jks"), "start123".toCharArray());

		KeyManagerFactory kmf = 
				  KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				kmf.init(iks, "start123".toCharArray());
				SSLContext ctx = SSLContext.getInstance("TLS");
				ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
				SocketFactory factory = ctx.getSocketFactory();
		
		LDAPConnection ldap = new LDAPConnection(new LDAPJSSESecureSocketFactory((SSLSocketFactory) factory));
		ldap.connect("127.0.0.1", 10636);
		
		LDAPSearchResults res = ldap.search("", 0, "(objectClass=*)", new String[] {"namingContexts","clientCertSubject"},false);
		res.hasMore();
		LDAPEntry entry = res.next();
		if (! entry.getAttribute("namingContexts").getStringValue().equalsIgnoreCase("o=mycompany,c=us")) {
			Assert.fail("Invalid namingContexts : '" + entry.getAttribute("namingContexts").getStringValue());
		}
		
		if (! entry.getAttribute("clientCertSubject").getStringValue().equalsIgnoreCase("CN=someuser, OU=dev, O=myvd-client, L=arlington, ST=virginia, C=us")) {
			Assert.fail("Invalid clientCertSubject : '" + entry.getAttribute("clientCertSubject").getStringValue());
		}
		
		ldap.disconnect();
	}

	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
	}

}
