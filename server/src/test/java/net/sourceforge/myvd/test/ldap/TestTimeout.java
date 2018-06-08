package net.sourceforge.myvd.test.ldap;

import org.junit.Assert;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import junit.framework.TestCase;

public class TestTimeout extends TestCase {

	
	private StartOpenLDAP baseServer;
	private Server server;
	private InsertChain globalChain;
	private Router router;
	
	protected void setUp() throws Exception {
		super.setUp();
		this.baseServer = new StartOpenLDAP();
		this.baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",10983,"cn=admin,dc=domain,dc=com","manager");
		
		
		
		server = new Server(System.getenv("PROJ_DIR") + "/test/TestServer/testtimeout.props");
		server.startServer();
		
		this.globalChain = server.getGlobalChain();
		this.router = server.getRouter();
		
		
 	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
		this.baseServer.stopServer();

	}
	
	public void testSearchTimeout() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		
		long now = System.currentTimeMillis();
		try {
			LDAPSearchResults res = con.search("dc=toolong,dc=com",2, "(objectClass=*)", new String[]{}, false);
			if (res.hasMore()) {
				res.next();
			}
			
			Assert.fail("Entry returned");
			
		} catch (LDAPException e) {
			long done = System.currentTimeMillis();
			if ((done - now) < 4000) {
				Assert.fail("Took too litle time");
			}
			
			if ((done - now) > 5000 ) {
				Assert.fail("Took too much time");
			}
		} finally {
			con.disconnect();
		}
		
		
	}
	
	public void testBindTimeout() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		
		long now = System.currentTimeMillis();
		try {
			con.bind(3, "cn=dne,dc=toolong,dc=com","doesntmatter".getBytes("UTF-8"));
			
		} catch (LDAPException e) {
			long done = System.currentTimeMillis();
			
			if ((done - now) < 4000 ) {
				Assert.fail("Took too litle time");
			}
			
			if ((done - now) > 5000 ) {
				Assert.fail("Took too much time");
			}
		} finally {
			con.disconnect();
		}
		
		
	}
}
