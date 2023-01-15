package net.sourceforge.myvd.test.ldap;

import org.junit.Assert;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class TestTimeout  {

	
	private static StartOpenLDAP baseServer;
	private static Server server;
	private static InsertChain globalChain;
	private static Router router;
	
	@Before
	public  void setUp() throws Exception {
		OpenLDAPUtils.killAllOpenLDAPS();
		baseServer = new StartOpenLDAP();
		baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",10983,"cn=admin,dc=domain,dc=com","manager");
		
		
		
		server = new Server(System.getenv("PROJ_DIR") + "/test/TestServer/testtimeout.props");
		server.startServer();
		
		globalChain = server.getGlobalChain();
		router = server.getRouter();
		
		
 	}
	
	@After
	public  void tearDown() throws Exception {
		
		server.stopServer();
		baseServer.stopServer();

	}
	
	@Test
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
	
	@Test
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
			
			System.out.println(done-now);
			
			if ((done - now) > 5100 ) {
				Assert.fail("Took too much time:" + (done-now));
			}
		} finally {
			con.disconnect();
		}
		
		
	}
}
