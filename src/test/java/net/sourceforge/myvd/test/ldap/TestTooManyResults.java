package net.sourceforge.myvd.test.ldap;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;

import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;

public class TestTooManyResults {
	
	private static StartOpenLDAP baseServer;
	private static  StartMyVD server;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		OpenLDAPUtils.killAllOpenLDAPS();
		baseServer = new StartOpenLDAP();
		baseServer.startServer(System.getenv("PROJ_DIR") + "/test/TooManyResults",10983, "cn=admin,ou=local,dc=domain,dc=com", "manager");
		
		server = new StartMyVD();
		server.startServer(System.getenv("PROJ_DIR")
				+ "/test/TestServer/toomany.props", 50983);
		
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		baseServer.stopServer();
		server.stopServer();
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
		
	}

	@Test
	public void testSearchMoreThenThousandDirectToOpenLDAP() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 10983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchConstraints sc = new LDAPSearchConstraints();
		sc.setMaxResults(2000);
		LDAPSearchResults res = con.search("ou=local,dc=domain,dc=com", 2,
				"(objectClass=*)", new String[0], false,sc);
		
		int num = 0;
		while (res.hasMore()) {
			res.next();
			num++;
		}
		
		con.clone();
		
		assertEquals(1010,num);
	}
	
	@Test
	public void testSearchMoreThenThousandMyVD() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchConstraints sc = new LDAPSearchConstraints();
		sc.setMaxResults(2000);
		LDAPSearchResults res = con.search("ou=local,dc=domain,dc=com", 2,
				"(objectClass=*)", new String[0], false,sc);
		
		int num = 0;
		while (res.hasMore()) {
			res.next();
			num++;
		}
		
		con.clone();
		
		assertEquals(1010,num);
	}

}
