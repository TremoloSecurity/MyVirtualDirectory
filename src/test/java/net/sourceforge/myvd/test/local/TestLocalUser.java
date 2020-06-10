package net.sourceforge.myvd.test.local;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import net.sourceforge.myvd.test.util.StartMyVD;

public class TestLocalUser {
	
	private static StartMyVD myvd;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		myvd = new StartMyVD();
		myvd.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/test-local-user.props",50983);
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		myvd.stopServer();
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testSearchBase() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPSearchResults res = con.search("uid=localuser,ou=localuser,dc=domain,dc=com", 0, "(objectClass=*)", new String[] {}, false);
		
		assertTrue(res.hasMore());
		LDAPEntry entry = res.next();
		assertNotNull(entry);
		
		assertEquals(entry.getDN(),"uid=localuser,ou=localuser,dc=domain,dc=com");
		assertEquals(entry.getAttribute("uid").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("cn").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("sn").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("objectClass").getStringValue(),"inetOrgPerson");
		
		con.disconnect();
	}
	
	@Test
	public void testSearchSubtree() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPSearchResults res = con.search("ou=localuser,dc=domain,dc=com", 2, "(uid=localuser)", new String[] {}, false);
		
		assertTrue(res.hasMore());
		LDAPEntry entry = res.next();
		assertNotNull(entry);
		
		assertEquals(entry.getDN(),"uid=localuser,ou=localuser,dc=domain,dc=com");
		assertEquals(entry.getAttribute("uid").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("cn").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("sn").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("objectClass").getStringValue(),"inetOrgPerson");
		
		con.disconnect();
	}
	
	@Test
	public void testSearchOneLevel() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPSearchResults res = con.search("ou=localuser,dc=domain,dc=com", 1, "(uid=localuser)", new String[] {}, false);
		
		assertTrue(res.hasMore());
		LDAPEntry entry = res.next();
		assertNotNull(entry);
		
		assertEquals(entry.getDN(),"uid=localuser,ou=localuser,dc=domain,dc=com");
		assertEquals(entry.getAttribute("uid").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("cn").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("sn").getStringValue(),"localuser");
		assertEquals(entry.getAttribute("objectClass").getStringValue(),"inetOrgPerson");
		
		con.disconnect();
	}
	
	@Test
	public void testBindSuccess() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		
		
		con.bind(3,"uid=localuser,ou=localuser,dc=domain,dc=com", "start123".getBytes("UTF-8"));
		
		
		
		
		con.disconnect();
	}
	
	@Test
	public void testBindFail() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		
		try {
			con.bind(3,"uid=localuser,ou=localuser,dc=domain,dc=com", "sdfsdf".getBytes("UTF-8"));
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),49);
		}
		
		
		
		
		
		con.disconnect();
	}

}
