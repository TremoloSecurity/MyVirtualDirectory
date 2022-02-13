/*
 * Copyright 2008 Marc Boorshtein 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package net.sourceforge.myvd.test.Server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.inserts.extensions.PasswordChangeOperation;
import net.sourceforge.myvd.inserts.ldap.LDAPInterceptor;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.chain.TestChain;
import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Result;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.types.SessionVariables;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.novell.ldap.asn1.ASN1Identifier;
import com.novell.ldap.asn1.ASN1OctetString;
import com.novell.ldap.asn1.ASN1Sequence;
import com.novell.ldap.asn1.ASN1Tagged;
import com.novell.ldap.asn1.LBEREncoder;
import com.novell.ldap.util.DN;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class TestStartServerSearchCompare {

	// Insert[] globalChain;
	// Router router;
	private static StartOpenLDAP baseServer;
	private static StartOpenLDAP internalServer;
	private static StartOpenLDAP externalServer;
	private static StartMyVD server;
	// private Server server;

	@BeforeClass
	public static void setUp() throws Exception {
		OpenLDAPUtils.killAllOpenLDAPS();
		baseServer = new StartOpenLDAP();
		baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base", 10983, "cn=admin,dc=domain,dc=com", "manager");

		internalServer = new StartOpenLDAP();
		internalServer.startServer(System.getenv("PROJ_DIR") + "/test/InternalUsers", 11983,
				"cn=admin,ou=internal,dc=domain,dc=com", "manager");

		externalServer = new StartOpenLDAP();
		externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsers", 12983,
				"cn=admin,ou=external,dc=domain,dc=com", "manager");

		server = new StartMyVD();
		server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/testconfig-searchcompare.props", 50983);

		// server = new Server(System.getenv("PROJ_DIR") +
		// "/test/TestServer/testconfig.props");
		// server.startServer();

		// globalChain = server.getGlobalChain();
		// router = server.getRouter();

		System.setProperty("javax.net.ssl.trustStore", System.getenv("PROJ_DIR") + "/test/TestServer/testconfig.jks");

	}

	@After
	public void after() throws Exception {
		baseServer.reloadAllData();
		internalServer.reloadAllData();
		externalServer.reloadAllData();
	}

	@Test
	public void testStartServer() throws Exception {

		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		// con.bind(3,"ou=internal,o=mycompany","secret".getBytes());

		LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
		while (res.hasMore()) {
			System.out.println(res.next().getDN());
		}

		con.disconnect();

	}
	
	
	@Test
	public void testNoSuchObject() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		
		// first do searches to make sure the objects exist
		try {
			LDAPSearchResults res = con.search("cn=Test Userx,ou=internal,o=mycompany,c=us", 0, "(uid=testUser)", new String[0], false);
			res.hasMore();
			res.next();
			fail("Search succeeded");
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),32);
		}
		
		
		try {
			LDAPSearchResults res = con.search("cn=Test Userx,ou=external,o=mycompany,c=us", 0, "(uid=testUser)", new String[0], false);
			res.hasMore();
			res.next();
			fail("Search succeeded");
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),32);
		}
		
		
		try {
			LDAPSearchResults res = con.search("cn=Test Userx,o=mycompany,c=us", 0, "(uid=testUser)", new String[0], false);
			res.hasMore();
			res.next();
			fail("Search succeeded");
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),32);
		}
		
		
		LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us", 2, "(uid=testUser)", new String[0], false);
		assertTrue(res.hasMore());
		LDAPEntry entry = res.next();
		assertNotNull(entry);
		assertEquals("cn=Test User,ou=internal,o=mycompany,c=us",entry.getDN());
	
		res = con.search("ou=internal,o=mycompany,c=us", 2, "(uid=testUserx)", new String[0], false);
		assertTrue(! res.hasMore());
		
		
		res = con.search("ou=external,o=mycompany,c=us", 2, "(uid=testCust)", new String[0], false);
		assertTrue(res.hasMore());
		entry = res.next();
		assertNotNull(entry);
		assertEquals("cn=Test Cust,ou=external,o=mycompany,c=us",entry.getDN());
	
		res = con.search("ou=external,o=mycompany,c=us", 2, "(uid=testUserx)", new String[0], false);
		assertTrue(! res.hasMore());
		
		
		
		
		
	}
	
	@Test
	public void testCopyAttribute() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		
		// first do searches to make sure the objects exist
		LDAPSearchResults res = con.search("cn=Test User,ou=internal,o=mycompany,c=us", 0, "(uid=testUser)", new String[0], false);
		assertTrue(res.hasMore());
		LDAPEntry entry = res.next();
		assertNotNull(entry);
		assertEquals("cn=Test User,ou=internal,o=mycompany,c=us",entry.getDN());
		assertNotNull(entry.getAttribute("sub"));
		assertEquals(entry.getAttribute("sub").getStringValue(),"testUser");
	}
	
	
	@Test
	public void testCompare() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		
		// first do searches to make sure the objects exist
		LDAPSearchResults res = con.search("cn=Test User,ou=internal,o=mycompany,c=us", 0, "(uid=testUser)", new String[0], false);
		assertTrue(res.hasMore());
		LDAPEntry entry = res.next();
		assertNotNull(entry);
		assertEquals("cn=Test User,ou=internal,o=mycompany,c=us",entry.getDN());
		
		
		res = con.search("cn=Test User,ou=internal,o=mycompany,c=us", 0, "(uid=testUserx)", new String[0], false);
		assertTrue(! res.hasMore());
		
		res = con.search("cn=Test Cust,ou=external,o=mycompany,c=us", 0, "(uid=testCust)", new String[0], false);
		assertTrue(res.hasMore());
		entry = res.next();
		assertNotNull(entry);
		assertEquals("cn=Test Cust,ou=external,o=mycompany,c=us",entry.getDN());
		
		
		res = con.search("cn=Test Cust,ou=external,o=mycompany,c=us", 0, "(uid=testUserx)", new String[0], false);
		assertTrue(! res.hasMore());
		
		
		// run compares
		assertTrue(con.compare("cn=Test User,ou=internal,o=mycompany,c=us", new LDAPAttribute("uid","testUser")));
		assertFalse(con.compare("cn=Test User,ou=internal,o=mycompany,c=us", new LDAPAttribute("uid","testUserx")));
		
		assertTrue(con.compare("cn=Test Cust,ou=external,o=mycompany,c=us", new LDAPAttribute("uid","testCust")));
		assertFalse(con.compare("cn=Test Cust,ou=external,o=mycompany,c=us", new LDAPAttribute("uid","testUserx")));
		
		
		
		
	}
	
	@Test
	public void testBind() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		
		
		con.bind(3, "cn=Test Cust,ou=external,o=mycompany,c=us", "secret".getBytes("UTF-8"));
		
		con.bind(3, "cn=Test User,ou=internal,o=mycompany,c=us", "secret".getBytes("UTF-8"));
		
		
		try {
			con.bind(3, "cn=Test Cust,ou=external,o=mycompany,c=us", "cstart123".getBytes("UTF-8"));
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),49);
		}
		
		try {
			con.bind(3, "cn=Test User,ou=internal,o=mycompany,c=us", "xstart123".getBytes("UTF-8"));
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),49);
		}
		
		
		try {
			con.bind(3, "cn=xTest Cust,ou=external,o=mycompany,c=us", "cstart123".getBytes("UTF-8"));
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),49);
		}
		
		try {
			con.bind(3, "cn=xTest User,ou=internal,o=mycompany,c=us", "xstart123".getBytes("UTF-8"));
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),49);
		}
	}

	

	@AfterClass
	public static void tearDown() throws Exception {

		baseServer.stopServer();
		internalServer.stopServer();
		externalServer.stopServer();
		server.stopServer();
		// server.stopServer();
	}

}
