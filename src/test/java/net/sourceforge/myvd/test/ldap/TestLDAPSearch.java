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
package net.sourceforge.myvd.test.ldap;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class TestLDAPSearch  {

	private static StartOpenLDAP baseServer;
	private static  StartOpenLDAP internalServer;
	private static  StartOpenLDAP externalServer;
	private static  StartMyVD server;
	private static  StartOpenLDAP adServer;

	
	@BeforeClass
	public static void setUp() throws Exception {
		OpenLDAPUtils.killAllOpenLDAPS();
		baseServer = new StartOpenLDAP();
		baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",
				10983, "cn=admin,dc=domain,dc=com", "manager");

		internalServer = new StartOpenLDAP();
		internalServer.startServer(System.getenv("PROJ_DIR")
				+ "/test/InternalUsersCustom", 11983,
				"cn=admin,ou=internal,dc=domain,dc=com", "manager");

		externalServer = new StartOpenLDAP();
		externalServer.startServer(System.getenv("PROJ_DIR")
				+ "/test/ExternalUsers", 12983,
				"cn=admin,ou=external,dc=domain,dc=com", "manager");

		adServer = new StartOpenLDAP();
		adServer.startServer(System.getenv("PROJ_DIR") + "/test/TestAD",
				13983, "cn=admin,dc=test,dc=mydomain,dc=com", "manager");

		server = new StartMyVD();
		server.startServer(System.getenv("PROJ_DIR")
				+ "/test/TestServer/basicvd.props", 50983);
	}

	@AfterClass
	public static void tearDown() throws Exception {

		baseServer.stopServer();
		internalServer.stopServer();
		externalServer.stopServer();
		server.stopServer();
		adServer.stopServer();
	}

	@Test
	public void testPresence() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn", "Test Cust"));
		attribs.add(new LDAPAttribute("sn", "Cust"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testCust"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry1 = new LDAPEntry(
				"cn=Test Cust,ou=external,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(objectClass=inetOrgPerson)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry1;
			} else if (size == 1) {
				controlEntry = entry2;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 2) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testSearchWithSlashInFilter() throws LDAPException {

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(cn=Test\\\\User)", new String[0], false);

		assertFalse(res.hasMore());

		

		con.disconnect();

	}
	
	@Test
	public void testEquals() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(cn=Test User)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testDoubleQuotesRDNs() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=\"mycompany\",c=\"us\"", 2,
				"(cn=Test User)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testDoubleQuotesCommass() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "User, Test3"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "tuser003"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=User\\, Test3,cn=users,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search(
				"cn=\"User, Test3\",cn=\"users\",dc=\"ad\",dc=\"com\"", 0,
				"(objectClass=*)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testRDNCommass() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "User, Test3"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "tuser003"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=User\\, Test3,cn=users,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search(
				"cn=User\\, Test3,cn=users,dc=ad,dc=com", 0, "(objectClass=*)",
				new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString()
						+ " / " + controlEntry);
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testGreaterThen() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(sumNum>=3)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testLessThen() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(sumNum<=8)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testSubStrInitial() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(cn=Test U*)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testSubStrFinal() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(cn=* User)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();
	}

	@Test
	public void testSubStrAny() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(cn=Test*User)", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testAnd() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(&(cn=Test User)(sn=User))", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testOr() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2,
				"(|(cn=Test User)(sn=User))", new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testNot() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con
				.search("o=mycompany,c=us",
						2,
						"(&(!(objectClass=organizationalUnit))(!(cn=Test Cust))(!(objectClass=domain))(!(cn=Test Group)))",
						new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testAndNotOr() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "customPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		attribs.add(new LDAPAttribute("sumNum", "5"));
		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Test User,ou=internal,o=mycompany,c=us", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con
				.search("o=mycompany,c=us",
						2,
						"(&(!(cn=Test Group))(!(cn=Test Cust))(!(|(objectClass=organizationalUnit)(objectClass=domain))))",
						new String[0], false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else if (size == 1) {
				controlEntry = null;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testGroupMemberComma() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();

		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "With Comma"));

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("cn=With Comma,cn=users,dc=ad,dc=com",
				attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=\"users\",dc=\"ad\",dc=\"com\"",
				2, "(uniqueMember=cn=User\\\\, Test3,cn=users,dc=ad,dc=com)",
				new String[] { "cn" }, false);

		/*
		 * if (results.size() != 3) { fail("incorrect number of result sets : "
		 * + results.size()); return; }
		 */

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testGroupMemberCommaQuotes() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();

		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "With Comma"));

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("cn=With Comma,cn=users,dc=ad,dc=com",
				attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con
				.search("cn=\"users\",dc=\"ad\",dc=\"com\"",
						2,
						"(uniqueMember=cn=\"User, Test3\",cn=\"users\",dc=\"ad\",dc=\"com\")",
						new String[] { "cn" }, false);

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString());
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testGroupMemberParnethasis() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();

		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Parenthasis (are) in my (cn)"));

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry(
				"cn=Parenthasis (are) in my (cn),cn=users,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con
				.search("cn=\"users\",dc=\"ad\",dc=\"com\"",
						2,
						"(uniqueMember=cn=\\(I\\) dont \\(understand\\) why,cn=users,dc=ad,dc=com)",
						new String[] { "cn" }, false);

		int size = 0;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;// control.get(fromDir.getEntry().getDN());

			if (size == 0) {
				controlEntry = entry2;
			} else {
				controlEntry = null;
			}

			if (controlEntry == null) {
				fail("Entry " + fromDir.getDN() + " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir, controlEntry)) {
				fail("The entry was not correct : " + fromDir.toString() + " / " + controlEntry);
				return;
			}

			size++;
		}

		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

}
