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

package net.sourceforge.myvd.test.setrdn;

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

public class TestSetRDNMutlValueRDNNoMapping {

	private static StartOpenLDAP externalServer;
	private static StartMyVD server;
	private static StartOpenLDAP adServer;

	@BeforeClass
	public static void setUp() throws Exception {
		OpenLDAPUtils.killAllOpenLDAPS();
		externalServer = new StartOpenLDAP();
		externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsers", 12983,
				"cn=admin,ou=external,dc=domain,dc=com", "manager");

		adServer = new StartOpenLDAP();
		adServer.startServer(System.getenv("PROJ_DIR") + "/test/TestAD2", 13983, "cn=admin,dc=test,dc=mydomain,dc=com",
				"manager");

		server = new StartMyVD();
		server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/setrdnmulti2.props", 50983);
	}

	@Test
	public void testStartup() {
		// do nothing
	}

	@Test
	public void testsamAccountNameSearch() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		attribs.add(new LDAPAttribute("givenName", "Test"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("samAccountName", "testmultiuser"));
		

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("samAccountName=testmultiuser,cn=users2,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=users2,dc=ad,dc=com", 2, "(samAccountName=testmultiuser)", new String[0], false);

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
	public void testsamAccountNameSearchWithAttributes() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		attribs.add(new LDAPAttribute("givenName", "Test"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("samAccountName", "testmultiuser"));
		

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("samAccountName=testmultiuser,cn=users2,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=users2,dc=ad,dc=com", 2, "(&(objectClass=inetOrgPerson)(samAccountName=testmultiuser))", new String[] {"samAccountName","sn"}, false);

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
	public void testOCSearch() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		attribs.add(new LDAPAttribute("givenName", "Test"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("samAccountName", "testmultiuser"));
		

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("samAccountName=testmultiuser,cn=users2,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=users2,dc=ad,dc=com", 1, "(objectClass=*)",
				new String[] { "objectClass", "hasSubordinates" }, false);

		int size = 3;

		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();

			size++;
		}

		if (size != 7) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();

	}

	@Test
	public void testsamAccountNameSearchOnlysamAccountName() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		attribs.add(new LDAPAttribute("givenName", "Test"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("samAccountName", "testmultiuser"));
		

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("samAccountName=testmultiuser,cn=users2,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=users2,dc=ad,dc=com", 2, "(samAccountName=testmultiuser)", new String[] { "samAccountName" }, false);

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
	public void testEntry() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		attribs.add(new LDAPAttribute("givenName", "Test"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("samAccountName", "testmultiuser"));
		

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("samAccountName=testmultiuser,cn=users2,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=users2,dc=ad,dc=com", 2, "(cn=Test User)", new String[0], false);

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
	public void testAnonBind() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		con.bind(3, "anonymous", new byte[0]);
	}

	@Test
	public void testBaseSearch() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		attribs.add(new LDAPAttribute("givenName", "Test"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("samAccountName", "testmultiuser"));
		

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("samAccountName=testmultiuser,cn=users2,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("samAccountName=testmultiuser,cn=users2,dc=ad,dc=com", 0, "(objectClass=*)",
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
	public void testGroupMemberBase() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "groupOfUniqueNames"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "UNIX SUDO Usersx"));
		attribs.add(new LDAPAttribute("uniqueMember", "samAccountName=testmultiuser,cn=users2,dc=ad,dc=com"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("cn=UNIX SUDO Usersx,cn=users2,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=UNIX SUDO Usersx,cn=users2,dc=ad,dc=com", 0, "(objectClass=*)",
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
	public void testGroupMemberFilter() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "groupOfUniqueNames"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "UNIX Usersx"));
		LDAPAttribute attr = new LDAPAttribute("uniqueMember", "samAccountName=testmultiuser,cn=users2,dc=ad,dc=com");
		attr.addValue("samAccountName=testmultiuserx,cn=users2,dc=ad,dc=com");

		attribs.add(attr);

		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry3 = new LDAPEntry("cn=UNIX Usersx,cn=users2,dc=ad,dc=com", attribs);

		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "groupOfUniqueNames"));
		// attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn", "UNIX SUDO Usersx"));
		attribs.add(new LDAPAttribute("uniqueMember", "samAccountName=testmultiuser,cn=users2,dc=ad,dc=com"));
		// attribs.add(new LDAPAttribute("testAttrib", "testVal"));

		// attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("cn=UNIX SUDO Usersx,cn=users2,dc=ad,dc=com", attribs);

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		// con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("dc=ad,dc=com", 2, "(uniqueMember=samAccountName=testmultiuser,cn=users2,dc=ad,dc=com)",
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
				controlEntry = entry3;
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
				fail("The entry was not correct for " + size + " : " + fromDir.toString() + " / " + controlEntry);
				return;
			}

			size++;
		}

		if (size != 2) {
			fail("Not the correct number of entries : " + size);
		}

		con.disconnect();
	}

	@AfterClass
	public static void tearDown() throws Exception {

		server.stopServer();
		externalServer.stopServer();
		adServer.stopServer();
	}
}
