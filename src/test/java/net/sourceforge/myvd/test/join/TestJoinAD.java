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
package net.sourceforge.myvd.test.join;

import java.io.FileInputStream;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.LDIFReader;

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

public class TestJoinAD  {

	private static StartOpenLDAP ad;
	private static StartOpenLDAP unix;
	private static StartMyVD myvd;
	
	@BeforeClass
	public static void setUp() throws Exception {
		OpenLDAPUtils.killAllOpenLDAPS();
		ad = new StartOpenLDAP();
		ad.startServer(
				System.getenv("PROJ_DIR") + "/test/TestAD", 10983,
				"cn=admin,dc=test,dc=mydomain,dc=com", "manager");
		
		unix = new StartOpenLDAP();
		unix.startServer(
				System.getenv("PROJ_DIR") + "/test/TestADPosix", 11983,
				"cn=admin,o=unix", "manager");
		
		myvd = new StartMyVD();
		myvd.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/ad-posix.conf",50983);
	}
	
	@Test
	public void testStartup() {
		//System.out.println("");
	}
	
	@Test
	public void testSearchUser() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("dc=domain,dc=com", 2, "(&(objectClass=posixAccount)(uid=tuser001))", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestADPosix/userSearch.ldif"));
		Util util = new Util();
		
		boolean found = false;
		
		while (res.hasMore()) {
			found = true;
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match\n from server: \n" + util.toLDIF(fromserver) + "\nfromldif:\n" + util.toLDIF(fromldif));
			}
			
		}
		
		con.disconnect();
		
		if (! found) {
			fail("no entries returned");
		}
	}
	
	@Test
	public void testSearchUserByUIDNumber() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("dc=domain,dc=com", 2, "(&(objectClass=posixAccount)(uidNumber=550))", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestADPosix/userSearch.ldif"));
		Util util = new Util();
		
		boolean found = false;
		
		while (res.hasMore()) {
			found = true;
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match\n from server: \n" + util.toLDIF(fromserver) + "\nfromldif:\n" + util.toLDIF(fromldif));
			}
			
		}
		
		con.disconnect();
		
		if (! found) {
			fail("no entries returned");
		}
	}
	
	@Test
	public void testSearchShadowUser() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("dc=domain,dc=com", 2, "(&(objectClass=shadowAccount)(uid=tuser001))", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestADPosix/userSearch.ldif"));
		Util util = new Util();
		
		boolean found = false;
		
		while (res.hasMore()) {
			found = true;
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match\n from server: \n" + util.toLDIF(fromserver) + "\nfromldif:\n" + util.toLDIF(fromldif));
			}
			
		}
		
		con.disconnect();
		
		if (! found) {
			fail("no entries returned");
		}
	}
	
	@Test
	public void testSearchLinuxGroup() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("dc=domain,dc=com", 2, "(&(objectClass=posixGroup)(|(memberUid=tuser001)(uniqueMember=cn=Test1 User,CN=Users,dc=domain,dc=com)))", new String[] {"gidNumber"}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestADPosix/groupLinuxSearch.ldif"));
		Util util = new Util();
		
		boolean found = false;
		
		while (res.hasMore()) {
			found = true;
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match\n from server: \n" + util.toLDIF(fromserver) + "\nfromldif:\n" + util.toLDIF(fromldif));
			}
			
		}
		
		con.disconnect();
		
		if (! found) {
			fail("no entries returned");
		}
	}
	
	@Test
	public void testBindUser() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("dc=domain,dc=com", 2, "(&(objectClass=posixAccount)(uid=tuser001))", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestADPosix/userSearch.ldif"));
		Util util = new Util();
		String DN = "";
		boolean found = false;
		
		while (res.hasMore()) {
			found = true;
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match\n from server: \n" + util.toLDIF(fromserver) + "\nfromldif:\n" + util.toLDIF(fromldif));
			}
			
			DN = fromserver.getDN();
			
		}
		
		try {
			con.bind(3,DN, "secret".getBytes());
		} catch (LDAPException e) {
			fail("failed to bind: " + e.toString());
		}
		
		try {
			con.bind(3,DN, "posixsecret".getBytes());
		} catch (LDAPException e) {
			fail("failed to bind: " + e.toString());
		}
		
		try {
			con.bind(3,DN, "posixsecretx".getBytes());
			fail("bind succeeded");
		} catch (LDAPException e) {
			assertEquals(e.getResultCode(),49);
		}
		
		con.disconnect();
		
		if (! found) {
			fail("no entries returned");
		}
	}

	@AfterClass
	public static void tearDown() throws Exception {
		
		myvd.stopServer();
		ad.stopServer();
		unix.stopServer();
	}

}
