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

import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import junit.framework.TestCase;

public class TestJoinAD extends TestCase {

	private StartOpenLDAP ad;
	private StartOpenLDAP unix;
	private StartMyVD myvd;
	
	protected void setUp() throws Exception {
		super.setUp();
		this.ad = new StartOpenLDAP();
		this.ad.startServer(
				System.getenv("PROJ_DIR") + "/test/TestAD", 10983,
				"cn=admin,dc=test,dc=mydomain,dc=com", "manager");
		
		this.unix = new StartOpenLDAP();
		this.unix.startServer(
				System.getenv("PROJ_DIR") + "/test/TestADPosix", 11983,
				"cn=admin,o=unix", "manager");
		
		this.myvd = new StartMyVD();
		this.myvd.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/ad-posix.conf",50983);
	}
	
	public void testStartup() {
		//System.out.println("");
	}
	
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
		
		con.disconnect();
		
		if (! found) {
			fail("no entries returned");
		}
	}

	protected void tearDown() throws Exception {
		super.tearDown();
		this.myvd.stopServer();
		this.ad.stopServer();
		this.unix.stopServer();
	}

}
