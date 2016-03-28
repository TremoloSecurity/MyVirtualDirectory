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

import java.io.FileInputStream;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPModifyRequest;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.LDIFReader;

import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import junit.framework.TestCase;

public class TestMapDNAttribute extends TestCase {

	private StartOpenLDAP server;
	private StartMyVD myvd;

	protected void setUp() throws Exception {
		super.setUp();
		
		this.server = new StartOpenLDAP();
		this.server.startServer(
				System.getenv("PROJ_DIR") + "/test/InternalUsers", 10983,
				"cn=admin,ou=internal,dc=domain,dc=com", "manager");
		
		this.myvd = new StartMyVD();
		this.myvd.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/testdnmap.conf",50983);
	}
	
	public void testStartup() {
		//do nothing
	}

	public void testBaseSearch() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/InternalUsers/basesearch.ldif"));
		
		
		
		
		LDAPSearchResults res = con.search("cn=Test Group,ou=groups,o=mycompany,c=us", 0, "(objectClass=*)", new String[0], false);
		
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		//con.delete("uid=user4,ou=people,o=mycompany,c=us");
		
		con.disconnect();
	}
	
	public void testFilterSearch() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/InternalUsers/basesearch.ldif"));
		
		
		
		
		LDAPSearchResults res = con.search("ou=groups,o=mycompany,c=us", 2, "(uniqueMember=uid=testuser1,ou=people,o=mycompany,c=us)", new String[0], false);
		
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
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		if (! found) {
			fail("No entry found!");
		}
		
		//con.delete("uid=user4,ou=people,o=mycompany,c=us");
		
		con.disconnect();
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.myvd.stopServer();
		this.server.stopServer();
	}

	public void testAdd() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/InternalUsers/add-src.ldif"));
		LDAPEntry toadd = ((LDAPSearchResult) reader.readMessage()).getEntry();
		
		con.add(toadd);
		
		con.disconnect();
		
		con = new LDAPConnection();
		con.connect("localhost", 10983);
		
		
		LDAPSearchResults res = con.search("cn=Test Group2,ou=groups,dc=domain,dc=com", 0, "(objectClass=*)", new String[0], false);
		reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/InternalUsers/add-result.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		
		
		con.disconnect();
	}
	
	public void testMod() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPModification mod = new LDAPModification(LDAPModification.ADD,new LDAPAttribute("uniqueMember","uid=testuser5,ou=people,o=mycompany,c=us"));
		
		
		con.modify("cn=Test Group,ou=groups,o=mycompany,c=us", mod);
		
		con.disconnect();
		
		con = new LDAPConnection();
		con.connect("localhost", 10983);
		
		
		LDAPSearchResults res = con.search("cn=Test Group,ou=groups,dc=domain,dc=com", 0, "(objectClass=*)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/InternalUsers/mod-result.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		
		
		con.disconnect();
	}
}
