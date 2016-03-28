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

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.LDIFReader;

import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import junit.framework.TestCase;

public class TestDynGroup extends TestCase {

	private StartOpenLDAP baseServer;
	private StartMyVD server;

	protected void setUp() throws Exception {
		super.setUp();
		this.baseServer = new StartOpenLDAP();
		this.baseServer.startServer(System.getenv("PROJ_DIR") + "/test/DynGroups",10983,"cn=admin,dc=domain,dc=com","manager");
		
		this.server = new StartMyVD();
		this.server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/dyngroups.conf",50983);
	}

	
	public void testStartup() {
		//do nothing
	}
	
	public void testGetDynGroup() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,dc=domain,dc=com", 2, "(cn=Sales)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch.ldif"));
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
	
	public void testSearchMemberships() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,dc=domain,dc=com", 2, "(&(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser1,ou=people,dc=domain,dc=com))", new String[] {"objectClass"}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/testMemberships.ldif"));
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
	
	public void testGetDynWNoURLsGroup() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,dc=domain,dc=com", 2, "(&(cn=Sales)(objectClass=groupOfUniqueNames))", new String[] {}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch.ldif"));
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
	
	public void testSearchSynGroupSMember() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,dc=domain,dc=com", 2, "(&(cn=Sales)(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser4,ou=people,dc=domain,dc=com))", new String[] {}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch.ldif"));
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
	
	public void testSearchSynGroupDMember() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,dc=domain,dc=com", 2, "(&(cn=Sales)(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser2,ou=people,dc=domain,dc=com))", new String[] {}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch.ldif"));
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
	
	public void testSearchSynGroupDMemberBase() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("cn=Sales,ou=groups,dc=domain,dc=com", 0, "(&(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser4,ou=people,dc=domain,dc=com))", new String[] {}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch.ldif"));
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
	
	public void testFailSearchSynGroupDMemberBase() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("cn=Sales,ou=groups,dc=domain,dc=com", 0, "(&(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser3,ou=people,dc=domain,dc=com))", new String[] {}, false);
		
		
		
		boolean found = false;
		while (res.hasMore()) {
			found = true;
			
			Util util = new Util();
			
			
			LDAPEntry fromserver = res.next();
			
				fail("Entries exist: \n" + util.toLDIF(fromserver));
			
			
		}
		
		con.disconnect();
		
		
	}
	
	public void testGetDynGroup2() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,o=ad", 2, "(cn=Sales)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch2.ldif"));
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
	
	public void testSearchMemberships2() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,o=ad", 2, "(&(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser1,ou=people,o=ad))", new String[] {"objectClass"}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/testMemberships2.ldif"));
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
	
	public void testGetDynWNoURLsGroup2() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,o=ad", 2, "(&(cn=Sales)(objectClass=groupOfUniqueNames))", new String[] {}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch2.ldif"));
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
	
	public void testSearchSynGroupSMember2() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,o=ad", 2, "(&(cn=Sales)(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser4,ou=people,o=ad))", new String[] {}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch2.ldif"));
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
	
	public void testSearchSynGroupDMember2() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("ou=groups,o=ad", 2, "(&(cn=Sales)(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser2,ou=people,o=ad))", new String[] {}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch2.ldif"));
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
	
	public void testSearchSynGroupDMemberBase2() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("cn=Sales,ou=groups,o=ad", 0, "(&(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser4,ou=people,o=ad))", new String[] {}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DynGroups/domainGroupSearch2.ldif"));
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
	
	public void testFailSearchSynGroupDMemberBase2() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("cn=Sales,ou=groups,o=ad", 0, "(&(objectClass=groupOfUniqueNames)(uniqueMember=uid=tuser3,ou=people,o=ad))", new String[] {}, false);
		
		
		
		boolean found = false;
		while (res.hasMore()) {
			found = true;
			
			Util util = new Util();
			
			
			LDAPEntry fromserver = res.next();
			
				fail("Entries exist: \n" + util.toLDIF(fromserver));
			
			
		}
		
		con.disconnect();
		
		
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.baseServer.stopServer();
		this.server.stopServer();
	}

}

