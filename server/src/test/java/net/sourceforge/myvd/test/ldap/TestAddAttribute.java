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

import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import junit.framework.TestCase;

public class TestAddAttribute extends TestCase {

	private StartOpenLDAP baseServer;
	private StartOpenLDAP internalServer;
	private StartOpenLDAP externalServer;
	private StartMyVD server;
	
	public void setUp() throws Exception {
		super.setUp();
		this.baseServer = new StartOpenLDAP();
		this.baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",10983,"cn=admin,dc=domain,dc=com","manager");
		
		this.internalServer = new StartOpenLDAP();
		this.internalServer.startServer(System.getenv("PROJ_DIR") + "/test/InternalUsersCustom",11983,"cn=admin,ou=internal,dc=domain,dc=com","manager");
		
		this.externalServer = new StartOpenLDAP();
		this.externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsers",12983,"cn=admin,ou=external,dc=domain,dc=com","manager");
		
		this.server = new StartMyVD();
		this.server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/addattribute.props",50983);
	}

	public void tearDown() throws Exception {
		super.tearDown();
		super.tearDown();
		this.baseServer.stopServer();
		this.internalServer.stopServer();
		this.externalServer.stopServer();
		this.server.stopServer();
	}
	


public void testUserSearchNoAttrs() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("o","myorg"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(cn=Test User)",new String[0],false);
	
	
	
	
	
	
	
	/*if (results.size() != 3) {
		fail("incorrect number of result sets : " + results.size());
		return;
	}*/
	
	
	
	int size = 0;
	
		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
			
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
			
			if (! Util.compareEntry(fromDir,controlEntry)) {
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

public void testUserSearchWithAttrs() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("o","myorg"));
	
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(cn=Test User)",new String[] {"uid","o"},false);
	
	
	
	
	
	
	
	/*if (results.size() != 3) {
		fail("incorrect number of result sets : " + results.size());
		return;
	}*/
	
	
	
	int size = 0;
	
		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
			
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
			
			if (! Util.compareEntry(fromDir,controlEntry)) {
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

public void testNoAttr() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	
	attribs.add(new LDAPAttribute("ou","internal"));
	attribs.add(new LDAPAttribute("objectClass","organizationalUnit"));
	
	
	LDAPEntry entry2 = new LDAPEntry("ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us",0,"(objectClass=*)",new String[0],false);
	
	
	
	
	
	
	
	/*if (results.size() != 3) {
		fail("incorrect number of result sets : " + results.size());
		return;
	}*/
	
	
	
	int size = 0;
	
		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
			
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
			
			if (! Util.compareEntry(fromDir,controlEntry)) {
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


}
