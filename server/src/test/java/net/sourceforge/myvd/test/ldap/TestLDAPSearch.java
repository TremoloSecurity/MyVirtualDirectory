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

public class TestLDAPSearch extends TestCase {

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
		this.server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/basicvd.props",50983);
	}

	public void tearDown() throws Exception {
		super.tearDown();
		super.tearDown();
		this.baseServer.stopServer();
		this.internalServer.stopServer();
		this.externalServer.stopServer();
		this.server.stopServer();
	}
	
public void testPresence() throws LDAPException {
		
		
		
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","customPerson"));
		//attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn","Test User"));
		attribs.add(new LDAPAttribute("sn","User"));
		//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid","testUser"));
		attribs.add(new LDAPAttribute("sumNum","5"));
		attribs.add(new LDAPAttribute("userPassword","secret"));
		//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test Cust"));
		attribs.add(new LDAPAttribute("sn","Cust"));
		//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid","testCust"));
		attribs.add(new LDAPAttribute("userPassword","secret"));
		//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry1 = new LDAPEntry("cn=Test Cust,ou=external,o=mycompany,c=us",attribs);
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(objectClass=inetOrgPerson)",new String[0],false);
		
		
		
		
		
		
		
		/*if (results.size() != 3) {
			fail("incorrect number of result sets : " + results.size());
			return;
		}*/
		
		
		
		int size = 0;
		
			while (res.hasMore()) {
				LDAPEntry fromDir = res.next();
				LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
				
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
				
				if (! Util.compareEntry(fromDir,controlEntry)) {
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

public void testEquals() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
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

public void testGreaterThen() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(sumNum>=3)",new String[0],false);
	
	
	
	
	
	
	
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

public void testLessThen() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(sumNum<=8)",new String[0],false);
	
	
	
	
	
	
	
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

public void testSubStrInitial() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(cn=Test U*)",new String[0],false);
	
	
	
	
	
	
	
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

public void testSubStrFinal() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(cn=* User)",new String[0],false);
	
	
	
	
	
	
	
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

public void testSubStrAny() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(cn=Test*User)",new String[0],false);
	
	
	
	
	
	
	
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

public void testAnd() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(&(cn=Test User)(sn=User))",new String[0],false);
	
	
	
	
	
	
	
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

public void testOr() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(|(cn=Test User)(sn=User))",new String[0],false);
	
	
	
	
	
	
	
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

public void testNot() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(&(!(objectClass=organizationalUnit))(!(cn=Test Cust))(!(objectClass=domain)))",new String[0],false);
	
	
	
	
	
	
	
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

public void testAndNotOr() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","customPerson"));
	attribs.add(new LDAPAttribute("cn","Test User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","testUser"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	attribs.add(new LDAPAttribute("sumNum","5"));
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(&(!(cn=Test Cust))(!(|(objectClass=organizationalUnit)(objectClass=domain))))",new String[0],false);
	
	
	
	
	
	
	
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
