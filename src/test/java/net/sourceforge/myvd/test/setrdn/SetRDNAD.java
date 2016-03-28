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

import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import junit.framework.TestCase;

public class SetRDNAD extends TestCase {

	
	private StartOpenLDAP externalServer;
	private StartMyVD server;
	private StartOpenLDAP adServer;

	public void setUp() throws Exception {
		super.setUp();
		this.externalServer = new StartOpenLDAP();
		this.externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsers",12983,"cn=admin,ou=external,dc=domain,dc=com","manager");
		
		this.adServer = new StartOpenLDAP();
		this.adServer.startServer(System.getenv("PROJ_DIR") + "/test/TestAD",13983,"cn=admin,dc=test,dc=mydomain,dc=com","manager");
		
		this.server = new StartMyVD();
		this.server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/setrdn.props",50983);
	}
	
	public void testStartup() {
		//do nothing
	}
	
	
public void testUidSearch() throws LDAPException {
		
		
		
		
		
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","Test1 User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","tuser001"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("uid=tuser001,cn=users,dc=ad,dc=com",attribs);
		
		
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("dc=ad,dc=com",2,"(uid=tuser001)",new String[0],false);
		
		
		
		
		
		
		
		
		
		
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

public void testOCSearch() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","Test1 User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","tuser001"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("uid=tuser001,cn=users,dc=ad,dc=com",attribs);
		
		
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=users,dc=ad,dc=com",1,"(objectClass=*)",new String[] {"objectClass","hasSubordinates"},false);
		
		
		
		
		
		
		
		
		
		
		int size = 0;
		
			while (res.hasMore()) {
				LDAPEntry fromDir = res.next();
				
				
				size++;
			}
		
		
		if (size != 8) {
			fail("Not the correct number of entries : " + size);
		}
			
		con.disconnect();
		
	}

public void testUidSearchOnlyUID() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","Test1 User"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","tuser001"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("uid=tuser001,cn=users,dc=ad,dc=com",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("dc=ad,dc=com",2,"(uid=tuser001)",new String[] {"uid"},false);
	
	
	
	
	
	
	
	
	
	
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

public void testUidSearchOnlyUIDWithComma() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","User, Test3"));
	attribs.add(new LDAPAttribute("sn","User"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
	attribs.add(new LDAPAttribute("uid","tuser003"));
	attribs.add(new LDAPAttribute("userPassword","secret"));
	
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("uid=tuser003,cn=users,dc=ad,dc=com",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("dc=ad,dc=com",2,"(uid=tuser003)",new String[] {"uid"},false);
	
	
	
	
	
	
	
	
	
	
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
	
	public void testEntry() throws LDAPException {
		
		
		
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		//attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn","Test1 User"));
		attribs.add(new LDAPAttribute("sn","User"));
		//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid","tuser001"));
		attribs.add(new LDAPAttribute("userPassword","secret"));
		
		//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("uid=tuser001,cn=users,dc=ad,dc=com",attribs);
		
		
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("dc=ad,dc=com",2,"(cn=Test1 User)",new String[0],false);
		
		
		
		
		
		
		
		
		
		
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
	
	public void testAnonBind() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3, "anonymous", new byte[0]);
	}
	
public void testBaseSearch() throws LDAPException {
		
		
		
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		//attribs.getAttribute("objectClass").addValue("customPerson");
		attribs.add(new LDAPAttribute("cn","User, Test3"));
		attribs.add(new LDAPAttribute("sn","User"));
		//attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid","tuser003"));
		attribs.add(new LDAPAttribute("userPassword","secret"));
		
		//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("cn=Users\\ Test3,cn=users,dc=ad,dc=com",attribs);
		
		
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("cn=Users\\ Test3,cn=users,dc=ad,dc=com",0,"(objectClass=*)",new String[0],false);
		
		
		
		
		
		
		
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
	
public void testGroupMemberBase() throws LDAPException {
	
	
	
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","groupOfUniqueNames"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","UNIX SUDO Users"));
	attribs.add(new LDAPAttribute("uniqueMember","uid=tuser001,cn=users,dc=ad,dc=com"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));

	
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=UNIX SUDO Users,cn=users,dc=ad,dc=com",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("cn=UNIX SUDO Users,cn=users,dc=ad,dc=com",0,"(objectClass=*)",new String[0],false);
	
	
	
	
	
	
	
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

public void testGroupMemberFilter() throws LDAPException {
	
	
	LDAPAttributeSet attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","groupOfUniqueNames"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","UNIX Users"));
	LDAPAttribute attr = new LDAPAttribute("uniqueMember","uid=tuser001,cn=users,dc=ad,dc=com");
	attr.addValue("uid=tuser002,cn=users,dc=ad,dc=com");
	
	attribs.add(attr);
	
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));

	
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry3 = new LDAPEntry("cn=UNIX Users,cn=users,dc=ad,dc=com",attribs);
	
	
	attribs = new LDAPAttributeSet();
	attribs.add(new LDAPAttribute("objectClass","groupOfUniqueNames"));
	//attribs.getAttribute("objectClass").addValue("customPerson");
	attribs.add(new LDAPAttribute("cn","UNIX SUDO Users"));
	attribs.add(new LDAPAttribute("uniqueMember","uid=tuser001,cn=users,dc=ad,dc=com"));
	//attribs.add(new LDAPAttribute("testAttrib", "testVal"));

	
	//attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
	LDAPEntry entry2 = new LDAPEntry("cn=UNIX SUDO Users,cn=users,dc=ad,dc=com",attribs);
	
	
	
	
	LDAPConnection con = new LDAPConnection();
	con.connect("localhost",50983);
	//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
	LDAPSearchResults res = con.search("dc=ad,dc=com",2,"(uniqueMember=uid=tuser001,cn=users,dc=ad,dc=com)",new String[0],false);
	
	
	
	
	
	
	
	/*if (results.size() != 3) {
		fail("incorrect number of result sets : " + results.size());
		return;
	}*/
	
	
	
	int size = 0;
	
		while (res.hasMore()) {
			LDAPEntry fromDir = res.next();
			LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
			
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
			
			if (! Util.compareEntry(fromDir,controlEntry)) {
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

	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
		this.externalServer.stopServer();
		this.adServer.stopServer();
	}
}
