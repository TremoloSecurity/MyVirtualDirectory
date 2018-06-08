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
package net.sourceforge.myvd.test.acl;

import java.util.ArrayList;
import java.util.HashMap;

import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.inserts.accessControl.AccessControlItem;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.SessionVariables;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.DN;

import junit.framework.TestCase;

public class TestACLPlugin extends TestCase {
	private StartOpenLDAP openldapServer;
	private Server server;
	private InsertChain globalChain;
	private Router router;
	
	protected void setUp() throws Exception {
		super.setUp();
		this.openldapServer = new StartOpenLDAP();
		this.openldapServer.startServer(System.getenv("PROJ_DIR") + "/test/ACITest",10983,"cn=admin,dc=domain,dc=com","manager");
		
		server = new Server(System.getenv("PROJ_DIR") + "/test/TestServer/testACLs.props");
		server.startServer();
		
		this.globalChain = server.getGlobalChain();
		this.router = server.getRouter();
 	}
	
	public void testAddAnonFail() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("cn","Test Add"));
		attribs.add(new LDAPAttribute("sn","Add"));
		attribs.add(new LDAPAttribute("uid","tadd"));
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		
		LDAPEntry entry = new LDAPEntry("uid=tadd,ou=users,dc=domain,dc=com",attribs);
		
		try {
			con.add(entry);
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INSUFFICIENT_ACCESS_RIGHTS) {
				throw e;
			} else {
				return;
			}
		}
		
		fail("add succeeded");
		con.disconnect();
	}
	
	public void testAddBoundFail() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"uid=testuser,ou=users,dc=domain,dc=com","secret".getBytes());
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("cn","Test Add"));
		attribs.add(new LDAPAttribute("sn","Add"));
		attribs.add(new LDAPAttribute("uid","tadd"));
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		
		LDAPEntry entry = new LDAPEntry("uid=tadd,ou=users,dc=domain,dc=com",attribs);
		
		try {
			con.add(entry);
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INSUFFICIENT_ACCESS_RIGHTS) {
				throw e;
			} else {
				return;
			}
		}
		
		fail("add succeeded");
		con.disconnect();
	}
	
	public void testAddBoundSucceed() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"cn=admin,dc=domain,dc=com","manager".getBytes());
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("cn","Test Add"));
		attribs.add(new LDAPAttribute("sn","Add"));
		attribs.add(new LDAPAttribute("uid","tadd"));
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		
		LDAPEntry entry = new LDAPEntry("uid=tadd,ou=users,dc=domain,dc=com",attribs);
		
		con.add(entry);
		con.disconnect();
	}
	
	public void testSearchUsersBound() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"uid=testuser,ou=users,dc=domain,dc=com","secret".getBytes());
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		attribs.add(new LDAPAttribute("sn","User1"));
		attribs.add(new LDAPAttribute("uid","testuser1"));
		attribs.add(new LDAPAttribute("l","location1"));
		
		LDAPSearchResults res = con.search("ou=users,dc=domain,dc=com",1,"(uid=testuser1)",new String[0],false);
		if (! res.hasMore()) {
			fail("no results");
		}
		
		LDAPEntry fromServer = res.next();
		LDAPEntry control = new LDAPEntry("uid=testuser1,ou=users,dc=domain,dc=com",attribs);
		
		if (! Util.compareEntry(fromServer,control)) {
			fail("invalid entry : " + fromServer.toString());
		}
		con.disconnect();
	}
	
	public void testSearchRootNotBound() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("namingContexts","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		attribs.add(new LDAPAttribute("sn","User1"));
		attribs.add(new LDAPAttribute("uid","testuser1"));
		attribs.add(new LDAPAttribute("l","location1"));
		
		LDAPSearchResults res = con.search("",0,"(objectClass=*)",new String[] {"1.1"},false);
		if (! res.hasMore()) {
			fail("no results");
		}
		
		LDAPEntry fromServer = res.next();
		/*LDAPEntry control = new LDAPEntry("uid=testuser1,ou=users,dc=domain,dc=com",attribs);
		
		if (! Util.compareEntry(fromServer,control)) {
			fail("invalid entry : " + fromServer.toString());
		}*/
		con.disconnect();
	}
	
	public void testSearchGroupsBound() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"uid=testuser,ou=users,dc=domain,dc=com","secret".getBytes());
		
		
		try {
			LDAPSearchResults res = con.search("ou=groups,dc=domain,dc=com",1,"(objectClass=*)",new String[0],false);
			if (res.hasMore()) {
				fail("has results : " + res.next());
			}
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INSUFFICIENT_ACCESS_RIGHTS) {
				throw e;
			} else {
				return;
			}
		}
		
		fail ("did not throw error");
		con.disconnect();
	}
	
	public void testSearchGroupsNoException() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"uid=testuser,ou=users,dc=domain,dc=com","secret".getBytes());
		
		
		
			LDAPSearchResults res = con.search("ou=groups,dc=domain,dc=com",1,"(objectClass=groupOfUniqueNames)",new String[0],false);
			if (res.hasMore()) {
				fail("has results " + res.next());
			}
		
		
		
			con.disconnect();
	}
	
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.openldapServer.stopServer();
		this.server.stopServer();
	}
}
