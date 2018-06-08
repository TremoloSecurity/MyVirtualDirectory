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
package net.sourceforge.myvd.test.interceptor;


import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;

import com.novell.ldap.LDAPConnection;

import junit.framework.TestCase;

import com.novell.ldap.*;



import com.novell.ldap.LDAPConnection;

import junit.framework.TestCase;

import com.novell.ldap.*;

public class TestJDBCLDAP extends TestCase {

	InsertChain globalChain;
	Router router;
	private StartOpenLDAP baseServer;
	private Server server;
	
	protected void setUp() throws Exception {
		super.setUp();
		this.baseServer = new StartOpenLDAP();
		this.baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",10983,"cn=admin,dc=domain,dc=com","manager");
		
		server = new Server(System.getenv("PROJ_DIR") + "/test/TestServer/testJDBCLDAP.props");
		server.startServer();
		
		this.globalChain = server.getGlobalChain();
		this.router = server.getRouter();
	}
	
	public void testAdd() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"cn=admin,o=mycompany,c=us","manager".getBytes());
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();

		
		LDAPEntry entry = new LDAPEntry("cn=testadd,o=mycompany,c=us",attribs);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(cn=testadd)",new String[] {"add"},false);
		LDAPEntry fromServer = res.next();
		if (! Util.compareEntry(entry,fromServer)) {
			fail("Did not retrieve correct data : " + fromServer.toString());
		}
		con.disconnect();
	}
	
	public void testUpdate() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"cn=admin,o=mycompany,c=us","manager".getBytes());
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		
		LDAPEntry entry = new LDAPEntry("cn=testadd,o=mycompany,c=us",attribs);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(sn=sntest)",new String[] {"update"},false);
		LDAPEntry fromServer = res.next();
		if (! Util.compareEntry(entry,fromServer)) {
			fail("Did not retrieve correct data : " + fromServer.toString());
		}
		con.disconnect();
	}
	
	public void testUpdateEntry() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"cn=admin,o=mycompany,c=us","manager".getBytes());
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		
		
		LDAPEntry entry = new LDAPEntry("cn=testadd,o=mycompany,c=us",attribs);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(uid=testuid)",new String[] {"updateentry"},false);
		LDAPEntry fromServer = res.next();
		if (! Util.compareEntry(entry,fromServer)) {
			fail("Did not retrieve correct data : " + fromServer.toString());
		}
		con.disconnect();
	}
	
	
	public void testDelete() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"cn=admin,o=mycompany,c=us","manager".getBytes());
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();

		
		LDAPEntry entry = new LDAPEntry("cn=testadd,o=mycompany,c=us",attribs);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(sn=add)",new String[] {"delete"},false);
		LDAPEntry fromServer = res.next();
		if (! Util.compareEntry(entry,fromServer) || res.hasMore()) {
			fail("Did not retrieve correct data : " + fromServer.toString());
		}
		con.disconnect();
	}
	
	public void testSearch() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		con.bind(3,"cn=admin,o=mycompany,c=us","manager".getBytes());
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();

		
		LDAPEntry entry = new LDAPEntry("cn=testadd,o=mycompany,c=us",attribs);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2,"(sn=add)",new String[] {"search"},false);
		LDAPEntry fromServer = res.next();
		if (! Util.compareEntry(entry,fromServer) || res.hasMore()) {
			fail("Did not retrieve correct data : " + fromServer.toString());
		}
		con.disconnect();
	}
	
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
		this.baseServer.stopServer();
	}

}
