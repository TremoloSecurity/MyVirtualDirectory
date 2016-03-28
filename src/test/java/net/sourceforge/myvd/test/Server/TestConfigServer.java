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
package net.sourceforge.myvd.test.Server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.inserts.extensions.PasswordChangeOperation;
import net.sourceforge.myvd.inserts.ldap.LDAPInterceptor;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.chain.TestChain;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Result;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.types.SessionVariables;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.asn1.ASN1Identifier;
import com.novell.ldap.asn1.ASN1OctetString;
import com.novell.ldap.asn1.ASN1Sequence;
import com.novell.ldap.asn1.ASN1Tagged;
import com.novell.ldap.asn1.LBEREncoder;
import com.novell.ldap.util.DN;

import junit.framework.TestCase;

public class TestConfigServer extends TestCase {


	
	
	InsertChain globalChain;
	Router router;
	private StartOpenLDAP baseServer;
	private StartOpenLDAP internalServer;
	private StartOpenLDAP externalServer;
	private Server server;
	
	
	protected void setUp() throws Exception {
		super.setUp();
		this.baseServer = new StartOpenLDAP();
		this.baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",10983,"cn=admin,dc=domain,dc=com","manager");
		
		this.internalServer = new StartOpenLDAP();
		this.internalServer.startServer(System.getenv("PROJ_DIR") + "/test/InternalUsers",11983,"cn=admin,ou=internal,dc=domain,dc=com","manager");
		
		this.externalServer = new StartOpenLDAP();
		this.externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsers",12983,"cn=admin,ou=external,dc=domain,dc=com","manager");
		
		server = new Server(System.getenv("PROJ_DIR") + "/test/TestServer/testconfig.props");
		server.startServer();
		
		this.globalChain = server.getGlobalChain();
		this.router = server.getRouter();
		
		
 	}
	
	public void testSearchSubtreeResults() throws Exception {
		
		
		
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User"));
		attribs.add(new LDAPAttribute("sn","User"));
		attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid","testUser"));
		attribs.add(new LDAPAttribute("userPassword","secret"));
		attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",attribs);
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test Cust"));
		attribs.add(new LDAPAttribute("sn","Cust"));
		attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("uid","testCust"));
		attribs.add(new LDAPAttribute("userPassword","secret"));
		attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry1 = new LDAPEntry("cn=Test Cust,ou=external,o=mycompany,c=us",attribs);
		
		
		
		
		Results res = new Results(this.globalChain);
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		BindInterceptorChain bindChain = new BindInterceptorChain(new DistinguishedName(""),new Password(),0,new InsertChain(new Insert[0]),session,new HashMap());
		bindChain.nextBind(new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")), new Password("manager".getBytes()),new LDAPConstraints());
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")), new Password("manager".getBytes()),0,this.globalChain,session,new HashMap<Object,Object>(),router);
		ArrayList<Attribute> attribsToRequest = new ArrayList<Attribute>();
		attribsToRequest.add(new Attribute("1.1"));
		chain.nextSearch(new DistinguishedName(new DN("o=mycompany")),new Int(2),new Filter("(objectClass=inetOrgPerson)"),attribsToRequest,new Bool(false),res,new LDAPSearchConstraints());
		
		ArrayList<Result> results = res.getResults();
		
		if (results.size() != 3) {
			fail("incorrect number of result sets : " + results.size());
			return;
		}
		
		
		
		int size = 0;
		res.start();
			while (res.hasMore()) {
				Entry fromDir = res.next();
				LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
				
				if (size == 0) {
					controlEntry = entry1;
				} else if (size == 1) {
					controlEntry = entry2;
				} else {
					controlEntry = null;
				}
				
				if (controlEntry == null) {
					fail("Entry " + fromDir.getEntry().getDN() + " should not be returned");
					return;
				}
				
				if (! Util.compareEntry(fromDir.getEntry(),controlEntry)) {
					fail("The entry was not correct : " + fromDir.getEntry().toString());
					return;
				}
				
				size++;
			}
		
		
		if (size != 2) {
			fail("Not the correct number of entries : " + size);
		}
			
		
		
	}
	
	
	


	
	
public void testSearchOneLevelResults() throws Exception {
		
		
		
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","organizationalUnit"));
		attribs.add(new LDAPAttribute("ou","internal"));
		attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry2 = new LDAPEntry("ou=internal,o=mycompany,c=us",attribs);
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","organizationalUnit"));
		attribs.add(new LDAPAttribute("ou","external"));
		attribs.add(new LDAPAttribute("testAttrib", "testVal"));
		attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		LDAPEntry entry1 = new LDAPEntry("ou=external,o=mycompany,c=us",attribs);
		
		
		
		
		Results res = new Results(this.globalChain);
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		BindInterceptorChain bindChain = new BindInterceptorChain(new DistinguishedName(""),new Password(),0,new InsertChain(new Insert[0]),session,new HashMap());
		bindChain.nextBind(new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")), new Password("manager".getBytes()),new LDAPConstraints());
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")), new Password("manager".getBytes()),0,this.globalChain,session,new HashMap<Object,Object>(),router);
		ArrayList<Attribute> attribsToRequest = new ArrayList<Attribute>();
		attribsToRequest.add(new Attribute("1.1"));
		chain.nextSearch(new DistinguishedName(new DN("o=mycompany")),new Int(1),new Filter("(objectClass=*)"),attribsToRequest,new Bool(false),res,new LDAPSearchConstraints());
		
		ArrayList<Result> results = res.getResults();
		
		if (results.size() != 3) {
			fail("incorrect number of result sets : " + results.size());
			return;
		}
		
		
		
		
		res.start();
		int size = 0;
		
		
			while (res.hasMore()) {
				Entry fromDir = res.next();
				LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
				
				if (size == 0) {
					controlEntry = entry1;
				} else if (size == 1) {
					controlEntry = entry2;
				} else {
					controlEntry = null;
				}
				
				if (controlEntry == null) {
					fail("Entry " + fromDir.getEntry().getDN() + " should not be returned");
					return;
				}
				
				if (! Util.compareEntry(fromDir.getEntry(),controlEntry)) {
					fail("The entry was not correct : " + fromDir.getEntry().toString());
					return;
				}
				
				size++;
			}
		
		
		if (size != 2) {
			fail("Not the correct number of entries : " + size);
		}
			
		
		
	}
	
	
	public void testAddInternal() throws Exception {
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		
		
		LDAPEntry entry = new LDAPEntry("cn=Test User1,ou=internal,o=mycompany",attribs);
		
		Entry newEntry = new Entry(entry);
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		AddInterceptorChain chain = new AddInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=internal,o=mycompany,c=us")), new Password("manager".getBytes()),0,this.globalChain,session,new HashMap<Object,Object>(),router);
		
		chain.nextAdd(newEntry,new LDAPConstraints());
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",11983);
		con.bind(3,"cn=admin,ou=internal,dc=domain,dc=com","manager".getBytes());
		LDAPSearchResults res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		LDAPEntry result = res.next();
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		attribs.add(new LDAPAttribute("sn","User1"));
		entry = new LDAPEntry("cn=Test User1,ou=internal,dc=domain,dc=com",attribs);
		
		
		if (!  Util.compareEntry(result,entry)) {
			fail("Entry not correct : " + result.toString());
		}
		
		con = new LDAPConnection();
		con.connect("localhost",12983);
		con.bind(3,"cn=admin,ou=external,dc=domain,dc=com","manager".getBytes());
		
		res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		if (res.hasMore()) {
			fail("User exists in external users directory");
			return;
		}
		
		con = new LDAPConnection();
		con.connect("localhost",10983);
		con.bind(3,"cn=admin,dc=domain,dc=com","manager".getBytes());
		
		res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		if (res.hasMore()) {
			fail("User exists in base users directory");
			return;
		}
		
		
		
		
	}
	
	public void testAddExternal() throws LDAPException {
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		
		
		LDAPEntry entry = new LDAPEntry("cn=Test User1,ou=external,o=mycompany",attribs);
		
		Entry newEntry = new Entry(entry);
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		AddInterceptorChain chain = new AddInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=external,o=mycompany,c=us")), new Password("manager".getBytes()),0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
		
		chain.nextAdd(newEntry,new LDAPConstraints());
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",12983);
		con.bind(3,"cn=admin,ou=external,dc=domain,dc=com","manager".getBytes());
		LDAPSearchResults res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		LDAPEntry result = res.next();
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		attribs.add(new LDAPAttribute("sn","User1"));
		entry = new LDAPEntry("cn=Test User1,ou=external,dc=domain,dc=com",attribs);
		
		
		if (!  Util.compareEntry(result,entry)) {
			fail("Entry not correct : " + result.toString());
		}
		
		con = new LDAPConnection();
		con.connect("localhost",11983);
		con.bind(3,"cn=admin,ou=internal,dc=domain,dc=com","manager".getBytes());
		
		res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		if (res.hasMore()) {
			fail("User exists in internal users directory");
			return;
		}
		
		con = new LDAPConnection();
		con.connect("localhost",10983);
		con.bind(3,"cn=admin,dc=domain,dc=com","manager".getBytes());
		
		res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		if (res.hasMore()) {
			fail("User exists in base users directory");
			return;
		}
		
		
		
		
	}
	
	
	public void testModifyExternal() throws LDAPException {
		LDAPEntry entry;
		
		
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		ModifyInterceptorChain chain = new ModifyInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=external,o=mycompany,c=us")), new Password("manager".getBytes()),0,this.globalChain,session,new HashMap<Object,Object>(),router);
		
		
		ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
		//mods.add(mod);
		
		chain.nextModify(new DistinguishedName("cn=Test Cust,ou=external,o=mycompany"),mods,new LDAPConstraints());
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",12983);
		con.bind(3,"cn=admin,ou=external,dc=domain,dc=com","manager".getBytes());
		LDAPSearchResults res = con.search("ou=external,dc=domain,dc=com",2,"(cn=Test Cust)",new String[0],false);
		LDAPEntry result = res.next();
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test Cust"));
		attribs.add(new LDAPAttribute("sn","Cust"));
		attribs.getAttribute("sn").addValue("Second Surname");
		attribs.add(new LDAPAttribute("uid","testCust"));
		attribs.add(new LDAPAttribute("userPassword","secret"));
		//attribs.add(new LDAPAttribute("sn","Second Surname"));
		entry = new LDAPEntry("cn=Test Cust,ou=external,dc=domain,dc=com",attribs);
		
		
		if (! Util.compareEntry(result,entry)  ) {
			fail("Entry not correct : " + result.toString());
		}
	}
	
	public void testModifyInternal() throws LDAPException {
		LDAPEntry entry;
		
		
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		ModifyInterceptorChain chain = new ModifyInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=internal,o=mycompany,c=us")), new Password("manager".getBytes()),0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
		
		
		ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
		//mods.add(mod);
		
		chain.nextModify(new DistinguishedName("cn=Test User,ou=internal,o=mycompany"),mods,new LDAPConstraints());
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",11983);
		con.bind(3,"cn=admin,ou=internal,dc=domain,dc=com","manager".getBytes());
		LDAPSearchResults res = con.search("ou=internal,dc=domain,dc=com",2,"(cn=Test User)",new String[0],false);
		LDAPEntry result = res.next();
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User"));
		attribs.add(new LDAPAttribute("sn","User"));
		attribs.getAttribute("sn").addValue("Second Surname");
		attribs.add(new LDAPAttribute("uid","testUser"));
		attribs.add(new LDAPAttribute("userPassword","secret"));
		//attribs.add(new LDAPAttribute("sn","Second Surname"));
		entry = new LDAPEntry("cn=Test User,ou=internal,dc=domain,dc=com",attribs);
		
		
		if (! Util.compareEntry(result,entry)  ) {
			fail("Entry not correct : " + result.toString());
		}
	}
	
	public void testBind() {
		BindInterceptorChain bindChain;
		
		//first try a failed bind
		HashMap<Object,Object> session = new HashMap<Object,Object>();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		bindChain = new BindInterceptorChain(null,null,0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
			
		try {
			bindChain.nextBind(new DistinguishedName(new DN("ou=internal,o=mycompany")),new Password("nopass".getBytes()),new LDAPConstraints());
			fail("Bind succeeded");
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				fail("Invalid error " + e.toString());
			}
				
		}
		
		//try a successfull bind
		session = new HashMap<Object,Object>();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		bindChain = new BindInterceptorChain(null,null,0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
			
		try {
			bindChain.nextBind(new DistinguishedName(new DN("ou=internal,o=mycompany")),new Password("secret".getBytes()),new LDAPConstraints());
			if (((ArrayList<String>) session.get(SessionVariables.BOUND_INTERCEPTORS)).size() != 1 || 
					(! ((ArrayList<String>) session.get(SessionVariables.BOUND_INTERCEPTORS)).get(0).equals("LDAPInternalServer"))) {
				fail("Invalid bound interceptors : " + ((ArrayList<String>) session.get(SessionVariables.BOUND_INTERCEPTORS)));
			}
		} catch (LDAPException e) {
			fail("Invalid error " + e.toString());	
		}
		
		
		
//		first try a failed bind
		session = new HashMap<Object,Object>();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		bindChain = new BindInterceptorChain(null,null,0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
			
		try {
			bindChain.nextBind(new DistinguishedName(new DN("ou=internal,o=mycompany")),new Password("nopass".getBytes()),new LDAPConstraints());
			fail("Bind succeeded");
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				fail("Invalid error " + e.toString());
			}
				
		}
	}
	
	public void testDelete() throws LDAPException {
		
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		DeleteInterceptorChain chain = new DeleteInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=internal,o=mycompany,c=us")), new Password("manager".getBytes()),0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
		
		chain.nextDelete(new DistinguishedName("ou=internal,o=mycompany"),new LDAPConstraints());
		
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",11983);
		con.bind(3,"cn=admin,ou=internal,dc=domain,dc=com","manager".getBytes());
		
		try {
			LDAPSearchResults res = con.search("cn=Test User,ou=internal,o=company,c=us",0,"(objectClass=*)",new String[0],false);
			LDAPEntry result = res.next();
			fail("Entry not deleted");
		} catch (LDAPException e) {
			
		}
		
		
	}
	
	public void testRenameRDN() throws LDAPException {
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		RenameInterceptorChain chain = new RenameInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, this.globalChain,
				session, new HashMap<Object, Object>(),this.router);

		chain.nextRename(new DistinguishedName("ou=internal,o=mycompany"),new DistinguishedName("cn=New Test User"),new Bool(true),new LDAPConstraints());

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 11983);
		con.bind(3, "cn=admin,ou=internal,dc=domain,dc=com", "manager".getBytes());

		try {
			LDAPSearchResults res = con.search(
					"cn=Test User,ou=internal,dc=domain,dc=com", 0,
					"(objectClass=*)", new String[0], false);
			LDAPEntry result = res.next();
			fail("Entry not deleted");
		} catch (LDAPException e) {

		}
		
		try {
			LDAPSearchResults res = con.search(
					"cn=New Test User,ou=internal,dc=domain,dc=com", 0,
					"(objectClass=*)", new String[0], false);
			LDAPEntry result = res.next();
			
		} catch (LDAPException e) {
			fail("entry not renamed");
		}
	}

	
	public void testRenameDN() throws LDAPException {
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		RenameInterceptorChain chain = new RenameInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, this.globalChain,
				session, new HashMap<Object, Object>(),this.router);

		chain.nextRename(new DistinguishedName("ou=internal,o=mycompany"),new DistinguishedName("cn=New Test User"),new DistinguishedName("ou=internal,o=mycompany,c=us"),new Bool(true),new LDAPConstraints());

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 11983);
		con.bind(3, "cn=admin,ou=internal,dc=domain,dc=com", "manager".getBytes());

		try {
			LDAPSearchResults res = con.search(
					"cn=Test User,ou=internal,dc=domain,dc=com", 0,
					"(objectClass=*)", new String[0], false);
			LDAPEntry result = res.next();
			fail("Entry not deleted");
		} catch (LDAPException e) {

		}
		
		try {
			LDAPSearchResults res = con.search(
					"cn=New Test User,ou=internal,dc=domain,dc=com", 0,
					"(objectClass=*)", new String[0], false);
			LDAPEntry result = res.next();
			
		} catch (LDAPException e) {
			fail("entry not renamed");
		}
	}
	
	public void testRenameDNSeperateServers() throws LDAPException {
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		RenameInterceptorChain chain = new RenameInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, this.globalChain,
			
				session, new HashMap<Object, Object>(),router);

		chain.getRequest().put("ISRENAME","ISRENAME");
		chain.nextRename(new DistinguishedName("ou=internal,o=mycompany"),new DistinguishedName("cn=New Test User"),new DistinguishedName("ou=external,o=mycompany,c=us"),new Bool(true),new LDAPConstraints());

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 11983);
		con.bind(3, "cn=admin,ou=internal,dc=domain,dc=com", "manager".getBytes());

		try {
			LDAPSearchResults res = con.search(
					"cn=Test User,ou=internal,dc=domain,dc=com", 0,
					"(objectClass=*)", new String[0], false);
			LDAPEntry result = res.next();
			fail("Entry not deleted");
		} catch (LDAPException e) {

		}
		
		
		con = new LDAPConnection();
		con.connect("localhost", 12983);
		con.bind(3, "cn=admin,ou=external,dc=domain,dc=com", "manager".getBytes());
		try {
			LDAPSearchResults res = con.search(
					"cn=New Test User,ou=external,dc=domain,dc=com", 0,
					"(objectClass=*)", new String[0], false);
			LDAPEntry result = res.next();
			
		} catch (LDAPException e) {
			fail("entry not renamed");
		}
	}
	
	public void testExtendedOp() throws IOException, LDAPException {
//		 first we weill run the extended operation
		ByteArrayOutputStream encodedData = new ByteArrayOutputStream();
		LBEREncoder encoder = new LBEREncoder();

		// we are using the "real" base as the ldap context has no way of
		// knowing how to parse the operation
		ASN1Tagged[] seq = new ASN1Tagged[3];
		seq[0] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,
				false, 0), new ASN1OctetString(
				"cn=Test User,ou=internal,o=mycompany,c=us"), false);
		seq[1] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,
				false, 1), new ASN1OctetString("secret"), false);
		seq[2] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,
				false, 2), new ASN1OctetString("mysecret"), false);

		ASN1Sequence opSeq = new ASN1Sequence(seq, 3);
		opSeq.encode(encoder, encodedData);

		LDAPExtendedOperation op = new LDAPExtendedOperation(
				"1.3.6.1.4.1.4203.1.11.1", encodedData.toByteArray());
		ExtendedOperation localOp = new ExtendedOperation(new DistinguishedName(""), op);

		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		ExetendedOperationInterceptorChain extChain = new ExetendedOperationInterceptorChain(
				new DistinguishedName(""), new Password(""), 0,
				this.globalChain, session, new HashMap<Object, Object>(),router);

		extChain.nextExtendedOperations(localOp,new LDAPConstraints());
		

		

		try {
			LDAPConnection con = new LDAPConnection();
			con.connect("localhost",11983);
			con.bind(3,"cn=Test User,ou=internal,dc=domain,dc=com","mysecret".getBytes());

		} catch (LDAPException e) {

			fail("Invalid error " + e.toString());

		}
	}
	
	

	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
		this.baseServer.stopServer();
		this.internalServer.stopServer();
		this.externalServer.stopServer();
	}

	
}


