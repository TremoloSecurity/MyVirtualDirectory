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
package net.sourceforge.myvd.test.router;

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
import net.sourceforge.myvd.inserts.ldap.LDAPInterceptorExperimental;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.test.chain.TestChain;
import net.sourceforge.myvd.test.util.OpenLDAPUtils;
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
import net.sourceforge.myvd.types.RequestVariables;
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class TestChooseRoute  {


	static LDAPInterceptorExperimental baseInterceptor;
	static InsertChain chain;
	static InsertChain globalChain;
	static Router router;
	private static StartOpenLDAP baseServer;
	private static StartOpenLDAP internalServer;
	private static StartOpenLDAP externalServer;
	private static StartOpenLDAP bogusInternalServer;
	private static StartOpenLDAP bogusExternalServer;
	private static PasswordChangeOperation pwdInterceptor;
	
	@BeforeClass
	public static void setUp() throws Exception {
		OpenLDAPUtils.killAllOpenLDAPS();
		baseServer = new StartOpenLDAP();
		baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",10983,"cn=admin,dc=domain,dc=com","manager");
		
		internalServer = new StartOpenLDAP();
		internalServer.startServer(System.getenv("PROJ_DIR") + "/test/InternalUsers",11983,"cn=admin,ou=internal,dc=domain,dc=com","manager");
		
		externalServer = new StartOpenLDAP();
		externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsers",12983,"cn=admin,ou=external,dc=domain,dc=com","manager");
		
		bogusExternalServer = new StartOpenLDAP();
		bogusExternalServer.startServer(System.getenv("PROJ_DIR") + "/test/BogusExternal",13983,"cn=admin,ou=external,dc=domain,dc=com","manager");
		
		bogusInternalServer = new StartOpenLDAP();
		bogusInternalServer.startServer(System.getenv("PROJ_DIR") + "/test/BogusInternal",14983,"cn=admin,ou=external,dc=domain,dc=com","manager");
		
		//setup the ldap interceptors
		baseInterceptor = new LDAPInterceptorExperimental();
		Properties props = new Properties();
		props.put("host","localhost");
		props.put("port","10983");
		props.put("remoteBase","dc=domain,dc=com");
		props.put("proxyDN","cn=admin,dc=domain,dc=com");
		props.put("proxyPass","manager");
		
		
		
		
		
		Insert[] tchain = new Insert[2];
		tchain[0] = new TestChainR();
		tchain[1] = baseInterceptor;
		chain = new InsertChain(tchain);
		
		
		NameSpace ns = new NameSpace("LDAP", new DistinguishedName(new DN("o=mycompany,c=us")), 0, chain,false);
		baseInterceptor.configure("TestLDAP",props,ns);
		
		router = new Router(new InsertChain(new Insert[0]));
		router.addBackend("LDAPBase",ns.getBase().getDN(),ns);
		
		
		baseInterceptor = new LDAPInterceptorExperimental();
		props = new Properties();
		props.put("host","localhost");
		props.put("port","11983");
		props.put("remoteBase","ou=internal,dc=domain,dc=com");
		props.put("proxyDN","cn=admin,ou=internal,dc=domain,dc=com");
		props.put("proxyPass","manager");
		
		tchain = new Insert[3];
		tchain[0] = new TestChainR();
		tchain[2] = baseInterceptor;
		tchain[1] = new PasswordChangeOperation();
		chain = new InsertChain(tchain);
		
		ns = new NameSpace("LDAPInternal", new DistinguishedName(new DN("ou=internal,o=mycompany,c=us")), 10, chain,false);
		baseInterceptor.configure("LDAPInternal",props,ns);
		router.addBackend("LDAPInternal",ns.getBase().getDN(),ns);
		
		Properties nprops = new Properties();
		nprops.put("remoteBase", "dc=domain,dc=com");
		nprops.put("localBase","o=mycompany,c=us");
		tchain[1].configure("localPwdChange",nprops,ns);
		
		
		
		baseInterceptor = new LDAPInterceptorExperimental();
		props = new Properties();
		props.put("host","localhost");
		props.put("port","14983");
		props.put("remoteBase","ou=internal,dc=domain,dc=com");
		props.put("proxyDN","cn=admin,ou=internal,dc=domain,dc=com");
		props.put("proxyPass","manager");
		
		tchain = new Insert[3];
		tchain[0] = new TestChainR();
		tchain[2] = baseInterceptor;
		tchain[1] = new PasswordChangeOperation();
		chain = new InsertChain(tchain);
		
		ns = new NameSpace("LDAPBogusInternal", new DistinguishedName(new DN("ou=internal,o=mycompany,c=us")), 20, chain,false);
		baseInterceptor.configure("LDAPInternal",props,ns);
		router.addBackend("LDAPBogusInternal",ns.getBase().getDN(),ns);
		
		nprops = new Properties();
		nprops.put("remoteBase", "dc=domain,dc=com");
		nprops.put("localBase","o=mycompany,c=us");
		tchain[1].configure("localPwdChange",nprops,ns);
		
		
		
		
		baseInterceptor = new LDAPInterceptorExperimental();
		props = new Properties();
		props.put("host","localhost");
		props.put("port","12983");
		props.put("remoteBase","ou=external,dc=domain,dc=com");
		props.put("proxyDN","cn=admin,ou=external,dc=domain,dc=com");
		props.put("proxyPass","manager");
		
		tchain = new Insert[3];
		tchain[0] = new TestChainR();
		tchain[2] = baseInterceptor;
		tchain[1] = new PasswordChangeOperation();
		chain = new InsertChain(tchain);
		ns = new NameSpace("LDAPExternal", new DistinguishedName(new DN("ou=external,o=mycompany,c=us")), 15, chain,false);
		
		nprops = new Properties();
		nprops.put("remoteBase", "dc=domain,dc=com");
		nprops.put("localBase","o=mycompany,c=us");
		tchain[1].configure("localPwdChange",nprops,ns);
		
		baseInterceptor.configure("LDAPExternal",props,ns);
		router.addBackend("LDAPExternal",ns.getBase().getDN(),ns);
		
		
		
		
		baseInterceptor = new LDAPInterceptorExperimental();
		props = new Properties();
		props.put("host","localhost");
		props.put("port","13983");
		props.put("remoteBase","ou=external,dc=domain,dc=com");
		props.put("proxyDN","cn=admin,ou=external,dc=domain,dc=com");
		props.put("proxyPass","manager");
		
		tchain = new Insert[3];
		tchain[0] = new TestChainR();
		tchain[2] = baseInterceptor;
		tchain[1] = new PasswordChangeOperation();
		chain = new InsertChain(tchain);
		
		ns = new NameSpace("LDAPBogusExternal", new DistinguishedName(new DN("ou=external,o=mycompany,c=us")), 25, chain,false);
		
		nprops = new Properties();
		nprops.put("remoteBase", "dc=domain,dc=com");
		nprops.put("localBase","o=mycompany,c=us");
		tchain[1].configure("localPwdChange",nprops,ns);
		
		baseInterceptor.configure("LDAPBogusExternal",props,ns);
		router.addBackend("LDAPBogusExternal",ns.getBase().getDN(),ns);
		
		
		
		
		
		tchain = new Insert[2];
		globalChain = new InsertChain(tchain);
		tchain[0] = new TestglobalChain();
		pwdInterceptor = new PasswordChangeOperation();
		nprops = new Properties();
		nprops.put("remoteBase", "o=mycompany,c=us");
		nprops.put("localBase","o=mycompany,c=us");
		pwdInterceptor.configure("pwdMgr",nprops,null);
		tchain[1] = pwdInterceptor;
		
 	}
	
	@After
	public void after() throws Exception {
		TestChooseRoute.baseServer.reloadAllData();
		//TestChooseRoute.bogusExternalServer.reloadAllData();
		//TestChooseRoute.bogusInternalServer.reloadAllData();
		TestChooseRoute.externalServer.reloadAllData();
		TestChooseRoute.internalServer.reloadAllData();
		
	}
	
	@Test
	public void testSearchSubtreeResults() throws LDAPException {
		
		
		
		
		
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
		attribs.add(new LDAPAttribute("l","shouldnotmatter"));
		LDAPEntry entry1 = new LDAPEntry("cn=Test Cust,ou=external,o=mycompany,c=us",attribs);
		
		
		
		
		Results res = new Results(globalChain);
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		
		HashMap request = new HashMap();
		ArrayList<String> backends = new ArrayList<String>();
		backends.add("LDAPExternal");
		backends.add("LDAPInternal");
		backends.add("LDAPBase");
		request.put(RequestVariables.ROUTE_NAMESPACE,backends);
		
		BindInterceptorChain bindChain = new BindInterceptorChain(new DistinguishedName(""),new Password(),0,new InsertChain(new Insert[0]),session,new HashMap());
		bindChain.nextBind(new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")), new Password("manager".getBytes()),new LDAPConstraints());
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")), new Password("manager".getBytes()),0,globalChain,session,request,router);
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
	
	
	


	@Test
	
public void testSearchOneLevelResults() throws LDAPException {
		
		
		
		
		
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
		
		
		
		HashMap request = new HashMap();
		ArrayList<String> backends = new ArrayList<String>();
		backends.add("LDAPExternal");
		backends.add("LDAPInternal");
		backends.add("LDAPBase");
		request.put(RequestVariables.ROUTE_NAMESPACE,backends);
		
		Results res = new Results(globalChain);
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		BindInterceptorChain bindChain = new BindInterceptorChain(new DistinguishedName(""),new Password(),0,new InsertChain(new Insert[0]),session,new HashMap());
		bindChain.nextBind(new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")), new Password("manager".getBytes()),new LDAPConstraints());
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")), new Password("manager".getBytes()),0,globalChain,session,request,router);
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
	
	@Test
	public void testAddInternal() throws LDAPException {
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		
		
		LDAPEntry entry = new LDAPEntry("cn=Test User1,ou=internal,o=mycompany",attribs);
		
		
		HashMap request = new HashMap();
		
		request.put(RequestVariables.ROUTE_NAMESPACE,"LDAPInternal");
		
		Entry newEntry = new Entry(entry);
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		AddInterceptorChain chain = new AddInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=internal,o=mycompany,c=us")), new Password("manager".getBytes()),0,globalChain,session,request,router);
		
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
	@Test
	public void testAddExternal() throws LDAPException {
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		
		
		LDAPEntry entry = new LDAPEntry("cn=Test User1,ou=external,o=mycompany",attribs);
		
		Entry newEntry = new Entry(entry);
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		
		HashMap request = new HashMap();
		request.put(RequestVariables.ROUTE_NAMESPACE,"LDAPExternal");
		
		
		AddInterceptorChain chain = new AddInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=external,o=mycompany,c=us")), new Password("manager".getBytes()),0,globalChain,session,request,router);
		
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
	
	@Test
	public void testModifyExternal() throws LDAPException {
		LDAPEntry entry;
		
		
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		
		HashMap request = new HashMap();
		ArrayList<String> backends = new ArrayList<String>();
		request.put(RequestVariables.ROUTE_NAMESPACE,"LDAPExternal");
		
		ModifyInterceptorChain chain = new ModifyInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=external,o=mycompany,c=us")), new Password("manager".getBytes()),0,globalChain,session,request,router);
		
		
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
		attribs.add(new LDAPAttribute("l","shouldnotmatter"));
		//attribs.add(new LDAPAttribute("sn","Second Surname"));
		entry = new LDAPEntry("cn=Test Cust,ou=external,dc=domain,dc=com",attribs);
		
		
		if (! Util.compareEntry(result,entry)  ) {
			fail("Entry not correct : " + result.toString());
		}
	}
	@Test
	public void testModifyInternal() throws LDAPException {
		LDAPEntry entry;
		
		
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		
		HashMap request = new HashMap();
		ArrayList<String> backends = new ArrayList<String>();
		request.put(RequestVariables.ROUTE_NAMESPACE,"LDAPInternal");
		
		ModifyInterceptorChain chain = new ModifyInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=internal,o=mycompany,c=us")), new Password("manager".getBytes()),0,globalChain,session,request,router);
		
		
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
	@Test
	public void testBind() {
		BindInterceptorChain bindChain;
		
		//first try a failed bind
		HashMap<Object,Object> session = new HashMap<Object,Object>();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		HashMap request = new HashMap();
		ArrayList<String> backends = new ArrayList<String>();
		
		backends.add("LDAPInternal");
		backends.add("LDAPBase");
		request.put(RequestVariables.ROUTE_NAMESPACE,backends);
		
		bindChain = new BindInterceptorChain(null,null,0,globalChain,session,request,router);
			
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
		bindChain = new BindInterceptorChain(null,null,0,globalChain,session,request,router);
			
		try {
			bindChain.nextBind(new DistinguishedName(new DN("ou=internal,o=mycompany")),new Password("secret".getBytes()),new LDAPConstraints());
			if (((ArrayList<String>) session.get(SessionVariables.BOUND_INTERCEPTORS)).size() != 1 || 
					(! ((ArrayList<String>) session.get(SessionVariables.BOUND_INTERCEPTORS)).get(0).equals("LDAPInternal"))) {
				fail("Invalid bound interceptors : " + ((ArrayList<String>) session.get(SessionVariables.BOUND_INTERCEPTORS)));
			}
		} catch (LDAPException e) {
			fail("Invalid error " + e.toString());	
		}
		
		
		
//		first try a failed bind
		session = new HashMap<Object,Object>();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		bindChain = new BindInterceptorChain(null,null,0,globalChain,session,request,router);
			
		try {
			bindChain.nextBind(new DistinguishedName(new DN("ou=internal,o=mycompany")),new Password("nopass".getBytes()),new LDAPConstraints());
			fail("Bind succeeded");
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				fail("Invalid error " + e.toString());
			}
				
		}
	}
	@Test
	public void testDelete() throws LDAPException {
		
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		HashMap request = new HashMap();
		
		request.put(RequestVariables.ROUTE_NAMESPACE,"LDAPInternal");
		DeleteInterceptorChain chain = new DeleteInterceptorChain(new DistinguishedName(new DN("cn=admin,ou=internal,o=mycompany,c=us")), new Password("manager".getBytes()),0,globalChain,session,request,router);
		
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
	@Test
	public void testRenameRDN() throws LDAPException {
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		
		HashMap request = new HashMap();
		ArrayList<String> backends = new ArrayList<String>();
		request.put(RequestVariables.ROUTE_NAMESPACE,"LDAPInternal");
		
		RenameInterceptorChain chain = new RenameInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, globalChain,
				session, request,router);

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

	@Test
	public void testRenameDN() throws LDAPException {
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		
		HashMap request = new HashMap();
		request.put(RequestVariables.ROUTE_NAMESPACE,"LDAPInternal");
		request.put(RequestVariables.ROUTE_NAMESPACE_RENAME,"LDAPInternal");
		
		
		RenameInterceptorChain chain = new RenameInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, globalChain,
				session, request,router);

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
	@Test
	public void testRenameDNSeperateServers() throws LDAPException {
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		
		HashMap request = new HashMap();
		request.put(RequestVariables.ROUTE_NAMESPACE,"LDAPInternal");
		request.put(RequestVariables.ROUTE_NAMESPACE_RENAME,"LDAPExternal");
		RenameInterceptorChain chain = new RenameInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, globalChain,
			
				session,request,router);

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
	@Test
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
				globalChain, session, new HashMap<Object, Object>(),router);

		extChain.nextExtendedOperations(localOp,new LDAPConstraints());
		

		

		try {
			LDAPConnection con = new LDAPConnection();
			con.connect("localhost",11983);
			con.bind(3,"cn=Test User,ou=internal,dc=domain,dc=com","mysecret".getBytes());

		} catch (LDAPException e) {

			fail("Invalid error " + e.toString());

		}
	}
	
	
	@AfterClass
	public static void tearDown() throws Exception {
		
		baseServer.stopServer();
		internalServer.stopServer();
		externalServer.stopServer();
		bogusExternalServer.stopServer();
		bogusInternalServer.stopServer();
	}

	
}


