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
import net.sourceforge.myvd.inserts.ldap.LDAPInterceptor;
import net.sourceforge.myvd.router.Router;
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

public class TestSingleRouteLDAP extends TestCase {

	StartOpenLDAP server;

	LDAPInterceptor interceptor;

	InsertChain chain;

	Router router;

	private PasswordChangeOperation pwdInterceptor;

	protected void setUp() throws Exception {
		super.setUp();
		this.server = new StartOpenLDAP();
		this.server.startServer(
				System.getenv("PROJ_DIR") + "/test/TestLDAP", 10983,
				"cn=admin,dc=domain,dc=com", "manager");

		// setup the ldap interceptor
		interceptor = new LDAPInterceptor();
		Properties props = new Properties();
		props.put("host", "localhost");
		props.put("port", "10983");
		props.put("remoteBase", "dc=domain,dc=com");
		props.put("proxyDN", "cn=admin,dc=domain,dc=com");
		props.put("proxyPass", "manager");

		pwdInterceptor = new PasswordChangeOperation();
		Properties nprops = new Properties();
		nprops.put("remoteBase", "dc=domain,dc=com");
		
		Insert[] tchain = new Insert[3];
		tchain[0] = new TestChainR();
		tchain[1] = this.pwdInterceptor;
		tchain[2] = interceptor;
		
		chain = new InsertChain(tchain);
		NameSpace ns = new NameSpace("LDAP", new DistinguishedName(new DN("o=mycompany,c=us")), 0, chain,false);
		interceptor.configure("TestLDAP", props, ns);
		this.pwdInterceptor.configure("pwdInterceptor",nprops,ns);
		this.router = new Router(new InsertChain(new Insert[0]));
		router.addBackend("TestLDAP", ns.getBase().getDN(), ns);

	}

	public void testSearch() throws LDAPException {
		HashMap<String, LDAPEntry> control = new HashMap<String, LDAPEntry>();

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "organizationalUnit"));
		attribs.add(new LDAPAttribute("ou", "internal"));

		LDAPEntry entry = new LDAPEntry("ou=internal,o=mycompany,c=us", attribs);
		control.put("ou=internal,o=mycompany,c=us", entry);

		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));

		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));

		entry = new LDAPEntry("cn=Test User,ou=internal,o=mycompany,c=us",
				attribs);
		control.put("cn=Test User,ou=internal,o=mycompany,c=us", entry);

		Results res = new Results(new InsertChain(new Insert[0]));
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		SearchInterceptorChain chain = new SearchInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, null,
				session, new HashMap<Object, Object>());
		ArrayList<Attribute> attribsToRequest = new ArrayList<Attribute>();
		attribsToRequest.add(new Attribute("1.1"));
		router.search(chain, new DistinguishedName(new DN(
				"ou=internal,o=mycompany,c=us")), new Int(2), new Filter(
				"(objectClass=*)"), attribsToRequest, new Bool(false), res,
				new LDAPSearchConstraints());

		ArrayList<Result> results = res.getResults();

		if (results.size() != 1) {
			fail("incorrect number of result sets");
			return;
		}

		EntrySet es = results.get(0).entrySet;

		int size = 0;
		while (es.hasMore()) {
			Entry fromDir = es.getNext();
			LDAPEntry controlEntry = control.get(fromDir.getEntry().getDN());
			if (controlEntry == null) {
				fail("Entry " + fromDir.getEntry().getDN()
						+ " should not be returned");
				return;
			}

			if (!Util.compareEntry(fromDir.getEntry(), controlEntry)) {
				fail("The entry was not correct : "
						+ fromDir.getEntry().toString());
				return;
			}

			size++;
		}

		if (size != control.size()) {
			fail("Not the correct number of entries");
		}

	}

	public void testAdd() throws LDAPException {

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User1"));

		LDAPEntry entry = new LDAPEntry("cn=Test User1,o=mycompany,c=us",
				attribs);

		Entry newEntry = new Entry(entry);

		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		AddInterceptorChain chain = new AddInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, null,
				session, new HashMap<Object, Object>());

		router.add(chain, newEntry, new LDAPConstraints());

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 10983);
		con.bind(3, "cn=admin,dc=domain,dc=com", "manager".getBytes());
		LDAPSearchResults res = con.search("dc=domain,dc=com", 2,
				"(cn=Test User1)", new String[0], false);
		LDAPEntry result = res.next();

		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User1"));
		attribs.add(new LDAPAttribute("sn", "User1"));
		entry = new LDAPEntry("cn=Test User1,dc=domain,dc=com", attribs);

		if (!Util.compareEntry(result, entry)) {
			fail("Entry not correct : " + result.toString());
		}

	}

	public void testModify() throws LDAPException {
		LDAPEntry entry;
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		ModifyInterceptorChain chain = new ModifyInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, null,
				session, new HashMap<Object, Object>());

		ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
		// mods.add(mod);

		router.modify(chain, new DistinguishedName(
				"cn=Test User,ou=internal,o=mycompany,c=us"), mods,
				new LDAPConstraints());

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 10983);
		con.bind(3, "cn=admin,dc=domain,dc=com", "manager".getBytes());
		LDAPSearchResults res = con.search("dc=domain,dc=com", 2,
				"(cn=Test User)", new String[0], false);
		LDAPEntry result = res.next();

		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass", "inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn", "Test User"));
		attribs.add(new LDAPAttribute("sn", "User"));
		attribs.getAttribute("sn").addValue("Second Surname");
		attribs.add(new LDAPAttribute("uid", "testUser"));
		attribs.add(new LDAPAttribute("userPassword", "secret"));
		// attribs.add(new LDAPAttribute("sn","Second Surname"));
		entry = new LDAPEntry("cn=Test User,ou=internal,dc=domain,dc=com",
				attribs);

		if (!Util.compareEntry(result, entry)) {
			fail("Entry not correct : " + result.toString());
		}
	}

	public void testBind() {
		BindInterceptorChain bindChain;
		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		// first try a failed bind
		bindChain = new BindInterceptorChain(null, null, 0, null,
				session, new HashMap<Object, Object>());

		try {
			router.bind(bindChain, new DistinguishedName(new DN(
					"ou=internal,o=mycompany,c=us")), new Password("nopass"
					.getBytes()), new LDAPConstraints());
			fail("Bind succeeded");
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				fail("Invalid error " + e.toString());
			}

		}

		// try a successfull bind
		session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		bindChain = new BindInterceptorChain(null, null, 0, null,
				session, new HashMap<Object, Object>());

		try {
			router.bind(bindChain, new DistinguishedName(new DN(
					"ou=internal,o=mycompany,c=us")), new Password("secret"
					.getBytes()), new LDAPConstraints());
		} catch (LDAPException e) {
			fail("Invalid error " + e.toString());
		}

		// first try a failed bind
		session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		bindChain = new BindInterceptorChain(null, null, 0, null,
				session, new HashMap<Object, Object>());

		try {
			router.bind(bindChain, new DistinguishedName(new DN(
					"ou=internal,o=mycompany,c=us")), new Password("nopass"
					.getBytes()), new LDAPConstraints());
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
		DeleteInterceptorChain chain = new DeleteInterceptorChain(
				new DistinguishedName(new DN("cn=admin,o=mycompany,c=us")),
				new Password("manager".getBytes()), 0, null,
				session, new HashMap<Object, Object>());

		router.delete(chain,
				new DistinguishedName("ou=internal,o=company,c=us"),
				new LDAPConstraints());

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 10983);
		con.bind(3, "cn=admin,dc=domain,dc=com", "manager".getBytes());

		try {
			LDAPSearchResults res = con.search(
					"cn=Test User,ou=internal,o=company,c=us", 0,
					"(objectClass=*)", new String[0], false);
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
				new Password("manager".getBytes()), 0, this.chain,
				session, new HashMap<Object, Object>());

		router.rename(chain,new DistinguishedName("ou=internal,o=mycompany,c=us"),new DistinguishedName("cn=New Test User"),new Bool(true),new LDAPConstraints());

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 10983);
		con.bind(3, "cn=admin,dc=domain,dc=com", "manager".getBytes());

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
				new Password("manager".getBytes()), 0, this.chain,
				session, new HashMap<Object, Object>());

		router.rename(chain,new DistinguishedName("ou=internal,o=mycompany,c=us"),new DistinguishedName("cn=New Test User"),new DistinguishedName("ou=internal,o=mycomapny,c=us"),new Bool(true),new LDAPConstraints());

		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 10983);
		con.bind(3, "cn=admin,dc=domain,dc=com", "manager".getBytes());

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
	
	public void testExtendedOp() throws IOException, LDAPException {
//		 first we weill run the extended operation
		ByteArrayOutputStream encodedData = new ByteArrayOutputStream();
		LBEREncoder encoder = new LBEREncoder();

		// we are using the "real" base as the ldap context has no way of
		// knowing how to parse the operation
		ASN1Tagged[] seq = new ASN1Tagged[3];
		seq[0] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,
				false, 0), new ASN1OctetString(
				"cn=Test User,ou=internal,dc=domain,dc=com"), false);
		seq[1] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,
				false, 1), new ASN1OctetString("secret"), false);
		seq[2] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,
				false, 2), new ASN1OctetString("mysecret"), false);

		ASN1Sequence opSeq = new ASN1Sequence(seq, 3);
		opSeq.encode(encoder, encodedData);

		LDAPExtendedOperation op = new LDAPExtendedOperation(
				"1.3.6.1.4.1.4203.1.11.1", encodedData.toByteArray());
		ExtendedOperation localOp = new ExtendedOperation(null, op);

		HashMap session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		ExetendedOperationInterceptorChain extChain = new ExetendedOperationInterceptorChain(
				new DistinguishedName(""), new Password(""), 0,
				new InsertChain(new Insert[0]), session, new HashMap<Object, Object>());

		extChain.nextExtendedOperations(localOp,
				new LDAPConstraints());

		BindInterceptorChain bindChain;

		// first try a failed bind
		session = new HashMap();
		session.put(SessionVariables.BOUND_INTERCEPTORS,
				new ArrayList<String>());
		bindChain = new BindInterceptorChain(new DistinguishedName(""),
				new Password(""), 0, new InsertChain(new Insert[0]), session,
				new HashMap<Object, Object>());

		try {
			bindChain.nextBind(new DistinguishedName(new DN(
					"cn=Test User,ou=internal,o=mycompany,c=us")),
					new Password("mysecret".getBytes()), new LDAPConstraints());

		} catch (LDAPException e) {

			fail("Invalid error " + e.toString());

		}
	}

	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
	}

}
