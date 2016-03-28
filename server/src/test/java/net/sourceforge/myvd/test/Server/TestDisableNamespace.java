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
import java.net.InetSocketAddress;
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
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.inserts.extensions.PasswordChangeOperation;
import net.sourceforge.myvd.inserts.ldap.LDAPInterceptor;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.chain.TestChain;
import net.sourceforge.myvd.test.util.StartMyVD;
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
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.novell.ldap.asn1.ASN1Identifier;
import com.novell.ldap.asn1.ASN1OctetString;
import com.novell.ldap.asn1.ASN1Sequence;
import com.novell.ldap.asn1.ASN1Tagged;
import com.novell.ldap.asn1.LBEREncoder;
import com.novell.ldap.util.DN;

import junit.framework.TestCase;

public class TestDisableNamespace extends TestCase {


	
	
	//Insert[] globalChain;
	//Router router;
	private StartOpenLDAP baseServer;
	private StartOpenLDAP internalServer;
	private StartOpenLDAP externalServer;
	private StartMyVD server;
	//private Server server;
	
	
	protected void setUp() throws Exception {
		super.setUp();
		this.baseServer = new StartOpenLDAP();
		this.baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",10983,"cn=admin,dc=domain,dc=com","manager");
		
		this.internalServer = new StartOpenLDAP();
		this.internalServer.startServer(System.getenv("PROJ_DIR") + "/test/InternalUsers",11983,"cn=admin,ou=internal,dc=domain,dc=com","manager");
		
		this.externalServer = new StartOpenLDAP();
		this.externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsers",12983,"cn=admin,ou=external,dc=domain,dc=com","manager");
		
		this.server = new StartMyVD();
		this.server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/testconfigdisable.props",50983);
		
		
		//server = new Server(System.getenv("PROJ_DIR") + "/test/TestServer/testconfig.props");
		//server.startServer();
		
		
		
		//this.globalChain = server.getGlobalChain();
		//this.router = server.getRouter();
		
		
 	}
	
	public void testStartServer() throws Exception {
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		//con.bind(3,"ou=internal,o=mycompany","secret".getBytes());
		
		LDAPSearchResults res = con.search("ou=internal,o=mycompany",2,"(objectClass=*)",new String[0],false);
		while (res.hasMore()) {
			System.out.println(res.next().getDN());
		}
		
		con.disconnect();
		
	}
	
	
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
		LDAPEntry entry1 = new LDAPEntry("cn=Test Cust,ou=external,o=mycompany,c=us",attribs);
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany",2,"(objectClass=inetOrgPerson)",new String[]{"1.1"},false);
		
		
		
		
		
		
		
		
		
		
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
					fail("The entry was not correct : \n" + Util.toLDIF(fromDir) + "\nfrom control:\n" + Util.toLDIF(controlEntry)) ;
					return;
				}
				
				size++;
			}
		
		
		if (size != 2) {
			fail("Not the correct number of entries : " + size);
		}
			
		
		con.disconnect();
	}
	
	
public void testSearchRootDSESSL() throws LDAPException {
		
		
		
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		
		
		attribs.add(new LDAPAttribute("namingContexts","o=mycompany,c=us"));
		attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		
		LDAPAttribute a = new LDAPAttribute("supportedLDAPVersion");
		a.addValue("2");
		a.addValue("3");
		attribs.add(a);
		
		a = new LDAPAttribute("subSchemaSubEntry");
		a.addValue("cn=schema");
		attribs.add(a);
		
		a = new LDAPAttribute("supportedControls");
		a.addValue("2.16.840.1.113730.3.4.18");
		a.addValue("2.16.840.1.113730.3.4.2");
		a.addValue("1.3.6.1.4.1.4203.1.10.1");
		a.addValue("1.2.840.113556.1.4.319");
		a.addValue("1.2.826.0.1.334810.2.3");
		a.addValue("1.2.826.0.1.3344810.2.3");
		a.addValue("1.3.6.1.1.13.2");
		a.addValue("1.3.6.1.1.13.1");
		a.addValue("1.3.6.1.1.12");
		attribs.add(a);

		a = new LDAPAttribute("supportedSaslMechanisms");
		a.addValue("NONE");
		attribs.add(a);
		
		LDAPEntry entry1 = new LDAPEntry("",attribs);
		
		
		LDAPSocketFactory ssf = new LDAPJSSESecureSocketFactory();
		
		
		LDAPConnection con = new LDAPConnection(ssf);
		con.connect("127.0.0.1",50636);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("",0,"(objectClass=*)",new String[]{"namingContexts"},false);
		
		
		
		
		
		
		
		int size = 0;
		
		
			while (res.hasMore()) {
				LDAPEntry fromDir = res.next();
				LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
				
				if (size == 0) {
					controlEntry = entry1;
				} else {
					controlEntry = null;
				}
				
				if (controlEntry == null) {
					fail("Entry " + fromDir.getDN() + " should not be returned");
					return;
				}
				
				if (! Util.compareEntry(fromDir,controlEntry)) {
					fail("The entry was not correct : " + Util.toLDIF(fromDir) + "\ncontrol:\n" + Util.toLDIF(controlEntry));
					return;
				}
				
				size++;
			}
		
		
		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}
			
		con.disconnect();
		
	}
	
public void testSearchRootDSE() throws LDAPException {
		
		
		
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		
		
		attribs.add(new LDAPAttribute("namingContexts","o=mycompany,c=us"));
		attribs.add(new LDAPAttribute("globalTestAttrib","globalTestVal"));
		
		LDAPAttribute a = new LDAPAttribute("supportedLDAPVersion");
		a.addValue("2");
		a.addValue("3");
		attribs.add(a);
		
		a = new LDAPAttribute("subSchemaSubEntry");
		a.addValue("cn=schema");
		attribs.add(a);
		
		a = new LDAPAttribute("supportedControls");
		a.addValue("2.16.840.1.113730.3.4.18");
		a.addValue("2.16.840.1.113730.3.4.2");
		a.addValue("1.3.6.1.4.1.4203.1.10.1");
		a.addValue("1.2.840.113556.1.4.319");
		a.addValue("1.2.826.0.1.334810.2.3");
		a.addValue("1.2.826.0.1.3344810.2.3");
		a.addValue("1.3.6.1.1.13.2");
		a.addValue("1.3.6.1.1.13.1");
		a.addValue("1.3.6.1.1.12");
		attribs.add(a);

		a = new LDAPAttribute("supportedSaslMechanisms");
		a.addValue("NONE");
		attribs.add(a);
		
		LDAPEntry entry1 = new LDAPEntry("",attribs);
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("",0,"(objectClass=*)",new String[]{"namingContexts"},false);
		
		
		
		
		
		
		
		int size = 0;
		
		
			while (res.hasMore()) {
				LDAPEntry fromDir = res.next();
				LDAPEntry controlEntry = null;//control.get(fromDir.getEntry().getDN());
				
				if (size == 0) {
					controlEntry = entry1;
				} else {
					controlEntry = null;
				}
				
				if (controlEntry == null) {
					fail("Entry " + fromDir.getDN() + " should not be returned");
					return;
				}
				
				if (! Util.compareEntry(fromDir,controlEntry)) {
					fail("The entry was not correct : " + Util.toLDIF(fromDir) + "\ncontrol:\n" + Util.toLDIF(controlEntry));
					return;
				}
				
				size++;
			}
		
		
		if (size != 1) {
			fail("Not the correct number of entries : " + size);
		}
			
		con.disconnect();
		
	}


	
	
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
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		LDAPSearchResults res = con.search("o=mycompany",1,"(objectClass=*)",new String[]{"1.1"},false);
		
		
		
		
		
		
		
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
					fail("The entry was not correct : " + Util.toLDIF(fromDir) + "\ncontrol:\n" + Util.toLDIF(controlEntry));
					return;
				}
				
				size++;
			}
		
		
		if (size != 2) {
			fail("Not the correct number of entries : " + size);
		}
			
		con.disconnect();
		
	}
	
	
	public void testAddInternal() throws LDAPException {
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		
		
		LDAPEntry entry = new LDAPEntry("cn=Test User1,ou=internal,o=mycompany",attribs);
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		con.add(entry);
		
		con.disconnect();
		
		con = new LDAPConnection();
		con.connect("127.0.0.1",11983);
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
		con.connect("127.0.0.1",12983);
		con.bind(3,"cn=admin,ou=external,dc=domain,dc=com","manager".getBytes());
		
		res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		if (res.hasMore()) {
			fail("User exists in external users directory");
			return;
		}
		
		con = new LDAPConnection();
		con.connect("127.0.0.1",10983);
		con.bind(3,"cn=admin,dc=domain,dc=com","manager".getBytes());
		
		res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		if (res.hasMore()) {
			fail("User exists in base users directory");
			return;
		}
		
		
		con.disconnect();
		
	}

	
	public void testAddExternal() throws LDAPException {
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User1"));
		
		
		LDAPEntry entry = new LDAPEntry("cn=Test User1,ou=external,o=mycompany",attribs);
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		con.add(entry);
		con.disconnect();
		con = new LDAPConnection();
		con.connect("127.0.0.1",12983);
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
		con.connect("127.0.0.1",11983);
		con.bind(3,"cn=admin,ou=internal,dc=domain,dc=com","manager".getBytes());
		
		res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		if (res.hasMore()) {
			fail("User exists in internal users directory");
			return;
		}
		
		con = new LDAPConnection();
		con.connect("127.0.0.1",10983);
		con.bind(3,"cn=admin,dc=domain,dc=com","manager".getBytes());
		
		res = con.search("dc=domain,dc=com",2,"(cn=Test User1)",new String[0],false);
		if (res.hasMore()) {
			fail("User exists in base users directory");
			return;
		}
		
		
		con.disconnect();
		
	}
	
	
	public void testModifyExternal() throws LDAPException {
		LDAPEntry entry;
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		//con.bind(3,"cn=admin,o=mycompany","manager".getBytes());
		con.modify("cn=Test Cust,ou=external,o=mycompany",new LDAPModification[] {new LDAPModification(2,new LDAPAttribute("userPassword","mysecret"))});
		con.disconnect();
		
		con = new LDAPConnection();
		con.connect("127.0.0.1",12983);
		con.bind(3,"cn=admin,ou=external,dc=domain,dc=com","manager".getBytes());
		LDAPSearchResults res = con.search("ou=external,dc=domain,dc=com",2,"(cn=Test Cust)",new String[0],false);
		LDAPEntry result = res.next();
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test Cust"));
		attribs.add(new LDAPAttribute("sn","Cust"));
		attribs.getAttribute("sn").addValue("Second Surname");
		attribs.add(new LDAPAttribute("uid","testCust"));
		attribs.add(new LDAPAttribute("userPassword","mysecret"));
		//attribs.add(new LDAPAttribute("sn","Second Surname"));
		entry = new LDAPEntry("cn=Test Cust,ou=external,dc=domain,dc=com",attribs);
		
		
		if (! Util.compareEntry(result,entry)  ) {
			fail("Entry not correct : " + result.toString());
		}
		
		con.disconnect();
	}
	
	
	public void testModifyInternal() throws LDAPException {
		LDAPEntry entry;
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		con.modify("cn=Test User,ou=internal,o=mycompany",new LDAPModification[] {new LDAPModification(2,new LDAPAttribute("userPassword","mysecret"))});
		con.disconnect();
		con = new LDAPConnection();
		con.connect("127.0.0.1",11983);
		con.bind(3,"cn=admin,ou=internal,dc=domain,dc=com","manager".getBytes());
		LDAPSearchResults res = con.search("ou=internal,dc=domain,dc=com",2,"(cn=Test User)",new String[0],false);
		LDAPEntry result = res.next();
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("cn","Test User"));
		attribs.add(new LDAPAttribute("sn","User"));
		attribs.getAttribute("sn").addValue("Second Surname");
		attribs.add(new LDAPAttribute("uid","testUser"));
		attribs.add(new LDAPAttribute("userPassword","mysecret"));
		//attribs.add(new LDAPAttribute("sn","Second Surname"));
		entry = new LDAPEntry("cn=Test User,ou=internal,dc=domain,dc=com",attribs);
		
		
		if (! Util.compareEntry(result,entry)  ) {
			fail("Entry not correct : " + result.toString());
		}
		
		con.disconnect();
	}
	
	public void testBind() throws LDAPException {
		BindInterceptorChain bindChain;
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		
		
			
		try {
			con.bind(3,"ou=internal,o=mycompany","nopass".getBytes());
			
			fail("Bind succeeded");
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				fail("Invalid error " + e.toString());
			}
				
		}
		
		//
			
		try {
			con.bind(3,"ou=internal,o=mycompany","secret".getBytes());
		} catch (LDAPException e) {
			fail("Invalid error " + e.toString());	
		}
		
		
		
			
		try {
			con.bind(3,"ou=internal,o=mycompany","nopass".getBytes());
			fail("Bind succeeded");
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				fail("Invalid error " + e.toString());
			}
				
		}
		
		con.disconnect();
	}
	
	public void testDelete() throws LDAPException {
		
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		con.delete("ou=internal,o=mycompany");
		
		con.disconnect();
		
		con = new LDAPConnection();
		con.connect("127.0.0.1",11983);
		con.bind(3,"cn=admin,ou=internal,dc=domain,dc=com","manager".getBytes());
		
		try {
			LDAPSearchResults res = con.search("cn=Test User,ou=internal,o=company,c=us",0,"(objectClass=*)",new String[0],false);
			LDAPEntry result = res.next();
			fail("Entry not deleted");
		} catch (LDAPException e) {
			
		}
		
		con.disconnect();
	}
	
	public void testRenameRDN() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		con.rename("ou=internal,o=mycompany","cn=New Test User",true);
		con.disconnect();
		con = new LDAPConnection();
		con.connect("127.0.0.1", 11983);
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
		
		con.disconnect();
	}

	
	public void testRenameDN() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		con.rename("ou=internal,o=mycompany","cn=New Test User","ou=internal,o=mycompany,c=us",true);
		con.disconnect();
		con = new LDAPConnection();
		con.connect("127.0.0.1", 11983);
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
		
		con.disconnect();
	}
	
	public void testRenameDNSeperateServers() throws LDAPException {
		

		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		con.rename("ou=internal,o=mycompany","cn=New Test User","ou=external,o=mycompany,c=us",true);
		con.disconnect();
		con = new LDAPConnection();
		con.connect("127.0.0.1", 11983);
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
		con.connect("127.0.0.1", 12983);
		con.bind(3, "cn=admin,ou=external,dc=domain,dc=com", "manager".getBytes());
		try {
			LDAPSearchResults res = con.search(
					"cn=New Test User,ou=external,dc=domain,dc=com", 0,
					"(objectClass=*)", new String[0], false);
			LDAPEntry result = res.next();
			
		} catch (LDAPException e) {
			fail("entry not renamed");
		}
		
		con.disconnect();
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

		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1",50983);
		con.extendedOperation(op);
		con.disconnect();
		

		try {
			con = new LDAPConnection();
			con.connect("127.0.0.1",11983);
			con.bind(3,"cn=Test User,ou=internal,dc=domain,dc=com","mysecret".getBytes());

		} catch (LDAPException e) {

			fail("Invalid error " + e.toString());

		}
		
		con.disconnect();
	}


	protected void tearDown() throws Exception {
		super.tearDown();
		this.baseServer.stopServer();
		this.internalServer.stopServer();
		this.externalServer.stopServer();
		this.server.stopServer();
		//this.server.stopServer();
	}

	
}


