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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import com.novell.ldap.LDAPLocalException;
import com.novell.ldap.LDAPMessage;
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
import com.novell.ldap.util.LDIFReader;

import junit.framework.Assert;
import junit.framework.TestCase;

public class TestAttributeRouter extends TestCase {


	
	
	InsertChain globalChain;
	Router router;
	private StartOpenLDAP baseServer;
	private StartOpenLDAP internalServer;
	private StartOpenLDAP externalServer;
	private StartOpenLDAP localServer;
	private Server server;
	
	
	protected void setUp() throws Exception {
		super.setUp();
		this.baseServer = new StartOpenLDAP();
		this.baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base",10983,"cn=admin,dc=domain,dc=com","manager");
		
		this.internalServer = new StartOpenLDAP();
		this.internalServer.startServer(System.getenv("PROJ_DIR") + "/test/InternalUsersRoute",11983,"cn=admin,ou=internal,dc=domain,dc=com","manager");
		
		this.externalServer = new StartOpenLDAP();
		this.externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsersRoute",12983,"cn=admin,ou=external,dc=domain,dc=com","manager");
		
		this.localServer = new StartOpenLDAP();
		this.localServer.startServer(System.getenv("PROJ_DIR") + "/test/LocalUsers",13983,"cn=admin,ou=local,dc=domain,dc=com","manager");
		
		server = new Server(System.getenv("PROJ_DIR") + "/test/TestServer/testAttributeRoute.props");
		server.startServer();
		
		this.globalChain = server.getGlobalChain();
		this.router = server.getRouter();
		
		
 	}
	
	public void testControl() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2, "(cn=testrouting)", new String[]{}, false);
		String chkRes = this.checkSearch(res, "control-results.ldif");
		
		if (! chkRes.isEmpty()) {
			Assert.fail(chkRes);
		}
		
		con.disconnect();
		
	}
	
	public void testInternal() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2, "(|(cn=testrouting)(mail=internaluser@internal.domain.com))", new String[]{}, false);
		String chkRes = this.checkSearch(res, "internal-results.ldif");
		
		if (! chkRes.isEmpty()) {
			Assert.fail(chkRes);
		}
		
		con.disconnect();
		
	}
	
	public void testInternalWithOrMailNoRoute() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us",2, "(|(uid=internaluser)(mail=internaluser))", new String[]{}, false);
		String chkRes = this.checkSearch(res, "internal-results.ldif");
		
		if (! chkRes.isEmpty()) {
			Assert.fail(chkRes);
		}
		
		con.disconnect();
		
	}
	
	public void testExternal() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2, "(|(cn=testrouting)(mail=externaluser@external.domain.com))", new String[]{}, false);
		String chkRes = this.checkSearch(res, "external-results.ldif");
		
		if (! chkRes.isEmpty()) {
			Assert.fail(chkRes);
		}
		
		con.disconnect();
		
	}
	
	public void testExternalWithInternalBase() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us",2, "(|(cn=testrouting)(mail=externaluser@external.domain.com))", new String[]{}, false);
		
		try {
		if (res.hasMore()) {
			LDAPEntry e1 = res.next();
			Assert.fail("Results came back");
		}
		} catch  (LDAPException e) {
			if (e.getResultCode() != 32) {
				throw e;
			}
		}
		
		con.disconnect();
		
	}
	
	public void testDefault() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2, "(|(cn=testrouting)(mail=localuser@local.domain.com))", new String[]{}, false);
		String chkRes = this.checkSearch(res, "default-results.ldif");
		
		if (! chkRes.isEmpty()) {
			Assert.fail(chkRes);
		}
		
		con.disconnect();
		
	}
	
	public void testInternalAndDefault() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us",2, "(|(cn=testrouting)(mail=internaluser@internal.domain.com)(mail=localuser@local.domain.com))", new String[]{}, false);
		String chkRes = this.checkSearch(res, "default_internal-results.ldif");
		
		if (! chkRes.isEmpty()) {
			Assert.fail(chkRes);
		}
		
		con.disconnect();
		
	}
	
	private String checkSearch(LDAPSearchResults res, String ldifName) throws LDAPException,
	IOException, LDAPLocalException, FileNotFoundException {

		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/LocalUsers/" + ldifName));
		Util util = new Util();
		
		while (res.hasMore()) {
			
			
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				return "number of results dont match";
				
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				return "Entries don't match : \nFrom Server\n" + Util.toLDIF(fromserver) + "\n\nFrom LDIF\n" + Util.toLDIF(fromldif);
			}
			
			
		}
		
		return "";
	}
	

	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
		this.baseServer.stopServer();
		this.internalServer.stopServer();
		this.externalServer.stopServer();
		this.localServer.stopServer();
	}

	
}


