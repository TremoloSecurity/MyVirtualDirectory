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
import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.SessionVariables;

import com.novell.ldap.util.DN;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class TestValidateSubjects  {
	private static StartOpenLDAP openldapServer;
	private static  Server server;
	private static  InsertChain globalChain;
	private static  Router router;
	
	@BeforeClass
	public static void setUp() throws Exception {
		OpenLDAPUtils.killAllOpenLDAPS();
		openldapServer = new StartOpenLDAP();
		openldapServer.startServer(System.getenv("PROJ_DIR") + "/test/ACITest",10983,"cn=admin,dc=domain,dc=com","manager");
		
		server = new Server(System.getenv("PROJ_DIR") + "/test/TestServer/testACI.props");
		server.startServer();
		
		globalChain = server.getGlobalChain();
		router = server.getRouter();
 	}
	
	@Test
	public void testPublic() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#public:");
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,new HashMap<Object,Object>(),new HashMap<Object,Object>(),this.router);
		
		if (! aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
	}
	
	@Test
	public void testSubtreePass() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#subtree:ou=users,dc=domain,dc=com");
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,new HashMap<Object,Object>(),new HashMap<Object,Object>(),this.router);
		
		if (! aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
	}
	
	@Test
	public void testSubtreeFail() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#subtree:ou=apps,dc=domain,dc=com");
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,new HashMap<Object,Object>(),new HashMap<Object,Object>(),this.router);
		
		if (aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
	}
	
	@Test
	public void testThisPass() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#this:");
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,new HashMap<Object,Object>(),new HashMap<Object,Object>(),this.router);
		
		if (! aci.checkSubject(chain,new DN("uid=testuser,ou=users,dc=domain,dc=com"))) {
			fail("subject check failed");
		}
	}
	
	@Test
	public void testThisFail() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#this:");
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,new HashMap<Object,Object>(),new HashMap<Object,Object>(),this.router);
		
		if (aci.checkSubject(chain,new DN("uid=testuser1,ou=users,dc=domain,dc=com"))) {
			fail("subject check failed");
		}
	}
	
	@Test
	public void testDNPass() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#dn:uid=testuser,ou=users,dc=domain,dc=com");
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,new HashMap<Object,Object>(),new HashMap<Object,Object>(),this.router);
		
		if (! aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
	}
	
	@Test
	public void testDNFail() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#dn:uid=testuser1,ou=users,dc=domain,dc=com");
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,new HashMap<Object,Object>(),new HashMap<Object,Object>(),this.router);
		
		if (aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
	}

	@Test
	public void testStaticGroupPass() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#group:cn=staticgroup1,ou=groups,dc=domain,dc=com");
		HashMap<Object,Object> session = new HashMap<Object,Object>();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
		
		if (! aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
		
		chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser2,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
		
		if (! aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
	}
	
	@Test
	public void testStaticGroupFail() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#group:cn=staticgroup1,ou=groups,dc=domain,dc=com");
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser1,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,new HashMap<Object,Object>(),new HashMap<Object,Object>(),this.router);
		
		if (aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
		
		
	}
	
	@Test
	public void testDynGroupPass() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#dynamic-group:cn=dynamicgroup1,ou=groups,dc=domain,dc=com");
		HashMap<Object,Object> session = new HashMap<Object,Object>();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
		
		if (! aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
		
		chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser1,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
		
		if (! aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
	}
	
	@Test
	public void testDynGroupFail() throws Exception {
		AccessControlItem aci = new AccessControlItem(0,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#dynamic-group:cn=dynamicgroup1,ou=groups,dc=domain,dc=com");
		HashMap<Object,Object> session = new HashMap<Object,Object>();
		session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser2,ou=users,dc=domain,dc=com"),new Password(""),0,this.globalChain,session,new HashMap<Object,Object>(),this.router);
		
		if (aci.checkSubject(chain,null)) {
			fail("subject check failed");
		}
		
	}
	
	@AfterClass
	public static void tearDown() throws Exception {
		
		openldapServer.stopServer();
		server.stopServer();
	}
}
