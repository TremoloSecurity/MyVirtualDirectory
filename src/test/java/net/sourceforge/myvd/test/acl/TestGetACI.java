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
import net.sourceforge.myvd.inserts.accessControl.AccessMgr;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.SessionVariables;

import com.novell.ldap.util.DN;

import junit.framework.TestCase;

public class TestGetACI extends TestCase {
	
	private AccessMgr accessManager;
	
	protected void setUp() throws Exception {
		super.setUp();
		
		this.accessManager = new AccessMgr();
		accessManager.addACI(new AccessControlItem(0,"dc=domain,dc=com#subtree#deny:v,c,d#[entry]#public:"));
		accessManager.addACI(new AccessControlItem(1,"dc=domain,dc=com#subtree#grant:v#[entry]#subtree:ou=users,dc=domain,dc=com"));
		accessManager.addACI(new AccessControlItem(2,"dc=domain,dc=com#subtree#deny:v#[entry]#dn:uid=testuser2,ou=users,dc=domain,dc=com"));
		accessManager.addACI(new AccessControlItem(3,"ou=users,dc=domain,dc=com#entry#grant:v#[entry]#dn:uid=testuser2,ou=users,dc=domain,dc=com"));
		accessManager.addACI(new AccessControlItem(4,"dc=domain,dc=com#subtree#deny:r,w,o,s,c,p#[all]#public:"));
		accessManager.addACI(new AccessControlItem(5,"dc=domain,dc=com#subtree#grant:r,w,s,c,p#[all]#this:"));
		
		
		
 	}
	
	
	public void testBindUserEntries() throws Exception {
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,new InsertChain(new Insert[0]),new HashMap<Object,Object>(),new HashMap<Object,Object>(),new Router(new InsertChain(new Insert[0])));
		AccessControlItem aci = this.accessManager.getApplicableACI(new DN("uid=testuser,ou=users,dc=domain,dc=com"),null,'v',chain); 
		if (aci == null || aci.getNum() != 1) {
			fail("invalid aci : " + aci);
		}
	}
	
	public void testBindUserAttribs() throws Exception {
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser,ou=users,dc=domain,dc=com"),new Password(""),0,new InsertChain(new Insert[0]),new HashMap<Object,Object>(),new HashMap<Object,Object>(),new Router(new InsertChain(new Insert[0])));
		AccessControlItem aci = this.accessManager.getApplicableACI(new DN("uid=testuser,ou=users,dc=domain,dc=com"),"attrib",'r',chain); 
		if (aci == null || aci.getNum() != 5) {
			fail("invalid aci : " + aci);
		}
		
	}
	
	public void testBindUserEntriesFail() throws Exception {
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser2,ou=users,dc=domain,dc=com"),new Password(""),0,new InsertChain(new Insert[0]),new HashMap<Object,Object>(),new HashMap<Object,Object>(),new Router(new InsertChain(new Insert[0])));
		AccessControlItem aci = this.accessManager.getApplicableACI(new DN("uid=testuser,ou=users,dc=domain,dc=com"),null,'v',chain); 
		if (aci == null || aci.getNum() != 2) {
			fail("invalid aci : " + aci);
		}
	}
	
	public void testBindUserEntriesSpecificEntry() throws Exception {
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName("uid=testuser2,ou=users,dc=domain,dc=com"),new Password(""),0,new InsertChain(new Insert[0]),new HashMap<Object,Object>(),new HashMap<Object,Object>(),new Router(new InsertChain(new Insert[0])));
		AccessControlItem aci = this.accessManager.getApplicableACI(new DN("ou=users,dc=domain,dc=com"),null,'v',chain); 
		if (aci == null || aci.getNum() != 3) {
			fail("invalid aci : " + aci);
		}
	}
	
	public void testNoBindEntry() throws Exception {
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName(""),new Password(""),0,new InsertChain(new Insert[0]),new HashMap<Object,Object>(),new HashMap<Object,Object>(),new Router(new InsertChain(new Insert[0])));
		AccessControlItem aci = this.accessManager.getApplicableACI(new DN("uid=testuser,ou=users,dc=domain,dc=com"),null,'v',chain); 
		if (aci == null || aci.getNum() != 0) {
			fail("invalid aci : " + aci);
		}
	}
	
	public void testNoBindAttribs() throws Exception {
		
		SearchInterceptorChain chain = new SearchInterceptorChain(new DistinguishedName(""),new Password(""),0,new InsertChain(new Insert[0]),new HashMap<Object,Object>(),new HashMap<Object,Object>(),new Router(new InsertChain(new Insert[0])));
		AccessControlItem aci = this.accessManager.getApplicableACI(new DN("uid=testuser,ou=users,dc=domain,dc=com"),"name",'r',chain); 
		if (aci == null || aci.getNum() != 4) {
			fail("invalid aci : " + aci);
		}
	}
	
	
}
