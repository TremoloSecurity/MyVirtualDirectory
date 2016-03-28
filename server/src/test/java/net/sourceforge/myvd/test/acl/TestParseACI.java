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

import net.sourceforge.myvd.inserts.accessControl.AccessControlItem;
import net.sourceforge.myvd.inserts.accessControl.AccessMgr;
import net.sourceforge.myvd.inserts.accessControl.SubjectType;

import com.novell.ldap.util.DN;

import junit.framework.TestCase;

public class TestParseACI extends TestCase {
	
	public void testLoadACIs() throws Exception {
		AccessMgr mgr = new AccessMgr();
		mgr.addACI(new AccessControlItem(1,"cn=test,ou=myorg,dc=domain,dc=com#entry#grant:r,w,o#[all]#public:"));
		mgr.addACI(new AccessControlItem(2,"ou=org,dc=domain,dc=com#subtree#grant:r,w,o#[all]#public:"));
		mgr.addACI(new AccessControlItem(3,"ou=org,dc=domain,dc=com#subtree#grant:v#[entry]#public:"));
		mgr.addACI(new AccessControlItem(4,"dc=domain,dc=com#subtree#grant:v#[entry]#public:"));
		
		mgr.addACI(new AccessControlItem(5,"cn=test,ou=myorg,dc=domain,dc=org#entry#grant:r,w,o#[all]#public:"));
		mgr.addACI(new AccessControlItem(6,"ou=org,dc=domain,dc=org#subtree#grant:r,w,o#[all]#public:"));
		mgr.addACI(new AccessControlItem(7,"ou=org,dc=domain,dc=org#subtree#grant:v#[entry]#public:"));
		mgr.addACI(new AccessControlItem(8,"dc=domain,dc=org#subtree#grant:v#[entry]#public:"));
		
		ArrayList<AccessControlItem> acl = mgr.getACLs(new DN("dc=com"));
		if (acl.get(0).getNum() != 1) {
			fail("invalid aci");
		}
		
		if (acl.get(1).getNum() != 2) {
			fail("invalid aci");
		}
		
		if (acl.get(2).getNum() != 3) {
			fail("invalid aci");
		}
		
		if (acl.get(3).getNum() != 4) {
			fail("invalid aci");
		}
		
		if (acl.size() != 4) {
			fail("invalid aci nums");
		}
		
		acl = mgr.getACLs(new DN("dc=domain,dc=com"));
		if (acl.get(0).getNum() != 1) {
			fail("invalid aci");
		}
		
		if (acl.get(1).getNum() != 2) {
			fail("invalid aci");
		}
		
		if (acl.get(2).getNum() != 3) {
			fail("invalid aci");
		}
		
		if (acl.get(3).getNum() != 4) {
			fail("invalid aci");
		}
		
		if (acl.size() != 4) {
			fail("invalid aci nums");
		}
		
		acl = mgr.getACLs(new DN("ou=myorg,dc=domain,dc=com"));
		if (acl.get(0).getNum() != 1) {
			fail("invalid aci");
		}
		
		if (acl.get(1).getNum() != 4) {
			fail("invalid aci");
		}
		
		
		if (acl.size() != 2) {
			fail("invalid aci nums");
		}
		
	}
	
	
	public void testGetBase() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#grant:r,w,o#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (! aci.getDn().equals(new DN("cn=testbranch,dc=domain,dc=com"))) {
			fail ("wrong dn : " + aci.getDn());
		}
	}
	
	public void testIsSubtree() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#grant:r,w,o#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (! aci.isSubtree()) {
			fail ("is not subtree  ");
		}
	}
	
	public void testIsEntry() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#entry#grant:r,w,o#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (aci.isSubtree()) {
			fail ("is subtree  ");
		}
	}
	
	public void testIsGrant() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#grant:r,w,o#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (! aci.isGrant()) {
			fail ("is not grant  ");
		}
	}
	
	public void testIsDeny() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#deny:r,w,o#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (aci.isGrant()) {
			fail ("is grant ");
		}
	}
	
	public void testIsCorrectAttribPerms() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#deny:r,w,o#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (! aci.isWrite()) {
			fail ("no write ");
		}
		
		if (! aci.isRead()) {
			fail ("no read ");
		}
		
		if (! aci.isObliterate()) {
			fail ("no obliterate ");
		}
	}
	
	public void testIsCorrectEntryPerms() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#deny:a,v#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (! aci.isCreate()) {
			fail ("no create ");
		}
		
		if (! aci.isView()) {
			fail ("no view ");
		}
		
		if (aci.isDelete()) {
			fail ("delete ");
		}
	}
	
	
	public void testIsEntryPerm() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#grant:r,w,o#[entry]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (! aci.isEntryPerms()) {
			fail ("is not entry perms  ");
		}
	}
	
	public void testIsAllAttribsPerm() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#grant:r,w,o#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (! aci.isAllAttributes()) {
			fail ("is not all attribs perms  ");
		}
	}
	
	public void testIsPublic() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#grant:r,w,o#[all]#public:";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (aci.getSubjectType() != SubjectType.PUBLIC) {
			fail ("not public");
		}
	}
	
	public void testIsGroup() throws Exception {
		String aciStr = "cn=testbranch,dc=domain,dc=com#subtree#grant:r,w,o#[all]#group:cn=mygroup,dc=domain,dc=com";
		
		AccessControlItem aci = new AccessControlItem(0,aciStr);
		
		if (aci.getSubjectType() != SubjectType.GROUP) {
			fail ("not public");
		}
		
		if (! aci.getSubjectValue().equalsIgnoreCase("cn=mygroup,dc=domain,dc=com")) {
			fail("invalid subject : " + aci.getSubjectType());
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
