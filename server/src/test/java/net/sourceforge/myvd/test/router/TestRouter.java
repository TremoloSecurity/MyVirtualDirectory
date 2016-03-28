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

import java.util.Iterator;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Level;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;

import com.novell.ldap.util.DN;

import junit.framework.TestCase;

public class TestRouter extends TestCase {
	public void testAddNamespaces() {
		NameSpace root = new NameSpace("root",new DistinguishedName("dc=domain,dc=com"),0,null,false);
		NameSpace internal = new NameSpace("internal",new DistinguishedName("ou=internal,dc=domain,dc=com"),10,null,false);
		NameSpace external = new NameSpace("external",new DistinguishedName("ou=external,dc=domain,dc=com"),15,null,false);
		
		
		Router router = new Router(new InsertChain(new Insert[0]));
		router.addBackend(root.getLabel(),root.getBase().getDN(),root);
		router.addBackend(internal.getLabel(),internal.getBase().getDN(),internal);
		router.addBackend(external.getLabel(),external.getBase().getDN(),external);
		
		checkRouts(router);
		
	}
	
	public void testAddNamespacesRev() {
		NameSpace root = new NameSpace("root",new DistinguishedName("dc=domain,dc=com"),0,null,false);
		NameSpace internal = new NameSpace("internal",new DistinguishedName("ou=internal,dc=domain,dc=com"),10,null,false);
		NameSpace external = new NameSpace("external",new DistinguishedName("ou=external,dc=domain,dc=com"),15,null,false);
		
		
		Router router = new Router(new InsertChain(new Insert[0]));
		router.addBackend(root.getLabel(),root.getBase().getDN(),root);
		router.addBackend(external.getLabel(),external.getBase().getDN(),external);
		router.addBackend(internal.getLabel(),internal.getBase().getDN(),internal);
		
		
		checkRouts(router);
		
	}

	private void checkRouts(Router router) {
		Iterator<DN> it = router.getSubtree().keySet().iterator();
		
		while (it.hasNext()) {
			DN curr = it.next();
			Level level = router.getSubtree().get(curr);
			
			
			this.checkLevel(curr,level);
			
		}
	}
	
	private void checkLevel(DN curr,Level level) {
		if (curr.equals(new DN("dc=com"))) {
			if (level.backends.size() != 3) {
				fail("incorrect backends for dc=com");
				return;
			}
			
			if (! level.backends.get(0).getLabel().equals("root")) {
				fail("First backend not root : " + level.backends.get(0).getLabel());
				return;
			}
			
			if (! level.backends.get(1).getLabel().equals("external")) {
				fail("First backend not external : " + level.backends.get(1).getLabel());
				return;
			}
			
			if (! level.backends.get(2).getLabel().equals("internal")) {
				fail("First backend not internal : " + level.backends.get(2).getLabel());
				return;
			}
		}
		
		if (curr.equals(new DN("dc=domain,dc=com"))) {
			if (level.backends.size() != 3) {
				fail("incorrect backends for dc=com");
				return;
			}
			
			if (! level.backends.get(0).getLabel().equals("root")) {
				fail("First backend not root : " + level.backends.get(0).getLabel());
				return;
			}
			
			if (! level.backends.get(1).getLabel().equals("external")) {
				fail("First backend not external : " + level.backends.get(1).getLabel());
				return;
			}
			
			if (! level.backends.get(2).getLabel().equals("internal")) {
				fail("First backend not internal : " + level.backends.get(2).getLabel());
				return;
			}
		}
		
		if (curr.equals(new DN("ou=external,dc=domain,dc=com"))) {
			if (level.backends.size() != 1) {
				fail("incorrect backends for dc=com");
				return;
			}
			
			
			if (! level.backends.get(0).getLabel().equals("external")) {
				fail("First backend not external : " + level.backends.get(0).getLabel());
				return;
			}
		}
		
		if (curr.equals(new DN("ou=internal,dc=domain,dc=com"))) {
			if (level.backends.size() != 1) {
				fail("incorrect backends for dc=com");
				return;
			}
			
			
			if (! level.backends.get(0).getLabel().equals("internal")) {
				fail("First backend not internal : " + level.backends.get(0).getLabel());
				return;
			}
		}
	}
	
	public void testSearchNamespaces() {
		NameSpace root = new NameSpace("root",new DistinguishedName("dc=domain,dc=com"),0,null,false);
		NameSpace internal = new NameSpace("internal",new DistinguishedName("ou=internal,dc=domain,dc=com"),10,null,false);
		NameSpace external = new NameSpace("external",new DistinguishedName("ou=external,dc=domain,dc=com"),15,null,false);
		
		
		Router router = new Router(new InsertChain(new Insert[0]));
		router.addBackend(root.getLabel(),root.getBase().getDN(),root);
		router.addBackend(external.getLabel(),external.getBase().getDN(),external);
		router.addBackend(internal.getLabel(),internal.getBase().getDN(),internal);
		
		this.checkLevel(new DN("dc=com"),router.getLevel(new DN("dc=com")));
		this.checkLevel(new DN("dc=domain,dc=com"),router.getLevel(new DN("dc=domain,dc=com")));
		this.checkLevel(new DN("ou=external,dc=domain,dc=com"),router.getLevel(new DN("ou=external,dc=domain,dc=com")));
		this.checkLevel(new DN("ou=internal,dc=domain,dc=com"),router.getLevel(new DN("ou=internal,dc=domain,dc=com")));
		
	}
	
	public void testSearchNamespacesRev() {
		NameSpace root = new NameSpace("root",new DistinguishedName("dc=domain,dc=com"),0,null,false);
		NameSpace internal = new NameSpace("internal",new DistinguishedName("ou=internal,dc=domain,dc=com"),10,null,false);
		NameSpace external = new NameSpace("external",new DistinguishedName("ou=external,dc=domain,dc=com"),15,null,false);
		
		
		Router router = new Router(new InsertChain(new Insert[0]));
		router.addBackend(root.getLabel(),root.getBase().getDN(),root);
		router.addBackend(internal.getLabel(),internal.getBase().getDN(),internal);
		router.addBackend(external.getLabel(),external.getBase().getDN(),external);
		
		
		this.checkLevel(new DN("dc=com"),router.getLevel(new DN("dc=com")));
		this.checkLevel(new DN("dc=domain,dc=com"),router.getLevel(new DN("dc=domain,dc=com")));
		this.checkLevel(new DN("ou=external,dc=domain,dc=com"),router.getLevel(new DN("ou=external,dc=domain,dc=com")));
		this.checkLevel(new DN("ou=internal,dc=domain,dc=com"),router.getLevel(new DN("ou=internal,dc=domain,dc=com")));
		
	}
}
