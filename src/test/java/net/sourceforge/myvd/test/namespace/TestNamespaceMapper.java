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
package net.sourceforge.myvd.test.namespace;


import net.sourceforge.myvd.util.NamingUtils;

import com.novell.ldap.util.DN;

import junit.framework.TestCase;



import com.novell.ldap.util.DN;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class TestNamespaceMapper  {

	@Test
	public void testNSRemoteSameLen() {
		NamingUtils utils = new NamingUtils();
		DN localBase = new DN("o=mycompany,c=us");
		DN remoteBase = new DN("dc=domain,dc=com");
		DN local = new DN("cn=user,ou=test,o=mycompany,c=us");
		DN mapped = utils.getRemoteMappedDN(local,localBase.explodeDN(false),remoteBase.explodeDN(false));
		
		if (! mapped.toString().equalsIgnoreCase("cn=user,ou=test,dc=domain,dc=com")) {
			fail("invalid remote base : " + mapped);
		}
		
	}
	
	@Test
	public void testNSRemoteGreaterLen() {
		NamingUtils utils = new NamingUtils();
		DN localBase = new DN("ou=joined");
		DN remoteBase = new DN("dc=domain,dc=com");
		DN local = new DN("cn=user,ou=test,ou=joined");
		DN mapped = utils.getRemoteMappedDN(local,localBase.explodeDN(false),remoteBase.explodeDN(false));
		
		if (! mapped.toString().equalsIgnoreCase("cn=user,ou=test,dc=domain,dc=com")) {
			fail("invalid remote base : " + mapped);
		}
		
	}
	
	@Test
	public void testNSRemoteLessLen() {
		NamingUtils utils = new NamingUtils();
		DN localBase = new DN("o=mycompany,c=us");
		DN remoteBase = new DN("ou=joined");
		DN local = new DN("cn=user,ou=test,o=mycompany,c=us");
		DN mapped = utils.getRemoteMappedDN(local,localBase.explodeDN(false),remoteBase.explodeDN(false));
		
		if (! mapped.toString().equalsIgnoreCase("cn=user,ou=test,ou=joined")) {
			fail("invalid remote base : " + mapped);
		}
		
	}
	
	@Test
	public void testNSLocalSameLen() {
		NamingUtils utils = new NamingUtils();
		DN localBase = new DN("o=mycompany,c=us");
		DN remoteBase = new DN("dc=domain,dc=com");
		DN remote = new DN("cn=user,ou=test,dc=domain,dc=com");
		DN mapped = utils.getLocalMappedDN(remote,remoteBase.explodeDN(false),localBase.explodeDN(false));
		
		if (! mapped.toString().equalsIgnoreCase("cn=user,ou=test,o=mycompany,c=us")) {
			fail("invalid remote base : " + mapped);
		}
		
	}
	@Test
	public void testNSLocalGreaterLen() {
		NamingUtils utils = new NamingUtils();
		DN localBase = new DN("o=joined");
		DN remoteBase = new DN("dc=domain,dc=com");
		DN remote = new DN("cn=user,ou=test,dc=domain,dc=com");
		DN mapped = utils.getLocalMappedDN(remote,remoteBase.explodeDN(false),localBase.explodeDN(false));
		
		if (! mapped.toString().equalsIgnoreCase("cn=user,ou=test,o=joined")) {
			fail("invalid remote base : " + mapped);
		}
		
	}
	@Test
	public void testNSLocalLessLen() {
		NamingUtils utils = new NamingUtils();
		DN localBase = new DN("o=mycompany,c=us");
		DN remoteBase = new DN("ou=joined");
		DN remote = new DN("cn=user,ou=test,ou=joined");
		DN mapped = utils.getLocalMappedDN(remote,remoteBase.explodeDN(false),localBase.explodeDN(false));
		
		if (! mapped.toString().equalsIgnoreCase("cn=user,ou=test,o=mycompany,c=us")) {
			fail("invalid remote base : " + mapped);
		}
		
	}
}
