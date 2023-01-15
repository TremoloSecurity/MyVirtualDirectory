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
package net.sourceforge.myvd.test.ldap;

import java.io.FileInputStream;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.LDIFReader;

import net.sourceforge.myvd.test.util.StartApacheDS;
import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenDS;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.AfterClass;
import static org.junit.Assert.*;

@Ignore
public class TestStaticDNMap  {

	
	private static StartMyVD server2;
	private static StartOpenDS opends;

	@BeforeClass
	public static void setUp() throws Exception {
		
		
		
		opends = new StartOpenDS();
		opends.startServer(System.getenv("PROJ_DIR") + "/test/EmbeddedGroups",12389,"cn=Directory Manager","secret");
		
		server2 = new StartMyVD();
		server2.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/staticdnmap.conf",50983);
		
		
	}

	@Test
	public void testStartup() {
		//do nothing
	}
	
	
	@Test
	public void testValidateNonPrived() throws Exception {
		//this should fail
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		try {
			con.delete("uid=tuser1,ou=people,dc=domain,dc=com");
			fail("Should not be able to delete");
		} catch (LDAPException e) {
			//worked
		} finally {
			con.disconnect();
		}
		
		
	}
	
	@Test
	public void testBindAsSysUser() throws Exception {
		//this should fail
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		try {
			con.bind(3,"uid=apacheadmin,dc=domain,dc=com", "secret".getBytes());
		
		
			con.delete("uid=tuser1,ou=people,dc=domain,dc=com");
			
		} catch (LDAPException e) {
			throw e;
		} finally {
			con.disconnect();
		}
		
		
	}
	
	@AfterClass
	public static void tearDown() throws Exception {
		
		
		server2.stopServer();
		opends.stopServer();
	}

}

