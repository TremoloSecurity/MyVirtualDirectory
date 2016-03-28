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
package net.sourceforge.myvd.test.adposix;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPLocalException;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.LDIFReader;

import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import junit.framework.TestCase;

public class ADPosix extends TestCase {

	private StartOpenLDAP simAd;
	private StartMyVD server;
	
	
	private void deleteDir(File path) {
		
		if (path.isDirectory()) {
			File[] children = path.listFiles();
			for (int i=0,m=children.length;i<m;i++) {
				deleteDir(children[i]);
			}
			path.delete();
		} else {
			path.delete();
		}
	}
	
	protected void setUp() throws Exception {
		super.setUp();
		
		System.getProperties().setProperty("derby.system.home", System.getenv("PROJ_DIR") + "/test/derbyHome");
		
		deleteDir(new File(System.getenv("PROJ_DIR") + "/test/derbyHome"));
		
		(new File(System.getenv("PROJ_DIR") + "/test/derbyHome")).mkdir();
		
		
		Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();
		Connection con = DriverManager.getConnection("jdbc:derby:myvdPosix;create=true");
		con.createStatement().execute("CREATE TABLE posixUsers (id int GENERATED ALWAYS AS IDENTITY (START WITH 500, INCREMENT BY 1),objectGuid varchar(255),homeDirectory varchar(255),loginShell varchar(255))");
		con.createStatement().execute("CREATE TABLE posixGroups (id int GENERATED ALWAYS AS IDENTITY (START WITH 500, INCREMENT BY 1),objectGuid varchar(255))");
		con.close();
		
		try {
			DriverManager.getConnection("jdbc:derby:myvdPosix;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
		
		simAd = new StartOpenLDAP();
		simAd.startServer(System.getenv("PROJ_DIR") + "/test/ADPosixSim",10983,"cn=administrator,cn=users,dc=test,dc=mydomain,dc=com","p@ssw0rd");
		
		this.server = new StartMyVD();
		this.server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/ad-join-posix-comp-derby.conf",50983);
	}

	public void testStartup() {
		boolean x = true;
		x=x;
	}
	
	public void testLinuxLogin() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		//need to pre-search to keep the numeric ids
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
		checkSearch(res,"fulldir.ldif");
		
		//nismap test
		res = con.search("cn=users,o=mycompany,c=us", 2, "(&(objectclass=nisMap)(nisMapName=auto.master))", new String[]{"1.1"}, false);
		if (res.hasMore()) {
			fail("Should be no resutls");
		}
		
		//system account, not existant
		res = con.search("cn=users,o=mycompany,c=us", 2, "(&(objectClass=posixAccount)(uid=gdm))", new String[]{}, false);
		if (res.hasMore()) {
			fail("Should be no resutls");
		}
		
		//system acount's group, non existant
		res = con.search("cn=users,o=mycompany,c=us", 2, "(&(objectClass=posixGroup)(memberUid=gdm))", new String[]{"gidNumber"}, false);
		if (res.hasMore()) {
			fail("Should be no resutls");
		}
		
		//user typed in their username
		res = con.search("cn=users,o=mycompany,c=us",2,"(uid=mlb)",new String[] {},false);
		String str = this.checkSearch(res, "uidSearch.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		//search and bind
		res = con.search("cn=users,o=mycompany,c=us",2,"(uid=mlb)",new String[] {},false);
		res.hasMore();
		LDAPEntry entry = res.next();
		String dn = entry.getDN();
		
		if(res.hasMore()) {
			fail("more then one user returned");
		}
		
		con.bind(3,dn, "mlbsecret".getBytes());
		
		//rebind as anon
		con.bind(3, "", new byte[0]);
		
		
		res = con.search("cn=users,o=mycompany,c=us", 2, "(&(objectClass=posixAccount)(uidNumber=505))", new String[] {"uid","uidNumber","gidNumber","cn","homeDirectory","loginShell","gecos","description","objectClass","userPassword"}, false);
		str = this.checkSearch(res, "uidNumberSearch.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		res = con.search("cn=users,o=mycompany,c=us",2,"(&(objectClass=posixAccount)(uid=mlb))",new String[] {},false);
		str = this.checkSearch(res, "uidSearch.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		//group memberships?
		res = con.search("cn=users,o=mycompany,c=us",2,"(&(objectClass=posixGroup)(|(memberUid=mlb)(uniqueMember=cn=Marc Boorshtein,cn=Users,o=mycompany,c=us)))",new String[] {"gidNumber"},false);
		str = this.checkSearch(res, "groupMemberships.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		
		
		con.disconnect();
		
	}
	
	public void testLinuxDirectoryListing() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		//need to pre-search to keep the numeric ids
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
		String str = checkSearch(res,"fulldir.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		con.bind(3,"", "".getBytes());
		
		res = con.search("cn=users,o=mycompany,c=us", 2, "(&(objectClass=posixAccount)(uidNumber=505))", new String[] {"uid", "userPassword", "uidNumber", "gidNumber", "cn", "homeDirectory", "loginShell", "gecos", "description", "objectClass"}, false);
		str = checkSearch(res,"uidNumberSearch.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		res = con.search("cn=users,o=mycompany,c=us", 2, "(&(objectClass=posixGroup)(gidNumber=500))", new String[] {"cn", "userPassword", "memberUid", "uniqueMember", "gidNumber"}, false);
		str = checkSearch(res,"gidNumberSearch.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		//Does the group have sub-groups? -- test only 1
		res = con.search("cn=Administrator,cn=Users,o=mycompany,c=us",0,"(objectClass=*)",new String[] {"uid","uniqueNumber","objectClass"},false);
		str = this.checkSearch(res, "groupHasGroups.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		con.disconnect();
	}
	
	
	public void testSearchJoined() throws Exception {
		
		
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
		String str = checkSearch(res,"fulldir.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		con.disconnect();
		
	}

	private String checkSearch(LDAPSearchResults res, String ldifName) throws LDAPException,
			IOException, LDAPLocalException, FileNotFoundException {
		
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/ADPosixSim/test-ldifs/" + ldifName));
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
	
	public void testLinuxSudo() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
		String str = checkSearch(res,"fulldir.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		res = con.search("cn=users,o=mycompany,c=us", 2, "(&(objectClass=posixAccount)(uidNumber=505))", new String[] {"uid", "userPassword", "uidNumber", "gidNumber", "cn", "homeDirectory", "loginShell", "gecos", "description", "objectClass"}, false);
		str = checkSearch(res,"uidNumberSearch.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		res = con.search("cn=users,o=mycompany,c=us", 2, "(&(objectClass=posixGroup)(cn=sudoers))", new String[] {"uniqueMember", "uid", "objectClass"}, false);
		str = checkSearch(res,"sudoersSearch.ldif");
		if (str.length() > 0) {
			fail(str);
		}
		
		
		
		con.disconnect();
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.simAd.stopServer();
		try {
			DriverManager.getConnection("jdbc:derby:;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
	}

}
