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
package net.sourceforge.myvd.test.jdbc;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.util.Util;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchResults;

import junit.framework.TestCase;

public class TestJDBCUid extends TestCase {

	Server server;
	
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
		Connection con = DriverManager.getConnection("jdbc:derby:dbuid;create=true");
		
		Statement stmt = con.createStatement();
		
		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DBAdapterUID/derby.sql")));
		String line;
		
		while ((line = in.readLine()) != null) {
			stmt.executeUpdate(line);
		}
		
		in.close();
		
		try {
			DriverManager.getConnection("jdbc:derby:dbuid;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
		
		
		this.server = new Server(System.getenv("PROJ_DIR") + "/test/DBAdapterUID/vldap.props");
		this.server.startServer();
	}

	public void testStartup() {
		//do notthing
	}
	
	public void testSimpleSearchAttrs() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(uid=aalberts)",new String[] {"cn","uid"},false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		LDAPEntry entry2 = res.next();
		if (! util.compareEntry(entry,entry2)) {
			fail("1st entry failed : " + entry2);
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	public void testSimpleSearchUIDSubstr3() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(uid=*erts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	public void testSimpleSearchUIDSubstr2() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(uid=a*erts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	/*public void testSimpleSearchUIDSubstr1() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(uid=*alberts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
	}
	*/
	
	public void testSimpleSearchCNSubstr1() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(cn=A*Alberts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	public void testSimpleSearchCNSubstr2() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(cn=*Alberts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	public void testAllUsers() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(objectClass=*)",new String[0],false);
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","domain"));
		attribs.add(new LDAPAttribute("dc","nam"));
		
		LDAPEntry entry = new LDAPEntry("dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("base entry failed");
		}
		
		
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","Boston"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjackson"));
		attribs.add(new LDAPAttribute("empid","1"));
		attribs.add(new LDAPAttribute("givenname","Jack"));
		attribs.add(new LDAPAttribute("sn","Jackson"));
		attribs.add(new LDAPAttribute("cn","Jack Jackson"));
		
		entry = new LDAPEntry("empid=1,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("2st entry failed");
		}	
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","Syracuse"));
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjeffords"));
		attribs.add(new LDAPAttribute("empid","3"));
		attribs.add(new LDAPAttribute("givenname","Jen"));
		attribs.add(new LDAPAttribute("sn","Jeffords"));
		attribs.add(new LDAPAttribute("cn","Jen Jeffords"));
		
		entry = new LDAPEntry("empid=3,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("3rd entry failed");
		}
		
		if (res.hasMore()) {
			fail("too many entries " + res.next().toString() );
		}
		
		con.disconnect();
	}
	
	
	public void testSimpleSearch() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(uid=aalberts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	public void testSimpleSearchCN() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(cn=Al Alberts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	public void testANDSearch() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(&(l=NY)(l=LA)(uid=aalberts))",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	
		
	public void testBaseSearchObject() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("empid=2,dc=nam,dc=compinternal,dc=com",0,"(objectClass=*)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	public void testSubtreeFromUser() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("empid=2,dc=nam,dc=compinternal,dc=com",2,"(objectClass=*)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("l","LA"));
		attribs.getAttribute("l").addValue("NY");
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("empid","2"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		attribs.add(new LDAPAttribute("cn","Al Alberts"));
		
		LDAPEntry entry = new LDAPEntry("empid=2,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		
		
		
		
		if (res.hasMore()) {
			fail("too many entries");
		}
		
		con.disconnect();
	}
	
	
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
		
		try {
			DriverManager.getConnection("jdbc:derby:dbuid;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
		//Thread.sleep(10000);
	}

}
