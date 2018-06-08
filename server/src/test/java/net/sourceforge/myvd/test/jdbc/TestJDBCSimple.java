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

public class TestJDBCSimple extends TestCase {

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
		Connection con = DriverManager.getConnection("jdbc:derby:dbsimple;create=true");
		
		Statement stmt = con.createStatement();
		
		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DBAdapter-Simple/derby.sql")));
		String line;
		
		while ((line = in.readLine()) != null) {
			stmt.executeUpdate(line);
		}
		
		in.close();
		
		try {
			DriverManager.getConnection("jdbc:derby:myvdPosix;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
		
		
		/*File dbdatalog = new File(System.getenv("PROJ_DIR") + "/test/DBAdapter-Simple/dbdata.log");
		File dbdata = new File(System.getenv("PROJ_DIR") + "/test/DBAdapter-Simple/dbdata.script.orig");
		File dbdatascript = new File(System.getenv("PROJ_DIR") + "/test/DBAdapter-Simple/dbdata.script");
		
		if (dbdatascript.exists()) {
			dbdatascript.delete();
		}
		
		if (dbdatalog.exists()) {
			dbdatalog.delete();
		}
		
		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(dbdata)));
		PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(dbdatascript)));
		String line;
		
		while ((line = in.readLine()) != null) {
			out.println(line);
		}
		
		in.close();
		out.close();
		*/
		
		this.server = new Server(System.getenv("PROJ_DIR") + "/test/DBAdapter-Simple/vldap.props");
		this.server.startServer();
	}

	public void testStartup() {
		//do notthing
		//System.out.println("");
	}
	
	public void testSearchNoAttribsFilter() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(uid=aa*)",new String[] {"1.1"},false);
		
		
		 
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		/*
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));*/
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		LDAPEntry fromServer = res.next();
		if (! util.compareEntry(entry,fromServer)) {
			fail("2nd entry failed : \n" + util.toLDIF(fromServer));
		}
		
	}
	
	public void testAllUsersNoWhereOrder() throws LDAPException {
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
		
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjackson"));
		attribs.add(new LDAPAttribute("givenname","Jack"));
		attribs.add(new LDAPAttribute("sn","Jackson"));
		
		entry = new LDAPEntry("uid=jjackson,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("1st entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("2nd entry failed");
		}
		
		
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjeffords"));
		attribs.add(new LDAPAttribute("givenname","Jen"));
		attribs.add(new LDAPAttribute("sn","Jeffords"));
		
		entry = new LDAPEntry("uid=jjeffords,dc=nam,dc=compinternal,dc=com",attribs);
		
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
	
	
	public void testSimpleSearchNoWhereOrder() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(sn=Alberts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
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
	
	public void testSimpleCaseFilter() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(Sn=Alberts)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
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
	
	public void testSimpleCaseAttrib() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com",2,"(Sn=Alberts)",new String[] {"objectclass","UiD","givenNamE","Sn"},false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","aalberts"));
		attribs.add(new LDAPAttribute("givenname","Al"));
		attribs.add(new LDAPAttribute("sn","Alberts"));
		
		LDAPEntry entry = new LDAPEntry("uid=aalberts,dc=nam,dc=compinternal,dc=com",attribs);
		
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
	
	public void testAllUsersWhereOrder() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam1,dc=compinternal,dc=com",2,"(objectClass=*)",new String[0],false);
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","domain"));
		attribs.add(new LDAPAttribute("dc","nam1"));
		
		LDAPEntry entry = new LDAPEntry("dc=nam1,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("base entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjeffords"));
		attribs.add(new LDAPAttribute("givenname","Jen"));
		attribs.add(new LDAPAttribute("sn","Jeffords"));
		
		entry = new LDAPEntry("uid=jjeffords,dc=nam1,dc=compinternal,dc=com",attribs);
		
		
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("2st entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjackson"));
		attribs.add(new LDAPAttribute("givenname","Jack"));
		attribs.add(new LDAPAttribute("sn","Jackson"));
		
		entry = new LDAPEntry("uid=jjackson,dc=nam1,dc=compinternal,dc=com",attribs);
		
		
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
	
	
	public void testSimpleSearchWhereOrder() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam1,dc=compinternal,dc=com",2,"(sn=Jeffords)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjeffords"));
		attribs.add(new LDAPAttribute("givenname","Jen"));
		attribs.add(new LDAPAttribute("sn","Jeffords"));
		
		LDAPEntry entry = new LDAPEntry("uid=jjeffords,dc=nam1,dc=compinternal,dc=com",attribs);
		
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
	
	public void testAllUsersWhereNoOrder() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam2,dc=compinternal,dc=com",2,"(objectClass=*)",new String[0],false);
		
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","domain"));
		attribs.add(new LDAPAttribute("dc","nam2"));
		
		LDAPEntry entry = new LDAPEntry("dc=nam2,dc=compinternal,dc=com",attribs);
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("base entry failed");
		}
		

		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjackson"));
		attribs.add(new LDAPAttribute("givenname","Jack"));
		attribs.add(new LDAPAttribute("sn","Jackson"));
		
		entry = new LDAPEntry("uid=jjackson,dc=nam2,dc=compinternal,dc=com",attribs);
		
		
		
		if (! res.hasMore()) {
			fail("entries not returned");
			return;
		}
		
		if (! util.compareEntry(entry,res.next())) {
			fail("2st entry failed");
		}
		
		attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjeffords"));
		attribs.add(new LDAPAttribute("givenname","Jen"));
		attribs.add(new LDAPAttribute("sn","Jeffords"));
		
		entry = new LDAPEntry("uid=jjeffords,dc=nam2,dc=compinternal,dc=com",attribs);
		
		
		
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
	
	
	public void testSimpleSearchWhereNoOrder() throws LDAPException {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost",50983);
		Util util = new Util();
		LDAPSearchResults res = con.search("dc=nam2,dc=compinternal,dc=com",2,"(sn=Jeffords)",new String[0],false);
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","inetOrgPerson"));
		attribs.add(new LDAPAttribute("uid","jjeffords"));
		attribs.add(new LDAPAttribute("givenname","Jen"));
		attribs.add(new LDAPAttribute("sn","Jeffords"));
		
		LDAPEntry entry = new LDAPEntry("uid=jjeffords,dc=nam2,dc=compinternal,dc=com",attribs);
		
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
			DriverManager.getConnection("jdbc:derby:;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
		
		//Thread.sleep(10000);
	}

}
