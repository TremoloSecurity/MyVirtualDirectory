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
package net.sourceforge.myvd.test.join;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;



import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.LDIFReader;

import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import junit.framework.TestCase;

import net.sourceforge.myvd.test.util.Util;

public class TestJoin extends TestCase {

	private StartOpenLDAP server;
	private StartMyVD myvd;

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
		
		/*File dbdatalog = new File(System.getenv("PROJ_DIR") + "/test/TestJoin/db/joindb.log");
		File dbdata = new File(System.getenv("PROJ_DIR") + "/test/TestJoin/db/joindb.script.orig");
		File dbdatascript = new File(System.getenv("PROJ_DIR") + "/test/TestJoin/db/joindb.script");
		
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
		
		System.getProperties().setProperty("derby.system.home", System.getenv("PROJ_DIR") + "/test/derbyHome");
		
		deleteDir(new File(System.getenv("PROJ_DIR") + "/test/derbyHome"));
		
		(new File(System.getenv("PROJ_DIR") + "/test/derbyHome")).mkdir();
		
		
		Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();
		Connection con = DriverManager.getConnection("jdbc:derby:myvdTestJoin;create=true");
		con.createStatement().execute("CREATE TABLE APPDATA(USERNAME VARCHAR(50),APPATTRIB1 VARCHAR(50),APPATTRIB2 VARCHAR(50))");
		con.createStatement().execute("INSERT INTO APPDATA VALUES('user1','sysx','app-g')");
		con.createStatement().execute("INSERT INTO APPDATA VALUES('user2','sysy','app-g')");
		con.createStatement().execute("INSERT INTO APPDATA VALUES('user3','sysx','app-i')");
		con.close();
		
		try {
			DriverManager.getConnection("jdbc:derby:myvdTestJoin;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
		
		this.server = new StartOpenLDAP();
		this.server.startServer(
				System.getenv("PROJ_DIR") + "/test/TestJoin/ldap", 10983,
				"cn=admin,dc=domain,dc=com", "manager");
		
		this.myvd = new StartMyVD();
		this.myvd.startServer(System.getenv("PROJ_DIR") + "/test/TestJoin/myvd.conf",50983);
		
	}

	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
		this.myvd.stopServer();
		
		try {
			DriverManager.getConnection("jdbc:derby:myvdTestJoin;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
	}
	
	public void testStartup() {
		//do nothing
		//System.out.println();
		
	}
	
	public void testAdd() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/joinadd.ldif"));
		LDAPEntry toadd = ((LDAPSearchResult) reader.readMessage()).getEntry();
		
		con.add(toadd);
		
		LDAPSearchResults res = con.search("uid=user4,ou=people,o=mycompany,c=us", 0, "(objectClass=*)", new String[0], false);
		reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/afterAdd.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : \nFrom Server\n" + Util.toLDIF(fromserver) + "\n\nFrom LDIF\n" + Util.toLDIF(fromldif));
			}
			
		}
		
		con.delete("uid=user4,ou=people,o=mycompany,c=us");
		
		con.disconnect();
	}
	
	public void testSearchWholeTree() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/wholeTree.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		con.disconnect();
	}
	
	public void testSearchPrimary() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2, "(cn=Test User2)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/filterPrimary.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		con.disconnect();
	}
	
	public void testSearchJoined() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2, "(appattrib1=sysx)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/filterJoined.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match \nfrom server\n" + Util.toLDIF(fromserver) + "\n\nfrom ldif\n" + Util.toLDIF(fromldif));
			}
			
		}
		
		con.disconnect();
	}
	
	public void testBaseSearch() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("uid=user3,ou=people,o=mycompany,c=us", 0, "(objectClass=*)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/baseSearch.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		con.disconnect();
	}

	public void testSearchPickAttribs() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		LDAPSearchResults res = con.search("o=mycompany,c=us", 2, "(appattrib1=sysx)", new String[] {"cn","appattrib1","appattrib2"}, false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/pickAttribs.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		con.disconnect();
	}
	
	public void testModPrimary() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPModification mod = new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute("givenName","TestName"));
		
		con.modify("uid=user3,ou=people,o=mycompany,c=us", mod);
		
		LDAPSearchResults res = con.search("uid=user3,ou=people,o=mycompany,c=us", 0, "(objectClass=*)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/afterModifyPrimary.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		con.disconnect();
	}
	
	public void testModJoined() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPModification mod = new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute("appattrib1","sysy"));
		
		con.modify("uid=user3,ou=people,o=mycompany,c=us", mod);
		
		LDAPSearchResults res = con.search("uid=user3,ou=people,o=mycompany,c=us", 0, "(objectClass=*)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/afterModifyJoined.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		mod = new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute("appattrib1","sysx"));
		
		con.modify("uid=user3,ou=people,o=mycompany,c=us", mod);
		
		con.disconnect();
	}
	
	public void testDelete() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		con.delete("uid=user2,ou=people,o=mycompany,c=us");
		
		LDAPSearchResults res = con.search("ou=people,o=mycompany,c=us", 1, "(objectClass=*)", new String[0], false);
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/TestJoin/ldifs/filterJoined.ldif"));
		Util util = new Util();
		
		while (res.hasMore()) {
			LDAPMessage msg = reader.readMessage();
			if (msg == null) {
				fail("number of results dont match");
				return;
			}
			
			
			LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
			LDAPEntry fromserver = res.next();
			if (! util.compareEntry(fromserver, fromldif)) {
				fail("Entries don't match : " + fromserver + "/" + fromldif);
			}
			
		}
		
		con.disconnect();
	}
	
	
}
