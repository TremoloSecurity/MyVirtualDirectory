package net.sourceforge.myvd.test.jdbc;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPLocalException;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.LDIFReader;

import net.sourceforge.myvd.server.Server;
import net.sourceforge.myvd.test.util.Util;
import junit.framework.TestCase;

public class TestDBGroup extends TestCase {

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
		
		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DBAdapter-Simple/derby-groups.sql")));
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
		
		this.server = new Server(System.getenv("PROJ_DIR") + "/test/DBAdapter-Simple/myvd-dbgroups.props");
		this.server.startServer();
	}

	
	public void testStartServer() {
		//System.out.println("");
	}
	
	public void testBaseSearch() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPSearchResults res = con.search("cn=1,dc=nam,dc=compinternal,dc=com", 0, "(objectClass=*)", new String[] {}, false);
		this.checkSearch(res, "groupBaseSearch.ldif");
		
	}
	
	public void testWildcardSearchSubtree() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com", 2, "(uniqueMember=Marc*)", new String[] {}, false);
		this.checkSearch(res, "groupBaseSearch.ldif");
		
	}
	
	public void testWildcardSearchOneLevel() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("localhost", 50983);
		
		LDAPSearchResults res = con.search("dc=nam,dc=compinternal,dc=com", 1, "(uniqueMember=Marc*)", new String[] {}, false);
		this.checkSearch(res, "groupBaseSearch.ldif");
		
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		this.server.stopServer();
		
		
		try {
			DriverManager.getConnection("jdbc:derby:;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
	}
	
	private String checkSearch(LDAPSearchResults res, String ldifName) throws LDAPException,
			IOException, LDAPLocalException, FileNotFoundException {
		
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/DBAdapter-Simple/ldif/" + ldifName));
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

}
