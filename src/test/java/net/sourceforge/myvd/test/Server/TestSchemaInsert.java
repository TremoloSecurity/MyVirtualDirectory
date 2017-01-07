package net.sourceforge.myvd.test.Server;

import java.io.FileInputStream;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.LDIFReader;

import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.Util;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class TestSchemaInsert  {

	private static StartMyVD server;
	
	@BeforeClass
	public static void setUp() throws Exception {
		
		
		server = new StartMyVD();
		server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/testSchema.conf",50983);
	}
	
	@AfterClass
	public static void shutDown() throws Exception {
		server.stopServer();
	}
	
	@Test
	public void testStartup() throws Exception {
		int x = 1;
	}
	
	@Test
	public void testReadSchema() throws Exception {
		LDAPConnection con = new LDAPConnection();
		con.connect("127.0.0.1", 50983);
		LDAPSearchResults res = con.search("cn=schema", 0, "(objectClass=*)", new String[0], false);
		res.hasMore();
		LDAPEntry fromserver = res.next();
		con.disconnect();
		
		LDIFReader reader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/dist/conf/openldap_schema.ldif"));
		Util util = new Util();
		LDAPMessage msg = reader.readMessage();
		if (msg == null) {
			fail("number of results dont match");
			return;
		}
		
		
		LDAPEntry fromldif = ((LDAPSearchResult) msg).getEntry();
		if (! util.compareEntry(fromserver, fromldif)) {
			fail("Entries don't match\n from server: \n" + util.toLDIF(fromserver) + "\nfromldif:\n" + util.toLDIF(fromldif));
		}
				
	}
	
	
}
