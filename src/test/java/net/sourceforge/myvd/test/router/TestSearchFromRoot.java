package net.sourceforge.myvd.test.router;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import org.junit.Test;

import net.sourceforge.myvd.server.Server;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

public class TestSearchFromRoot  {

	static Server  server;
	
	private static void deleteDir(File path) {
		
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
	
	@BeforeClass
	public static void setUp() throws Exception {
		
		
		System.getProperties().setProperty("derby.system.home", System.getenv("PROJ_DIR") + "/test/derbyHome");
		
		deleteDir(new File(System.getenv("PROJ_DIR") + "/test/derbyHome"));
		
		(new File(System.getenv("PROJ_DIR") + "/test/derbyHome")).mkdir();
		
		
		Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();
		Connection con = DriverManager.getConnection("jdbc:derby:dbdb;create=true");
		
		Statement stmt = con.createStatement();
		
		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/FromRoot/derby.sql")));
		String line;
		
		while ((line = in.readLine()) != null) {
			stmt.executeUpdate(line);
		}
		
		in.close();
		
		try {
			DriverManager.getConnection("jdbc:derby:dbdb;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
		
		
		server = new Server(System.getenv("PROJ_DIR") + "/test/FromRoot/myvd-db.conf");
		server.startServer();
	}
	
	@AfterClass
	public static void tearDown() throws Exception {
		server.stopServer();
		
		try {
			DriverManager.getConnection("jdbc:derby:dbdb;shutdown=true");
		} catch (Throwable t) {
			//ignore?
		}
	}
	
	@Test
	public void testStartup() {
		//System.out.println();
	}

}
