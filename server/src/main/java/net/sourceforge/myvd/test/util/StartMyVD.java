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
package net.sourceforge.myvd.test.util;

import java.io.*;
import java.util.HashMap;

import net.sourceforge.myvd.server.Server;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPLocalException;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.util.LDIFReader;

public class StartMyVD {
	
	static HashMap<Integer,StartMyVD> servers = new HashMap<Integer,StartMyVD>();
	
	Server server;
	int port;

	private String apachedsPath;
	
	public void stopServer() throws Exception {
		if (this.server != null) {
			this.server.stopServer();
		}
		
		for (int i=0,m=100;i<m;i++) {
			try {
				LDAPConnection con = new LDAPConnection();
				con.connect("127.0.0.1",port);
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					
				}
			} catch (LDAPException e) {
				servers.remove(port);
				break;
			}
		}
		
		
		
	}
	
	
	private void deletePath(File f) {
		if (f.isFile()) {
			f.delete();
		} else {
			if (f.listFiles() != null) {
				for (File ff : f.listFiles()) {
					deletePath(ff);
				}
			}
			
			f.delete();
		}
	}
	
	public boolean startServer(String configFile,int port) throws IOException,Exception {
		
		this.apachedsPath = configFile.substring(0,configFile.lastIndexOf(File.separator) + 1) + "apacheds-data";
		File cfgDir = new File(this.apachedsPath);
		
		if (! cfgDir.exists()) {
			cfgDir.mkdirs();
		}
		
		this.port = port;
		LDAPConnection con = new LDAPConnection();
		try {
			con.connect("localhost",port);
			con.disconnect();
			
			
			if (! servers.containsKey(port)) {
				throw new Exception("Server on port " + port + "not stopped");
			} else {
				servers.get(port).stopServer();
			}
		} catch (LDAPException e) {
			
		} catch (Exception e) {
			throw e;
		}
		
		
		server = new Server(configFile);
		server.startServer();
		
		
		for (int i=0,m=10;i<m;i++) {
			con = new LDAPConnection();
			try {
				con.connect("localhost",port);
				con.disconnect();
				
				
				servers.put(port, this);
				return true;
			} catch (LDAPException e) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e1) {
					//do nothing
				}
			}
		}
		
		return false;
	}
	
	
}

