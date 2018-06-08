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
import java.util.Iterator;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPLocalException;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.util.LDIFReader;

public class StartApacheDS {
	
	static HashMap<Integer,StartApacheDS> servers = new HashMap<Integer,StartApacheDS>();
	
	Process process;
	int port;
	
	public void stopServer() throws Exception {
		/*if (this.process != null) {
			this.process.destroy();
		}*/
		
		String exec = System.getenv("PROJ_DIR") + "/test/apacheds102/bin/server.init stop";
		//System.out.println(exec);
		
		
		
		String[] nenv = new String[System.getenv().keySet().size() + 2];
		
		int i=0,m;
		Iterator<String> keyIt = System.getenv().keySet().iterator();
		
		while (keyIt.hasNext()) {
			String key = keyIt.next();
			nenv[i] = key + "=" + System.getenv(key);
			i++;
		}
		
		nenv[i] = "APACHEDS_HOME=" + System.getenv("PROJ_DIR") + "/test/apacheds102";
		i++;
		nenv[i] = "SERVER_HOME=" + System.getenv("PROJ_DIR") + "/test/apacheds102";
		
		process = Runtime.getRuntime().exec(exec,nenv);
		
		StreamReader reader = new StreamReader(process.getInputStream(),false);
		StreamReader errReader = new StreamReader(process.getErrorStream(),false);
		
		reader.start();
		errReader.start();
		
		
		
		for (i=0,m=100;i<m;i++) {
			try {
				LDAPConnection con = new LDAPConnection();
				con.connect("127.0.0.1",port);
				con.disconnect();
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					
				}
			} catch (LDAPException e) {
				servers.remove(port);
				break;
			}
		}
		
		Thread.sleep(10000);
	}
	
	
	private void clearData(String path) {
		String dataPath = path + "/var/partitions";
		File dir = new File(dataPath);
		if (dir.exists()) {
			File[] files = dir.listFiles();
			
			if (files != null) {
				for (int i=0,m=files.length;i<m;i++) {
					if (files[i].isDirectory()) {
						clearDir(files[i].getAbsolutePath());
					}
					files[i].delete();
				}
			}
		} else {
			dir.mkdir();
		}
		
	}
	
	private void clearDir(String dataPath) {
		File dir = new File(dataPath);
		if (dir.exists()) {
			File[] files = dir.listFiles();
			
			if (files != null) {
				for (int i=0,m=files.length;i<m;i++) {
					if (files[i].isDirectory()) {
						clearDir(files[i].getAbsolutePath());
					}
					files[i].delete();
				}
			}
		} 
	}
	
	private void loadLDIF(String path,String adminDN,String adminPass,int port) throws LDAPException, FileNotFoundException, IOException {
		try {
			this.port = port;
			LDAPConnection con = new LDAPConnection();
			con.connect("localhost",port);
			con.bind(3,adminDN,adminPass.getBytes());
			
			//System.out.println(path + "/data-apacheds.ldif");
			
			LDIFReader reader = new LDIFReader(new FileInputStream(path + "/data-apacheds.ldif"));
			
			
			LDAPMessage msg;
			
			while ((msg = reader.readMessage()) != null) {
				System.err.println("Msg : " + msg);
				con.add(((LDAPSearchResult) msg).getEntry());
			}
			
			con.disconnect();
		} catch (LDAPLocalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (LDAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public boolean startServer(String fullPath,int port,String adminDN,String adminPass) throws IOException,Exception {
		return this.startServer(fullPath, port, adminDN, adminPass,0);
	}
	
	private boolean startServer(String fullPath,int port,String adminDN,String adminPass,int num) throws IOException,Exception {
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
		
		clearData(System.getenv("PROJ_DIR") + "/test/apacheds102");
		//this.createTestConf(fullPath);
		String exec = System.getenv("PROJ_DIR") + "/test/apacheds102/bin/server.init start";
		//System.out.println(exec);
		
		
		
		String[] nenv = new String[System.getenv().keySet().size() + 2];
		
		int i=0,m;
		Iterator<String> keyIt = System.getenv().keySet().iterator();
		
		while (keyIt.hasNext()) {
			String key = keyIt.next();
			nenv[i] = key + "=" + System.getenv(key);
			i++;
		}
		
		nenv[i] = "APACHEDS_HOME=" + System.getenv("PROJ_DIR") + "/test/apacheds102";
		i++;
		nenv[i] = "SERVER_HOME=" + System.getenv("PROJ_DIR") + "/test/apacheds102";
		
		process = Runtime.getRuntime().exec(exec,nenv);
		
		StreamReader reader = new StreamReader(process.getInputStream(),true);
		StreamReader errReader = new StreamReader(process.getErrorStream(),false);
		
		reader.start();
		errReader.start();
		
		for (i=0,m=10;i<m;i++) {
			con = new LDAPConnection();
			try {
				con.connect("localhost",port);
				con.disconnect();
				
				this.loadLDIF(fullPath,adminDN,adminPass,port);
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
		
		if (num < 3) {
			Thread.sleep(30000);
			return this.startServer(fullPath, port, adminDN, adminPass, num + 1);
		} else {
			return false;
		}
	}
	
	private void createTestConf(String fullPath) throws IOException {
		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(fullPath + "/slapd.conf")));
		
		StringBuffer buf = new StringBuffer();
		
		String line;
		
		while ((line = in.readLine()) != null) {
			buf.append(line).append('\n');
		}
		
		String tmp = buf.toString().replaceAll("[%]PROJ_DIR[%]", System.getenv("PROJ_DIR"));
		tmp = tmp.replaceAll("[%]SCHEMA_DIR[%]", System.getenv("SCHEMA_DIR"));
		
		PrintWriter out = new PrintWriter(new FileWriter(fullPath + "/slapd-gen.conf"));
		out.println("# GENERATED FILE - DO NOT EDIT");
		out.print(tmp);
		out.close();
		
	}
	
	public static final void main(String[] args) throws Exception {
		StartApacheDS start = new StartApacheDS();
		boolean isStarted = start.startServer(System.getenv("PROJ_DIR") + "/test/EmbeddedGroups",10983,"uid=admin,ou=system","secret");
		
		if (isStarted) {
			//System.out.println("Server started on 10983....");
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			in.readLine();
			start.stopServer();
		}
	}
}

