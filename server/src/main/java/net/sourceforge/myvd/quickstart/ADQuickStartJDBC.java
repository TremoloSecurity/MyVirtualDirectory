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
package net.sourceforge.myvd.quickstart;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.StringTokenizer;

import javax.security.cert.CertificateEncodingException;
import javax.security.cert.X509Certificate;

import net.sourceforge.myvd.quickstart.util.GetSSLCert;
import net.sourceforge.myvd.test.util.StreamReader;
import net.sourceforge.myvd.test.util.StreamWriter;

public class ADQuickStartJDBC {

	/**
	 * @param args
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 * @throws SQLException 
	 */
	public static void main(String[] args) throws IOException, InstantiationException, IllegalAccessException, ClassNotFoundException, SQLException {
		
		String myVDHome = args[0];
		
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		
		String ksPath = myVDHome + "/conf/myvd-server.ks";
		String ksPass;
		
		String dnServer;
		String dnOu;
		String dnO;
		String dnL;
		String dnState;
		String dnC;
		
		String dn;
		String keyTool = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
		System.err.println(keyTool);
		String cacerts = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
		
		HashMap<String,String> vars = new HashMap<String,String>();
		
		vars.put("MYVD_HOME", myVDHome);
		
		//System.out.println("MyVirtualDirectory Active Directory Quick-Start JDBC");
		//System.out.println("===============================================");
		
		//System.out.println("This quick start will guide you through building out a virtual directory ");
		//System.out.println("that will expose an Active Directory domain for use by a Linux system.\n\n");
		
		//System.out.println("In order to move forward you will need:");
		//System.out.println("ActiveDirectory Domain Controller hostname or ip");
		//System.out.println("ActiveDirectory user with no search restrictions");
		//System.out.println("JDBC Driver");
		//System.out.println("JDBC URL");
		//System.out.println("JDBC User");
		//System.out.println("JDBC Password");

		//System.out.println("Creating MyVirtualDirectory Keystore...");
		
		String srcKsPwd = getPassword("CACERTS Password (usually 'changeit')",in);
		ksPass = getPassword("MyVirtualDirectory Keystore Password",in);
		
		ProcessBuilder pb = new ProcessBuilder();
		pb.redirectErrorStream(true);
		ArrayList<String> cmd = new ArrayList<String>();
		cmd.add(keyTool);
		cmd.add("-importkeystore");
		cmd.add("-srckeystore");
		cmd.add(cacerts);
		cmd.add("-destkeystore");
		cmd.add(ksPath);
		cmd.add("-deststorepass");
		cmd.add(ksPass);
		cmd.add("-srcstorepass");
		cmd.add(srcKsPwd);
		cmd.add("-noprompt");
		
		
		pb.command(cmd);
		//pb.command("/usr/java/jdk1.6.0_03/bin/keytool -genkeypair -v -keystore /home/mlb/test.ks -alias selfsigned -keyalg rsa -keysize 1024 -validity 365");
		//pb.command("/usr/java/jdk1.6.0_03/bin/keytool");
		
		Process process = pb.start();
		//Process process = Runtime.getRuntime().exec("/usr/java/jdk1.6.0_03/bin/keytool");
		
		
		//StreamReader errReader = new StreamReader(process.getErrorStream(),true);
		StreamReader sr = new StreamReader(process.getInputStream(),true);
		//StreamWriter sw = new StreamWriter(process.getInputStream(),new PrintWriter(process.getOutputStream()));
		//sr.start();
		//errReader.start();
		sr.start();
		//System.setIn(process.getInputStream());
		
		while (! sr.isDone()) {
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				
			}
		}
		
		//System.out.println("Keystore created");
		
		String myvdBase = getInput("MyVirtualDirectory Base (ie ou=unix,o=mycompany)",in);
		vars.put("VD_BASE", myvdBase);
		
		String myvdPort = getInput("MyVirtualDirectory Port (usualy 389)",in);
		vars.put("VD_PORT", myvdPort);
		
		
		
		String adHost = getInput("Active Directroy Host",in);
		vars.put("AD_HOST", adHost);
		String adPort = getInput("Active Directroy Port (usualy 389)",in);
		vars.put("AD_PORT", adPort);
		String adIsSSL = getInput("Use SSL? (y/n)",in);
		
		String adDomain = getInput("Active Directory Domain Name",in);
		String remoteBase = "";
		
		StringTokenizer toker = new StringTokenizer(adDomain,".",false);
		while (toker.hasMoreTokens()) {
			remoteBase += "DC=" + toker.nextToken() + ",";
		}
		
		remoteBase = remoteBase.substring(0,remoteBase.length() - 1);
		
		vars.put("AD_BASE", remoteBase);
		
		String adBase = getInput("User base (not including the domain, typically cn=users)",in);
		vars.put("AD_USERS_BASE", adBase);
		
		String adSearchDN = getInput("Active Directory User DN (do not include the domain name, ie cn=MyVDUser,cn=Users)",in);
		vars.put("AD_CRED", adSearchDN);
		String adPassword = getPassword("Active Directory User Password",in);
		vars.put("AD_PWD", adPassword);
		
		
		if (adIsSSL.equalsIgnoreCase("y")) {
			//System.out.println("Retrieving certificate parent from " + adHost + ":" + adPort + "...");
			X509Certificate cert = GetSSLCert.getCert(adHost, Integer.parseInt(adPort));
			
			//System.out.println("Exporting certificate parent from " + adHost + ":" + adPort + "...");
			File f = new File(myVDHome + "/tmp.ad.der");
			FileOutputStream out = new FileOutputStream(f);
			try {
				out.write(cert.getEncoded());
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			out.flush();
			out.close();
			
			//System.out.println("Import certificate parent from " + adHost + ":" + adPort + " into MyVirtualDirectory keystore...");
			
			pb = new ProcessBuilder();
			pb.redirectErrorStream(true);
			cmd = new ArrayList<String>();
			cmd.add(keyTool);
			cmd.add("-importcert");
			cmd.add("-v");
			cmd.add("-keystore");
			cmd.add(ksPath);
			cmd.add("-alias");
			cmd.add("ad-" + adHost + ":" + adPort);
			cmd.add("-file");
			cmd.add(f.getAbsolutePath());
			cmd.add("-trustcacerts");
			cmd.add("-noprompt");
			cmd.add("-keypass");
			cmd.add(ksPass);
			cmd.add("-storepass");
			cmd.add(ksPass);
			
			
			pb.command(cmd);
			//pb.command("/usr/java/jdk1.6.0_03/bin/keytool -genkeypair -v -keystore /home/mlb/test.ks -alias selfsigned -keyalg rsa -keysize 1024 -validity 365");
			//pb.command("/usr/java/jdk1.6.0_03/bin/keytool");
			
			process = pb.start();
			//Process process = Runtime.getRuntime().exec("/usr/java/jdk1.6.0_03/bin/keytool");
			
			
			//StreamReader errReader = new StreamReader(process.getErrorStream(),true);
			sr = new StreamReader(process.getInputStream(),true);
			//StreamWriter sw = new StreamWriter(process.getInputStream(),new PrintWriter(process.getOutputStream()));
			//sr.start();
			//errReader.start();
			sr.start();
			//System.setIn(process.getInputStream());
			
			while (! sr.isDone()) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					
				}
			}
			f.delete();
			//System.out.println("Import certificate parent from " + adHost + ":" + adPort + " into MyVirtualDirectory keystore complete");
			vars.put("AD_TYPE", "LDAPS");
			
		} else {
			vars.put("AD_TYPE", "LDAP");
		}
		
		String useKerb = getInput("Use Kerberos? (y/n)",in);
		
		if (useKerb.equalsIgnoreCase("y")) {
			vars.put("AD_USE_KERB", "true");
		} else {
			vars.put("AD_USE_KERB", "false");
		}
		
		
		
		
		
		
		
		
		String createSelfSignedCert = getInput("Create a self signed certificate? (y/n)",in);
		
		
		
		
		
		if (createSelfSignedCert.equalsIgnoreCase("y")) {
			//System.out.println("Creating a self signed SSL certificate...");
			
			String myvdSecurePort = getInput("LDAPS Port (typically 636)",in);  
			
			
			
			dnServer = getInput("Server Name",in);
			dnOu = getInput("Org Unit",in);
			dnO = getInput("Organization",in);
			dnL = getInput("City/Locality",in);
			dnState = getInput("State/Province",in);
			dnC = getInput("2 Letter Country Code",in);
			
			dn = "CN=" + dnServer + ",OU=" + dnOu + ",O=" + dnO + ",L=" + dnL + ",ST=" + dnState + ",C=" + dnC;
			
			pb = new ProcessBuilder();
			pb.redirectErrorStream(true);
			cmd = new ArrayList<String>();
			cmd.add(keyTool);
			cmd.add("-genkeypair");
			cmd.add("-v");
			cmd.add("-keystore");
			cmd.add(ksPath);
			cmd.add("-alias");
			cmd.add("selfsigned");
			cmd.add("-keyalg");
			cmd.add("rsa");
			cmd.add("-keysize");
			cmd.add("1024");
			cmd.add("-validity");
			cmd.add("365");
			cmd.add("-keypass");
			cmd.add(ksPass);
			cmd.add("-storepass");
			cmd.add(ksPass);
			
			cmd.add("-dname");
			cmd.add(dn);
			
			pb.command(cmd);
			//pb.command("/usr/java/jdk1.6.0_03/bin/keytool -genkeypair -v -keystore /home/mlb/test.ks -alias selfsigned -keyalg rsa -keysize 1024 -validity 365");
			//pb.command("/usr/java/jdk1.6.0_03/bin/keytool");
			
			process = pb.start();
			//Process process = Runtime.getRuntime().exec("/usr/java/jdk1.6.0_03/bin/keytool");
			
			
			//StreamReader errReader = new StreamReader(process.getErrorStream(),true);
			sr = new StreamReader(process.getInputStream(),true);
			//StreamWriter sw = new StreamWriter(process.getInputStream(),new PrintWriter(process.getOutputStream()));
			//sr.start();
			//errReader.start();
			sr.start();
			//System.setIn(process.getInputStream());
			
			while (! sr.isDone()) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					
				}
			}
			
			vars.put("SSL_CFG", "#SSL Config\nserver.secure.listener.port=" + myvdSecurePort + "\nserver.secure.keystore=" + ksPath + "\nserver.secure.keypass=" + ksPass + "\n\n");
			
		} else {
			vars.put("SSL_CFG", "");
		}
		
		
		String jdbcDriver = getInput("JDBC Driver",in);
		String jdbcUrl = getInput("JDBC URL",in);
		String jdbcUser = getInput("JDBC User",in);
		String jdbcPassword = getInput("JDBC Password",in);
		
		vars.put("JDBC_DRIVER", jdbcDriver);
		vars.put("JDBC_URL", jdbcUrl);
		vars.put("JDBC_USER", jdbcUser);
		vars.put("JDBC_PASS", jdbcPassword);
		
		genConfig(myVDHome + "/quickStarts/ad2linuxjdbc.conf",myVDHome + "/conf/myvd.conf",vars);
		
		File f = new File(myVDHome + "/derbyHome");
		f.mkdir();
		
		System.getProperties().setProperty("derby.system.home", myVDHome + "/derbyHome");
		
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

	}
	
	public static String getInput(String label,BufferedReader in) throws IOException {
		//System.out.print(label + " : ");
		String data = in.readLine();
		
		//System.out.print("Is \"" + data + "\" correct? (y/n) : ");
		String resp = in.readLine();
		
		while (! resp.equalsIgnoreCase("y")) {
			//System.out.print(label + " : ");
			data = in.readLine();
			
			//System.out.print("Is \"" + data + "\" correct? (y/n) : ");
			resp = in.readLine();
		}
		
		return data;
	}
	
	public static String getPassword(String label,BufferedReader in) throws IOException {
		//System.out.print(label + " : ");
		String data = in.readLine();
		
		//System.out.print("Please verify : ");
		String resp = in.readLine();
		
		while (! resp.equals(data)) {
			//System.out.println("Passwords don't match");
			//System.out.print(label + " : ");
			data = in.readLine();
			
			//System.out.print("Please verify : ");
			resp = in.readLine();
		}
		
		return data;
	}
	
	public static void genConfig(String sourcePath,String resultPath,HashMap<String,String> vars) throws IOException {
		String cfgFile = "";
		BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(sourcePath)));
		String line;
		
		while ((line = br.readLine()) != null) {
			cfgFile += line + "\n";
		}
		
		br.close();
		
		Iterator<String> keyIt = vars.keySet().iterator();
		
		while (keyIt.hasNext()) {
			String key = keyIt.next();
			String val = vars.get(key);
			if (cfgFile.contains("%" + key + "%")) {
				//System.out.println("key:" + key);
				//System.out.println("val:" + val);
				
				cfgFile = cfgFile.replaceAll("[%]" + key + "[%]", val);
			}
		}
		
		PrintWriter out = new PrintWriter(new FileOutputStream(resultPath));
		
		out.print(cfgFile);
		out.flush();
		out.close();
		
	}

}
