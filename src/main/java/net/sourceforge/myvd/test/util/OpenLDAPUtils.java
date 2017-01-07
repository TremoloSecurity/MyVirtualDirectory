package net.sourceforge.myvd.test.util;

public class OpenLDAPUtils {

	public static void killAllOpenLDAPS() throws Exception {
		Process p = Runtime.getRuntime().exec("/usr/bin/killall slapd");
		
		StreamReader out = new StreamReader(p.getInputStream(),true);
		StreamReader err = new StreamReader(p.getErrorStream(),true);
		
		out.start();
		err.start();
		
		
	}
}
