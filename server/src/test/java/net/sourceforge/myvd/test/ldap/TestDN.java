package net.sourceforge.myvd.test.ldap;

import com.novell.ldap.util.DN;

import junit.framework.TestCase;

public class TestDN extends TestCase {
	public void testDNWithPlus() throws Exception {
		//DN dn = new DN("cn=my\\+dn,dc=domain,dc=com");
		DN dn = new DN("CN=Schedule\\+ Free Busy Information - COG,CN=Microsoft Exchange System Objects,DC=mwcog,DC=org");
		String dnStr = dn.toString();
		System.out.println(dnStr);
		dn = new DN(dnStr);
	}
	
	/*public void testDNWithDash() throws Exception {
		DN dn = new DN("cn=my-dn,dc=domain,dc=com");
	}
	
	public void testDNWithSpace() throws Exception {
		DN dn = new DN("cn=my dn,dc=domain,dc=com");
	}*/
}
