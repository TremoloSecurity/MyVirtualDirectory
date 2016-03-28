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
package net.sourceforge.myvd.util;


import java.util.Vector;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;



import java.util.Vector;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;



import java.util.Vector;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public class EntryUtil {
	public static LDAPEntry createBaseEntry(DN name) {
		Vector<RDN> comps =  name.getRDNs();
		
		RDN firstComp = comps.get(0);
		
		String rdnAttrib = firstComp.getType();
		
		if (rdnAttrib.equalsIgnoreCase("ou")) {
			LDAPAttributeSet attribs = new LDAPAttributeSet();
			attribs.add(new LDAPAttribute("objectClass","organizationalUnit"));
			attribs.add(new LDAPAttribute("ou",firstComp.getValue()));
			LDAPEntry entry = new LDAPEntry(name.toString(),attribs);
			return entry;
		} else if (rdnAttrib.equalsIgnoreCase("o")) {
			LDAPAttributeSet attribs = new LDAPAttributeSet();
			attribs.add(new LDAPAttribute("objectClass","organization"));
			attribs.add(new LDAPAttribute("o",firstComp.getValue()));
			LDAPEntry entry = new LDAPEntry(name.toString(),attribs);
			return entry;
		} else if (rdnAttrib.equalsIgnoreCase("dc")) {
			LDAPAttributeSet attribs = new LDAPAttributeSet();
			attribs.add(new LDAPAttribute("objectClass","domain"));
			attribs.add(new LDAPAttribute("dc",firstComp.getValue()));
			LDAPEntry entry = new LDAPEntry(name.toString(),attribs);
			return entry;
		} else if (rdnAttrib.equalsIgnoreCase("cn")) {
			LDAPAttributeSet attribs = new LDAPAttributeSet();
			attribs.add(new LDAPAttribute("objectClass","container"));
			attribs.add(new LDAPAttribute("cn",firstComp.getValue()));
			LDAPEntry entry = new LDAPEntry(name.toString(),attribs);
			return entry;
		} else {
			LDAPAttributeSet attribs = new LDAPAttributeSet();
			attribs.add(new LDAPAttribute("objectClass","dc"));
			attribs.add(new LDAPAttribute(firstComp.getType(),firstComp.getValue()));
			LDAPEntry entry = new LDAPEntry(name.toString(),attribs);
			return entry;
		}
	}
}
