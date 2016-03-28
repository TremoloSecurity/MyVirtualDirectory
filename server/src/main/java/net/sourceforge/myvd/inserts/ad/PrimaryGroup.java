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
package net.sourceforge.myvd.inserts.ad;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class PrimaryGroup implements Insert {

	
	DN domainUsersGroupDN;
	
	String url;

	private String name; 
	private Attribute attrib;
	private Attribute allAttrib;

	private String base;

	private String groupObjectClass;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		
		this.base = props.getProperty("searchBase",nameSpace.getBase().toString());
		this.groupObjectClass = props.getProperty("groupObjectClass");
		
		this.attrib = new Attribute("memberUrl");
		this.allAttrib = new Attribute("*");

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	public String getName() {
		return this.name;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		
		if (this.checkObjectClass(entry)) {
			
			String sid = entry.getEntry().getAttribute("objectSid").getStringValue();
			String primaryGroupID = sid.substring(sid.lastIndexOf('-') + 1);
			StringBuffer buf = new StringBuffer();
			buf.append("ldap:///").append(this.base).append("??sub?(primaryGroupID=").append(primaryGroupID).append(")");
			LDAPAttribute attrib = new LDAPAttribute("memberUrl",buf.toString());
			
			if (entry.getEntry().getAttribute("objectclass") != null) {
				entry.getEntry().getAttribute("objectClass").addValue("groupOfUrls");
				entry.getEntry().getAttributeSet().add(attrib);
			}
			
		}
		
		

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		
		boolean addObjectClass = true;
		boolean addObjectSID = true;
		boolean foundAll = false;
		
		ArrayList<Attribute> newAttribs = new ArrayList<Attribute>();
		
		if (attributes.size() > 0) {
			Iterator<Attribute> it = attributes.iterator();
			while (it.hasNext()) {
				Attribute attrib = it.next();
				if (attrib.getAttribute().getName().equals("*")) {
					addObjectClass = false;
					addObjectSID = false;
				} else if (attrib.getAttribute().getName().equals("objectClass")) {
					addObjectClass = false;
				} else if (attrib.getAttribute().getName().equals("objectSID")) {
					addObjectSID = false;
				}
				
				newAttribs.add(new Attribute(attrib.getAttribute().getName()));
			}
			
			if (addObjectClass) {
				newAttribs.add(new Attribute("objectClass"));
			}
			
			if (addObjectSID) {
				newAttribs.add(new Attribute("objectSID"));
			}
		}
		
		chain.nextSearch(base, scope, filter, newAttribs, typesOnly, results, constraints);

	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}
	
	private boolean checkObjectClass(Entry entry) {
		
		boolean isDynGroup = false;
		
		LDAPAttribute ocs = entry.getEntry().getAttribute("objectClass");
		if (ocs != null) {
			String[] vals = ocs.getStringValueArray();
			for (int i=0;i<vals.length;i++) {
				if (vals[i].equalsIgnoreCase(this.groupObjectClass)) {
					return true;
				} 
			}
			
			
			
		}
		
		return false;
	}

}
