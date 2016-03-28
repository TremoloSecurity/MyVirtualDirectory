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
package net.sourceforge.myvd.inserts.idm;


import java.util.ArrayList;
import java.util.Properties;
import java.util.Vector;

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

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public class CreateSPMLIdentity implements Insert {
	String idType;
	String idAttrib;
	boolean keepNameAsAttribute;
	String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.idType = props.getProperty("type");
		this.idAttrib = props.getProperty("attribute").toLowerCase();
		this.keepNameAsAttribute = props.getProperty("keepNameAsAttribute","").equalsIgnoreCase("1");

	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		Vector rdns = (new DN(entry.getEntry().getDN())).getRDNs();
		RDN rdn = (RDN) rdns.get(0);
		RDN newRdn = new RDN();
		
		if (rdn.getType().equalsIgnoreCase(this.idAttrib)) {
			newRdn.add(this.idType,rdn.getValue(),null);
		} else {
			newRdn.add(this.idType,entry.getEntry().getAttribute(this.idAttrib).getStringValue(),null);
		}
		
		DN newDn = new DN();
		newDn.addRDN(newRdn);
		
		for (int i=1,m=rdns.size();i<m;i++) {
			newDn.addRDNToBack((RDN)rdns.get(i));
		}
		
		entry.setDN(newDn);
		
		if (! this.keepNameAsAttribute) {
			entry.getEntry().getAttributeSet().remove(this.idAttrib);
		}
		
		chain.nextAdd(entry,constraints);


	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		Vector rdns = dn.getDN().getRDNs();
		RDN rdn = (RDN) rdns.get(0);
		RDN newRdn = new RDN();
		
		if (rdn.getType().equalsIgnoreCase(this.idAttrib)) {
			newRdn.add(this.idType,rdn.getValue(),null);
		} else {
			//TODO: add jdbc call here?
			//newRdn.add(this.idType,entry.getEntry().getAttribute(this.idAttrib).getStringValue(),null);
		}
		
		DN newDn = new DN();
		newDn.addRDN(newRdn);
		
		for (int i=1,m=rdns.size();i<m;i++) {
			newDn.addRDN((RDN)rdns.get(i));
		}
		
		dn.setDN(newDn);
		chain.nextDelete(dn,constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		Vector rdns = dn.getDN().getRDNs();
		RDN rdn = (RDN) rdns.get(0);
		RDN newRdn = new RDN();
		
		if (rdn.getType().equalsIgnoreCase(this.idAttrib)) {
			newRdn.add(this.idType,rdn.getValue(),null);
		} else {
			//TODO add jdbc?
			//newRdn.add(this.idType,entry.getEntry().getAttribute(this.idAttrib).getStringValue(),null);
		}
		
		DN newDn = new DN();
		newDn.addRDN(newRdn);
		
		for (int i=1,m=rdns.size();i<m;i++) {
			newDn.addRDN((RDN)rdns.get(i));
		}
		
		dn.setDN(newDn);
		
		chain.nextModify(dn,mods,constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
