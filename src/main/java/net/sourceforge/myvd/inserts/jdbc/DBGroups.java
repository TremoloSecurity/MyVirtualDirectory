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
package net.sourceforge.myvd.inserts.jdbc;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

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
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

public class DBGroups implements Insert {

	private String attribName;
	private String suffix;
	private String rdnAttrib;
	String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.attribName = props.getProperty("memberAttribute");
		this.suffix = props.getProperty("suffix");
		this.rdnAttrib = props.getProperty("rdn");

	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry,constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn,pwd,constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		//System.out.println("here");
		chain.nextCompare(dn,attrib,constraints);

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn,constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextExtendedOperations(op,constraints);

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn,mods,constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		Filter newFilter = new Filter(filter.getValue());
		updateFilter(newFilter.getRoot());
		
		
		
		if (attributes.size() > 0) {
			boolean doAdd = true;
			
			for (Attribute attr : attributes) {
				if (attr.getAttribute().getName().equalsIgnoreCase("*")) {
					doAdd = false;
				}
			}
			
			if (doAdd) {
				ArrayList nattribs = new ArrayList<Attribute>();
				//nattribs.addAll(attributes);
				//nattribs.add(new Attribute(new LDAPAttribute(this.attribName)));
				attributes = nattribs;
			}
		}
		
		chain.nextSearch(base,scope,newFilter,attributes,typesOnly,results,constraints);

	}

	private void updateFilter(FilterNode root) {
		switch (root.getType()) {
			case AND:
			case OR: 
					ArrayList<FilterNode> children = root.getChildren();
					Iterator<FilterNode> it = children.iterator();
					while (it.hasNext()) {
						updateFilter(it.next());
					}
					
					break;
			case NOT: 
					updateFilter(root.getNot());
					break;
			
			case PRESENCE:
			case SUBSTR:
					break;
			
			case EQUALS:
			case GREATER_THEN:
			case LESS_THEN:
				if (root.getName().equalsIgnoreCase(this.attribName)) {
					DN dn = new DN(root.getValue());
					root.setValue(dn.explodeDN(true)[0]);
				}
			
		
		}
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn,newRdn,deleteOldRdn,constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextRename(dn,newRdn,newParentDN,deleteOldRdn,constraints);

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);
		
		LDAPAttribute member = entry.getEntry().getAttribute(this.attribName);
		if (member != null) {
			entry.getEntry().getAttributeSet().remove(member);
			LDAPAttribute newMembers = new LDAPAttribute(this.attribName);
			
			String[] vals = member.getStringValueArray();
			for (int i=0,m=vals.length;i<m;i++) {
				newMembers.addValue(this.rdnAttrib + "=" + vals[i] + "," + this.suffix);
			}
			
			entry.getEntry().getAttributeSet().add(newMembers);
		}

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);

	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
