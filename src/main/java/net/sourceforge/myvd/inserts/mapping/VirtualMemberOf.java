/*******************************************************************************
 * Copyright 2017 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package net.sourceforge.myvd.inserts.mapping;

import java.util.ArrayList;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

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
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class VirtualMemberOf implements Insert {

	String name;
	private NameSpace nameSpace;
	
	String searchBase;
	String applyToObjectClass;
	String attributeName;
	String searchObjectClass;
	String searchAttribute;
	
	boolean replace;
	
	@Override
	public String getName() {
		return name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		this.nameSpace = nameSpace;
		
		this.searchBase = props.getProperty("searchBase");
		this.applyToObjectClass = props.getProperty("applyToObjectClass");
		this.attributeName = props.getProperty("attributeName");
		this.searchObjectClass = props.getProperty("searchObjectClass");
		this.searchAttribute = props.getProperty("searchAttribute");
		
		this.replace = props.getProperty("replace","false").equalsIgnoreCase("true");

	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);

	}

	@Override
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	@Override
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn,
			DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		boolean doAdd = false;
		
		if (attributes.size() == 0) {
			doAdd = true;
		} else {
			for (Attribute attr : attributes) {
				if (attr.getAttribute().getName().equalsIgnoreCase(this.attributeName)) {
					doAdd = true;
				}
			}
		}
		
		if (doAdd) {
			boolean found = false;
			for (String oc : entry.getEntry().getAttribute("objectClass").getStringValueArray()) {
				if (oc.equalsIgnoreCase(this.applyToObjectClass)) {
					found = true;
				}
			}
			doAdd = doAdd && found;
		}
		
		if (doAdd) {
			FilterNode oc = new FilterNode(FilterType.EQUALS,"objectClass",this.searchObjectClass);
			FilterNode dn = new FilterNode(FilterType.EQUALS,this.searchAttribute,entry.getEntry().getDN());
			ArrayList<FilterNode> nodes = new ArrayList<FilterNode>();
			nodes.add(oc);
			nodes.add(dn);
			Filter newFilter = new Filter(new FilterNode(FilterType.AND,nodes));
			
			ArrayList<Attribute> nattrs = new ArrayList<Attribute>();
			
			Results nres = new Results(this.nameSpace.getChain(),this.nameSpace.getChain().getPositionInChain(this) + 1 );
			SearchInterceptorChain nchain = new SearchInterceptorChain(new DistinguishedName(this.searchBase),chain.getBindPassword(),this.nameSpace.getChain().getPositionInChain(this) + 1,nameSpace.getChain(),chain.getSession(),chain.getRequest(),this.nameSpace.getRouter());
			
			
			//SearchInterceptorChain nchain = this.nameSpace.createSearchChain(this.nameSpace.getChain().getPositionInChain(this) + 1);
			
			nchain.nextSearch(new DistinguishedName(this.searchBase), new Int(2), newFilter, nattrs, new Bool(false), nres, constraints);
			
			nres.start();
			
			LDAPAttribute memberof = new LDAPAttribute(this.attributeName);
			
			
			while (nres.hasMore()) {
				Entry group = nres.next();
				memberof.addValue(group.getEntry().getDN());
			}
			
			if (memberof.getStringValueArray() != null && memberof.getStringValueArray().length > 0) {
				entry.getEntry().getAttributeSet().add(memberof);
			}
		}

	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);

	}

	@Override
	public void shutdown() {
		

	}

}
