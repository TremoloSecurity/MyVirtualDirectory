/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
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
package net.sourceforge.myvd.inserts.join;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Properties;
import java.util.StringTokenizer;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.ByteArray;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.InterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
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

public class JoinSearchMapDNAttribute implements Insert {

	String name;
	HashSet<String> attributes;
	String joinAttribute;
	String in2outSearchRoot;
	String out2inSearchRoot;
	
	String searchFilter;
	
	HashMap<String,String> in2out, out2in;
	NameSpace ns;

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		
		this.attributes = new HashSet<String>();
		
		StringTokenizer toker = new StringTokenizer(props.getProperty("dnAttributes"),",",false);
		while (toker.hasMoreTokens()) {
			this.attributes.add(toker.nextToken().toLowerCase());
		}
		
		this.joinAttribute = props.getProperty("joinAttribute");
		this.in2outSearchRoot = props.getProperty("in2outSearchRoot");
		this.searchFilter = props.getProperty("searchFilter");

		this.out2inSearchRoot = props.getProperty("out2inSearchRoot");
		
		this.ns = nameSpace;
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
		// TODO Auto-generated method stub

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
					throws LDAPException {
		
		
		Filter newFilter = new Filter(filter.getRoot().toString());
		this.renameFilter(newFilter.getRoot(), chain);
		
		chain.nextSearch(base, scope, newFilter, attributes, typesOnly, results, constraints);

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
		
		
		if (entry.isReturnEntry()) {
			LDAPAttributeSet attrs = entry.getEntry().getAttributeSet();
			ArrayList<LDAPAttribute> newAttrs = new ArrayList<LDAPAttribute>();
			for (Object o : attrs) {
				LDAPAttribute attr = (LDAPAttribute) o;
				if (this.attributes.contains(attr.getName().toLowerCase())) {
					LDAPAttribute newAttr = new LDAPAttribute(attr.getName());
					newAttrs.add(newAttr);
					LinkedList<ByteArray> vals = attr.getAllValues();
					for (ByteArray b : vals) {
						String newDN = this.mapIn2Out(b.toString(),chain);
						newAttr.addValue(newDN);
					}
				}
			}
			
			for (LDAPAttribute attr : newAttrs) {
				entry.getEntry().getAttributeSet().remove(attr.getName());
				entry.getEntry().getAttributeSet().add(attr);
			}
			
		}

	}

	private String mapIn2Out(String dn,InterceptorChain chain) throws LDAPException {
		Results results = new Results(this.ns.getRouter().getGlobalChain(),0);
		
		SearchInterceptorChain searchChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),this.ns.getRouter().getGlobalChain().getLength(),this.ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),this.ns.getRouter());
		ArrayList<Attribute> nattrs  = new ArrayList<Attribute>();
		//SearchInterceptorChain searchChain = chain.createSearchChain();
		searchChain.nextSearch(new DistinguishedName(dn),new Int(0),new Filter("(objectClass=*)"),nattrs,new Bool(false),results,new LDAPSearchConstraints());
		results.start();
		
		if (! results.hasMore()) {
			return dn;
		} else {
			Entry entry = results.next();
			while (results.hasMore()) results.next();
			
			
			
			LDAPAttribute attr = entry.getEntry().getAttribute(this.joinAttribute);
			if (attr != null) {
				String joinVal = attr.getStringValue();
				String searchFilter = this.searchFilter.replace("#", joinVal);
				
				searchChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),this.ns.getRouter().getGlobalChain().getLength(),this.ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),this.ns.getRouter());
				nattrs  = new ArrayList<Attribute>();
				searchChain.nextSearch(new DistinguishedName(this.in2outSearchRoot),new Int(2),new Filter(searchFilter),nattrs,new Bool(false),results,new LDAPSearchConstraints());
				results.start();
				
				if (! results.hasMore()) {
					return dn;
				} else {
					entry = results.next();
					while (results.hasMore()) results.next();
					return entry.getEntry().getDN();
				}
				
			} else {
				//how to handle not mapped
				return dn;
			}
		}
		
	}
	
	private String mapOut2In(String dn,InterceptorChain chain) throws LDAPException {
		Results results = new Results(this.ns.getRouter().getGlobalChain(),0);
		
		SearchInterceptorChain searchChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),this.ns.getRouter().getGlobalChain().getLength(),this.ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),this.ns.getRouter());
		ArrayList<Attribute> nattrs  = new ArrayList<Attribute>();
		//SearchInterceptorChain searchChain = chain.createSearchChain();
		searchChain.nextSearch(new DistinguishedName(dn),new Int(0),new Filter("(objectClass=*)"),nattrs,new Bool(false),results,new LDAPSearchConstraints());
		results.start();
		
		if (! results.hasMore()) {
			return dn;
		} else {
			Entry entry = results.next();
			while (results.hasMore()) results.next();
			
			
			
			LDAPAttribute attr = entry.getEntry().getAttribute(this.joinAttribute);
			if (attr != null) {
				String joinVal = attr.getStringValue();
				String searchFilter = this.searchFilter.replace("#", joinVal);
				
				searchChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),this.ns.getRouter().getGlobalChain().getLength(),this.ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),this.ns.getRouter());
				nattrs  = new ArrayList<Attribute>();
				searchChain.nextSearch(new DistinguishedName(this.out2inSearchRoot),new Int(2),new Filter(searchFilter),nattrs,new Bool(false),results,new LDAPSearchConstraints());
				results.start();
				
				if (! results.hasMore()) {
					return dn;
				} else {
					entry = results.next();
					while (results.hasMore()) results.next();
					return entry.getEntry().getDN();
				}
				
			} else {
				//how to handle not mapped
				return dn;
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

	private void renameFilter(FilterNode node,InterceptorChain chain) throws LDAPException {
		String name;
		String newName;
		switch (node.getType()) {
			case SUBSTR	: 
			case EQUALS 	  :
			case GREATER_THEN :
			case LESS_THEN:
			case PRESENCE : name = node.getName().toLowerCase();
							if (this.attributes.contains(name.toLowerCase())) {
								node.setValue(this.mapOut2In(node.getValue(), chain));
							}
							break;
			case AND:
			case OR:
							Iterator<FilterNode> it = node.getChildren().iterator();
							while (it.hasNext()) {
								renameFilter(it.next(),chain);
							}
							break;
			case NOT :		renameFilter(node.getNot(),chain);
		}
		
		
	}
}
