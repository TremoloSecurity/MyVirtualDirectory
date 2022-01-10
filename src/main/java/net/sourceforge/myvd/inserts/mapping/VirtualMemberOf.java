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
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.ByteArray;

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
	String oldFilterName;
	String skipPostSearchName;
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
		this.oldFilterName = "myvd.vmemberof.orig.filter." + name;
		this.skipPostSearchName = "myvd.vmemberof.skip." + name;
		this.searchBase = props.getProperty("searchBase");
		this.applyToObjectClass = props.getProperty("applyToObjectClass");
		this.attributeName = props.getProperty("attributeName");
		this.searchObjectClass = props.getProperty("searchObjectClass");
		this.searchAttribute = props.getProperty("searchAttribute");
		
		this.replace = props.getProperty("replace","false").equalsIgnoreCase("true");
		
		LDAPAttribute oc = new LDAPAttribute("objectClass");
		oc.addValue("top");
		oc.addValue(this.applyToObjectClass);


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
		
		
		if (chain.getRequest().containsKey(this.oldFilterName)) {
			chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);
		} else {
		
			HashSet<String> memberofs = new HashSet<String>();
			FilterNode noMemberOfs = null;
			Bool foundAttr = new Bool(false);
			try {
				noMemberOfs = trimMemberOf(filter.getRoot(),memberofs,foundAttr);
			} catch (CloneNotSupportedException e) {
				throw new LDAPException("Error converting filter",LDAPException.OPERATIONS_ERROR,"Error converting filter",e);
				
			}
			
			chain.getRequest().put(this.oldFilterName, filter);
			
			if (memberofs.isEmpty() || foundAttr.getValue()) {
				chain.nextSearch(base, scope, new Filter(noMemberOfs), attributes, typesOnly, results, constraints);
			}
			
			
			
			chain.getRequest().put(this.skipPostSearchName, this.skipPostSearchName);
			for (String memberof : memberofs) {
				Results nres = new Results(this.nameSpace.getRouter().getGlobalChain(),0 );
				DistinguishedName searchBase = new DistinguishedName(memberof);
				
				
				
				
				
				
				
				SearchInterceptorChain nchain = new SearchInterceptorChain(searchBase,chain.getBindPassword(),0,nameSpace.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),this.nameSpace.getRouter());
				ArrayList<Attribute> nattrs = new ArrayList<Attribute>();
				nchain.nextSearch(searchBase, new Int(0), new Filter("(objectClass=*)"), nattrs, new Bool(false), nres, constraints);
				
				nres.start();
				
				if (nres.hasMore()) {
					Entry group = nres.next();
					LDAPAttribute members = group.getEntry().getAttribute(this.searchAttribute);
					if (members != null) {
						LinkedList<ByteArray> memberVals = members.getAllValues();
						for (ByteArray b : memberVals) {
							String member = b.toString();
							//if base?
							
							DistinguishedName userDN = new DistinguishedName(member);
							SearchInterceptorChain userChain = new SearchInterceptorChain(userDN,chain.getBindPassword(),0,nameSpace.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),this.nameSpace.getRouter());
							
							userChain.nextSearch(userDN, new Int(0), new Filter(noMemberOfs), attributes, new Bool(false), results, constraints);
						}
					}
					
					
				}
				
				nres.finish();
			}
			chain.getRequest().remove(this.skipPostSearchName);
		}

	}
	
	
	private FilterNode trimMemberOf(FilterNode root,HashSet<String> memberofs, Bool foundAttr) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if (root.getName().equalsIgnoreCase(this.attributeName)) {
					if (! memberofs.contains(root.getValue())) {
						memberofs.add(root.getValue());
					}
					return new FilterNode(FilterType.PRESENCE,"objectClass","*");
					
				} else {
					
					if (! root.getName().equalsIgnoreCase("objectclass")) {
						foundAttr.setValue(true);
					}
					
					return new FilterNode(root.getType(),root.getName(),root.getValue());
							
				}
				
				
				
			case AND:
			case OR:
				
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = trimMemberOf(it.next(),memberofs,foundAttr);
					if (node != null) {
						newChildren.add(node);
					}
					
				}
				
				return new FilterNode(root.getType(),newChildren);
				
				
			case NOT:
				FilterNode node = trimMemberOf(root.getNot(),memberofs,foundAttr);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
		
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
		
		if (! chain.getRequest().containsKey(this.skipPostSearchName)) {
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
				LinkedList<ByteArray> ocs = entry.getEntry().getAttribute("objectClass").getAllValues();
				for (ByteArray oc : ocs) {
					if (oc.toString().equalsIgnoreCase(this.applyToObjectClass)) {
						found = true;
					}
				}
				doAdd = doAdd && found;
			}
			
			if (doAdd) {
				
				chain.getRequest().put(this.skipPostSearchName, this.skipPostSearchName);
				
				FilterNode oc = new FilterNode(FilterType.EQUALS,"objectClass",this.searchObjectClass);
				FilterNode dn = new FilterNode(FilterType.EQUALS,this.searchAttribute,entry.getEntry().getDN());
				ArrayList<FilterNode> nodes = new ArrayList<FilterNode>();
				nodes.add(oc);
				nodes.add(dn);
				Filter newFilter = new Filter(new FilterNode(FilterType.AND,nodes));
				
				ArrayList<Attribute> nattrs = new ArrayList<Attribute>();
				
				//Results nres = new Results(this.nameSpace.getChain(),this.nameSpace.getChain().getPositionInChain(this) + 1 );
				//SearchInterceptorChain nchain = new SearchInterceptorChain(new DistinguishedName(this.searchBase),chain.getBindPassword(),this.nameSpace.getChain().getPositionInChain(this) + 1,nameSpace.getChain(),chain.getSession(),chain.getRequest(),this.nameSpace.isGlobal() ? this.nameSpace.getRouter() : null);
				
				Results nres = new Results(this.nameSpace.getRouter().getGlobalChain(),0);
				SearchInterceptorChain nchain = new SearchInterceptorChain(new DistinguishedName(this.searchBase),chain.getBindPassword(),0,nameSpace.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(), this.nameSpace.getRouter());
				
				//SearchInterceptorChain nchain = this.nameSpace.createSearchChain(this.nameSpace.getChain().getPositionInChain(this) + 1);
				
				nchain.nextSearch(new DistinguishedName(this.searchBase), new Int(2), newFilter, nattrs, new Bool(false), nres, constraints);
				
				nres.start();
				
				LDAPAttribute memberof = null;
				if (this.replace) {
					if (entry.getEntry().getAttribute(this.attributeName) != null) {
						entry.getEntry().getAttributeSet().remove(this.attributeName);
					}
					
					memberof = new LDAPAttribute(this.attributeName);
				} else {
					if (entry.getEntry().getAttribute(this.attributeName) != null) {
						memberof = entry.getEntry().getAttributeSet().getAttribute(this.attributeName);
						entry.getEntry().getAttributeSet().remove(this.attributeName);
					} else {
						memberof = new LDAPAttribute(this.attributeName);
					}
				}
						
				
				
				while (nres.hasMore()) {
					Entry group = nres.next();
					memberof.addValue(group.getEntry().getDN());
				}
				
				if (memberof.getAllValues() != null && ! memberof.getAllValues().isEmpty()) {
					entry.getEntry().getAttributeSet().add(memberof);
				}
				
				chain.getRequest().remove(this.skipPostSearchName);
			}
			
			if (chain.getRequest().containsKey(this.oldFilterName)) {
				Filter origFilter = (Filter) chain.getRequest().get(this.oldFilterName);
				entry.setReturnEntry(origFilter.getRoot().checkEntry(entry.getEntry()));
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
