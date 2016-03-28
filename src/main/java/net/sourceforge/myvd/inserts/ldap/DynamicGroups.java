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
package net.sourceforge.myvd.inserts.ldap;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;
import java.util.Stack;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPUrl;
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
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.EntryUtil;

public class DynamicGroups implements Insert {
	private static Logger logger = Logger.getLogger(DynamicGroups.class);
	
	
	
	
	private String name;
	
	private String urlAttribute;
	private String staticAttribute;
	private String dynOC;
	private String staticOC;
	private boolean mapOC;
	
	String stackKey;
	
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
		this.urlAttribute = props.getProperty("urlAttribute");
		this.staticAttribute = props.getProperty("staticAttribute");
		this.dynOC = props.getProperty("dynamicObjectClass");
		this.staticOC = props.getProperty("staticObjectClass");
		this.mapOC = props.getProperty("mapObjectClass","true").equalsIgnoreCase("true");
		this.stackKey = "DG_" + nameSpace.getBase().getDN().toString() + "_" + name;
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
		
	
		
		Stack<DGRequest> stack = (Stack<DGRequest>) chain.getRequest().get(this.stackKey);
		
		
		if (stack.size() > 0) {
			
			stack.pop();
			
			
		}
		
	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		Stack<DGRequest> stack = (Stack<DGRequest>) chain.getRequest().get(this.stackKey);
		
		DGRequest req = stack.peek();
		

		
		LDAPAttribute nocs = new LDAPAttribute("objectClass");
		if (checkObjectClass(entry, nocs)) {
			
			boolean requestedMembers = req.requestedMembers;
			
			LDAPAttribute urls = entry.getEntry().getAttribute(urlAttribute);
		
			
			ArrayList<TestMembers> testmembers = req.testmembers;
			Iterator<TestMembers> it = testmembers.iterator();
			
			
			
			while (it.hasNext()) {
				TestMembers tm = it.next();
				checkMember(tm,urls,entry.getEntry().getDN(),chain);
			}
			
			Filter useFilter = req.newFilter;
			
			entry.setReturnEntry(useFilter.getRoot().checkEntry(entry.getEntry()));
			
			if (requestedMembers && entry.isReturnEntry()) {
				LDAPAttribute members = entry.getEntry().getAttribute(staticAttribute);
				if (members == null) {
					members = new LDAPAttribute(staticAttribute);
					entry.getEntry().getAttributeSet().add(members);
				}
				createStaticMembers(chain, entry, constraints, urls, members);
				if (members.size() == 0) {
					entry.getEntry().getAttributeSet().remove(staticAttribute);
				}
			}
			
			
			
			if (nocs.size() > 0) {
				entry.getEntry().getAttributeSet().remove("objectClass");
				entry.getEntry().getAttributeSet().add(nocs);
			}
			
		}

	}

	private void checkMember(TestMembers tm, LDAPAttribute urls, String dn,PostSearchEntryInterceptorChain chain) throws LDAPException {
		//first check static members
		
		Results results = new Results(null,chain.getPositionInChain(this) + 1);
		SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
		
		ArrayList<Attribute> attribs = new ArrayList<Attribute>();
		attribs.add(new Attribute("1.1"));
		
		try {
			schain.nextSearch(new DistinguishedName(dn), new Int(0), new Filter("(" + this.staticAttribute + "=" + tm.member + ")"), attribs, new Bool(false), results, new LDAPSearchConstraints());
			results.start();
			boolean found = false;
			if (results.hasMore()) {
				found = true;
				results.next();
				while (results.hasMore()) {
					results.next();
				}
				
			}
			
			results.finish();
			
			if (found) {
				tm.filterNode.setName("objectClass");
				tm.filterNode.setType(FilterType.PRESENCE);
				tm.filterNode.setValue("*");
				return;
			} 
			
		} catch (LDAPException e) {
			logger.error("Error searching group",e);
		}
		
		//check dynamic urls
		
		DN memberDN = new DN(tm.member);
		boolean found = false;
		
		if (urls != null) {
			Enumeration enumer = urls.getStringValues();
			while (enumer.hasMoreElements()) {
				String url = (String) enumer.nextElement();
				LDAPUrl ldapurl = null;
				
				try {
					ldapurl = new LDAPUrl(url);
					
				} catch (MalformedURLException e) {
					throw new LDAPException("Invalid URL : " + url,LDAPException.CONSTRAINT_VIOLATION,"Constraint Violation");
				}
				
				DN urlDN = new DN(ldapurl.getDN());
				
				
				if (memberDN.isDescendantOf(urlDN) && 
						((ldapurl.getScope() == 0 && urlDN.equals(memberDN)) || 
						(ldapurl.getScope() == 1 && (urlDN.getRDNs().size() - memberDN.getRDNs().size()) == 1) || 
						(ldapurl.getScope() == 2)) )  {
					results = new Results(null,chain.getPositionInChain(this) + 1);
					schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
					
					attribs = new ArrayList<Attribute>();
					attribs.add(new Attribute("1.1"));
					
					try {
						schain.nextSearch(new DistinguishedName(memberDN), new Int(0), new Filter(ldapurl.getFilter()), attribs, new Bool(false), results, new LDAPSearchConstraints());
						results.start();
						
						if (results.hasMore()) {
							found = true;
							results.next();
							while (results.hasMore()) {
								results.next();
							}
							results.finish();
						}
						
						results.finish();
						
						if (found) {
							tm.filterNode.setName("objectClass");
							tm.filterNode.setType(FilterType.PRESENCE);
							tm.filterNode.setValue("*");
							return;
						} 
						
					} catch (LDAPException e) {
						logger.error("Error searching group",e);
					}
				}
				
				
			}
		}
		
		if (! found) {
			FilterNode node = new FilterNode(FilterType.PRESENCE,"objectclass","*");
			tm.filterNode.setType(FilterType.NOT);
			tm.filterNode.setNot(node);
			tm.filterNode.setName(null);
			tm.filterNode.setValue(null);
		}
	}

	private boolean checkObjectClass(Entry entry, LDAPAttribute nocs) {
		
		boolean isDynGroup = false;
		
		LDAPAttribute ocs = entry.getEntry().getAttribute("objectClass");
		if (ocs != null) {
			String[] vals = ocs.getStringValueArray();
			for (int i=0;i<vals.length;i++) {
				if (vals[i].equalsIgnoreCase(dynOC)) {
					isDynGroup = true;
					nocs.addValue(staticOC);
				} else {
					nocs.addValue(vals[i]);
				}
			}
			
			
			
		}
		
		return isDynGroup;
	}

	private void createStaticMembers(PostSearchEntryInterceptorChain chain, Entry entry, LDAPSearchConstraints constraints, LDAPAttribute urls, LDAPAttribute members) throws LDAPException {
		
		if (urls == null) {
			return;
		}
		
		Enumeration enumer = urls.getStringValues();
		while (enumer.hasMoreElements()) {
			String url = (String) enumer.nextElement();
			LDAPUrl ldapurl = null;
			
			try {
				ldapurl = new LDAPUrl(url);
				
			} catch (MalformedURLException e) {
				throw new LDAPException("Invalid URL : " + url,LDAPException.CONSTRAINT_VIOLATION,"Constraint Violation");
			}
			
			Results results = new Results(null,chain.getPositionInChain(this) + 1);
			SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
			
			ArrayList<Attribute> attribs = new ArrayList<Attribute>();
			attribs.add(new Attribute("1.1"));
			
			schain.nextSearch(new DistinguishedName(ldapurl.getDN()), new Int(ldapurl.getScope()), new Filter(ldapurl.getFilter()), attribs, new Bool(false), results, constraints);
			
			results.start();
			
			while (results.hasMore()) {
				members.addValue(results.next().getEntry().getDN().getBytes());
			}
			
			
		}
		
		entry.getEntry().getAttributeSet().remove(urls);
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
		
		Stack<DGRequest> stack = (Stack<DGRequest>) chain.getRequest().get(this.stackKey);
		if (stack == null) {
			stack = new Stack<DGRequest>();
			chain.getRequest().put(this.stackKey, stack);
		}
		
		DGRequest req = new DGRequest();
		stack.push(req);
		
		
		req.requestedMembers = false;
		req.requestedUrls = false;
		boolean requestedOC = false;
		
		if (attributes.size() == 0) {
			req.requestedMembers = true;
			req.requestedUrls = true;
			requestedOC = true;
		}
		
		ArrayList<Attribute> nattribs = new ArrayList<Attribute>();
		
		Iterator<Attribute> it = attributes.iterator();
		while (it.hasNext()) {
			Attribute attrib = it.next();
			String name = attrib.getAttribute().getBaseName();
			if (name.equalsIgnoreCase("*")) {
				req.requestedMembers = true;
				req.requestedUrls = true;
				requestedOC = true;
				
				nattribs.add(new Attribute("*"));
				
			} else if (name.equalsIgnoreCase(staticAttribute)) {
				req.requestedMembers = true;
			} else if (name.equalsIgnoreCase(urlAttribute)) {
				req.requestedUrls = true;
				nattribs.add(new Attribute(name));
			} else if (name.equalsIgnoreCase("objectclass")) {
				requestedOC = true;
				nattribs.add(new Attribute(name));
			} else {
				nattribs.add(new Attribute(name));
			}
		}
		
		
		if (! req.requestedUrls) {
			nattribs.add(new Attribute(urlAttribute));
		}
		
		if (! requestedOC) {
			nattribs.add(new Attribute("objectclass"));
		}
		
		if (req.requestedMembers) {
			if (attributes.size() != 0) {
				nattribs.add(new Attribute(this.staticAttribute));
			}
		}
		
		
		
		
		
		Filter newfilter = null; 
		req.testmembers = new ArrayList<TestMembers>();
		
		try {
			newfilter =	new Filter(this.trimSearchFilter(filter.getRoot(), req.testmembers,nattribs));
		} catch (CloneNotSupportedException e) {
			
		}
		
		
		
		
		req.newFilter =	newfilter; //new Filter(newfilter.getRoot().toString());
		
		chain.nextSearch(base, scope, req.newFilter, nattribs, typesOnly, results, constraints);

	}
	
	private void addAttribute(ArrayList<Attribute> nattribs,String name) {
		if (name == null) {
			name = "objectClass";
		}
		
		Attribute attrib = new Attribute(name);
		
		if (! (nattribs.size() == 0 || nattribs.contains(attrib))) {
			nattribs.add(attrib);
		}
	}
	
	private FilterNode trimSearchFilter(FilterNode root,ArrayList<TestMembers> members,ArrayList<Attribute> nattribs) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if (root.getName().equalsIgnoreCase(staticAttribute)) {
					newNode = (FilterNode) root.clone();
					TestMembers tm = new TestMembers();
					tm.filterNode = newNode;
					tm.member = root.getValue();
					newNode.setName("objectClass");
					newNode.setValue("*");
					newNode.setType(FilterType.PRESENCE);
					members.add(tm);
					return newNode;
					
				} else {
					newNode = (FilterNode) root.clone();
					if (root.getName().equalsIgnoreCase("objectclass")) {
						if (newNode.getValue().equalsIgnoreCase(staticOC)) {
							if (this.mapOC) {
								newNode.setValue(dynOC);
							} else {
								ArrayList<FilterNode> orChildren = new ArrayList<FilterNode>();
								orChildren.add(newNode);
								orChildren.add(new FilterNode(FilterType.EQUALS,"objectClass",this.dynOC));
								
								FilterNode newOr = new FilterNode(FilterType.OR,orChildren);
								newNode = newOr;
							}
						}
					}
					
					this.addAttribute(nattribs, newNode.getName());
					
					return newNode;
				}
				
				
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = trimSearchFilter(it.next(),members,nattribs);
					if (node != null) {
						newChildren.add(node);
					}
					
				}
				
				if (newChildren.size() == 0) {
					return null;
				} else if (newChildren.size() == 1) {
					return newChildren.get(0);
				} else {
					newNode = new FilterNode(root.getType(),newChildren);
					return newNode;
				}
				
				
			case NOT:
				FilterNode node = trimSearchFilter(root.getNot(),members,nattribs);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
		
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}

class TestMembers {
	String member;
	FilterNode filterNode;
}

class DGRequest {
	boolean requestedMembers;
	boolean requestedUrls;
	Filter newFilter;
	ArrayList<TestMembers> testmembers;
}