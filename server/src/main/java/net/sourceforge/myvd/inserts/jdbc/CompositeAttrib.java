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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

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
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class CompositeAttrib implements Insert {

	private static final int FIRST_SPACE = -1;
	private static final int LAST_SPACE = -2;
	private static final Object MYVD_COMPATTRIB_TRUE = "MYVD_COMPATTRIB_TRUE";
	private String attributeName;
	Attribute attrib;
	ArrayList<AttribComp> attribComps;
	private String name;
	boolean properCase;
	String objectClass;
	
	
	HashMap<DN,String> uidMap;
	HashMap<String,FilterNode> filterMap;
	
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
		this.attributeName = props.getProperty("attribute");
		this.attrib = new Attribute(attributeName);
		StringTokenizer toker = new StringTokenizer(props.getProperty("components"),",",false);
		
		this.attribComps = new ArrayList<AttribComp>();
		
		while (toker.hasMoreTokens()) {
			String token = toker.nextToken();
			AttribComp comp = new AttribComp();
			comp.attribName = token.substring(0,token.indexOf(':'));
			String tmp = token.substring(token.indexOf(':') + 1);
			
			if (tmp.equals("*")) {
				comp.num = 0;
			} else if (tmp.equals("fs")) {
				comp.num = CompositeAttrib.FIRST_SPACE;
			} else if (tmp.equals("ls")) {
				comp.num = CompositeAttrib.LAST_SPACE;
			} else {
				comp.num = Integer.parseInt(tmp);
			}
			
			this.attribComps.add(comp);
			
			this.name = nameSpace.getLabel();
		}

		uidMap = new HashMap<DN,String>();
		filterMap = new HashMap<String,FilterNode>();
		
		this.properCase = Boolean.parseBoolean(props.getProperty("properCase"));
		this.objectClass = props.getProperty("objectClass");
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
		
		if (chain.getRequest().containsKey(CompositeAttrib.MYVD_COMPATTRIB_TRUE)) {
			String uid = this.uidMap.get(new DN(entry.getEntry().getDN()));
			
			
			
			if (uid == null) {
			
				String[] ocs = entry.getEntry().getAttribute("objectClass").getStringValueArray();
				
				boolean isoc = false;
				
				for (int i=0;i<ocs.length;i++) {
					if (ocs[i].equalsIgnoreCase(this.objectClass)) {
						isoc = true;
						break;
					}
				}
				
				
				if (isoc) {
					StringBuffer buf = new StringBuffer();
					Iterator<AttribComp> it = this.attribComps.iterator();
					while (it.hasNext()) {
						AttribComp comp = it.next();
						LDAPAttribute attr = entry.getEntry().getAttribute(comp.attribName);
						if (attr == null) {
							throw new LDAPException("Attribute not persent",LDAPException.OPERATIONS_ERROR,comp.attribName + " not present");
						}
						
						if (comp.num == 0) {
							buf.append(attr.getStringValue());
						} else if (comp.num == FIRST_SPACE || comp.num == LAST_SPACE) {
							buf.append(attr.getStringValue()).append(' ');
						} else {
							buf.append(attr.getStringValue().substring(0, comp.num));
						}
					}
					
					if (this.properCase) {
						uid = buf.toString().toLowerCase();
					} else {
						uid = buf.toString();
					}
				
				
				} else {
					uid = "";
				}
				
				this.uidMap.put(new DN(entry.getEntry().getDN()), uid);
			}
			
			
			if (uid.length() > 0) {
				entry.getEntry().getAttributeSet().add(new LDAPAttribute(this.attributeName,uid));
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
		
		
		
		Filter newFilter = null;
		
		try {
			newFilter = new Filter((FilterNode) filter.getRoot().clone());
		} catch (CloneNotSupportedException e) {
			//can't happen
		}
		
		this.rebuildFilter(newFilter.getRoot());
		
		
		if (attributes.size() == 0 || requestsAttrib(attributes)) {
			ArrayList<Attribute> newAttribs = createNewAttribs(attributes);
			chain.getRequest().put(MYVD_COMPATTRIB_TRUE, MYVD_COMPATTRIB_TRUE);
			chain.nextSearch(base, scope, newFilter, newAttribs, typesOnly, results, constraints);
		} else {
			chain.nextSearch(base, scope, newFilter, attributes, typesOnly, results, constraints);
		}

	}

	private ArrayList<Attribute> createNewAttribs(ArrayList<Attribute> attributes) {
		ArrayList<Attribute> newAttribs = new ArrayList<Attribute>();
		Iterator<Attribute> it = attributes.iterator();
		
		while (it.hasNext()) {
			Attribute attrib = it.next();
			if (attrib.getAttribute().equals(this.attrib)) {
				continue;
			} else {
				newAttribs.add(new Attribute(attrib.getAttribute().getName()));
			}
		}
		
		if (newAttribs.size() != 0) {
			Iterator<AttribComp> itcomp = this.attribComps.iterator();
			while (itcomp.hasNext()) {
				newAttribs.add(new Attribute(itcomp.next().attribName));
			}
			newAttribs.add(new Attribute("objectClass"));
		}
		return newAttribs;
	}

	private boolean requestsAttrib(ArrayList<Attribute> attributes) {
		Iterator<Attribute> it = attributes.iterator();
		
		while (it.hasNext()) {
			Attribute attrib = it.next();
			if (attrib.getAttribute().getName().equalsIgnoreCase(this.attrib.getAttribute().getName()) || attrib.getAttribute().getName().equals("*")) {
				return true;
			}
		}
		
		return false;
	}
	
	private void rebuildFilter(FilterNode node) throws LDAPException  {
		String name;
		String newName;
		switch (node.getType()) {
			case SUBSTR	: 
			case EQUALS 	  :
			case GREATER_THEN :
			case LESS_THEN:
			case PRESENCE : name = node.getName().toLowerCase();
							
							if (name.equalsIgnoreCase(this.attributeName)) {
								FilterNode nnode;
								try {
									nnode = (FilterNode) this.createNewNode(node).clone();
									node.setType(FilterType.AND);
									node.setChildren(nnode.getChildren());
									node.setName(null);
									node.setValue(null);
								} catch (CloneNotSupportedException e) {
									//can't happen
								}
								
							}
							break;
			case AND:
			case OR:
							Iterator<FilterNode> it = node.getChildren().iterator();
							while (it.hasNext()) {
								rebuildFilter(it.next());
							}
							break;
			case NOT :		rebuildFilter(node.getNot());
		}
		
		
	}
	
	private FilterNode createNewNode(FilterNode orig) {
		FilterNode tmp = this.filterMap.get(orig.toString());
		
		if (tmp != null) {
			return tmp;
		}
		
		String val = orig.getValue();
		
		ArrayList<FilterNode> nodes = new ArrayList<FilterNode>();
		
		Iterator<AttribComp> it = this.attribComps.iterator();
		int pos = 0;
		while (it.hasNext()) {
			AttribComp comp = it.next();
			String nval = "";
			boolean isSubStr = false;
			if (comp.num == 0) {
				nval = val.substring(pos);
				
			} else if (comp.num == FIRST_SPACE) {
				int index = val.indexOf(' ',pos);
				if (index == -1) {
					index = val.indexOf('*',pos);
					nval = val.substring(pos,index + 1);
					pos = index;
				} else {
					nval = val.substring(pos,index);
					pos = index + 1;
				}
				
				
			} else if (comp.num == LAST_SPACE) {
				int index = val.lastIndexOf(' ');
				if (index == -1) {
					index = val.indexOf('*',pos);
					nval = val.substring(pos,index + 1);
					pos = index;
				} else {
					nval = val.substring(pos,index);
					pos = index + 1;
				}
			} else {
				int index =  comp.num + pos;
				System.err.println("index : " + index);
				System.err.println("char : " + val.charAt(index - 1));
				
				if (val.charAt(index - 1) == '*') {
					nval = val.substring(pos,index);
					pos += comp.num - 1;
					isSubStr = true;
				} else {
					nval = val.substring(pos,index) + "*";
					pos += comp.num;
					isSubStr = true;
				}
			}
			
			if (this.properCase) {
				nval = nval.substring(0,1).toUpperCase() + (nval.length() > 1 ? nval.substring(1) : "");
			}
			
			FilterNode nd = new FilterNode(( isSubStr ? FilterType.SUBSTR : orig.getType()),comp.attribName,nval);
			nodes.add(nd);
			
		}
		
		FilterNode newNode = new FilterNode(FilterType.AND,nodes);
		
		this.filterMap.put(orig.toString(), newNode);
		
		return newNode;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}

class AttribComp {
	String attribName;
	int num;
}