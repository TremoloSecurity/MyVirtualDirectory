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
package net.sourceforge.myvd.inserts.mapping;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Properties;
import java.util.StringTokenizer;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.ByteArray;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.ListIterator;
import java.util.Properties;
import java.util.StringTokenizer;

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
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

public class AttributeValueMapper implements Insert {

	HashMap<String,HashMap<String,String>> remoteMap,localMap;
	String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		remoteMap = new HashMap<String,HashMap<String,String>>();
		localMap = new HashMap<String,HashMap<String,String>>();
		
		String mapping  =  props.getProperty("mapping");
		StringTokenizer toker = new StringTokenizer(mapping,",");
		
		while (toker.hasMoreTokens()) {
			String map = toker.nextToken();
			
			String local = map.substring(0,map.indexOf('='));
			String attrib = local.substring(0,local.indexOf('.'));
			local = local.substring(local.indexOf('.') + 1);
			
			
			String remote = map.substring(map.indexOf('=') + 1);
			
			HashMap<String,String> attribVals = localMap.get(attrib.toLowerCase());
			if (attribVals == null) {
				attribVals = new HashMap<String,String>();
				this.localMap.put(attrib.toLowerCase(),attribVals);
			}
			
			attribVals.put(local.toLowerCase(),remote);
			
			attribVals = remoteMap.get(attrib.toLowerCase());
			if (attribVals == null) {
				attribVals = new HashMap<String,String>();
				this.remoteMap.put(attrib.toLowerCase(),attribVals);
			}
			
			attribVals.put(remote.toLowerCase(),local);
		}
		
		
	}

	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		
		Iterator<String> it = this.localMap.keySet().iterator();
		while (it.hasNext()) {
			String name = it.next();
			entry.revalueAttribute(name,this.localMap.get(name));
		}
		
		chain.nextAdd(entry,constraints);
		
	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn,pwd,constraints);
		
	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		HashMap<String,String> map = this.localMap.get(attrib.getAttribute().getName().toLowerCase()); 
		if (map != null) {
			String newVal = map.get(attrib.getAttribute().getStringValue().toLowerCase());
			if (newVal != null) {
				attrib.getAttribute().removeValue(attrib.getAttribute().getStringValue());
				attrib.getAttribute().addValue(newVal);
			}
		}
		
		chain.nextCompare(dn,attrib,constraints);
		
	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn,constraints);
		
	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op, LDAPConstraints constraints) throws LDAPException {
		chain.nextExtendedOperations(op,constraints);
		
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods, LDAPConstraints constraints) throws LDAPException {
		
		ListIterator<LDAPModification> it = mods.listIterator();
		while (it.hasNext()) {
			LDAPModification mod = it.next();
			HashMap<String,String> newvals = this.localMap.get(mod.getAttribute().getBaseName().toLowerCase());
			if (newvals != null) {
				
				
				LinkedList<ByteArray> vals = mod.getAttribute().getAllValues();
				LinkedList<ByteArray> newVals = new LinkedList<ByteArray>();
				for (ByteArray b : vals) {
					String sval = b.toString();
					String newVal = newvals.get(sval.toLowerCase());
					if (newVal != null) {
						newVals.add(new ByteArray(newVal));
						
					} else {
						newVals.add(b);
					}
				}

				mod.getAttribute().setAllValues(newVals);
			}
		}
		
		chain.nextModify(dn,mods,constraints);
		
	}

	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints) throws LDAPException {
		FilterNode newRoot;
		try {
			newRoot = (FilterNode) filter.getRoot().clone();
		} catch (CloneNotSupportedException e) {
			throw new LDAPException("Could not map filter " + e.toString(),LDAPException.OPERATIONS_ERROR,"");
		}
		this.renameFilter(newRoot);
		
		chain.nextSearch(base,scope,new Filter(newRoot),attributes,typesOnly,results,constraints);
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn,newRdn,deleteOldRdn,constraints);
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn,newRdn,newParentDN,deleteOldRdn,constraints);
		
	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		
		chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);
		
		Iterator<String> it = this.remoteMap.keySet().iterator();
		while (it.hasNext()) {
			String name = it.next();
			entry.revalueAttribute(name,this.remoteMap.get(name));
		}
		
		
		
	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);
		
	}
	
	
	private void renameFilter(FilterNode node) {
		String name;
		String newVal;
		HashMap<String,String> map;
		switch (node.getType()) {
			case SUBSTR	: 
			case EQUALS 	  :
			case GREATER_THEN :
			case LESS_THEN:
			case PRESENCE : name = node.getName().toLowerCase();
							map= this.localMap.get(name);
							if (map != null) {
								newVal = map.get(node.getValue().toLowerCase());
								if (newVal != null) {
									node.setValue(newVal);
								}
							}
							break;
			case EXT:
							name = node.getName().toLowerCase();
							String ruleid = "";
							int sepIndex = name.indexOf(':');
							if (sepIndex > 0) {
								ruleid = name.substring(sepIndex + 1);
								name = name.substring(0,sepIndex);
							}
							map= this.localMap.get(name);
							if (map != null) {
								newVal = map.get(node.getValue().toLowerCase());
								if (newVal != null) {
									node.setValue(newVal);
								}
							}
							break;
			case AND:
			case OR:
							Iterator<FilterNode> it = node.getChildren().iterator();
							while (it.hasNext()) {
								renameFilter(it.next());
							}
							break;
			case NOT :		renameFilter(node.getNot());
		}
		
		
	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}


