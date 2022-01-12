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
import java.util.ListIterator;
import java.util.Properties;
import java.util.StringTokenizer;
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
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public class AttributeMapper implements Insert {

	HashMap<String,String> remoteMap,localMap;
	String name;
	HashMap<String,String> in2out;
	HashMap<String,String> out2in;
	
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		remoteMap = new HashMap<String,String>();
		localMap = new HashMap<String,String>();
		
		String mapping  =  props.getProperty("mapping");
		StringTokenizer toker = new StringTokenizer(mapping,",");
		
		while (toker.hasMoreTokens()) {
			String map = toker.nextToken();
			String local = map.substring(0,map.indexOf('='));
			String remote = map.substring(map.indexOf('=') + 1);
			
			localMap.put(local.toLowerCase(),remote);
			remoteMap.put(remote.toLowerCase(),local);
		}
		
		this.out2in = new HashMap<String,String>();
		this.in2out = new HashMap<String,String>();
		
		
	}

	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		
		Iterator<String> it = this.localMap.keySet().iterator();
		while (it.hasNext()) {
			String name = it.next();
			entry.renameAttribute(name,this.localMap.get(name));
		}
		
		chain.nextAdd(entry,constraints);
		
	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints) throws LDAPException {
		
		String newDN = this.getDnFromIn2Out(dn.getDN().toString());
		
		if (newDN != null) {
			dn = new DistinguishedName(newDN);
		}
		
		chain.nextBind(dn,pwd,constraints);
		
	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib, LDAPConstraints constraints) throws LDAPException {

		
		String oldName = attrib.getAttribute().getName().toLowerCase();
		String newName = this.localMap.get(oldName);
		
		if (newName != null) {
			Attribute nattrib = new Attribute(new LDAPAttribute(newName,attrib.getAttribute().getByteValue()));
			chain.nextCompare(dn,nattrib,constraints);
		} else {
			chain.nextCompare(dn,attrib,constraints);
		}
		
		
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
			String newName = this.localMap.get(mod.getAttribute().getBaseName().toLowerCase());
			if (newName != null) {
				LDAPAttribute newAttrib = new LDAPAttribute(newName);
				mod.getAttribute().setName(newName);
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
		
		
		Iterator<Attribute> it = attributes.iterator();
		while (it.hasNext()) {
			Attribute attrib = it.next();
			String newName = this.localMap.get(attrib.getAttribute().getBaseName().toLowerCase());
			if (newName != null) {
				attrib.rename(newName);
			}
		}
		
		chain.nextSearch(base,scope,new Filter(newRoot),attributes,typesOnly,results,constraints);
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn,newRdn,deleteOldRdn,constraints);
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn,newRdn,newParentDN,deleteOldRdn,constraints);
		
	}

	private String getDnFromIn2Out(String dnin) {
		String dnFromCache = this.out2in.get(dnin);
		if (dnFromCache != null) {
			return dnFromCache;
		}
		
		DN dnInDN = new DN(dnin);
		Vector rdns = dnInDN.getRDNs();
		RDN rdn = (RDN) rdns.get(0);
		String newRdnType = this.localMap.get(rdn.getType().toLowerCase());
		if (newRdnType == null) {
			return dnin;
		}
		
		RDN newRDN = new RDN();
		newRDN.add(newRdnType, rdn.getValue(), rdn.getValue());
		
		DN newDN = new DN();
		newDN.addRDNToBack(newRDN);
		
		for (int i=1;i<rdns.size();i++) {
			newDN.addRDNToBack((RDN) rdns.get(i));
		}
		
		String newDNStr = newDN.toString();
		
		this.out2in.put(dnin, newDNStr);
		this.in2out.put(newDNStr, dnin);
		
		return newDNStr;
	
	}
	
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		
		chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);
		StringBuilder sb = new StringBuilder();
		Iterator<String> it = this.remoteMap.keySet().iterator();
		String lowercasedn = entry.getEntry().getDN().toLowerCase();
		boolean mapDN = false;
		String mapDnTo = null;
		while (it.hasNext()) {
			String name = it.next();
			entry.renameAttribute(name,this.remoteMap.get(name));
			sb.setLength(0);
			sb.append(name.toLowerCase()).append('=');
			if (lowercasedn.startsWith(sb.toString())) {
				mapDN = true; 
				mapDnTo = this.remoteMap.get(name);
			}
		}
		
		if (mapDN) {
			
			String newDNFromCache = this.in2out.get(entry.getEntry().getDN());
			DN newDN;
			
			if (newDNFromCache != null) {
				newDN = new DN(newDNFromCache);
			} else {
				newDN = new DN(entry.getEntry().getDN());
				Vector rdns = newDN.getRDNs();
				RDN curRDN = (RDN) rdns.get(0);
				RDN newRDN = new RDN();
				newRDN.add(mapDnTo, curRDN.getValue(), curRDN.getValue());
				rdns.remove(0);
				rdns.insertElementAt(newRDN, 0);
				
				newDN = new DN();
				for (int i = 0;i<rdns.size();i++) {
					newDN.addRDNToBack((RDN) rdns.get(i));
				}
				this.out2in.put(newDN.toString(), entry.getEntry().getDN());
				this.in2out.put(entry.getEntry().getDN(), newDN.toString());
			}
			
			
			
			entry.setDN(newDN);
			LDAPEntry newEntry = new LDAPEntry(newDN.toString(),entry.getEntry().getAttributeSet());
			entry.setEntry(newEntry);
		}
		
		
		
		
	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);
		
	}
	
	
	private void renameFilter(FilterNode node) {
		String name;
		String newName;
		switch (node.getType()) {
			case SUBSTR	: 
			case EQUALS 	  :
			case GREATER_THEN :
			case LESS_THEN:
			case PRESENCE : name = node.getName().toLowerCase();
							newName = this.localMap.get(name);
							if (newName != null) {
								node.setName(newName);
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


