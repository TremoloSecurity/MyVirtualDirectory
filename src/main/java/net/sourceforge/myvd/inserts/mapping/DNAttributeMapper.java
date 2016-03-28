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
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.NamingUtils;

public class DNAttributeMapper implements Insert {

	HashSet<String> dnAttribs;
	HashSet<String> urlAttribs;
	
	String[] localBase;
	String[] remoteBase;
	
	String localBaseDN;
	String remoteBaseDN;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		
		Entry nentry = new Entry(this.mapEntry(entry.getEntry(), true));
		chain.nextAdd(nentry, constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		
		
		if (this.dnAttribs.contains(attrib.getAttribute().getBaseName())) {
			LDAPAttribute nattrib = new LDAPAttribute(attrib.getAttribute().getName());
			NamingUtils util = new NamingUtils();
			nattrib.addValue(util.getRemoteMappedDN(new DN(attrib.getAttribute().getStringValue()), this.localBase, this.remoteBase).toString());
			
			chain.nextCompare(dn, new Attribute(nattrib), constraints);
		} else {
			chain.nextCompare(dn, attrib, constraints);
		}

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.dnAttribs = new HashSet<String>();
		this.urlAttribs = new HashSet<String>();
		
		StringTokenizer toker = new StringTokenizer(props.getProperty("dnAttribs",""),",",false);
		
		while (toker.hasMoreTokens()) {
			String attrib = toker.nextToken();
			this.dnAttribs.add(attrib.toLowerCase());
		}
		
		toker = new StringTokenizer(props.getProperty("urlAttribs",""),",",false);
		
		while (toker.hasMoreTokens()) {
			String attrib = toker.nextToken();
			this.urlAttribs.add(attrib.toLowerCase());
		}
		
		this.remoteBase = (new DN(props.getProperty("remoteBase",""))).explodeDN(false);
		this.localBase = (new DN(props.getProperty("localBase",""))).explodeDN(false);
		this.localBaseDN = props.getProperty("localBase","").toLowerCase();
		this.remoteBaseDN = props.getProperty("remoteBase","").toLowerCase();
		

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
		// TODO Auto-generated method stub
		return null;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		NamingUtils util = new NamingUtils();
		
		ArrayList<LDAPModification> nmods = new ArrayList<LDAPModification>();
		
		Iterator<LDAPModification> it = mods.iterator();
		while (it.hasNext()) {
			LDAPModification mod = it.next();
			LDAPAttribute attrib = mod.getAttribute();
			LDAPAttribute nattrib = this.mapAttribute(true, util, attrib);
			nmods.add(new LDAPModification(mod.getOp(),nattrib));
		}
		
		chain.nextModify(dn, nmods, constraints);

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
		entry.setEntry(this.mapEntry(entry.getEntry(), false));

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
		
		Filter nfilter = null;
		
		
		try {
			nfilter = new Filter((FilterNode) filter.getRoot().clone());
		} catch (CloneNotSupportedException e) {
			//can't happen
		}
		
		this.mapFilter(nfilter.getRoot());
		
		chain.nextSearch(base, scope, nfilter, attributes, typesOnly, results, constraints);

	}
	
	public LDAPEntry mapEntry(LDAPEntry origEntry,boolean outbound) {
		NamingUtils util = new NamingUtils();
		
		LDAPAttributeSet nattribs = new LDAPAttributeSet();
		
		LDAPAttributeSet origAttribs = origEntry.getAttributeSet();
		Iterator it = origAttribs.iterator();
		while (it.hasNext()) {
			LDAPAttribute origAttrib = (LDAPAttribute) it.next();
			LDAPAttribute nattrib = mapAttribute(outbound, util, origAttrib);
			
			nattribs.add(nattrib);
		}
		
		return new LDAPEntry(origEntry.getDN(),nattribs);
	}

	private LDAPAttribute mapAttribute(boolean outbound, NamingUtils util, LDAPAttribute origAttrib) {
		LDAPAttribute nattrib = new LDAPAttribute(origAttrib.getName());
		
		if (this.dnAttribs.contains(origAttrib.getName().toLowerCase())) {
			Enumeration enumer = origAttrib.getStringValues();
			while (enumer.hasMoreElements()) {
				String dn = (String) enumer.nextElement();
				
				if (outbound) {
					if (dn.toLowerCase().endsWith(this.localBaseDN)) {
						nattrib.addValue(util.getRemoteMappedDN(new DN(dn), this.localBase, this.remoteBase).toString());
					} else {
						nattrib.addValue(dn);
					}
				} else {
					if (dn.toLowerCase().endsWith(this.remoteBaseDN)) {
						nattrib.addValue(util.getLocalMappedDN(new DN(dn), this.remoteBase, this.localBase).toString());
					} else {
						nattrib.addValue(dn);
					}
				}
			}
		} else if (this.urlAttribs.contains(origAttrib.getName().toLowerCase())) {
			Enumeration enumer = origAttrib.getStringValues();
			while (enumer.hasMoreElements()) {
				String url = (String) enumer.nextElement();
				String urlbase = url.substring(url.indexOf('/') + 3,url.indexOf('?'));
				String nurl;
				
				if (outbound) {
					nurl = util.getRemoteMappedDN(new DN(urlbase), this.localBase, this.remoteBase).toString();
				} else {
					nurl = util.getLocalMappedDN(new DN(urlbase), this.remoteBase, this.localBase).toString();
				}
				
				nattrib.addValue("ldap:///" + nurl + url.substring(url.indexOf('?')));
			}
		} else {
			Enumeration enumer = origAttrib.getByteValues();
			while (enumer.hasMoreElements()) {
				nattrib.addValue((byte[]) enumer.nextElement());
			}
		}
		
		return nattrib;
	}

	
	
	private void mapFilter(FilterNode node) {
		String name;
		String newName;
		NamingUtils util = new NamingUtils();
		
		switch (node.getType()) {
			case EQUALS 	  :
				if (this.dnAttribs.contains(node.getName().toLowerCase()) && node.getValue().toLowerCase().endsWith(this.localBaseDN)) {
					node.setValue(util.getRemoteMappedDN(new DN(node.getValue()), this.localBase, this.remoteBase).toString());
				}
				break;
			case SUBSTR	: 
			
			case GREATER_THEN :
			case LESS_THEN:
			case PRESENCE : 
							break;
			case AND:
			case OR:
							Iterator<FilterNode> it = node.getChildren().iterator();
							while (it.hasNext()) {
								mapFilter(it.next());
							}
							break;
			case NOT :		mapFilter(node.getNot());
		}
		
		
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}
}
