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
package net.sourceforge.myvd.inserts.join;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
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
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.inserts.join.Joiner;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.NamingUtils;

public class SimpleJoinModify implements Insert {
	
	NameSpace ns;

	String name;
	
	String joinerName;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		
		chain.nextAdd(entry, constraints);
		
		
	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.ns = nameSpace;
		this.name = name;

		this.joinerName = props.getProperty("joinerName");
	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		DistinguishedName primaryDN = (DistinguishedName) chain.getRequest().get(Joiner.MYVD_JOIN_PDN + this.joinerName);
		ArrayList<DistinguishedName> joinedDns = (ArrayList<DistinguishedName>) chain.getRequest().get(Joiner.MYVD_JOIN_JDN + this.joinerName);
		HashSet joinAttribs = (HashSet) chain.getRequest().get(Joiner.MYVD_JOIN_JATTRIBS + this.joinerName);

		
		DeleteInterceptorChain nchain = null;
		
		nchain = new DeleteInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,new InsertChain(new Insert[0]),chain.getSession(),chain.getRequest(),ns.getRouter());
		nchain.nextDelete(primaryDN, constraints);
		
		nchain = new DeleteInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,new InsertChain(new Insert[0]),chain.getSession(),chain.getRequest(),ns.getRouter());
		nchain.nextDelete(joinedDns.get(0), constraints);
	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		
		DistinguishedName primaryDN = (DistinguishedName) chain.getRequest().get(Joiner.MYVD_JOIN_PDN + this.joinerName);
		ArrayList<DistinguishedName> joinedDns = (ArrayList<DistinguishedName>) chain.getRequest().get(Joiner.MYVD_JOIN_JDN + this.joinerName);
		HashSet joinAttribs = (HashSet) chain.getRequest().get(Joiner.MYVD_JOIN_JATTRIBS + this.joinerName);
		
		ArrayList<LDAPModification> primaryMods = new ArrayList<LDAPModification>();
		ArrayList<LDAPModification> joinedMods = new ArrayList<LDAPModification>();
		
		Iterator<LDAPModification> it = mods.iterator();
		
		while (it.hasNext()) {
			LDAPModification mod = it.next();
			
			if (joinAttribs.contains(mod.getAttribute().getName())) {
				joinedMods.add(mod);
			} else {
				primaryMods.add(mod);
			}
		}
		
		ModifyInterceptorChain modchain = null;
		
		if (primaryMods.size() != 0) {
			modchain = new ModifyInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,new InsertChain(new Insert[0]),chain.getSession(),chain.getRequest(),ns.getRouter());
			modchain.nextModify(primaryDN, primaryMods, constraints);
		}
		
		if (joinedMods.size() != 0) {
			modchain = new ModifyInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,new InsertChain(new Insert[0]),chain.getSession(),chain.getRequest(),ns.getRouter());
			modchain.nextModify(joinedDns.get(0), joinedMods, constraints);
		}

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
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

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
