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
package net.sourceforge.myvd.inserts.kerberos;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;
import java.util.Vector;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

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
import net.sourceforge.myvd.util.EntryUtil;
import net.sourceforge.myvd.util.IteratorEntrySet;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;


public class KerberosInterceptor implements Insert {

	private static final String CREATE_ENTRY = "createEntry";
	String base;
	boolean createEntry;
	String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		base = nameSpace.getBase().getDN().toString();
		createEntry = props.getProperty(KerberosInterceptor.CREATE_ENTRY) != null && props.getProperty(KerberosInterceptor.CREATE_ENTRY).equalsIgnoreCase("true");
		this.name = name;
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		String user = ((RDN) dn.getDN().getRDNs().get(0)).getValue();
		LoginContext lc = null;
		try {
			lc = new LoginContext("MyVD", new KerbHandler(user,pwd.getValue()));
		} catch (LoginException le) {
			le.printStackTrace();
			throw new LDAPException(le.toString(),LDAPException.INVALID_CREDENTIALS,le.toString());
		} catch (SecurityException se) {
			se.printStackTrace();
			throw new LDAPException(se.toString(),LDAPException.INVALID_CREDENTIALS,se.toString());
		}

		try {
			// attempt authentication
			lc.login();
		} catch (LoginException le) {
			le.printStackTrace();
			throw new LDAPException(le.toString(),LDAPException.INVALID_CREDENTIALS,le.toString());
		}

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);

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

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		if (createEntry) {
			if (scope.getValue() == 0) {
				
				if (base.getDN().toString().equals(this.base)) {
					ArrayList<Entry> entries = new ArrayList<Entry>();
					
					entries.add(new Entry(EntryUtil.createBaseEntry(new DN(this.base))));
					
					chain.addResult(results,new IteratorEntrySet(entries.iterator()),base,scope,filter,attributes,typesOnly,constraints);
					
				} else {
					Vector<RDN> rdns = base.getDN().getRDNs();
					String domain = rdns.get(1).getValue();
					String user = rdns.get(0).getValue();
					
					ArrayList<Entry> entries = new ArrayList<Entry>();
					
					entries.add(new Entry(this.getUserEntry(user)));
					
					chain.addResult(results,new IteratorEntrySet(entries.iterator()),base,scope,filter,attributes,typesOnly,constraints);
				}
				
				
			} else {
				ArrayList<FilterNode> nodes = filter.listNodes("uid");
				ArrayList<Entry> res = new ArrayList<Entry>();
				Iterator<FilterNode> it = nodes.iterator();
				
				while (it.hasNext()) {
					String val = it.next().getValue();
					String user = val;
					
					
					res.add(new Entry(this.getUserEntry(user)));
				}
				
				chain.addResult(results,new IteratorEntrySet(res.iterator()),base,scope,filter,attributes,typesOnly,constraints);
			}
			
		} else {
			chain.nextSearch(base, scope, filter, attributes, typesOnly,
					results, constraints);
		}

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn,constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes,
				typesOnly, constraints);

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes,
				typesOnly, constraints);

	}
	
	private LDAPEntry getUserEntry(String user) {
		String dn = "uid=" + user + "," + base;
		LDAPAttributeSet attribSet = new LDAPAttributeSet();
		
		attribSet.add(new LDAPAttribute("uid",user));
		attribSet.add(new LDAPAttribute("objectClass","kerbUser"));
		
		
		return new LDAPEntry(dn,attribSet);
	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
