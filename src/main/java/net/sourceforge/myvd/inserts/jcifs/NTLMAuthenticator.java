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
package net.sourceforge.myvd.inserts.jcifs;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;
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
import net.sourceforge.myvd.types.SessionVariables;
import net.sourceforge.myvd.util.EntryUtil;
import net.sourceforge.myvd.util.IteratorEntrySet;

import jcifs.UniAddress;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbSession;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public class NTLMAuthenticator implements Insert {

	String host;
	String name;
	String base;
	
	UniAddress addr;

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.host = props.getProperty("host");
		try {
			addr = UniAddress.getByName(host);
		} catch (UnknownHostException e) {
			throw new LDAPException("Could not lookup host : " + e.toString(),
					LDAPException.OPERATIONS_ERROR, "");
		}
		
		base = nameSpace.getBase().getDN().toString();
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Add not supported",
				LDAPException.LDAP_NOT_SUPPORTED, "");

	}

public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		Vector<RDN> rdns = dn.getDN().getRDNs();
		
		
		String domain = rdns.get(1).getValue();
		String user = rdns.get(0).getValue();
		
		
		
		try {
			SmbSession.logon(this.addr,new NtlmPasswordAuthentication(domain,user,new String(pwd.getValue())));
		} catch (SmbException e) {
			e.printStackTrace();
			throw new LDAPException(e.toString(),LDAPException.INVALID_CREDENTIALS,"");
		}
		
		chain.getSession().put(SessionVariables.BOUND_INTERCEPTORS,this.name);

	}	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Add not supported",
				LDAPException.LDAP_NOT_SUPPORTED, "");

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Add not supported",
				LDAPException.LDAP_NOT_SUPPORTED, "");

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Add not supported",
				LDAPException.LDAP_NOT_SUPPORTED, "");

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Add not supported",
				LDAPException.LDAP_NOT_SUPPORTED, "");

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
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
				
				entries.add(new Entry(this.getUserEntry(domain,user)));
				
				chain.addResult(results,new IteratorEntrySet(entries.iterator()),base,scope,filter,attributes,typesOnly,constraints);
			}
			
			
		} else {
			ArrayList<FilterNode> nodes = filter.listNodes("userName");
			ArrayList<Entry> res = new ArrayList<Entry>();
			Iterator<FilterNode> it = nodes.iterator();
			
			while (it.hasNext()) {
				String val = it.next().getValue();
				String user = val.substring(0,val.indexOf('@'));
				String domain = val.substring(val.indexOf('@') + 1);
				
				res.add(new Entry(this.getUserEntry(domain,user)));
			}
			
			chain.addResult(results,new IteratorEntrySet(res.iterator()),base,scope,filter,attributes,typesOnly,constraints);
		}

	}
	
	private LDAPEntry getUserEntry(String domain,String user) {
		String dn = "uid=" + user + ",dc=" + domain + "," + base;
		LDAPAttributeSet attribSet = new LDAPAttributeSet();
		
		attribSet.add(new LDAPAttribute("uid",user));
		attribSet.add(new LDAPAttribute("dc",domain));
		attribSet.add(new LDAPAttribute("objectClass","ntlmUser"));
		attribSet.add(new LDAPAttribute("userName",user + "@" + domain));
		
		return new LDAPEntry(dn,attribSet);
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Add not supported",
				LDAPException.LDAP_NOT_SUPPORTED, "");

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Add not supported",
				LDAPException.LDAP_NOT_SUPPORTED, "");

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {

	}

	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}
}
