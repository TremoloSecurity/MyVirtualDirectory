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
import java.util.HashMap;
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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.RequestVariables;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPUrl;

/**
 * @author mlb
 *
 */
public class ReferallInterceptor implements Insert {

	HashMap<String,String> hostToNS;
	String name;
	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#configure(java.lang.String, java.util.Properties, net.sourceforge.myvd.core.NameSpace)
	 */
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		
		this.hostToNS = new HashMap<String,String>();
		String mapping = props.getProperty("mapping");
		StringTokenizer toker = new StringTokenizer(mapping,",");
		
		while (toker.hasMoreTokens()) {
			String map = toker.nextToken();
			String local = map.substring(0,map.indexOf('='));
			String remote = map.substring(map.indexOf('=') + 1);
			
			hostToNS.put(local.toLowerCase(),remote);
		}
		
		this.name = name;

	}
	
	private String getNS(LDAPReferralException ref)  {
		String refURL = ref.getReferrals()[0];
		
		LDAPUrl url;
		try {
			url = new LDAPUrl(refURL);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
		String ns = this.hostToNS.get(url.getHost() + ":" + url.getPort());
		
		return ns;
		
	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#add(net.sourceforge.myvd.chain.AddInterceptorChain, net.sourceforge.myvd.types.Entry, com.novell.ldap.LDAPConstraints)
	 */
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		try {
			chain.nextAdd(entry,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.nextAdd(entry,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#bind(net.sourceforge.myvd.chain.BindInterceptorChain, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.Password, com.novell.ldap.LDAPConstraints)
	 */
	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		try {
			chain.nextBind(dn,pwd,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.nextBind(dn,pwd,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#compare(net.sourceforge.myvd.chain.CompareInterceptorChain, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.Attribute, com.novell.ldap.LDAPConstraints)
	 */
	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		try {
			chain.nextCompare(dn,attrib,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.nextCompare(dn,attrib,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#delete(net.sourceforge.myvd.chain.DeleteInterceptorChain, net.sourceforge.myvd.types.DistinguishedName, com.novell.ldap.LDAPConstraints)
	 */
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		try {
			chain.nextDelete(dn,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.nextDelete(dn,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#extendedOperation(net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain, net.sourceforge.myvd.types.ExtendedOperation, com.novell.ldap.LDAPConstraints)
	 */
	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		try {
			chain.nextExtendedOperations(op,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.nextExtendedOperations(op,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#modify(net.sourceforge.myvd.chain.ModifyInterceptorChain, net.sourceforge.myvd.types.DistinguishedName, java.util.ArrayList, com.novell.ldap.LDAPConstraints)
	 */
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		try {
			chain.nextModify(dn,mods,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.nextModify(dn,mods,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#search(net.sourceforge.myvd.chain.SearchInterceptorChain, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.Int, net.sourceforge.myvd.types.Filter, java.util.ArrayList, net.sourceforge.myvd.types.Bool, net.sourceforge.myvd.types.Results, com.novell.ldap.LDAPSearchConstraints)
	 */
	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		try {
			chain.nextSearch(base,scope,filter,attributes,typesOnly,results,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.nextSearch(base,scope,filter,attributes,typesOnly,results,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#rename(net.sourceforge.myvd.chain.RenameInterceptorChain, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.Bool, com.novell.ldap.LDAPConstraints)
	 */
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		try {
			chain.nextRename(dn,newRdn,deleteOldRdn,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.nextRename(dn,newRdn,deleteOldRdn,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#rename(net.sourceforge.myvd.chain.RenameInterceptorChain, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.Bool, com.novell.ldap.LDAPConstraints)
	 */
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		try {
			chain.nextRename(dn,newRdn,newParentDN,deleteOldRdn,constraints); 
		} catch (LDAPReferralException r) {
			String ns = this.getNS(r);
			if (ns == null) {
				throw r;
			} else {
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,ns);
				chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE_RENAME,ns);
				chain.nextRename(dn,newRdn,newParentDN,deleteOldRdn,constraints);
			}
			
		}

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#postSearchEntry(net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain, net.sourceforge.myvd.types.Entry, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.Int, net.sourceforge.myvd.types.Filter, java.util.ArrayList, net.sourceforge.myvd.types.Bool, com.novell.ldap.LDAPSearchConstraints)
	 */
	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);

	}

	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.inserts.Insert#postSearchComplete(net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain, net.sourceforge.myvd.types.DistinguishedName, net.sourceforge.myvd.types.Int, net.sourceforge.myvd.types.Filter, java.util.ArrayList, net.sourceforge.myvd.types.Bool, com.novell.ldap.LDAPSearchConstraints)
	 */
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);

	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
