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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Properties;
import java.util.StringTokenizer;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

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
import net.sourceforge.myvd.types.Results;

public class StaticDNMap implements Insert {

	private HashMap<String,String> inboundMap,outboundMap;
	private String name;
	private String insertName;
	private boolean mapBindDN;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapInboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;

			}
		}
		
		chain.nextAdd(entry, constraints);
		
		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}

	}

	private String mapInboundDN(String dn) {
		if (dn != null) {
			return this.inboundMap.get(dn.toLowerCase());
		} else {
			return null;
		}
	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		
		String newDN = mapInboundDN(dn.getDN().toString());
		if (newDN != null) {
			dn = new DistinguishedName(newDN);
			if (this.mapBindDN) {
				chain.getSession().put(LDAPInterceptor.NO_MAP_BIND_DN + this.insertName, "TRUE");
			}
		}
		
		chain.nextBind(dn, pwd, constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapInboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;
			}
		}
		
		
		
		chain.nextCompare(dn, attrib, constraints);
		
		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		
		this.name = name;
		String mappings = props.getProperty("dnmap");
		this.inboundMap = new HashMap<String,String>();
		this.outboundMap = new HashMap<String,String>();
		
		StringTokenizer toker = new StringTokenizer(mappings,"|",false);
		
		while (toker.hasMoreTokens()) {
			String map = toker.nextToken();
			String inbound = map.substring(0,map.indexOf('^'));
			String outbound = map.substring(map.indexOf('^') + 1);
			
			this.inboundMap.put(inbound.toLowerCase(), outbound);
			this.outboundMap.put(outbound.toLowerCase(), inbound);
		}
		
		this.insertName = props.getProperty("insertName");
		this.mapBindDN = props.getProperty("mapBindDN","false").equalsIgnoreCase("true");
		

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapInboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;
			}
		}
		
		chain.nextDelete(dn, constraints);
		
		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapInboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;
			}
		}
		
		chain.nextExtendedOperations(op, constraints);
		
		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}

	}

	public String getName() {
		return this.name;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapInboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;
			}
		}

		chain.nextModify(dn, mods, constraints);
		
		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}
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
		
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapOutboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;
			}
		}
		
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}
		
		
		

	}

	private String mapOutboundDN(String dn) {
		if (dn != null) {
			return this.outboundMap.get(dn.toLowerCase());
		} else {
			return null;
		}
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapInboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;
			}
		}
		
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapInboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;
			}
		}
		
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}
	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		DistinguishedName bindDN = (DistinguishedName) chain.getSession().get("MYVD_BINDDN");
		boolean didMap = false;
		if (bindDN != null) {
			String newDN = mapInboundDN(bindDN.getDN().toString());
			if (newDN != null) {
				DistinguishedName ndn = new DistinguishedName(newDN);
				chain.setBindDN(ndn);
				chain.getSession().put("MYVD_BINDDN",ndn );
				didMap = true;
			}
		}
		
		chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);
		
		if (didMap) {
			chain.getSession().put("MYVD_BINDDN", bindDN);
			chain.setBindDN(bindDN);
		}

	}

	public void shutdown() {
		// TODO Auto-generated method stub

	}

}
