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
package net.sourceforge.myvd.inserts.cache.simple;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import com.novell.ldap.LDAPConstraints;
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

public class SimpleCache implements Insert {

	public static final String SIMPLE_CACHE_IS_CACHED = "SIMPLE_CACHE_IS_CACHED_";
	private static final String SIMPLE_CACHE_ENTRY_SET = "SIMPLE_CACHE_ENTRY_SET_";
	
	String name;
	NameSpace ns;
	
	HashMap<CacheKey,SimpleCacheEntrySet> cache;
	
	String isCachedKey;
	String cacheESKey;
	
	long ttl;
	
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
		
		CacheKey key = new CacheKey(dn.getDN().toString(),new Attribute(attrib.getAttribute().getName(),attrib.getAttribute().getStringValue()));
		
		SimpleCacheEntrySet cacheResults = this.cache.get(key);
		
		if (cacheResults != null) {
			if (! cacheResults.isCompareTrue()) {
				throw new LDAPException("Compare failed",LDAPException.COMPARE_FALSE,"Failed to compare on DN : " + dn.getDN().toString());
			}
		} else {
			try {
				chain.nextCompare(dn, attrib, constraints);
				cacheResults = new SimpleCacheEntrySet(key,true);
				this.cache.put(key, cacheResults);
			} catch (LDAPException ldape) {
				if (ldape.getResultCode() == LDAPException.COMPARE_FALSE || ldape.getResultCode() == LDAPException.COMPARE_TRUE) {
					cacheResults = new SimpleCacheEntrySet(key,(ldape.getResultCode() == LDAPException.COMPARE_TRUE));
					this.cache.put(key, cacheResults);
				}
				
				throw ldape;
			}
		}

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.cache = new HashMap<CacheKey,SimpleCacheEntrySet>();
		this.name = name;
		this.ns = nameSpace;
		
		this.isCachedKey = SimpleCache.SIMPLE_CACHE_IS_CACHED + this.name;
		this.cacheESKey = SimpleCache.SIMPLE_CACHE_ENTRY_SET + this.name;
		
		this.ttl = Long.parseLong(props.getProperty("timeToLive","10000"));

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
		
		
		
		Boolean isCache = (Boolean) chain.getRequest().get(this.isCachedKey);
		
		if (! isCache) {
			chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);
			SimpleCacheEntrySet cache = (SimpleCacheEntrySet) chain.getRequest().get(this.cacheESKey);
			synchronized (this.cache) {
				this.cache.put(cache.getKey(), cache);
			}
		}

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		Boolean isCache = (Boolean) chain.getRequest().get(this.isCachedKey);
		
		if (! isCache) {
			chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
			
			SimpleCacheEntrySet cache = (SimpleCacheEntrySet) chain.getRequest().get(this.cacheESKey);
			if (entry.isReturnEntry()) {
				cache.addEntry(entry.getEntry());
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
		
		CacheKey key = new CacheKey(base.getDN().toString(),filter.getRoot().toString(),attributes,scope.getValue());
		
		SimpleCacheEntrySet cacheResults = this.cache.get(key);
		
		if (cacheResults != null && cacheResults.getLife() < this.ttl) {
			chain.getRequest().put(this.isCachedKey, true);
			results.addResult(chain, cacheResults.getCopy(), base, scope, filter, attributes, typesOnly, constraints, this.ns.getChain());
		} else {
			chain.getRequest().put(this.cacheESKey, new SimpleCacheEntrySet(key));
			chain.getRequest().put(this.isCachedKey, false);
			chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);
		}
		
		
		

	}

	public void shutdown() {
		// TODO Auto-generated method stub

	}

}
