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

import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchConstraints;



import java.util.ArrayList;

import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

public class JoinerEntrySet implements EntrySet {

	Results results;
	
	
	public JoinerEntrySet(Router router,SearchInterceptorChain chain,DistinguishedName base,Int scope,Filter filter,ArrayList<Attribute> attributes,Bool typesOnly,LDAPSearchConstraints constraints,DistinguishedName bindDN) throws LDAPException {
		results = new Results(new InsertChain(new Insert[0]),0);
		
		SearchInterceptorChain searchChain = new SearchInterceptorChain(bindDN,chain.getBindPassword(),router.getGlobalChain().getLength(),router.getGlobalChain(),chain.getSession(),chain.getRequest(),router);
		searchChain.nextSearch(base,scope,filter,attributes,typesOnly,results,constraints);
		results.start();
	}
	
	public boolean hasMore() throws LDAPException {
		return this.results.hasMore();
	}

	public Entry getNext() throws LDAPException {
		return results.next();
	}

	public void abandon() throws LDAPException {
		results.finish();

	}

}
