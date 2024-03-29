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
package net.sourceforge.myvd.chain.jdbcLdapImpl;

import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

public class EntrySetSearchResults extends LDAPSearchResults {

	Results res;
	LDAPException exception = null;
	
	public EntrySetSearchResults(Results res) {
		this.res = res;
		try {
			this.res.start();
		} catch (LDAPException e) {
			exception = e;
		}
	}
	
	@Override
	public boolean hasMore() {
		try {
			return res.hasMore();
		} catch (LDAPException e) {
			exception = e;
			return false;
		}
	}

	@Override
	public LDAPEntry next() throws LDAPException {
		if (exception != null) {
			throw exception;
		}
		
		Entry entry = this.res.next();
		if (entry != null) {
			return entry.getEntry();
		} else {
			return null;
		}
		
	}

}
