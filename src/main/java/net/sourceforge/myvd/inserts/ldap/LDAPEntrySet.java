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

import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;

import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.novell.ldap.util.DN;

public class LDAPEntrySet implements EntrySet {

	LDAPInterceptor interceptor;
	ConnectionWrapper wrapper;
	LDAPSearchResults results;
	
	Entry currEntry;
	
	boolean done;
	boolean entryFetched;
	boolean isFirst;
	
	int numRes;
	
	LDAPControl[] curCtls;
	private String remoteBase;
	private int scope;
	private String filter;
	private String[] attrs;
	private boolean typesOnly;
	private LDAPSearchConstraints constraints;
	
	
	
	public LDAPEntrySet(LDAPInterceptor interceptor,ConnectionWrapper wrapper,LDAPSearchResults results, String remoteBase, int scope, String filter, String[] attribs, boolean typesOnly, LDAPSearchConstraints constraints) {
		this.done = false;
		this.entryFetched = true;
		this.interceptor = interceptor;
		this.wrapper = wrapper;
		this.results = results;
		this.isFirst = true;
		this.numRes = 0;
		this.remoteBase = remoteBase;
		this.scope = scope;
		this.filter = filter;
		this.attrs = attribs;
		this.typesOnly = typesOnly;
		this.constraints = constraints;
	}
	
	public boolean hasMore() throws LDAPException {
		if (! done) {
			if (entryFetched || isFirst) {
				isFirst = false;
				return getNextLDAPEntry();
			} else {
				return true;
			}
		} else {
			return false;
		}
	}

	private boolean getNextLDAPEntry() throws LDAPException {
		try {
			if (results.hasMore()) {
				
				LDAPEntry entry = null;
				LDAPControl[] respControls = null;
				try {
					entry = results.next();
					this.numRes++;
					
					respControls = results.getResponseControls();
					this.curCtls = respControls;
					
				} catch (LDAPReferralException e) {
					if (this.interceptor.isIgnoreRefs()) {
						//skip this entry
						return getNextLDAPEntry();
					} else {
						//TODO create named referal?
					}
				}
				
				String dn = entry.getDN();
				

				dn = dn.replaceAll("[\\\\][2][C]", "\\\\,");
				
				this.currEntry = new Entry(new LDAPEntry(interceptor.getLocalMappedDN(new DN(dn)).toString(),entry.getAttributeSet()),respControls);
				this.entryFetched = false;
				return true;
			} else {
				
				if (this.interceptor.isUsePaging()) {
					if (this.numRes == this.interceptor.getPageSize()) {
						//need to load the next page
						for (LDAPControl control : this.results.getResponseControls()) {
							if (control instanceof LDAPPagedResultsResponse) {
								LDAPPagedResultsResponse resp = (LDAPPagedResultsResponse) control;
								LDAPPagedResultsControl page = (LDAPPagedResultsControl) constraints.getControls()[constraints.getControls().length - 1];
								page.setCookie(resp.getCookie());
							}
						}
						
						this.results = this.wrapper.getConnection().search(remoteBase, scope, filter, attrs, typesOnly,this.constraints);
						this.numRes = 0;
						return this.getNextLDAPEntry();
					}
				}
				
				this.done = true;
				interceptor.returnLDAPConnection(this.wrapper);
				return false;
			}
		} catch (LDAPException e) {
			interceptor.returnLDAPConnection(wrapper);
			throw e;
		}
	}

	public Entry getNext() throws LDAPException {
		if (! done) {
			if (! entryFetched) {
				entryFetched = true;
				return this.currEntry;
			} else {
				this.hasMore();
				return this.getNext();
			}
		} else {
			return null;
		}
	}

	public void abandon() throws LDAPException {
		this.interceptor.returnLDAPConnection(this.wrapper);

	}

}
