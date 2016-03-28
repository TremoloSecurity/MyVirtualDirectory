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
package net.sourceforge.myvd.types;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.TreeSet;

import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchResult;

import net.sourceforge.myvd.chain.InterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.inserts.Insert;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

public class Results {
	InsertChain globalChain;
	
	ArrayList<Result> results;
	ArrayList<Result> finished;
	
	TreeSet<DN> processed;
	int numResults;
	
	Result ldapResults;
	boolean entryGotten;
	Entry currentEntry;
	int notFounds;
	
	boolean completed;

	private int start;
	private boolean skipDupes;
	
	
	public Results(InsertChain globalChain) {
		this.results = new ArrayList<Result>();
		this.finished = new ArrayList<Result>();
		this.processed = new TreeSet<DN>(new DNComparer());
		entryGotten = true;
		notFounds = 0;
		this.globalChain = globalChain;
		this.start = 0;
		this.skipDupes = true;
		this.completed = false;
	}
	
	public Results(InsertChain globalChain,int start) {
		this(globalChain);
		this.start = start;
		this.skipDupes = true;
	}
	
	public void addResult(SearchInterceptorChain chain,EntrySet entrySet, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints,InsertChain local) {
		Result res = new Result();
		res.entrySet = entrySet;
		res.attribs = attributes;
		res.base = base;
		res.filter = filter;
		res.scope = scope;
		res.typesOnly = typesOnly;
		res.globalSource = globalChain;
		res.localSource = local;
		res.chain = chain;
		
		this.results.add(res);
	}
	
	public ArrayList<Result> getResults() {
		return this.results;
	}
	
	public void start() throws LDAPException {
		this.numResults = this.results.size();
		if (this.results.size() == 0) {
			this.ldapResults = null;
		} else {
			this.ldapResults = this.results.remove(0);
			this.finished.add(this.ldapResults);
			this.hasMore();
		}
	}
	
	public boolean hasMore() throws LDAPException {
		if (! this.entryGotten) {
			return this.currentEntry != null;
		}
		
		if (ldapResults == null) {
			return false;
		}
		
		boolean hasMore = ldapResults.entrySet.hasMore();
		if (! hasMore) {
			return finishSet();
		} else {
			try {
				this.currentEntry = nextEntry();
				if (! this.currentEntry.isReturnEntry()) {
					return this.hasMore();
				}
				this.entryGotten = false;
			} catch (LDAPException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				
				if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
					this.notFounds++;
					if (this.notFounds == this.numResults) {
						throw new LDAPException("Base not found",LDAPException.NO_SUCH_OBJECT,"");
					} else {
						return finishSet();
					}
				} else {
					throw e;
				}
			}
			
			return true;
		}
	}
	
	/**
	 * @return
	 * @throws NamingException
	 */
	private boolean finishSet() throws LDAPException {
		if (this.results.size() > 0) {
			this.ldapResults =  results.remove(0);
			this.finished.add(ldapResults);
			return this.hasMore();
		} else {
			if (! this.completed) {
				this.complete();
				this.completed = true;
			}
			return false;
		}
	}
	
	public void finish() throws LDAPException {
		Iterator<Result> it = this.results.iterator();
		while (it.hasNext()) {
			it.next().entrySet.abandon();
		}
	}
	
	/* (non-Javadoc)
	 * @see javax.naming.NamingEnumeration#next()
	 */
	public Entry next() throws LDAPException {
		
		if (this.currentEntry == null) {
			return null;
		}
		
		this.entryGotten = true;
		Entry entry = this.currentEntry;
		
		if ((! this.skipDupes) || ! this.processed.contains(new DN(entry.getEntry().getDN()))) {
			this.processed.add(new DN(entry.getEntry().getDN()));
			
			return entry;
		} else {
			if (this.hasMore()) {
				return this.next();
			} else {
				return null;
			}
		}
	}
	
	private Entry nextEntry() throws LDAPException {
		Entry entry = ldapResults.entrySet.getNext();
		
		PostSearchEntryInterceptorChain chain = new PostSearchEntryInterceptorChain(ldapResults.chain.getBindDN(),ldapResults.chain.getBindPassword(),this.start,ldapResults.localSource,this.globalChain,ldapResults.chain.getSession(),ldapResults.chain.getRequest());
		chain.nextPostSearchEntry(entry,ldapResults.base,ldapResults.scope,ldapResults.filter,ldapResults.attribs,ldapResults.typesOnly,ldapResults.constraints);
		
		
		return entry;
	}
	
	private void complete() throws LDAPException {
		
		Iterator<Result> it = this.finished.iterator();
		
		while (it.hasNext()) {
			Result ldapResults = it.next();
			PostSearchCompleteInterceptorChain chain = new PostSearchCompleteInterceptorChain(ldapResults.chain.getBindDN(),ldapResults.chain.getBindPassword(),this.start,ldapResults.localSource,this.globalChain,ldapResults.chain.getSession(),ldapResults.chain.getRequest());
			chain.nextPostSearchComplete(ldapResults.base,ldapResults.scope,ldapResults.filter,ldapResults.attribs,ldapResults.typesOnly,ldapResults.constraints);
		}
		
		
		
	}

	public boolean isSkipDupes() {
		return skipDupes;
	}

	public void setSkipDupes(boolean skipDupes) {
		this.skipDupes = skipDupes;
	}
	
}


