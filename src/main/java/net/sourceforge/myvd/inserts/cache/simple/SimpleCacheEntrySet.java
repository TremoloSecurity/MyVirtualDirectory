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
import java.util.Iterator;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;
import com.novell.ldap.*;

public class SimpleCacheEntrySet implements EntrySet {

	
	ArrayList<LDAPEntry> res;
	CacheKey key;
	
	Iterator<LDAPEntry> iter;
	
	Boolean compareResults;
	
	long created;
	
	public SimpleCacheEntrySet (CacheKey key) {
		this.res = new ArrayList<LDAPEntry>();
		this.key = key;
		
		this.created = System.currentTimeMillis();
	}
	
	
	public SimpleCacheEntrySet(CacheKey key, ArrayList<LDAPEntry> copy) {
		this.res = copy;
		this.key = key;
		this.iter = this.res.iterator();
		
		this.created = System.currentTimeMillis();
	}
	
	public SimpleCacheEntrySet(CacheKey key, Boolean compareResults) {
		
		this.key = key;
		this.compareResults = new Boolean(compareResults.booleanValue());
		
		this.created = System.currentTimeMillis();
	}


	public void abandon() throws LDAPException {
		

	}

	public Entry getNext() throws LDAPException {
		return new Entry(iter.next());
	}

	public boolean hasMore() throws LDAPException {
		return iter.hasNext();
	}
	
	public void addEntry(LDAPEntry entry) {
		this.res.add(this.copyEntry(entry));
	}
	
	private LDAPEntry copyEntry(LDAPEntry old) {
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		
		Iterator<LDAPAttribute> it = old.getAttributeSet().iterator();
		while (it.hasNext()) {
			LDAPAttribute attrib = it.next();
			LDAPAttribute nattrib = new LDAPAttribute(attrib.getName());
			
			byte[][] vals = attrib.getByteValueArray();
			
			for (int i=0;i<vals.length;i++) {
				nattrib.addValue(vals[i]);
			}
			
			attribs.add(nattrib);
		}
		
		return new LDAPEntry(old.getDN(),attribs);
	}


	public CacheKey getKey() {
		return this.key;
	}


	public EntrySet getCopy() {
		ArrayList<LDAPEntry> copy = new ArrayList<LDAPEntry>(this.res.size());
		Iterator<LDAPEntry> it = res.iterator();
		while (it.hasNext()) {
			copy.add(this.copyEntry(it.next()));
		}
		return new SimpleCacheEntrySet(key,copy);
	}
	
	public boolean isCompareTrue() {
		return this.compareResults.booleanValue();
	}
	
	public long getLife() {
		return System.currentTimeMillis() - this.created;
	}

}
