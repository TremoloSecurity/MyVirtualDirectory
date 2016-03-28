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
package net.sourceforge.myvd.util;

import java.util.Iterator;

import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.EntrySet;

import com.novell.ldap.LDAPException;

public class IteratorEntrySet implements EntrySet {

	Iterator it;
	
	public IteratorEntrySet(Iterator it) {
		this.it = it;
	}
	
	public boolean hasMore() throws LDAPException {
		return it.hasNext();
	}

	public Entry getNext() throws LDAPException {
		return (Entry) it.next();
	}

	public void abandon() throws LDAPException {
	

	}

}
