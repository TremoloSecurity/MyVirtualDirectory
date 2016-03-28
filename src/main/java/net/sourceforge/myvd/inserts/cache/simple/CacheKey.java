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

import net.sourceforge.myvd.types.Attribute;

public class CacheKey {
	String base;
	String filter;
	String attribs;
	int scope;
	
	String key;
	
	boolean isSearch;
	
	Attribute compareAttrib;
	
	CacheKey(String base, String filter, ArrayList<Attribute> attribs, int scope) {
		this.base = base.toLowerCase();
		this.filter = filter.toLowerCase();
		StringBuffer attribsBuf = new StringBuffer();
		
		Iterator<Attribute> it = attribs.iterator();
		while (it.hasNext()) {
			attribsBuf.append(it.next().getAttribute().getName().toLowerCase());
		}
		
		this.scope = scope;
		
		StringBuffer buf = new StringBuffer();
		buf.append(base).append(filter).append(attribsBuf.toString()).append(scope);
		this.isSearch = true;
		this.key = buf.toString();
	}
	
	CacheKey(String dn,Attribute attrib) {
		StringBuffer buff = new StringBuffer();
		this.base = dn;
		this.compareAttrib = attrib;
		
		buff.append(dn).append(attrib.getAttribute().getName()).append(attrib.getAttribute().getStringValue());
		this.isSearch = false;
		this.key = buff.toString();
	}
	
	public boolean equals(Object obj) {
		if (! (obj instanceof CacheKey)) {
			return false;
		}
		
		if (this.key.equals(((CacheKey) obj).key)) {
			return true;
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return this.key.hashCode();
	}
	
	
}
