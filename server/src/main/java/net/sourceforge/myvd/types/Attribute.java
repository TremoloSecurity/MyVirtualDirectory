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

import com.novell.ldap.LDAPAttribute;

public class Attribute {
	LDAPAttribute attribute;

	public Attribute(String name) {
		this.attribute = new LDAPAttribute(name);
	}
	
	public Attribute(String name, String val) {
		this.attribute = new LDAPAttribute(name,val);
	}
	
	public Attribute(LDAPAttribute attrib) {
		this.attribute = attrib;
	}

	public LDAPAttribute getAttribute() {
		return attribute;
	}

	public void setAttribute(LDAPAttribute attribute) {
		this.attribute = attribute;
	}
	
	public void rename(String newName) {
		LDAPAttribute newAttrib = new LDAPAttribute(newName);
		
		byte[][] vals = this.attribute.getByteValueArray();
		for (int i=0,m=vals.length;i<m;i++) {
			newAttrib.addValue(vals[i]);
		}
		
		this.attribute = newAttrib;
	}

	@Override
	public boolean equals(Object obj) {
		if (! (obj instanceof Attribute)) {
			return false;
		}
		
		Attribute attrib = (Attribute) obj;
		
		return attrib.getAttribute().getName().toLowerCase().equals(this.attribute.getName().toLowerCase());
	}
	
	public String toString() {
		if (this.attribute != null) {
			return this.attribute.toString();
		} else {
			return "NONE";
		}
	}
	
	
}
