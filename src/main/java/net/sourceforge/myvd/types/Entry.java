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

import java.util.HashMap;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.util.DN;

public class Entry {
	LDAPEntry entry;
	boolean returnEntry;
	LDAPControl[] controls;
	
	public Entry(LDAPEntry entry) {
		this.entry = entry;
		returnEntry = true;
		this.controls = null;
	}
	
	public Entry(LDAPEntry entry,LDAPControl[] controls) {
		this(entry);
		this.controls = controls;
	}
	
	public LDAPEntry getEntry() {
		return this.entry;
	}
	
	public void setDN(DN dn) {
		this.entry = new LDAPEntry(dn.toString(),entry.getAttributeSet());
	}
	
	public void revalueAttribute(String attrib,HashMap<String,String> map) {
		LDAPAttribute attribute = this.entry.getAttribute(attrib);
		
		if (attribute == null) {
			return;
		}
		
		String[] vals = attribute.getStringValueArray();
		for (int i=0,m=vals.length;i<m;i++) {
			String newVal = map.get(vals[i].toLowerCase());
			if (newVal != null) {
				attribute.removeValue(vals[i]);
				attribute.addValue(newVal);
			}
		}
	}
	
	public void renameAttribute(String oldAttribName,String newAttribName) {
		LDAPAttribute attrib = entry.getAttribute(oldAttribName);
		if (attrib == null) {
			
			
			return;
		}
		entry.getAttributeSet().remove(attrib);
		
		LDAPAttribute newAttrib = new LDAPAttribute(newAttribName);
		
		byte[][] vals = attrib.getByteValueArray();
		for (int i=0,m=vals.length;i<m;i++) {
			newAttrib.addValue(vals[i]);
		}
		
		entry.getAttributeSet().add(newAttrib);
	}

	public void setEntry(LDAPEntry entry) {
		this.entry = entry;
		
	}

	public boolean isReturnEntry() {
		return returnEntry;
	}

	public void setReturnEntry(boolean returnEntry) {
		this.returnEntry = returnEntry;
	}
	
	public LDAPControl[] getControls() {
		return this.controls;
	}
}
