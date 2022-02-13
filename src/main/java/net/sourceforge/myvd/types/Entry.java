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

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.LinkedList;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.util.ByteArray;
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
		

		LinkedList<ByteArray> vals = attribute.getAllValues();
		LinkedList<ByteArray> newVals = new LinkedList<ByteArray>();
		for (ByteArray b : vals) {
			String val = null;
			try {
				val = new String(b.getValue(),"UTF-8");
			} catch (UnsupportedEncodingException e) {
				//can't happen
			}
			String newVal = map.get(val.toLowerCase());
			if (newVal != null) {
				try {
					newVals.add(new ByteArray(newVal.getBytes("UTF-8")));
				} catch (UnsupportedEncodingException e) {
					// can't happen
				}
			} else {
				newVals.add(b);
			}
		}

		attribute.setAllValues(newVals);
	}
	
	public void renameAttribute(String oldAttribName,String newAttribName) {
		LDAPAttribute attrib = entry.getAttribute(oldAttribName);
		if (attrib == null) {
			
			
			return;
		}
		entry.getAttributeSet().remove(attrib);
		
		attrib.setName(newAttribName);
		
		entry.getAttributeSet().add(attrib);
	}
	
	public void copyAttribute(String oldAttribName,String newAttribName) {
		LDAPAttribute attrib = entry.getAttribute(oldAttribName);
		if (attrib == null) {
			
			
			return;
		}

		
		LDAPAttribute newAttrib = new LDAPAttribute(attrib);
		newAttrib.setName(newAttribName);
		
		
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
