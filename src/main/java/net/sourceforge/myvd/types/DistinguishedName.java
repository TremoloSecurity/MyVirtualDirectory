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

import com.novell.ldap.util.DN;

public class DistinguishedName {
	DN dn;
	
	public DistinguishedName(String dn) {
		if (dn != null) {
			this.dn = new DN(dn);
		} else {
			this.dn = new DN("");
		}
	}
	
	public DistinguishedName(DN dn) {
		this.dn = new DN(dn.toString());
	}
	
	public DN getDN() {
		if (this.dn == null) {
			return new DN("");
		} else {
			return this.dn;
		}
	}

	public void setDN(DN dn2) {
		this.dn = dn2;
		
	}
	
	public String toString() {
		String str = this.getDN().toString();
		if (str != null) {
			return str;
		} else {
			return "";
		}
	}
}
