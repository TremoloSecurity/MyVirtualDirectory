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

import java.util.Comparator;

import com.novell.ldap.util.DN;

public class DNComparer implements Comparator {

	/* (non-Javadoc)
	 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
	 */
	public int compare(Object o1, Object o2) {
		DN dn1 = (DN) o1;
		DN dn2 = (DN) o2;
		
		int num1 = dn1.countRDNs();
		int num2 = dn2.countRDNs();
		
		if (num1 < num2) {
			return -1;
		}
		
		if (num1 > num2) {
			return 1;
		}
		
		try {
			if (dn1.equals(dn2)) {
				return 0;
			}
		} catch (IllegalArgumentException e) {
			
		}
		
		return dn1.toString().compareTo(dn2.toString());
	}
	
}
