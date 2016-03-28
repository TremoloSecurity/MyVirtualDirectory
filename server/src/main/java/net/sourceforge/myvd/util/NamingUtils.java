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

import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public class NamingUtils {
	
	
	
	public DN getRemoteMappedDN(DN dn,String[] explodedLocalBase,String[] explodedRemoteBase) {
		int i,m;
		DN newDN = new DN();
		String[] currDN = dn.explodeDN(false);
		
		//first add the non-remote base pieces
		for (i=0,m=currDN.length - explodedLocalBase.length;i<m;i++) {
			RDN rdn = new RDN();
			int eq = currDN[i].indexOf('=');
			String attrType = currDN[i].substring(0,eq);
			String attrVal = currDN[i].substring(eq + 1);
			rdn.add(attrType, attrVal, currDN[i]);
			newDN.addRDNToBack(rdn);
		}
		
		for (i=0,m=explodedRemoteBase.length;i<m;i++) {
			RDN rdn = new RDN();
			int eq = explodedRemoteBase[i].indexOf('=');
			String attrType = explodedRemoteBase[i].substring(0,eq);
			String attrVal = explodedRemoteBase[i].substring(eq + 1);
			rdn.add(attrType, attrVal, explodedRemoteBase[i]);
				newDN.addRDNToBack(rdn);
		}
		
		return newDN;
		
	}
	
	public DN getLocalMappedDN(DN dn,String[] explodedRemoteBase,String[] explodedLocalBase) {
		int i,m;
		DN newDN = new DN();
		String[] currDN = dn.explodeDN(false);
		
		//first add the non-remote base pieces
		for (i=0,m=currDN.length - explodedRemoteBase.length;i<m;i++) {
			RDN rdn = new RDN();
			int eq = currDN[i].indexOf('=');
			String attrType = currDN[i].substring(0,eq);
			String attrVal = currDN[i].substring(eq + 1);
			rdn.add(attrType, attrVal, currDN[i]);
			newDN.addRDNToBack(rdn);
		}
		
		for (i=0,m=explodedLocalBase.length;i<m;i++) {
			RDN rdn = new RDN();
			int eq = explodedLocalBase[i].indexOf('=');
			String attrType = explodedLocalBase[i].substring(0,eq);
			String attrVal = explodedLocalBase[i].substring(eq + 1);
			rdn.add(attrType, attrVal, explodedLocalBase[i]);
			
			newDN.addRDNToBack(rdn);
		}
		
		return newDN;
		
	}
}
