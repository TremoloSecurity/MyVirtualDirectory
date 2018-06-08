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

import com.novell.ldap.LDAPExtendedOperation;

public class ExtendedOperation {
	LDAPExtendedOperation op;
	DistinguishedName dn;
	boolean isWrite;
	
	public ExtendedOperation(DistinguishedName dn,LDAPExtendedOperation op) {
		this.dn = dn;
		this.op = op;
		this.isWrite = true;
	}

	public DistinguishedName getDn() {
		if (this.dn == null) {
			return new DistinguishedName("");
		} else {
			return dn;
		}
	}

	public void setDn(DistinguishedName dn) {
		this.dn = dn;
	}

	public LDAPExtendedOperation getOp() {
		return op;
	}

	public void setOp(LDAPExtendedOperation op) {
		this.op = op;
	}

	public boolean isWrite() {
		return isWrite;
	}

	public void setWrite(boolean isWrite) {
		this.isWrite = isWrite;
	}
}
