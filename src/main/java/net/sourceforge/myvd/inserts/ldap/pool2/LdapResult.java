/*******************************************************************************
 * Copyright (c) 2023 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package net.sourceforge.myvd.inserts.ldap.pool2;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

public class LdapResult {
	LDAPException exception;
	LDAPEntry entry;
	boolean done;
	
	
	public LdapResult(LDAPException e) {
		this.exception = e;
		this.entry = null;
		this.done = false;
	}
	
	public LdapResult(LDAPEntry entry) {
		this.exception = null;
		this.entry = entry;
		this.done = false;
	}
	
	public LdapResult(boolean done) {
		this.done = done;
		this.entry = null;
		this.exception = null;
	}

	public LDAPException getException() {
		return exception;
	}

	public LDAPEntry getEntry() {
		return entry;
	}

	public boolean isDone() {
		return done;
	}
	
	
}
