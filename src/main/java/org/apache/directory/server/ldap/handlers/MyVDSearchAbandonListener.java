/*
 * Copyright 2022 Tremolo Security, Inc. 
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

package org.apache.directory.server.ldap.handlers;

import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.message.AbandonableRequest;
import org.apache.directory.server.ldap.LdapServer;

import net.sourceforge.myvd.server.apacheds.MyVDBaseCursor;
import net.sourceforge.myvd.server.apacheds.MyVDCursor;

public class MyVDSearchAbandonListener extends SearchAbandonListener {
	MyVDBaseCursor cursor;
	public MyVDSearchAbandonListener(LdapServer ldapServer, Cursor<Entry> cursor) {
		super(ldapServer, cursor);
		this.cursor = (MyVDBaseCursor) cursor;
	}

	@Override
	public void requestAbandoned(AbandonableRequest req) {
		super.requestAbandoned(req);
		
		this.cursor.setAbandoned(req.isAbandoned());
	}

}
