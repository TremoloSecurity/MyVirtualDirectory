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

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPException;

import net.sourceforge.myvd.inserts.ldap.LDAPInterceptor;

public class LdapPool {
	static Logger logger = Logger.getLogger(LdapPool.class);
	
	List<LdapConnection> pool;
	LDAPInterceptor interceptor;
	
	public LdapPool(LDAPInterceptor interceptor) throws LDAPException {
		this.pool = new ArrayList<LdapConnection>();
		this.interceptor = interceptor;
		
		new Thread() {

			@Override
			public void run() {
				for (int i=0;i<interceptor.getMinConnections();i++) {
					try {
						pool.add(new LdapConnection(interceptor));
					} catch (Throwable t) {
						logger.warn(String.format("Could not initialize connections to %s:%s", interceptor.getHost(),interceptor.getPort()),t);
					}
				}
			}
			
			
			
		
		}.start();
	}
	
	public LdapConnection checkOut(String dn,byte[] password, boolean forceBind, int count) throws LDAPException {
		
		if (! forceBind) {
			// first see if a bound connection exists for this DN
			for (LdapConnection ldap : this.pool) {
				synchronized (ldap) {
					if (ldap.isAvailable(dn,password,false)) {
						return ldap;
					}
				}
			}
		}
		
		// no existing account was found, get any available
		for (LdapConnection ldap : this.pool) {
			synchronized (ldap) {
				if (ldap.isAvailable(dn,password,true)) {
					return ldap;
				}
			}
		}
		
		if (pool.size() < this.interceptor.getMaxConnections()) {
			LdapConnection ldap = new LdapConnection(this.interceptor);
			ldap.isAvailable(dn, password, true);
			this.pool.add(ldap);
			return ldap;
		} else {
			if (count < 1) {
				logger.warn(String.format("Could not get connection to %s:%s for %s",this.interceptor.getHost(),this.interceptor.getPort(),dn));
				return null;
			} else {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					
				}
				
				return this.checkOut(dn, password, forceBind, count - 1);
			}
		}
		
		
		
	}

	public void executeHeartBeat() {
		for (LdapConnection ldap : this.pool) {
			ldap.heartbeat();
		}
		
	}

	public void shutDownPool() {
		for (LdapConnection ldap : this.pool) {
			
		}
		
	}
}
