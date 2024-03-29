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
package net.sourceforge.myvd.inserts.ldap;

import org.apache.logging.log4j.Logger;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.Password;

import java.util.UUID;


import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.util.DN;

public class ConnectionWrapper {
	LDAPConnection con;
	Bool locked;
	DN bindDN;
	Password pass;
	LDAPInterceptor interceptor;
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(ConnectionWrapper.class);
	
	long lastAccessed;
	
	int numOps;
	
	
	String uuid;
	
	public ConnectionWrapper(LDAPInterceptor interceptor) {
		this.interceptor = interceptor;
		this.locked = new Bool(false);
		this.locked.setValue(false);
		this.bindDN = null;
		this.uuid = UUID.randomUUID().toString();
		
	}
	
	public synchronized boolean wasLocked() {
		
		synchronized (this.locked) {
			if (! this.locked.getValue()) {
				this.locked.setValue(true);
				
				if (  this.interceptor.getMaxOpsPerCon() > 0 && this.numOps > this.interceptor.getMaxOpsPerCon()  ) {
					logger.warn("Too many operations on this connection, re-creating");
					return closeAndConnect(false);
				} else {
					
					return false;
				}
				
				
			} else {
				
				if ( ((System.currentTimeMillis() - this.lastAccessed) >= this.interceptor.getMaxStailTime())   ) {
					logger.warn("Connection stale, re-creating");
					return closeAndConnect(false);
				} else if ( this.interceptor.getMaxCheckoutTimePerCon() > 0 && (System.currentTimeMillis() - this.lastAccessed) > this.interceptor.getMaxCheckoutTimePerCon()) {
					logger.warn("Connection checked out too long, killing and re-creating");
					return closeAndConnect(false);
				} else {
					return true;
				}
				
				
				
			}
		}
	}

	private boolean closeAndConnect(boolean keepCredentials) {
		final LDAPConnection localCon = this.con;
		this.con = null;
		this.interceptor.closeConnection(localCon);
		try {
			this.reConnect(keepCredentials);
		} catch (LDAPException e) {
			logger.error("Could not reconnect",e);
			this.con = null;
		}
		this.locked.setValue(true);
		this.numOps = 1;
		return false;
	}
	
	public void bind(DN bindDN,Password password) throws LDAPException {
		

		
		
		
		try {
			LDAPConstraints constraints = new LDAPConstraints();
			if (this.interceptor.getMaxTimeoutMillis() > 0) {
				constraints.setTimeLimit(this.interceptor.getMaxTimeoutMillis());
			}
			
			con.bind(3,bindDN.toString(),password.getValue(),constraints);
			this.bindDN = bindDN;
			this.pass = password;
		} catch (Throwable e) {
			logger.warn(String.format("Error attempting to bind to %s: %s",bindDN.toString(),e.toString()));
			
			this.bindDN = null;
			this.pass = null;
			
			
			
			if (e instanceof LDAPException) {
				throw e;
			} else {
				throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,String.format("Error binding to %s",bindDN.toString()));
			}
		}
		
	}
	
	private boolean conValid() {
		long now = System.currentTimeMillis();
		
		
		if (this.interceptor.getMaxIdleTime() == 0) {
			return true;
		} else {
			if ((now - this.lastAccessed >= this.interceptor.getMaxIdleTime())) {
				
				return false;
			} else {
				return true;
			}
		}
	}
	
	public LDAPConnection getConnection() throws LDAPException {
		
		if (this.con.isConnected() && this.con.isConnectionAlive() && conValid()) {
			
			this.lastAccessed = System.currentTimeMillis();
			return this.con;
		} else {
			
			this.lastAccessed = System.currentTimeMillis();
			this.localReConnect();
			return this.con;
		}
	}
	
	private void localReConnect() throws LDAPException {
		if (con != null && con.isConnectionAlive()) {
			con.disconnect();
		}
		
		this.con = this.createConnection();
		this.reBind();
	}
	
	public void reConnect() throws LDAPException {
		this.reConnect(false);
	}
	
	public void reConnect(boolean keepCredentials) throws LDAPException {
		if (con != null && con.isConnectionAlive()) {
			try {
				this.interceptor.closeConnection(con);
			} catch (Throwable t) {
				
				if (logger.isDebugEnabled()) {
					logger.warn("Trying to force disconnect: " + t.getMessage(),t);
				} else {
					logger.warn("Trying to force disconnect: " + t.getMessage());
				}
			}
		}
		
		this.con = this.createConnection();
		
		if (keepCredentials) {
			if (this.bindDN != null && this.pass != null) {
				this.reBind();
			}
		} else {
			this.bindDN = null;
			this.pass = null;
		}
		
	}
	
	private LDAPConnection createConnection() throws LDAPException {
		LDAPConnection ldapcon = null;
		switch (interceptor.type) {
			case LDAPS :
						if (this.interceptor.getSocketFactory() == null) {
							
							ldapcon = new LDAPConnection(new LDAPJSSESecureSocketFactory());
						} else {
							
							ldapcon = new LDAPConnection(new LDAPJSSESecureSocketFactory(this.interceptor.getSocketFactory().getSSLSocketFactory()));
						}
				//ldapcon = new LDAPConnection();
						break;
						
			case LDAP : ldapcon = new LDAPConnection();
			            break;
			case DSMLV2 : 
			case SPML : throw new LDAPException("Not supported",LDAPException.OPERATIONS_ERROR,LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR));
			
		}
		
		this.lastAccessed = System.currentTimeMillis();
		
		if (ldapcon == null) {
			return null;
		} else {
			String host = this.interceptor.host;

			if (this.interceptor.useSrvDNS) {
				Record[] records;
				try {
					records = new Lookup(host, Type.SRV).run();
				} catch (TextParseException e) {
					throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),LDAPException.OPERATIONS_ERROR,"Could not lookup srv",e);
				}
				if (records == null) {
					throw new LDAPException("No SRV records",LDAPException.OPERATIONS_ERROR,"");
				}
				SRVRecord srv = (SRVRecord) records[0];
				host = srv.getTarget().toString();
			}

			ldapcon.connect(host,this.interceptor.port);
			return ldapcon;
		}
	}
	
	public synchronized void unlock() {
		synchronized (this.locked) {
			this.numOps++;
			this.locked.setValue(false);
		}
	}
	
	public DN getBindDN() {
		return this.bindDN;
	}

	public void reBind() throws LDAPException {
		if (this.bindDN != null) {
			this.bind(this.bindDN,this.pass);
		}
		
	}
	
	public String toString() {
		return Boolean.toString(this.locked.getValue());
	}

	public String getInfo() {
		return new StringBuilder().append("uuid=").append(this.uuid).append("/").append("dn=").append(this.bindDN).toString();
	}
	
}
