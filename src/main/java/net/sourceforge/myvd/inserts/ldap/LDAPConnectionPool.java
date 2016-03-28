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

import java.util.ArrayList;
import java.util.Iterator;

import org.apache.log4j.Logger;

import net.sourceforge.myvd.types.Password;

import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.DN;

public class LDAPConnectionPool {
	static Logger logger = Logger.getLogger(LDAPConnectionPool.class.getName());
	ArrayList<ConnectionWrapper> pool;
	
	int maxRetries;
	int maxCons;
	int minCons;
	
	
	LDAPConnectionType type;
	
	private LDAPInterceptor interceptor;
	
	public LDAPConnectionPool(LDAPInterceptor interceptor,int minCons,int maxCons,int maxRetries, LDAPConnectionType type,String spmlImpl,boolean isSOAP) throws LDAPException {
		this.interceptor = interceptor;
		
		this.minCons = minCons;
		this.maxCons = maxCons;
		this.maxRetries = maxRetries;
		
		
		this.type = type;
		
		this.pool = new ArrayList<ConnectionWrapper>();
		
		try {
		
			for (int i=0;i<minCons;i++) {
				ConnectionWrapper wrapper = new ConnectionWrapper(this.interceptor);
				wrapper.unlock();
				wrapper.reConnect();
				

				
				this.pool.add(wrapper);
			}
		
		} catch (Throwable t) {
			logger.warn("Could not initialize pool",t);
		}
		
	}
	
	public ConnectionWrapper getConnection(DN bindDN,Password pass,boolean force) throws LDAPException {
		return this.getConnection(bindDN,pass,force,0);
	}
	
	public ConnectionWrapper getConnection(DN bindDN,Password pass,boolean force,int trys) throws LDAPException {
		
		if (trys >= this.maxRetries) {
			return null;
		}
		
		Iterator<ConnectionWrapper> it = this.pool.iterator();
		boolean wasfound = false;
		
		while (it.hasNext()) {
			ConnectionWrapper wrapper = it.next();
			
			//See if the connection is locked
			if (wrapper.wasLocked()) {
				continue;
			}
			
			//if there is an available connection, make sure to make a note
			wasfound = true;
			
			//if we are binding, we want to return the connection
			if (force) {
				return wrapper;
			}
			
			//check to see if the currnt connection has the right binddn
			if ((wrapper.getBindDN() == null && bindDN.toString() == null) || (wrapper.getBindDN() != null && bindDN.equals(wrapper.getBindDN()))) {
				return wrapper;
			}
			
			//we have not yet found a connection
			//so we can re-lock the connection
			wrapper.unlock();
		}
		
		if (wasfound) {
			it = this.pool.iterator();
			
			
			while (it.hasNext()) {
				ConnectionWrapper wrapper = it.next();
				
				//See if the connection is locked
				if (wrapper.wasLocked()) {
					continue;
				}
				
				/*
				if (wrapper == null) {
					//System.out.println("wrapper is null");
				}
				
				if (bindDN == null) {
					//System.out.println("bindDN is null");
				}
				
				if (wrapper.getBindDN() == null) {
					//System.out.println("wrapper.getBindDN is null");
				}
				
				if (bindDN.toString() == null) {
					//System.out.println("bindDN.toString() is null");
				}*/
				
				////System.out.println("?" + wrapper.getBindDN().toString());
				
				if (wrapper.getBindDN() != null && bindDN.toString().equals(wrapper.getBindDN().toString())) {
					return wrapper;
				} else {
					try {
						wrapper.bind(bindDN,pass);
						return wrapper;
					} catch (LDAPException e) {
						wrapper.unlock();
						wrapper.reBind();
						throw e;
					}
				}
			}
		}
		
		
		////System.out.println("max cons:" + this.maxCons + "; cur cons : " + this.pool.size());
		
		if (this.maxCons > this.pool.size()) {
			ConnectionWrapper wrapper = new ConnectionWrapper(this.interceptor);
			wrapper.wasLocked();
			wrapper.reConnect();
			//If this is a bind, we only want to do it once
			if (! force) {
				wrapper.bind(bindDN,pass);
			}
			this.pool.add(wrapper);
			return wrapper;
		} else {
			this.waitForConnection();
			return this.getConnection(bindDN,pass,force,trys + 1);
		}
		
	}
	
	
	private synchronized void waitForConnection() {
		
		try {
			this.wait(10000);
		} catch (InterruptedException e) {
			//dont care
		}
	}
	
	public synchronized void returnConnection(ConnectionWrapper con) {
		con.unlock();
		synchronized (this) {
			this.notifyAll();
		}
	}

	public void shutDownPool() {
		Iterator<ConnectionWrapper> it = this.pool.iterator();
		while (it.hasNext()) {
			try {
				it.next().getConnection().disconnect();
			} catch (Throwable t) {
				LDAPInterceptor.logger.error("Error disconnecting", t);
			}
		}
		
	}
	
	public void executeHeartBeat() {
		if (logger.isDebugEnabled()) {
			logger.debug("Running heartbeats for '" + this.interceptor.getHost() + "'");
		}
		for (ConnectionWrapper wrapper : this.pool) {
			if (logger.isDebugEnabled()) {
				logger.debug("Checking for '" + this.interceptor.getHost() + "' / " + wrapper);
			}
			//skip locked connection
			if (! wrapper.wasLocked()) {
				
				if (logger.isDebugEnabled()) {
					logger.debug("Sending heartbeat to '" + this.interceptor.getHost() + "' / " + wrapper);
				}
				
				//run a heartbeat
				try {
					//reset the bind
					wrapper.bind(new DN(interceptor.proxyDN),new Password(interceptor.proxyPass));
					
					//search
					LDAPSearchResults res = wrapper.getConnection().search(interceptor.getRemoteBase().toString(), 0, "(objectClass=*)", new String[]{"1.1"}, false);
					while (res.hasMore()) {
						res.next();
					}
					
					if (logger.isDebugEnabled()) {
						logger.debug("Heartbeat successful for '" + this.interceptor.getHost() + "' / " + wrapper);
					}
					
				} catch (LDAPException e) {
					logger.warn("Could not execute ldap heartbeat for " + this.interceptor.getHost() + "/" + this.interceptor.getPort() + ", recreating connection",e);
					try {
						wrapper.reConnect();
					} catch (LDAPException e1) {
						logger.warn("Could not reconnect",e1);
					}
				}
				
				wrapper.unlock();
			} else {
				if (logger.isDebugEnabled()) {
					logger.debug("Connection locked for '" + this.interceptor.getHost() + "' / " + wrapper);
				}
			}
		}
	}
}
