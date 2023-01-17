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

import java.util.Map;

import javax.net.SocketFactory;

import org.apache.log4j.Logger;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPExtendedResponse;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPMessageQueue;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPResponseQueue;
import com.novell.ldap.LDAPSchema;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchQueue;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.novell.ldap.LDAPUnsolicitedNotificationListener;

import net.sourceforge.myvd.inserts.ldap.LDAPConnectionType;
import net.sourceforge.myvd.inserts.ldap.LDAPInterceptor;

public class LdapConnection extends com.novell.ldap.LDAPConnection {
	static Logger logger = Logger.getLogger(LdapConnection.class);

	String dn;
	byte[] password;

	com.novell.ldap.LDAPConnection ldap;

	boolean locked;

	int numCheckouts;
	long lastAccessed;

	private LDAPInterceptor interceptor;

	public LdapConnection(LDAPInterceptor interceptor) throws LDAPException {
		synchronized (this) {
			this.locked = true;
			this.numCheckouts = 0;
			this.interceptor = interceptor;
			this.dn = this.interceptor.getBindDN();
			this.password = this.interceptor.getBindPassword();
			this.connect();
			this.locked = false;
		}

	}

	public void shutdown() {
		if (this.ldap != null) {
			try {
				this.ldap.disconnect();
			} catch (Throwable t) {
				logger.warn("Could not shutdown", t);
			}
		}
	}

	private void connect() throws LDAPException {
		if (this.interceptor.getType() == LDAPConnectionType.LDAPS) {
			if (this.interceptor.getSocketFactory() == null) {
				this.ldap = new LDAPConnection(new LDAPJSSESecureSocketFactory());
			} else {

				this.ldap = new LDAPConnection(
						new LDAPJSSESecureSocketFactory(this.interceptor.getSocketFactory().getSSLSocketFactory()));
			}
		} else if (this.interceptor.getType() == LDAPConnectionType.LDAP) {
			this.ldap = new LDAPConnection();
		} else {

		}

		String host = this.interceptor.getHost();

		if (this.interceptor.useSrvDNS) {
			Record[] records;
			try {
				records = new Lookup(host, Type.SRV).run();
			} catch (TextParseException e) {
				throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),
						LDAPException.OPERATIONS_ERROR, "Could not lookup srv", e);
			}
			if (records == null) {
				throw new LDAPException("No SRV records", LDAPException.OPERATIONS_ERROR, "");
			}
			SRVRecord srv = (SRVRecord) records[0];
			host = srv.getTarget().toString();
		}

		ldap.connect(host, this.interceptor.getPort());

		if (this.dn != null && !this.dn.isBlank()) {
			this.bindToHost(this.dn, this.password);
		}

		this.lastAccessed = System.currentTimeMillis();
		this.numCheckouts = 0;

	}

	private void closeAndConnect(boolean keepCredentials) throws LDAPException {
		synchronized (this) {
			final LDAPConnection localCon = this.ldap;
			this.ldap = null;
			this.interceptor.closeConnection(localCon);
			if (!keepCredentials) {
				this.dn = null;
				this.password = null;
			}
			this.connect();
		}
	}

	public void heartbeat() {
		synchronized (this) {
			if (this.locked) {
				return;
			} else {
				if (logger.isDebugEnabled()) {
					logger.debug("Sending heartbeat to '" + this.interceptor.getHost() + "' / " + this);
				}

				try {
					this.locked = true;
					if (this.dn == null) {
						this.bindToHost(this.interceptor.getBindDN(), this.interceptor.getBindPassword());
					} else {
						LDAPSearchResults res = this.ldap.search(this.interceptor.getRemoteBase().toString(), 0,
								"(objectClass=*)", new String[] { "1.1" }, false);
						while (res.hasMore())
							res.next();

						if (logger.isDebugEnabled()) {
							logger.debug("Heartbeat successful for '" + this.interceptor.getHost() + "' / " + this);
						}
					}
				} catch (Throwable t) {
					logger.warn(String.format("Could not perform heartbeat to %s:%s", this.interceptor.getHost(),
							this.interceptor.getPort()), t);
					try {
						this.connect();
					} catch (LDAPException e) {
						logger.warn(String.format("Could not perform heartbeat to %s:%s", this.interceptor.getHost(),
								this.interceptor.getPort()), e);
					}

				}

				this.locked = false;
			}
		}
	}

	private void testConnection() {
		synchronized (this) {

			if (logger.isDebugEnabled()) {
				logger.debug("Sending heartbeat to '" + this.interceptor.getHost() + "' / " + this);
			}

			try {

				LDAPSearchResults res = this.ldap.search(this.interceptor.getRemoteBase().toString(), 0,
						"(objectClass=*)", new String[] { "1.1" }, false);
				while (res.hasMore())
					res.next();

				if (logger.isDebugEnabled()) {
					logger.debug("Heartbeat successful for '" + this.interceptor.getHost() + "' / " + this);
				}

			} catch (LDAPException e) {
			
				if (e.getResultCode() == LDAPException.CONNECT_ERROR) {
					// connection error, reconnect
					try {
						this.connect();
					} catch (LDAPException e1) {
						logger.warn(String.format("Could not connect to %s:%s", this.interceptor.getHost(),
								this.interceptor.getPort()), e1);
					}
				}
				
			} catch (Throwable t) {
				logger.warn(String.format("Could not connect to %s:%s", this.interceptor.getHost(),
						this.interceptor.getPort()), t);
				try {
					this.connect();
				} catch (LDAPException e) {
					logger.warn(String.format("Could not connect to %s:%s", this.interceptor.getHost(),
							this.interceptor.getPort()), e);
				}

			}

			this.locked = false;

		}
	}

	public synchronized boolean isAvailable(String dn, byte[] password, boolean needConnection) throws LDAPException {
		synchronized (this) {
			if (locked) {

				if (((System.currentTimeMillis() - this.lastAccessed) >= this.interceptor.getMaxStailTime())) {
					logger.warn("Connection stale, re-creating");
					closeAndConnect(false);
					return checkoutConnection(dn, password, needConnection);
				} else if (this.interceptor.getMaxCheckoutTimePerCon() > 0
						&& (System.currentTimeMillis() - this.lastAccessed) > this.interceptor
								.getMaxCheckoutTimePerCon()) {
					logger.warn("Connection checked out too long, killing and re-creating");
					closeAndConnect(false);
					return checkoutConnection(dn, password, needConnection);
				} else {
					return false;
				}

			} else {
				this.locked = true;

				if (this.interceptor.getMaxOpsPerCon() > 0 && this.numCheckouts > this.interceptor.getMaxOpsPerCon()) {
					logger.warn("Too many operations on this connection, re-creating");
					closeAndConnect(false);
					bindToHost(dn, password);
					return true;
				} else {
					return checkoutConnection(dn, password, needConnection);
				}
			}
		}
	}

	private boolean checkoutConnection(String dn, byte[] password, boolean needConnection) throws LDAPException {
		this.testConnection();
		
		if ((this.dn == null && dn == null) || (this.dn != null && this.dn.equalsIgnoreCase(dn))) {
			boolean pwdMatches = false;

			if (password == null && this.password == null) {
				pwdMatches = true;
			} else if (password == null && this.password != null) {
				pwdMatches = false;
			} else if (password != null && this.password == null) {
				pwdMatches = false;
			} else {
				pwdMatches = this.password.length == password.length;

				if (pwdMatches) {
					for (int i = 0; i < this.password.length; i++) {
						pwdMatches = this.password[i] == password[i];
						if (!pwdMatches) {
							break;
						}
					}
				}

			}

			if (needConnection || !pwdMatches) {
				bindToHost(dn, password);

			}

			this.lastAccessed = System.currentTimeMillis();
			this.numCheckouts++;

			return true;
		} else {
			if (needConnection) {
				bindToHost(dn, password);
				this.numCheckouts++;
				this.lastAccessed = System.currentTimeMillis();
				return true;
			} else {
				this.locked = false;
				return false;
			}
		}
	}

	private void bindToHost(String dn, byte[] password) throws LDAPException {
		try {
			LDAPConstraints constraints = new LDAPConstraints();
			if (this.interceptor.getMaxTimeoutMillis() > 0) {
				constraints.setTimeLimit(this.interceptor.getMaxTimeoutMillis());
			}
			this.ldap.bind(3, dn, password, constraints);
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.INVALID_CREDENTIALS) {
				// this is now an anonumous connection
				this.dn = null;
				this.password = null;
			} else {

			}

			throw e;
		} catch (Throwable t) {
			String msg = String.format("Non LDAP error when binding %s to %s:%s secure:%s", dn,
					this.interceptor.getHost(), this.interceptor.getPort());
			logger.warn(msg, t);
			throw new LDAPException(LDAPException.resultCodeToString(LDAPException.OPERATIONS_ERROR),
					LDAPException.OPERATIONS_ERROR, msg, t);
		}
		this.dn = dn;
		this.password = password;

	}

	public void checkConnectionStatus() {
		synchronized (this) {
			if (this.locked) {
				if ((System.currentTimeMillis() - this.lastAccessed) > this.interceptor.getMaxCheckoutTimePerCon()) {
					logger.warn(
							String.format("Connection to %s:%s checkedout too long, closing and returning to the pool",
									this.interceptor.getHost(), this.interceptor.getPort()));
					try {
						this.closeAndConnect(false);
					} catch (LDAPException e) {
						logger.warn("Could not reconnect", e);
					}
					this.numCheckouts = 0;
					this.lastAccessed = 0;
					this.locked = false;
				}
			}
		}

	}

	// override all methods

	@Override
	public Object clone() {
		return ldap.clone();
	}

	@Override
	protected void finalize() throws LDAPException {
		ldap.disconnect();
	}

	@Override
	public int getProtocolVersion() {
		return ldap.getProtocolVersion();
	}

	@Override
	public String getAuthenticationDN() {

		return ldap.getAuthenticationDN();
	}

	@Override
	public String getAuthenticationMethod() {

		return ldap.getAuthenticationMethod();
	}

	@Override
	public Map getSaslBindProperties() {

		return ldap.getSaslBindProperties();
	}

	@Override
	public Object getSaslBindCallbackHandler() {

		return ldap.getSaslBindCallbackHandler();
	}

	@Override
	public LDAPConstraints getConstraints() {

		return ldap.getConstraints();
	}

	@Override
	public String getHost() {

		return ldap.getHost();
	}

	@Override
	public int getPort() {

		return ldap.getPort();
	}

	@Override
	public Object getProperty(String name) {

		return ldap.getProperty(name);
	}

	@Override
	public LDAPSearchConstraints getSearchConstraints() {

		return ldap.getSearchConstraints();
	}

	@Override
	public LDAPSocketFactory getSocketFactory() {

		return ldap.getSocketFactory();
	}

	@Override
	public boolean isBound() {

		return ldap.isBound();
	}

	@Override
	public boolean isConnected() {

		return ldap.isConnected();
	}

	@Override
	public boolean isConnectionAlive() {

		return ldap.isConnectionAlive();
	}

	@Override
	public boolean isTLS() {

		return ldap.isTLS();
	}

	@Override
	public int getSocketTimeOut() {

		return ldap.getSocketTimeOut();
	}

	@Override
	public void setSocketTimeOut(int timeout) {

		ldap.setSocketTimeOut(timeout);
	}

	@Override
	public void setConstraints(LDAPConstraints cons) {

		ldap.setConstraints(cons);
	}

	@Override
	public void addUnsolicitedNotificationListener(LDAPUnsolicitedNotificationListener listener) {

		ldap.addUnsolicitedNotificationListener(listener);
	}

	@Override
	public void removeUnsolicitedNotificationListener(LDAPUnsolicitedNotificationListener listener) {

		ldap.removeUnsolicitedNotificationListener(listener);
	}

	@Override
	public void startTLS() throws LDAPException {

		ldap.startTLS();
	}

	@Override
	public void stopTLS() throws LDAPException {

		ldap.stopTLS();
	}

	@Override
	public void abandon(LDAPSearchResults results) throws LDAPException {

		ldap.abandon(results);
	}

	@Override
	public void abandon(LDAPSearchResults results, LDAPConstraints cons) throws LDAPException {

		ldap.abandon(results, cons);
	}

	@Override
	public void abandon(int id) throws LDAPException {

		ldap.abandon(id);
	}

	@Override
	public void abandon(int id, LDAPConstraints cons) throws LDAPException {

		ldap.abandon(id, cons);
	}

	@Override
	public void abandon(LDAPMessageQueue queue) throws LDAPException {

		ldap.abandon(queue);
	}

	@Override
	public void abandon(LDAPMessageQueue queue, LDAPConstraints cons) throws LDAPException {

		ldap.abandon(queue, cons);
	}

	@Override
	public void add(LDAPEntry entry) throws LDAPException {

		ldap.add(entry);
	}

	@Override
	public void add(LDAPEntry entry, LDAPConstraints cons) throws LDAPException {

		ldap.add(entry, cons);
	}

	@Override
	public LDAPResponseQueue add(LDAPEntry entry, LDAPResponseQueue queue) throws LDAPException {

		return ldap.add(entry, queue);
	}

	@Override
	public LDAPResponseQueue add(LDAPEntry entry, LDAPResponseQueue queue, LDAPConstraints cons) throws LDAPException {

		return ldap.add(entry, queue, cons);
	}

	@Override
	public void bind(String dn, String passwd) throws LDAPException {

		ldap.bind(dn, passwd);
	}

	@Override
	public void bind(int version, String dn, String passwd) throws LDAPException {

		ldap.bind(version, dn, passwd);
	}

	@Override
	public void bind(String dn, String passwd, LDAPConstraints cons) throws LDAPException {

		ldap.bind(dn, passwd, cons);
	}

	@Override
	public void bind(int version, String dn, String passwd, LDAPConstraints cons) throws LDAPException {

		ldap.bind(version, dn, passwd, cons);
	}

	@Override
	public void bind(int version, String dn, byte[] passwd) throws LDAPException {

		ldap.bind(version, dn, passwd);
	}

	@Override
	public void bind(int version, String dn, byte[] passwd, LDAPConstraints cons) throws LDAPException {

		ldap.bind(version, dn, passwd, cons);
	}

	@Override
	public LDAPResponseQueue bind(int version, String dn, byte[] passwd, LDAPResponseQueue queue) throws LDAPException {

		return ldap.bind(version, dn, passwd, queue);
	}

	@Override
	public LDAPResponseQueue bind(int version, String dn, byte[] passwd, LDAPResponseQueue queue, LDAPConstraints cons)
			throws LDAPException {

		return ldap.bind(version, dn, passwd, queue, cons);
	}

	@Override
	public void bind(String dn, String authzId, Map props, Object cbh) throws LDAPException {

		ldap.bind(dn, authzId, props, cbh);
	}

	@Override
	public void bind(String dn, String authzId, Map props, Object cbh, LDAPConstraints cons) throws LDAPException {

		ldap.bind(dn, authzId, props, cbh, cons);
	}

	@Override
	public void bind(String dn, String authzId, String[] mechanisms, Map props, Object cbh) throws LDAPException {

		ldap.bind(dn, authzId, mechanisms, props, cbh);
	}

	@Override
	public void bind(String dn, String authzId, String[] mechanisms, Map props, Object cbh, LDAPConstraints cons)
			throws LDAPException {

		ldap.bind(dn, authzId, mechanisms, props, cbh, cons);
	}

	@Override
	public boolean compare(String dn, LDAPAttribute attr) throws LDAPException {

		return ldap.compare(dn, attr);
	}

	@Override
	public boolean compare(String dn, LDAPAttribute attr, LDAPConstraints cons) throws LDAPException {

		return ldap.compare(dn, attr, cons);
	}

	@Override
	public LDAPResponseQueue compare(String dn, LDAPAttribute attr, LDAPResponseQueue queue) throws LDAPException {

		return ldap.compare(dn, attr, queue);
	}

	@Override
	public LDAPResponseQueue compare(String dn, LDAPAttribute attr, LDAPResponseQueue queue, LDAPConstraints cons)
			throws LDAPException {

		return ldap.compare(dn, attr, queue, cons);
	}

	@Override
	public void connect(String host, int port) throws LDAPException {

		ldap.connect(host, port);
	}

	@Override
	public void delete(String dn) throws LDAPException {

		ldap.delete(dn);
	}

	@Override
	public void delete(String dn, LDAPConstraints cons) throws LDAPException {

		ldap.delete(dn, cons);
	}

	@Override
	public LDAPResponseQueue delete(String dn, LDAPResponseQueue queue) throws LDAPException {

		return ldap.delete(dn, queue);
	}

	@Override
	public LDAPResponseQueue delete(String dn, LDAPResponseQueue queue, LDAPConstraints cons) throws LDAPException {

		return ldap.delete(dn, queue, cons);
	}

	@Override
	public void disconnect() throws LDAPException {

		synchronized (this) {
			this.locked = false;
			this.interceptor.getConnectionPool().dequeThread();
		}

	}

	@Override
	public void disconnect(LDAPConstraints cons) throws LDAPException {

		synchronized (this) {
			this.locked = false;
			this.interceptor.getConnectionPool().dequeThread();
		}
	}

	@Override
	public LDAPExtendedResponse extendedOperation(LDAPExtendedOperation op) throws LDAPException {

		return ldap.extendedOperation(op);
	}

	@Override
	public LDAPExtendedResponse extendedOperation(LDAPExtendedOperation op, LDAPConstraints cons) throws LDAPException {

		return ldap.extendedOperation(op, cons);
	}

	@Override
	public LDAPResponseQueue extendedOperation(LDAPExtendedOperation op, LDAPResponseQueue queue) throws LDAPException {

		return ldap.extendedOperation(op, queue);
	}

	@Override
	public LDAPResponseQueue extendedOperation(LDAPExtendedOperation op, LDAPConstraints cons, LDAPResponseQueue queue)
			throws LDAPException {

		return ldap.extendedOperation(op, cons, queue);
	}

	@Override
	public LDAPControl[] getResponseControls() {

		return ldap.getResponseControls();
	}

	@Override
	public void modify(String dn, LDAPModification mod) throws LDAPException {

		ldap.modify(dn, mod);
	}

	@Override
	public void modify(String dn, LDAPModification mod, LDAPConstraints cons) throws LDAPException {

		ldap.modify(dn, mod, cons);
	}

	@Override
	public void modify(String dn, LDAPModification[] mods) throws LDAPException {

		ldap.modify(dn, mods);
	}

	@Override
	public void modify(String dn, LDAPModification[] mods, LDAPConstraints cons) throws LDAPException {

		ldap.modify(dn, mods, cons);
	}

	@Override
	public LDAPResponseQueue modify(String dn, LDAPModification mod, LDAPResponseQueue queue) throws LDAPException {

		return ldap.modify(dn, mod, queue);
	}

	@Override
	public LDAPResponseQueue modify(String dn, LDAPModification mod, LDAPResponseQueue queue, LDAPConstraints cons)
			throws LDAPException {

		return ldap.modify(dn, mod, queue, cons);
	}

	@Override
	public LDAPResponseQueue modify(String dn, LDAPModification[] mods, LDAPResponseQueue queue) throws LDAPException {

		return ldap.modify(dn, mods, queue);
	}

	@Override
	public LDAPResponseQueue modify(String dn, LDAPModification[] mods, LDAPResponseQueue queue, LDAPConstraints cons)
			throws LDAPException {

		return ldap.modify(dn, mods, queue, cons);
	}

	@Override
	public LDAPEntry read(String dn) throws LDAPException {

		return ldap.read(dn);
	}

	@Override
	public LDAPEntry read(String dn, LDAPSearchConstraints cons) throws LDAPException {

		return ldap.read(dn, cons);
	}

	@Override
	public LDAPEntry read(String dn, String[] attrs) throws LDAPException {

		return ldap.read(dn, attrs);
	}

	@Override
	public LDAPEntry read(String dn, String[] attrs, LDAPSearchConstraints cons) throws LDAPException {

		return ldap.read(dn, attrs, cons);
	}

	@Override
	public void rename(String dn, String newRdn, boolean deleteOldRdn) throws LDAPException {

		ldap.rename(dn, newRdn, deleteOldRdn);
	}

	@Override
	public void rename(String dn, String newRdn, boolean deleteOldRdn, LDAPConstraints cons) throws LDAPException {

		ldap.rename(dn, newRdn, deleteOldRdn, cons);
	}

	@Override
	public void rename(String dn, String newRdn, String newParentdn, boolean deleteOldRdn) throws LDAPException {

		ldap.rename(dn, newRdn, newParentdn, deleteOldRdn);
	}

	@Override
	public void rename(String dn, String newRdn, String newParentdn, boolean deleteOldRdn, LDAPConstraints cons)
			throws LDAPException {

		ldap.rename(dn, newRdn, newParentdn, deleteOldRdn, cons);
	}

	@Override
	public LDAPResponseQueue rename(String dn, String newRdn, boolean deleteOldRdn, LDAPResponseQueue queue)
			throws LDAPException {

		return ldap.rename(dn, newRdn, deleteOldRdn, queue);
	}

	@Override
	public LDAPResponseQueue rename(String dn, String newRdn, boolean deleteOldRdn, LDAPResponseQueue queue,
			LDAPConstraints cons) throws LDAPException {

		return ldap.rename(dn, newRdn, deleteOldRdn, queue, cons);
	}

	@Override
	public LDAPResponseQueue rename(String dn, String newRdn, String newParentdn, boolean deleteOldRdn,
			LDAPResponseQueue queue) throws LDAPException {

		return ldap.rename(dn, newRdn, newParentdn, deleteOldRdn, queue);
	}

	@Override
	public LDAPResponseQueue rename(String dn, String newRdn, String newParentdn, boolean deleteOldRdn,
			LDAPResponseQueue queue, LDAPConstraints cons) throws LDAPException {

		return ldap.rename(dn, newRdn, newParentdn, deleteOldRdn, queue, cons);
	}

	@Override
	public LDAPSearchResults search(String base, int scope, String filter, String[] attrs, boolean typesOnly)
			throws LDAPException {

		return ldap.search(base, scope, filter, attrs, typesOnly);
	}

	@Override
	public LDAPSearchResults search(String base, int scope, String filter, String[] attrs, boolean typesOnly,
			LDAPSearchConstraints cons) throws LDAPException {

		return ldap.search(base, scope, filter, attrs, typesOnly, cons);
	}

	@Override
	public LDAPSearchQueue search(String base, int scope, String filter, String[] attrs, boolean typesOnly,
			LDAPSearchQueue queue) throws LDAPException {

		return ldap.search(base, scope, filter, attrs, typesOnly, queue);
	}

	@Override
	public LDAPSearchQueue search(String base, int scope, String filter, String[] attrs, boolean typesOnly,
			LDAPSearchQueue queue, LDAPSearchConstraints cons) throws LDAPException {

		return ldap.search(base, scope, filter, attrs, typesOnly, queue, cons);
	}

	@Override
	public LDAPMessageQueue sendRequest(LDAPMessage request, LDAPMessageQueue queue) throws LDAPException {

		return ldap.sendRequest(request, queue);
	}

	@Override
	public LDAPMessageQueue sendRequest(LDAPMessage request, LDAPMessageQueue queue, LDAPConstraints cons)
			throws LDAPException {

		return ldap.sendRequest(request, queue, cons);
	}

	@Override
	public LDAPSchema fetchSchema(String schemaDN) throws LDAPException {

		return ldap.fetchSchema(schemaDN);
	}

	@Override
	public String getSchemaDN() throws LDAPException {

		return ldap.getSchemaDN();
	}

	@Override
	public String getSchemaDN(String dn) throws LDAPException {

		return ldap.getSchemaDN(dn);
	}

	@Override
	public int hashCode() {

		return ldap.hashCode();
	}

	@Override
	public boolean equals(Object obj) {

		return ldap.equals(obj);
	}

	@Override
	public String toString() {

		return ldap.toString();
	}

}
