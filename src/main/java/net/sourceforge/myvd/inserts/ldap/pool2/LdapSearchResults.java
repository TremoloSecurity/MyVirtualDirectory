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

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.novell.ldap.util.ByteArray;

import net.sourceforge.myvd.inserts.ldap.LDAPInterceptorExperimental;

public class LdapSearchResults extends LDAPSearchResults {
	static Logger logger = Logger.getLogger(LdapSearchResults.class);
	
	
	ConcurrentLinkedQueue<LdapResult> messages;
	boolean done;
	LDAPInterceptorExperimental interceptor;
	
	private String remoteBase;
	private int scope;
	private String filter;
	private String[] attrs;
	private boolean typesOnly;
	LDAPSearchConstraints constraints;
	LDAPControl[] responseControls;
	
	
	public LdapSearchResults(LDAPInterceptorExperimental interceptor,String remoteBase, int scope, String filter, String[] attribs, boolean typesOnly, LDAPSearchConstraints constraints) {
		this.messages = new ConcurrentLinkedQueue<LdapResult>();
		this.done = false;
		this.interceptor = interceptor;
		this.remoteBase = remoteBase;
		this.scope = scope;
		this.filter = filter;
		this.attrs = attribs;
		this.typesOnly = typesOnly;
		this.constraints = constraints;
	}
	
	public void setResults(LDAPConnection ldap,LDAPEntry firstEntry,LDAPSearchResults res) throws LDAPException {
		this.responseControls = res.getResponseControls();
		if (firstEntry != null) {
			handleRangeAttributes(ldap,firstEntry);
		
			messages.add(new LdapResult(firstEntry));
			
			this.interceptor.getThreadPool().submit(
			
			new Runnable() {
				public void run() {
					if (loadResults(ldap,res,1)) {
						messages.add(new LdapResult(true));
					}
					
					
					
					
					try {
						ldap.disconnect();
					} catch (LDAPException e) {
						//do nothing
					}
					
				}
			});
			
		} else {
			messages.add(new LdapResult(true));
			try {
				ldap.disconnect();
			} catch (LDAPException e) {
				//do nothing
			}
		}
		
		
	}
	
	private boolean loadResults(LDAPConnection ldap,LDAPSearchResults res,int start) {
		
		int numResults = start;
		try {
			while (res.hasMore()) {
				LDAPEntry entry = null;
				try {
					entry = res.next();
				} catch (LDAPReferralException re) {
					if (this.interceptor.isIgnoreRefs()) {
						continue;
					} else {
						throw re;
					}
				}
				
				numResults++;
		
				handleRangeAttributes(ldap,entry);
				
				messages.add(new LdapResult(entry));
			}
			
			
			if (this.interceptor.isUsePaging()) {
				if (numResults == this.interceptor.getPageSize()) {
					for (LDAPControl control : res.getResponseControls()) {
						if (control instanceof LDAPPagedResultsResponse) {
							LDAPPagedResultsResponse resp = (LDAPPagedResultsResponse) control;
							LDAPPagedResultsControl page = (LDAPPagedResultsControl) this.constraints
									.getControls()[constraints.getControls().length - 1];
							page.setCookie(resp.getCookie());
							
						}
						
						LDAPSearchResults pagedRes = ldap.search(remoteBase, scope, filter, attrs, typesOnly,this.constraints);
						return loadResults(ldap,pagedRes,0);
					}
				}
			} 
			
			
			
		} catch (LDAPException e) {
			messages.add(new LdapResult(e));
			return false;
		} 
		
		return true;
		
		
	}
	
	
	private void handleRangeAttributes(LDAPConnection ldap,LDAPEntry entry) throws LDAPException {
		
		List<AttrRange> ranges = new ArrayList<AttrRange>();
		
		// first loop through attributes to see if there are any ranges
		Set attributeNames = new HashSet();
		attributeNames.addAll(entry.getAttributeSet().keySet());
		
		for (Object o : attributeNames) {
			LDAPAttribute attr = (LDAPAttribute) entry.getAttribute((String)o);
			
			if (attr.getName().contains(";range=")) {
				AttrRange rangeAttr = new AttrRange();
				ranges.add(rangeAttr);

				if (logger.isDebugEnabled()) {
					logger.info("attribute : " + attr.getName() + " is a range");
				}
				rangeAttr.name = attr.getName().substring(0, attr.getName().indexOf(';'));
				

				
				rangeAttr.attr = attr;

				

				String range = attr.getName().substring(attr.getName().indexOf('=') + 1);
				logger.debug(range);
				rangeAttr.start = Integer.parseInt(range.substring(0, range.indexOf('-')));
				rangeAttr.end = Integer.parseInt(range.substring(range.indexOf('-') + 1));
				rangeAttr.total = rangeAttr.start + rangeAttr.end + 1;
				
				
				attr.removeRange(entry);
				
				
				if (logger.isDebugEnabled()) {
					logger.debug("total : " + rangeAttr.total);
				}
			}
		}
		
		// pull in attribute values
		StringBuilder sb = new StringBuilder();
		
		if (ranges.size() > 0) {
			LDAPAttribute attr = null;
			boolean done = false;
			while (!done) {
				ArrayList<String> attrsToRequest = new ArrayList<String>();

				for (AttrRange rangeAttr : ranges) {
					if (!rangeAttr.done) {
						
						sb.setLength(0);
						sb.append(rangeAttr.name)
						  .append(";range=" )
						  .append(rangeAttr.end + 1)
						  .append("-")
						  .append(rangeAttr.end + rangeAttr.total);
						
						rangeAttr.currentRangeAttr = sb.toString();
						
						attrsToRequest.add(rangeAttr.currentRangeAttr);
					}
				}

				if (attrsToRequest.size() == 0) {
					done = true; break;
				}
				
				String[] attributesToRequest = attrsToRequest.toArray(new String[] {});

				if (attributesToRequest.length > 0) {

					LDAPSearchResults lres = ldap.search(entry.getDN(), 0,
							"(objectClass=*)", attributesToRequest, false);
					if (!lres.hasMore()) {
						done = true;
						logger.warn("Could not find " + entry.getDN() + " for range lookup");
					} else {
						LDAPEntry nentry = lres.next();

						for (AttrRange rangeAttr : ranges) {

							attr = nentry.getAttribute(rangeAttr.currentRangeAttr);
							if (attr == null) {
								
								sb.setLength(0);
								sb.append(rangeAttr.name)
								  .append(";range=")
								  .append(rangeAttr.end + 1)
								  .append("-*");
								
								String attrName = sb.toString();  //rangeAttr.name + ";range=" + (rangeAttr.end + 1) + "-*";
								attr = nentry.getAttribute(attrName);

								if (attr == null) {
									logger.warn("no range attribute");

								}

								rangeAttr.done = true;
							}

							if (attr != null) {

								

								ByteArray vals = null;
								while ((vals = attr.getAndRemoveFirstValue()) != null) {
									rangeAttr.attr.getAllValues().add(vals);
								}
								

								
								if (!rangeAttr.done) {
									String range = attr.getName()
											.substring(attr.getName().indexOf('=') + 1);
									logger.debug(range);
									rangeAttr.start = Integer
											.parseInt(range.substring(0, range.indexOf('-')));
									rangeAttr.end = Integer
											.parseInt(range.substring(range.indexOf('-') + 1));
								}
							}

						}
					}

				}

			}
		}
		
		
	}
	
	@Override
	public int getCount() {
		// TODO Auto-generated method stub
		return super.getCount();
	}

	@Override
	public LDAPControl[] getDeSerializedControls() {
		// TODO Auto-generated method stub
		return super.getDeSerializedControls();
	}

	@Override
	public Vector getDeSerializedEntries() {
		return null;
	}

	@Override
	public LDAPControl[] getResponseControls() {
		return this.responseControls;
	}

	
	private LdapResult peek() {
		long started = System.currentTimeMillis();
		LdapResult res = this.messages.peek();
		
		while (res == null) {
			if (System.currentTimeMillis() - started >= interceptor.getMaxTimeoutMillis()) {
				res = new LdapResult(new LDAPException(LDAPException.resultCodeToString(LDAPException.LDAP_TIMEOUT),LDAPException.LDAP_TIMEOUT,"Timeout retrieving messages"));
			}
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
				
			}
			res = this.messages.peek();
		}
		
		return res;
	}
	
	private LdapResult poll() {
		long started = System.currentTimeMillis();
		LdapResult res = this.messages.poll();
		while (res == null) {
			if (System.currentTimeMillis() - started >= interceptor.getMaxTimeoutMillis()) {
				res = new LdapResult(new LDAPException(LDAPException.resultCodeToString(LDAPException.LDAP_TIMEOUT),LDAPException.LDAP_TIMEOUT,"Timeout retrieving messages"));
			}
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			res = this.messages.poll();
		}
		
		return res;
	}
	
	@Override
	public boolean hasMore() {
		if (this.done) {
			return false;
		} else {
			LdapResult res = this.peek();
			if (res == null) {
				//TODO not sure
				return false;
			} else {
				if (res.isDone()) {
					this.poll();
					this.done = true;
					return !this.done;
				} else {
					return true;
				}
			}
		}
	}

	@Override
	public LDAPEntry next() throws LDAPException {
		LdapResult res = this.poll();
		
		if (res == null) {
			//TODO not sure how to handle this one
			return null;
		} else {
			if (res.isDone()) {
				//shouldn't happen but...
				this.done = true;
				return null;
			} else if (res.getException() != null) {
				this.done = true;
				throw res.getException();
			} else {
				return res.getEntry();
			}
		}
	}

	@Override
	public void readExternal(ObjectInput arg0) throws IOException, ClassNotFoundException {
		
	}

	@Override
	public void writeExternal(ObjectOutput arg0) throws IOException {
		
	}

	
	
	
	
}

class AttrRange {
	String name;
	String currentRangeAttr;
	int start;
	int end;
	int total;
	LDAPAttribute attr;
	boolean done;
}
