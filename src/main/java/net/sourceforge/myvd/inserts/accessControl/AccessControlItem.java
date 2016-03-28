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
package net.sourceforge.myvd.inserts.accessControl;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.StringTokenizer;
import java.util.Vector;

import net.sourceforge.myvd.chain.InterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Results;



import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPUrl;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public class AccessControlItem {
	int num;
	DN dn;
	
	boolean isGrant;
	boolean isSubtree;
	
	//attribute permisions
	boolean isRead;
	boolean isWrite;
	boolean isObliterate;
	boolean isSearch;
	boolean isCompare;
	boolean isPresenceSearch;
	
	//entry permisionds
	boolean isCreate;
	boolean isDelete;
	boolean isView;
	boolean isRename;
	
	boolean isEntryPerms;
	boolean isAllAttributes;
	
	HashSet<String> attributes;
	private SubjectType subjectType;
	private String subjectValue;
	private DN SubjectDN;
	
	public AccessControlItem(int index,String aci) throws Exception {
		this.num = index;
		////System.out.println(aci);
		StringTokenizer toker = new StringTokenizer(aci,"#");
		
		//first the DN
		this.dn = new DN(toker.nextToken());
		
		//determine scope
		this.isSubtree = toker.nextToken().equalsIgnoreCase("subtree");
		
		//determine permisions
		String grant = toker.nextToken();
		this.isGrant = grant.substring(0,grant.indexOf(':')).equalsIgnoreCase("grant");
		
		StringTokenizer toker1 = new StringTokenizer(grant.substring(grant.indexOf(':') + 1),",");
		
		while (toker1.hasMoreTokens()) {
			String perm = toker1.nextToken();
			if (perm.equals("r")) {
				this.isRead = true;
			} else if (perm.equals("w")) {
				this.isWrite = true;
			} else if (perm.equals("s")) {
				this.isSearch = true;
			} else if (perm.equals("o")) {
				this.isObliterate = true;
			} else if (perm.equals("p")) {
				this.isPresenceSearch = true;
			} else if (perm.equals("c")) {
				this.isCompare = true;
			} else if (perm.equals("a")) {
				this.isCreate = true;
			} else if (perm.equals("d")) {
				this.isDelete = true;
			} else if (perm.equals("v")) {
				this.isView = true;
			} else if (perm.equals("n")) {
				this.isRename = true;
			}
		}
		
		//get attributes
		String attribs = toker.nextToken();
		
		if (attribs.equalsIgnoreCase("[entry]")) {
			this.isEntryPerms = true;
		} else {
			this.isAllAttributes = false;
			
			if (attribs.equalsIgnoreCase("[all]")) {
				this.isAllAttributes = true;
			} else {
				this.isAllAttributes = false;
				toker1 = new StringTokenizer(attribs,",");
				this.attributes = new HashSet<String>();
				int i=0;
				while (toker1.hasMoreTokens()) {
					this.attributes.add(toker1.nextToken().toLowerCase());
				}
			}
		}
		
		//determine subject
		String fullSubject = toker.nextToken();
		String subjectType = fullSubject.substring(0,fullSubject.indexOf(':'));
		
		if (subjectType.equalsIgnoreCase("this")) {
			this.subjectType = SubjectType.THIS;
		} else if (subjectType.equalsIgnoreCase("subtree")) {
			this.subjectType = SubjectType.SUBTREE;
		}   else if (subjectType.equalsIgnoreCase("group")) {
			this.subjectType = SubjectType.GROUP;
		} else if (subjectType.equalsIgnoreCase("DN")) {
			this.subjectType = SubjectType.DN;
		} else if (subjectType.equalsIgnoreCase("public")) {
			this.subjectType = SubjectType.PUBLIC;
		} else if (subjectType.equalsIgnoreCase("dynamic-group")) {
			this.subjectType = SubjectType.DYNAMIC_GROUP;
		}
		
		this.subjectValue = fullSubject.substring(fullSubject.indexOf(':') + 1);
		
		if (this.subjectType == SubjectType.DN || this.subjectType == SubjectType.SUBTREE || this.subjectType == SubjectType.GROUP || this.subjectType == SubjectType.DYNAMIC_GROUP) {
			this.SubjectDN = new DN(this.subjectValue);
		}
		
	}

	public HashSet<String> getAttributes() {
		return attributes;
	}

	public DN getDn() {
		return dn;
	}

	public boolean isAllAttributes() {
		return isAllAttributes;
	}

	public boolean isCompare() {
		return isCompare;
	}

	public boolean isCreate() {
		return isCreate;
	}

	public boolean isDelete() {
		return isDelete;
	}

	public boolean isEntryPerms() {
		return isEntryPerms;
	}

	public boolean isGrant() {
		return isGrant;
	}

	public boolean isObliterate() {
		return isObliterate;
	}

	public boolean isPresenceSearch() {
		return isPresenceSearch;
	}

	public boolean isRead() {
		return isRead;
	}

	public boolean isSearch() {
		return isSearch;
	}

	public boolean isSubtree() {
		return isSubtree;
	}

	public boolean isView() {
		return isView;
	}

	public boolean isWrite() {
		return isWrite;
	}

	public int getNum() {
		return num;
	}

	public DN getSubjectDN() {
		return SubjectDN;
	}

	public SubjectType getSubjectType() {
		return subjectType;
	}

	public String getSubjectValue() {
		return subjectValue;
	}
	
	
	
	public String toString() {
		return Integer.toString(this.num);
	}
	
	
	public boolean checkSubject(InterceptorChain chain, DN entryDN) {
		boolean subjectPassed = false;
		
		switch (this.subjectType) {
			case PUBLIC : subjectPassed = true; break;
			case DN : subjectPassed = this.SubjectDN.equals(chain.getBindDN().getDN()); break;
			case THIS : subjectPassed = entryDN.equals(chain.getBindDN().getDN()); break;
			case SUBTREE : subjectPassed = isDescendantOf(this.SubjectDN,chain.getBindDN().getDN()); break;
			case GROUP : subjectPassed = checkStaticGroup(chain); break;
			case DYNAMIC_GROUP : subjectPassed = checkDynamicGroup(chain); break;
		}
		
		return subjectPassed;
	}

	private boolean checkDynamicGroup(InterceptorChain chain) {
		try {
			SearchInterceptorChain searchChain = chain.createSearchChain();
			Results res = new Results(searchChain.getInterceptors());
			ArrayList<Attribute> attribs = new ArrayList<Attribute>();
			attribs.add(new Attribute("objectClass"));
			attribs.add(new Attribute("memberURL"));
			
			searchChain.nextSearch(new DistinguishedName(this.SubjectDN),new Int(0),new Filter("(objectClass=*)"),attribs,new Bool(false),res,new LDAPSearchConstraints());
			res.start();
			
			if (! res.hasMore()) {
				res.finish();
				return false;
			} else {
				LDAPEntry entry = res.next().getEntry();
				res.finish();
				LDAPAttribute attr = entry.getAttribute("objectClass");
				String[] vals = attr.getStringValueArray();
				for (int i=0;i<vals.length;i++) {
					if (vals[i].equalsIgnoreCase("groupofnames") || vals[i].equalsIgnoreCase("groupofuniquenames")) {
						boolean passed = this.checkStaticGroup(chain);
						if (passed) {
							return true;
						}
					}
				}
				
				Enumeration<String> enumer = entry.getAttribute("memberurl").getStringValues();
				while (enumer.hasMoreElements()) {
					if (passURL(chain,enumer.nextElement())) {
						return true;
					}
				}
				
				return false;
			}
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
	}

	private boolean passURL(InterceptorChain chain, String urlString) {
		try {
			LDAPUrl url = new LDAPUrl(urlString);
			DistinguishedName base = new DistinguishedName(url.getDN());
			Filter filter = new Filter("(&(" + chain.getBindDN().getDN().explodeDN(false)[0] + ")" + url.getFilter() + ")");
			ArrayList<Attribute> attribs = new ArrayList<Attribute>();
			attribs.add(new Attribute("1.1"));
			
			SearchInterceptorChain searchChain = chain.createSearchChain();
			Results res = new Results(searchChain.getInterceptors());
			
			searchChain.nextSearch(base,new Int(url.getScope()),filter,attribs,new Bool(false),res,new LDAPSearchConstraints());
			res.start();
			
			
			while (res.hasMore()) {
				
				if (new DN(res.next().getEntry().getDN()).equals(chain.getBindDN().getDN())) {
					res.finish();
					return true;
				}
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}

	private boolean checkStaticGroup(InterceptorChain chain) {
		try {
			SearchInterceptorChain searchChain = chain.createSearchChain();
			Results res = new Results(searchChain.getInterceptors());
			ArrayList<Attribute> attribs = new ArrayList<Attribute>();
			attribs.add(new Attribute("1.1"));
			searchChain.nextSearch(new DistinguishedName(this.SubjectDN),new Int(0),new Filter("(|(uniqueMember=" + chain.getBindDN().getDN() + ")(member=" + chain.getBindDN().getDN() + "))"),attribs,new Bool(false),res,new LDAPSearchConstraints());
			
			res.start();
			boolean passed = res.hasMore();
			res.finish();
			
			return passed;
			
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
	}
	
	private boolean isDescendantOf(DN parent,DN child) {
		Vector<RDN> parentRDNs = parent.getRDNs();
		Vector<RDN> childRDNs = child.getRDNs();
		
		if (childRDNs.size() <= parentRDNs.size()) {
			return false;
		}
		
		int i = childRDNs.size() - 1;
		int l = parentRDNs.size() - 1;
		
		for ( ;l>=0;) {
			if (! parentRDNs.get(l).equals(childRDNs.get(i))) {
				return false;
			}
			i--;
			l--;
		}
		
		return true;
	}

	public boolean isRename() {
		return isRename;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
