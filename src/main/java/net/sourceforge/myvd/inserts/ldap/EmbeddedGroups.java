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

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Stack;

import org.apache.log4j.Category;
import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPUrl;
import com.novell.ldap.controls.LDAPEntryChangeControl;
import com.novell.ldap.controls.LDAPPersistSearchControl;
import com.novell.ldap.util.DN;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.InterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.ConnectionUtil;
import net.sourceforge.myvd.util.EntryUtil;

public class EmbeddedGroups implements Insert {
	private static Logger logger = Logger.getLogger(EmbeddedGroups.class);

	private String StackKey;
	private String name;
	private NameSpace ns;
	
	private String staticAttribute;
	private DN groupBase;
	private DN userDN;
	private byte[] userPwd;
	
	private String staticOC;
	private boolean refreshBySync;
	private HashSet<String> groups;
	private boolean initialized;
	private Int chainPos = new Int(-1);
	
	private boolean isGlobal;
	private ConnectionUtil conUtil;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		startSyncProcess();
		chain.nextAdd(entry, constraints);
		

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		startSyncProcess();
		chain.nextBind(dn, pwd, constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		startSyncProcess();
		chain.nextCompare(dn, attrib, constraints);

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		
		this.staticAttribute = props.getProperty("staticAttribute");
		this.groupBase = new DN(props.getProperty("groupSearchBase"));
		this.staticOC = props.getProperty("staticObjectClass");
		
		this.userDN = new DN(props.getProperty("userDN"));
		this.userPwd = props.getProperty("userPwd").getBytes();
		
		this.refreshBySync = props.getProperty("useSync","false").equalsIgnoreCase("true");
		
		this.initialized = false;
		
		this.groups = new HashSet<String>();
		
		this.chainPos = new Int(-1);
		
		this.ns = nameSpace;
		
		this.isGlobal = nameSpace.isGlobal();
		
		this.StackKey = "EmbeddedGroups_" + ns.getBase().getDN().toString() + "_" + name;
		
		
		
	
	}

	private void startSyncProcess() throws LDAPException {
		synchronized (this.chainPos) {
			if (this.conUtil == null) {
				this.chainPos.setValue(this.ns.getPositionInChain(this) + 1);
				this.conUtil = new ConnectionUtil(this.ns,this.chainPos.getValue());
				this.conUtil.bind(new DistinguishedName(this.userDN),new Password(this.userPwd),new LDAPConstraints());
				
				Thread thread = new Thread(new RebuildGroups(this));
				thread.setName("EmbeddedGroups-" + this.name + "-Sync");
				thread.start();
			}
		}
		
		
	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		startSyncProcess();
		chain.nextDelete(dn, constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		startSyncProcess();
		chain.nextExtendedOperations(op, constraints);

	}

	public String getName() {
		return this.name;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		startSyncProcess();
		chain.nextModify(dn, mods, constraints);

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);
		Stack<EmbRequest> req = (Stack<EmbRequest>) chain.getRequest().get(this.StackKey);
		if (req.size() > 0) {
			req.pop();
		}

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		Stack<EmbRequest> req = (Stack<EmbRequest>) chain.getRequest().get(this.StackKey);
		EmbRequest embreq = req.peek();
		
		if (checkObjectClass(entry)) {
			
			boolean requestedMembers = embreq.requestedMembers;
			
			LDAPAttribute members = entry.getEntry().getAttribute(staticAttribute);
			if (members == null) {
				members = new LDAPAttribute(staticAttribute);
				entry.getEntry().getAttributeSet().add(members);
			}
			
			ArrayList<EmbTestMembers> testmembers = embreq.testmembers;
			Iterator<EmbTestMembers> it = testmembers.iterator();
			while (it.hasNext()) {
				EmbTestMembers tm = it.next();
				checkMember(tm,entry.getEntry().getDN(),chain);
			}
			
			Filter useFilter = embreq.newfilter;
			
			entry.setReturnEntry(useFilter.getRoot().checkEntry(entry.getEntry()));
			
			if (requestedMembers && entry.isReturnEntry()) {
				createStaticMembers(chain, new DN(entry.getEntry().getDN()), constraints, members,true);
			}
			
			if (members.size() == 0) {
				entry.getEntry().getAttributeSet().remove(staticAttribute);
			}
			
			
		}

	}

	
	private void checkMember (EmbTestMembers tm, String dn,PostSearchEntryInterceptorChain chain) throws LDAPException {
		if (this.checkMemberInGroup(tm, dn, chain)) {
			tm.filterNode.setName("objectClass");
			tm.filterNode.setType(FilterType.PRESENCE);
			tm.filterNode.setValue("*");
		} else {
			FilterNode node = new FilterNode(FilterType.PRESENCE,"objectclass","*");
			tm.filterNode.setType(FilterType.NOT);
			tm.filterNode.setNot(node);
			tm.filterNode.setName(null);
			tm.filterNode.setValue(null);
		}
		
	}
	
	private boolean checkMemberInGroup(EmbTestMembers tm, String dn,PostSearchEntryInterceptorChain chain) throws LDAPException {
	
	
		//first check static members
		
		Results results = new Results(null,chain.getPositionInChain(this) + 1);
		SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
		
		ArrayList<Attribute> attribs = new ArrayList<Attribute>();
		attribs.add(new Attribute("1.1"));
		
		try {
			schain.nextSearch(new DistinguishedName(dn), new Int(0), new Filter("(" + this.staticAttribute + "=" + tm.member + ")"), attribs, new Bool(false), results, new LDAPSearchConstraints());
			results.start();
			boolean found = false;
			if (results.hasMore()) {
				found = true;
				results.next();
				while (results.hasMore()) {
					results.next();
				}
				
			}
			
			results.finish();
			
			if (found) {
				
				return true;
			} 
			
		} catch (LDAPException e) {
			logger.error("Error searching group",e);
			return false;
		}
		
		//check group members
		
		
		
		
		HashSet<String> groups = this.getGroupDNs();
		
		results = new Results(null,chain.getPositionInChain(this) + 1);
		schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
		
		attribs = new ArrayList<Attribute>();
		attribs.add(new Attribute(this.staticAttribute));
		
		try {
			schain.nextSearch(new DistinguishedName(dn), new Int(0), new Filter("(objectClass=*)"), attribs, new Bool(false), results, new LDAPSearchConstraints());
			results.start();
			
			while (results.hasMore()) {
				LDAPEntry entry = results.next().getEntry();
				LDAPAttribute members = entry.getAttribute(this.staticAttribute);
				
				if (members != null) {
					
				
					Enumeration enumer = members.getStringValues();
					while (enumer.hasMoreElements()) {
						
						String member = (String) enumer.nextElement();
						if (groups.contains(new DN(member).toString().toLowerCase())) {
							if (this.checkMemberInGroup(tm, member, chain)) {
								results.finish();
								return true;
							}
						}
					}
				}
				
			}
			
			results.finish();
			
			 
			
		} catch (LDAPException e) {
			logger.error("Error searching group",e);
		}
				
		return false;
		
		
	}

	private boolean checkObjectClass(Entry entry) {
		
		boolean isGroup = false;
		
		LDAPAttribute ocs = entry.getEntry().getAttribute("objectClass");
		if (ocs != null) {
			String[] vals = ocs.getStringValueArray();
			for (int i=0;i<vals.length;i++) {
				if (vals[i].equalsIgnoreCase(staticOC)) {
					isGroup = true;
				} 
			}
			
			
			
		}
		
		return isGroup;
	}

	private void createStaticMembers(PostSearchEntryInterceptorChain chain, DN currentGroup, LDAPSearchConstraints constraints, LDAPAttribute members,boolean isFirst) throws LDAPException {
		
		HashSet<String> groups = this.getGroupDNs();
		
		if (members == null) {
			return;
		}
		
		
		if (isFirst) {
			Enumeration enumer = members.getStringValues();
			while (enumer.hasMoreElements()) {
				String member = (String) enumer.nextElement();
				DN memberDN = new DN(member);
				
				if (groups.contains(memberDN.toString().toLowerCase())) {
					this.createStaticMembers(chain, memberDN, constraints, members, false);
				}
			}
		} else {
			Results results;
			
			
			ArrayList<Attribute> attribs = new ArrayList<Attribute>();
			attribs.add(new Attribute(this.staticAttribute));
			
			results = this.conUtil.search(new DistinguishedName(currentGroup), new Int(0), new Filter("(objectClass=*)"), attribs, new Bool(false),  constraints);
			
			results.start();
			
			while (results.hasMore()) {
				LDAPEntry entry = results.next().getEntry();
				LDAPAttribute nmembers = entry.getAttribute(this.staticAttribute);
				
				if (nmembers != null) {
					Enumeration enumer = nmembers.getStringValues();
					while (enumer.hasMoreElements()) {
						String member = (String) enumer.nextElement();
						DN memberDN = new DN(member);
						if (groups.contains(memberDN)) {
							this.createStaticMembers(chain, memberDN, constraints, members, false);
						}
						members.addValue(member);
					}
				}
			}
		}
		
		
		
		
		
		
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		startSyncProcess();
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		startSyncProcess();
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		Stack<EmbRequest> req = (Stack<EmbRequest>) chain.getRequest().get(this.StackKey);
		if (req == null) {
			req = new Stack<EmbRequest>();
			chain.getRequest().put(this.StackKey, req);
		}
		
		EmbRequest embreq = new EmbRequest();
		req.push(embreq);
		
		startSyncProcess();
		
		embreq.requestedMembers = false;
		boolean requestedOC = false;
		
		if (attributes.size() == 0) {
			embreq.requestedMembers = true;
			requestedOC = true;
		}
		
		ArrayList<Attribute> nattribs = new ArrayList<Attribute>();
		
		Iterator<Attribute> it = attributes.iterator();
		while (it.hasNext()) {
			Attribute attrib = it.next();
			String name = attrib.getAttribute().getBaseName();
			if (name.equalsIgnoreCase("*")) {
				embreq.requestedMembers = true;
				requestedOC = true;
				
				nattribs.add(new Attribute("*"));
				
			} else if (name.equalsIgnoreCase(staticAttribute)) {
				embreq.requestedMembers = true;
			} else if (name.equalsIgnoreCase("objectclass")) {
				requestedOC = true;
				nattribs.add(new Attribute(name));
			} else {
				nattribs.add(new Attribute(name));
			}
		}
		
		
		if (attributes.size() != 0) {
			if (embreq.requestedMembers) {
				nattribs.add(new Attribute(staticAttribute));
			}
			
			if (! requestedOC) {
				nattribs.add(new Attribute("objectclass"));
			}
		}
		
		
		
		
		embreq.newfilter = null; 
		embreq.testmembers = new ArrayList<EmbTestMembers>();
		
		try {
			embreq.newfilter =	new Filter(this.trimSearchFilter(filter.getRoot(), embreq.testmembers,nattribs));
		} catch (CloneNotSupportedException e) {
			
		}
		
		
		
		Filter useNewFilter = null;
		
		
		useNewFilter =	new Filter(embreq.newfilter.getRoot().toString());
		
		chain.nextSearch(base, scope, useNewFilter, nattribs, typesOnly, results, constraints);

	}
	
	private void addAttribute(ArrayList<Attribute> nattribs,String name) {
		Attribute attrib = new Attribute(name);
		
		if (! (nattribs.size() == 0 || nattribs.contains(attrib))) {
			nattribs.add(attrib);
		}
	}
	
	private FilterNode trimSearchFilter(FilterNode root,ArrayList<EmbTestMembers> members,ArrayList<Attribute> nattribs) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if (root.getName().equalsIgnoreCase(staticAttribute)) {
					newNode = (FilterNode) root.clone();
					EmbTestMembers tm = new EmbTestMembers();
					tm.filterNode = newNode;
					tm.member = root.getValue();
					newNode.setName("objectClass");
					newNode.setValue("*");
					newNode.setType(FilterType.PRESENCE);
					members.add(tm);
					return newNode;
					
				} else {
					newNode = (FilterNode) root.clone();
					
					
					this.addAttribute(nattribs, newNode.getName());
					
					return newNode;
				}
				
				
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = trimSearchFilter(it.next(),members,nattribs);
					if (node != null) {
						newChildren.add(node);
					}
					
				}
				
				if (newChildren.size() == 0) {
					return null;
				} else if (newChildren.size() == 1) {
					return newChildren.get(0);
				} else {
					newNode = new FilterNode(root.getType(),newChildren);
					return newNode;
				}
				
				
			case NOT:
				FilterNode node = trimSearchFilter(root.getNot(),members,nattribs);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
		
	}
	
	private HashSet<String> getGroupDNs () throws LDAPException {
		if (! this.initialized) {
			synchronized (this.groups) {
				staticLoadGroups(this.groups);
			}
			
			this.initialized = true;
		} 
		
		
		return this.groups;
	
		
				
	}

	protected HashSet<String> staticLoadGroups(HashSet<String> groups) throws LDAPException {
		
		Results results;
		
		
		ArrayList<Attribute> attribs = new ArrayList<Attribute>();
		attribs.add(new Attribute("1.1"));
		
		results = this.conUtil.search(new DistinguishedName(this.groupBase), new Int(2), new Filter("(objectClass=" + this.staticOC + ")"), attribs, new Bool(false), new LDAPSearchConstraints());
		
		results.start();
		
		while (results.hasMore()) {
			groups.add(new DN(results.next().getEntry().getDN()).toString().toLowerCase());
		}
		
		results.finish();
		return groups;
	}
	
	protected void psearchLoadGroups(HashSet<String> groups) throws LDAPException {
		
		
		Results results;
		
		
		ArrayList<Attribute> attribs = new ArrayList<Attribute>();
		attribs.add(new Attribute("1.1"));
		
		LDAPSearchConstraints constraints = new LDAPSearchConstraints();
		
		LDAPPersistSearchControl psCtrl;
		
		psCtrl = new LDAPPersistSearchControl(LDAPPersistSearchControl.ADD + LDAPPersistSearchControl.DELETE,true,true,true);
		
		constraints.setControls(psCtrl);
		
		results = this.conUtil.search(new DistinguishedName(this.groupBase), new Int(2), new Filter("(objectClass=groupOfUniqueNames)"), attribs, new Bool(false), constraints);
		results.setSkipDupes(false);
		
		results.start();
		
		while (results.hasMore()) {
			//groups.add(new DN(results.next().getEntry().getDN()).toString().toLowerCase());
			
			logger.info("New change detected");
			Entry entry = results.next();
			
			LDAPControl[] respCtls = entry.getControls();
			
			if (respCtls != null) {
				for (int i=0,m=respCtls.length;i<m;i++) {
					if (respCtls[i] instanceof LDAPEntryChangeControl) {
						LDAPEntryChangeControl ctl = (LDAPEntryChangeControl) respCtls[i];
						
						if (ctl.getChangeType() == LDAPPersistSearchControl.ADD) {
							synchronized(groups) {
								logger.info("Adding " + entry.getEntry().getDN().toLowerCase());
								groups.add(entry.getEntry().getDN().toLowerCase());
							}
						} else if (ctl.getChangeType() == LDAPPersistSearchControl.DELETE) {
							synchronized(groups) {
								logger.info("Deleting " + entry.getEntry().getDN().toLowerCase());
								groups.remove(entry.getEntry().getDN().toLowerCase());
							}
						}
						
						break;
					}
				}
			}
			
			
		}
		
		results.finish();
		
	}

	public boolean isRefreshBySync() {
		return refreshBySync;
	}

	public HashSet<String> getGroups() {
		return groups;
	}

	public Logger getLogger() {
		return EmbeddedGroups.logger;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}


class EmbTestMembers {
	String member;
	FilterNode filterNode;
}

class RebuildGroups implements Runnable {

	EmbeddedGroups insert;
	
	public RebuildGroups(EmbeddedGroups insert) {
		this.insert = insert;
	}
	
	
	
	public void run() {
		if (! insert.isRefreshBySync()) {
			while (true) {
				try {
					Thread.sleep(20000);
				} catch (InterruptedException e) {
					return;
				}
				
				synchronized (insert.getGroups()) {
					insert.getGroups().clear();
					try {
						insert.staticLoadGroups(insert.getGroups());
					} catch (LDAPException e) {
						insert.getLogger().error("Error Synchronizing Groups",e);
					}
				}
			}
		} else {
			synchronized (insert.getGroups()) {
				insert.getGroups().clear();
				try {
					insert.staticLoadGroups(insert.getGroups());
					
				} catch (LDAPException e) {
					insert.getLogger().error("Error Synchronizing Groups",e);
				}
			}
			
			try {
				insert.psearchLoadGroups(insert.getGroups());
			} catch (Throwable e) {
				insert.getLogger().error("Error during persistant search",e);
			}
			
			
		}
		
	}
	
}

class EmbRequest {
	boolean requestedMembers;
	ArrayList<EmbTestMembers> testmembers;
	Filter newfilter;
}