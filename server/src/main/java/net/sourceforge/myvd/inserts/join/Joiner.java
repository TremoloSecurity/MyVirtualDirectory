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
package net.sourceforge.myvd.inserts.join;


import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Stack;
import java.util.StringTokenizer;
import java.util.Vector;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;



import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;


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
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
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
import net.sourceforge.myvd.util.NamingUtils;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

public class Joiner implements Insert {
	static Logger logger = Logger.getLogger(Joiner.class);
	
	public static final String MYVD_JOIN_JATTRIBS = "MYVD_JOIN_JATTRIBS_";

	public static final String MYVD_JOIN_JDN = "MYVD_JOIN_JDN_";

	public static final String MYVD_JOIN_PDN = "MYVD_JOIN_PDN_";

	private static  Filter OBJ_CLASS_FILTER = null; 

	public static final String PRIMARY_DN = "primaryDN";
	
	public static final String PRIMARY_BASE = "primaryBase";

	public static final String PRIMARY = "PRIMARY";
	
	public static final String JOINED = "JOINED";
	
	public static final Attribute ALL_ATTRIBS = new Attribute("*");

	private static final Object BOUND_DNS  = "BOUND_DNS_";
	
	DN primaryNamespace;
	DN joinedNamespace;
	DN localNameSpace;
	
	String[] explodedPrimaryNamespace;
	String[] explodedJoinedNamespace;
	String[] explodedLocalNameSpace;
	
	ArrayList<Attribute> joinFilterAttribs;
	
	NamingUtils util;
	
	NameSpace ns;
	
	HashSet<String> joinedAttrbutes;
	HashSet<String> joinedOCs;
	
	String key;
	String filterKey;
	String primaryFilterKey;
	String joinedFilterKey;
	String attributesKey;
	String baseKey;
	String scopeKey;
	String primaryAttribsKey;
	String joinedAttribsKey;
	
	FilterNode joinFilter;
	
	String name;

	private String stackKey;
	
	static {
		try {
			OBJ_CLASS_FILTER = new Filter("(objectClass=*)");
			logger.info("Def Filter : " + OBJ_CLASS_FILTER.getRoot());
		} catch (LDAPException e) {
			//can't happen
		}
	}
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		
		this.name = name;
		
		this.primaryNamespace = new DN(props.getProperty("primaryNamespace"));
		this.explodedPrimaryNamespace = this.primaryNamespace.explodeDN(false);
		
		this.joinedNamespace = new DN(props.getProperty("joinedNamespace"));
		this.explodedJoinedNamespace = this.joinedNamespace.explodeDN(false);
		
		this.localNameSpace = new DN(nameSpace.getBase().getDN().toString());
		this.explodedLocalNameSpace = this.localNameSpace.explodeDN(false);
		
		this.joinedAttrbutes = new HashSet<String>();
		StringTokenizer toker = new StringTokenizer(props.getProperty("joinedAttributes"),",");
		while (toker.hasMoreTokens()) {
			this.joinedAttrbutes.add(toker.nextToken().toLowerCase());
		}
		
		if (! this.joinedAttrbutes.contains("objectclass")) {
			this.joinedAttrbutes.add("objectclass");
		}
	
		this.joinFilter = (new Filter(props.getProperty("joinFilter"))).getRoot();
		
		this.joinFilterAttribs = new ArrayList<Attribute>();
		getFilterAttributes(this.joinFilter,this.joinFilterAttribs);
		
		this.joinedOCs = new HashSet<String>();
		toker = new StringTokenizer(props.getProperty("joinedObjectClasses",""),",",false);
		while (toker.hasMoreTokens()) {
			joinedOCs.add(toker.nextToken().toLowerCase());
		}
		
		key = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_KEY";
		filterKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_FILTER_KEY";
		primaryFilterKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_PRIMARY_FILTER_KEY";
		joinedFilterKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_JOINED_FILTER_KEY";
		attributesKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_ATTRIBUTES_KEY";
		baseKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_BASE_KEY";
		scopeKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_SCOPE_KEY";
		primaryAttribsKey = name + "." + nameSpace.getBase().getDN().toString() + ".PRIMARY_ATTRIBS_KEY";
		joinedAttribsKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_ATTRIBS_KEY";
		
		this.stackKey = name + "." + nameSpace.getBase().getDN().toString() + ".JOIN_STACK_KEY";
		
		util = new NamingUtils();
		this.ns = nameSpace;
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		this.loadRequestADD(chain);
		chain.nextAdd(entry, constraints);
		this.unloadRequest(chain);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		boolean primaryBindFailed = false;
		
		HashMap<DN,DistinguishedName> boundNameSpaces = new HashMap<DN,DistinguishedName>();
		chain.getSession().put(Joiner.BOUND_DNS + this.name, boundNameSpaces);
		
		BindInterceptorChain bindChain = new BindInterceptorChain(chain.getBindDN(),chain.getBindPassword(),ns.getRouter().getGlobalChain().getLength(),ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),ns.getRouter());
		int trys = 1;
		try {
			DistinguishedName newBindDN = new DistinguishedName(util.getRemoteMappedDN(dn.getDN(),this.explodedLocalNameSpace,this.explodedPrimaryNamespace));
			bindChain.nextBind(newBindDN,pwd,constraints);
			
			boundNameSpaces.put(this.primaryNamespace, newBindDN);
			
		} catch (LDAPException e) {
			primaryBindFailed = true;
			if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
				throw e;
			}
		}
		
		SearchInterceptorChain searchChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),ns.getRouter().getGlobalChain().getLength(),ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),ns.getRouter());
		Results res = new Results(new InsertChain(new Insert[0]));
		ArrayList<Attribute> attribs = new ArrayList<Attribute>();
		attribs.add(new Attribute("joinedDNs"));
		attribs.add(new Attribute("joinedBases"));
		searchChain.nextSearch(dn,new Int(0),Joiner.OBJ_CLASS_FILTER,attribs,new Bool(false),res,new LDAPSearchConstraints());
		
		res.start();
		if (! res.hasMore() && primaryBindFailed) {
			throw new LDAPException("Could not bind to any services",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
		}
		
		LDAPEntry entry = res.next().getEntry();
		res.finish();
		
		LDAPAttribute joinDNs = entry.getAttribute("joinedDNs");
		LDAPAttribute joinBases = entry.getAttribute("joinedBases");
		if (joinDNs == null) {
			if (primaryBindFailed) {
				throw new LDAPException("Could not bind to any services",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
			}
		} else {
			String[] dns = joinDNs.getStringValueArray();
			String[] bases = joinBases.getStringValueArray();
			for (int i=0,m=dns.length;i<m;i++) {
				bindChain = new BindInterceptorChain(chain.getBindDN(),chain.getBindPassword(),ns.getRouter().getGlobalChain().getLength(),ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),ns.getRouter());
				try {
					DistinguishedName binddn = new DistinguishedName(dns[i]);
					bindChain.nextBind(binddn,pwd,constraints);
					boundNameSpaces.put(new DN(bases[i]), binddn);
				} catch (LDAPException e) {
					if (e.getResultCode() != LDAPException.INVALID_CREDENTIALS) {
						throw e;
					}
					trys++;
					
					boundNameSpaces.put(new DN(bases[i]), new DistinguishedName(""));
				}
			}
			
			if (trys == dns.length + 1 && primaryBindFailed) {
				throw new LDAPException("Could not bind to any services",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
			}
		}

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		
		SearchInterceptorChain nchain = chain.createSearchChain(chain.getPositionInChain(this));
		Results res = new Results(null,chain.getPositionInChain(this));
		ArrayList<net.sourceforge.myvd.types.Attribute> attribs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
		attribs.add(new Attribute("1.1"));
		
		FilterNode node = new FilterNode(FilterType.EQUALS,attrib.getAttribute().getName(),attrib.getAttribute().getStringValue());
		Filter filter = new Filter(node);
		
		
		nchain.nextSearch(dn, new Int(0), filter, attribs, new Bool(false), res, new LDAPSearchConstraints());
		boolean compareSucceeds = false;
		
		res.start();
		if (res.hasMore()) {
			res.next();
			while (res.hasMore()) res.next();
			compareSucceeds = true;
		}
		
		if (! compareSucceeds) {
			throw new LDAPException(LDAPException.resultCodeToString(LDAPException.COMPARE_FALSE),LDAPException.COMPARE_FALSE,"Compare failed");
		}

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		this.loadRequest(chain, dn);
		chain.nextDelete(dn, constraints);
		this.unloadRequest(chain);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		this.loadRequest(chain, dn);
		chain.nextModify(dn, mods, constraints);
		this.unloadRequest(chain);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		JoinData jd = new JoinData();
		Stack<JoinData> stack = (Stack<JoinData>) chain.getRequest().get(this.stackKey);
		if (stack == null) {
			stack = new Stack<JoinData>();
			chain.getRequest().put(this.stackKey, stack);
		}
		stack.push(jd);
		jd.joinedAttribsSet = this.joinedAttrbutes;
		
		jd.joinFilter = filter;
		jd.joinAttribs = attributes;
		jd.joinBase = base;
		jd.joinScope = scope;
		
		/*
		chain.getRequest().put(filterKey,filter);
		chain.getRequest().put(attributesKey,attributes);
		chain.getRequest().put(baseKey,base);
		chain.getRequest().put(scopeKey,scope);
		*/
		
		ArrayList<Attribute> primaryAttribsToUse = new ArrayList<Attribute>();
		primaryAttribsToUse.addAll(attributes);
		
		ArrayList<Attribute> joinedAttribsToUse = new ArrayList<Attribute>();
		
		Iterator<String> it = this.joinedAttrbutes.iterator();
		while (it.hasNext()) {
			Attribute attrib = new Attribute(it.next());
			if (attributes.contains(attrib)) {
				joinedAttribsToUse.add(attrib);
			}
		}
		
		//this ensures that if there were specific attributes requested, all the joined attrbutes will not be included
		if (joinedAttribsToUse.size() == 0 && primaryAttribsToUse.size() != 0) {
			joinedAttribsToUse.add(new Attribute("1.1"));
		}
		
		if (primaryAttribsToUse.size() != 0 && ! primaryAttribsToUse.contains(ALL_ATTRIBS)) {
			Iterator<Attribute> attribIt = joinFilterAttribs.iterator();
			while (attribIt.hasNext()) {
				Attribute attrib = attribIt.next();
				if (! primaryAttribsToUse.contains(attrib)) {
					primaryAttribsToUse.add(attrib);
				}
			}
		}
		
		if (joinedAttribsToUse.size() != 0 && ! joinedAttribsToUse.contains(ALL_ATTRIBS)) {
			Iterator<Attribute> attribIt = joinFilterAttribs.iterator();
			while (attribIt.hasNext()) {
				Attribute attrib = attribIt.next();
				if (! joinedAttribsToUse.contains(attrib)) {
					joinedAttribsToUse.add(attrib);
				}
			}
		}
		
		
		
		Filter primaryFilter=null, joinedFilter=null;
		FilterNode node;
		
		try {
			node = trimPrimaryFilter(filter.getRoot(),primaryAttribsToUse);
			if (node == null) {
				primaryFilter = new Filter((FilterNode) OBJ_CLASS_FILTER.getRoot().clone());
				
				
			} else {
				primaryFilter = new Filter(node);
			}
			
			
			node = trimJoinedFilter(filter.getRoot(),joinedAttribsToUse);
			if (node == null) {
				joinedFilter = new Filter((FilterNode) OBJ_CLASS_FILTER.getRoot().clone());
			} else {
				joinedFilter = new Filter(node);
			}

		} catch (CloneNotSupportedException e) {
			//can't happen
		}
		
		
		
		jd.joinPrimaryFilter = primaryFilter;
		jd.joinJoinedFilter = joinedFilter;
		jd.joinPrimaryAttribs = primaryAttribsToUse;
		jd.joinJoinAttribs = joinedAttribsToUse;
		
		/*
		chain.getRequest().put(primaryFilterKey,primaryFilter);
		chain.getRequest().put(joinedFilterKey,joinedFilter);
		chain.getRequest().put(primaryAttribsKey,primaryAttribsToUse);
		chain.getRequest().put(joinedAttribsKey,joinedAttribsToUse);
		*/
		
		int primaryWeight = primaryFilter.getRoot().getWeight();
		int joinedWeight = joinedFilter.getRoot().getWeight();
		
		
		DN newSearchBase;
		Filter filterToUse;
		ArrayList<Attribute> attribsToUse;
		DistinguishedName bindDN;
		
		HashMap<DN,DistinguishedName> boundNameSpaces = (HashMap<DN, DistinguishedName>) chain.getSession().get(Joiner.BOUND_DNS + this.name);
		if (boundNameSpaces == null) {
			boundNameSpaces = new HashMap<DN,DistinguishedName>();
		}
		
		if (primaryWeight >= joinedWeight) {
			newSearchBase = util.getRemoteMappedDN(base.getDN(),this.explodedLocalNameSpace,this.explodedPrimaryNamespace);
			filterToUse = primaryFilter;
			attribsToUse = primaryAttribsToUse;
			//chain.getRequest().put(key,PRIMARY);
			jd.joinType = PRIMARY;
			DistinguishedName dn = boundNameSpaces.get(this.primaryNamespace);
			if (dn == null) {
				bindDN = new DistinguishedName("");
			} else {
				bindDN = new DistinguishedName(new DN(dn.getDN().toString()));
			}
		} else {
			//newSearchBase = util.getRemoteMappedDN(base.getDN(),this.explodedLocalNameSpace,this.explodedJoinedNamespace);
			newSearchBase = new DN(this.joinedNamespace.toString());
			filterToUse = joinedFilter;
			attribsToUse = joinedAttribsToUse;
			//chain.getRequest().put(key,JOINED);
			jd.joinType = JOINED;
			DistinguishedName dn = boundNameSpaces.get(this.joinedNamespace);
			if (dn == null) {
				bindDN = new DistinguishedName("");
			} else {
				bindDN = new DistinguishedName(new DN(dn.getDN().toString()));
			}
		}
		
		
		
		JoinerEntrySet es = new JoinerEntrySet(ns.getRouter(),chain,new DistinguishedName(newSearchBase),scope,filterToUse,attribsToUse,typesOnly,constraints,bindDN);
		results.addResult(chain,es,new DistinguishedName(newSearchBase),scope,filterToUse,attributes,typesOnly,constraints,ns.getChain());
		
		

	}

	private FilterNode trimJoinedFilter(FilterNode root,ArrayList<Attribute> attribs) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if (this.joinedAttrbutes.contains(root.getName().toLowerCase())) {
					newNode = (FilterNode) root.clone();
					Attribute attribReq = new Attribute(newNode.getName());
					if (attribs.size() != 0 && ! attribs.contains(ALL_ATTRIBS) && ! attribs.contains(attribReq)) {
						attribs.add(attribReq);
					}
					return newNode;
				} else {
					return null;
				}
				
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = trimJoinedFilter(it.next(),attribs);
					if (node != null) {
						newChildren.add(node);
					}
					
				}
				
				if (newChildren.size() == 0) {
					return null;
				} else if (newChildren.size() == 1) {
					FilterNode nallwaystrue = new FilterNode(FilterType.PRESENCE,"objectclass","*");
					newChildren.add(nallwaystrue);
					newNode = new FilterNode(root.getType(),newChildren);
					return newNode;
				} else {
					newNode = new FilterNode(root.getType(),newChildren);
					return newNode;
				}
				
				
			case NOT:
				FilterNode node = trimJoinedFilter(root.getNot(),attribs);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
		
	}

	private FilterNode trimPrimaryFilter(FilterNode root,ArrayList<Attribute> attribs) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if ((root.getName().toLowerCase().equals("objectclass") && ! this.joinedOCs.contains(root.getValue().toLowerCase())) || ! this.joinedAttrbutes.contains(root.getName().toLowerCase())) {
					newNode = (FilterNode) root.clone();
					Attribute attribReq = new Attribute(newNode.getName());
					if (attribs.size() != 0 && ! attribs.contains(ALL_ATTRIBS) && ! attribs.contains(attribReq)) {
						attribs.add(attribReq);
					}
					return newNode;
				} else {
					return null;
				}
				
				
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = trimPrimaryFilter(it.next(),attribs);
					if (node != null) {
						newChildren.add(node);
					}
					
				}
				
				if (newChildren.size() == 0) {
					return null;
				} else if (newChildren.size() == 1) {
					FilterNode nallwaystrue = new FilterNode(FilterType.PRESENCE,"objectclass","*");
					newChildren.add(nallwaystrue);
					newNode = new FilterNode(root.getType(),newChildren);
					return newNode;
				} else {
					newNode = new FilterNode(root.getType(),newChildren);
					return newNode;
				}
				
				
			case NOT:
				FilterNode node = trimPrimaryFilter(root.getNot(),attribs);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		
		
		Stack<JoinData> stack = (Stack<JoinData>) chain.getRequest().get(this.stackKey);
		
		JoinData jd = stack.peek();
		
		FilterNode newJoinFilter = null;
		Int joinCount = new Int(0);
		Int joinAttribCount = new Int(0);
		try {
			
			newJoinFilter = createJoinFilter(this.joinFilter,entry.getEntry(),joinCount,joinAttribCount);
		} catch (CloneNotSupportedException e) {
			//not possible
		}
		
		boolean isPrimary = jd.joinType.equals(PRIMARY);
		//Filter originalFilter = (Filter) chain.getRequest().get(filterKey);
		Filter originalFilter = jd.joinFilter;
		if (newJoinFilter == null || (joinCount.getValue() != 0 && joinCount.getValue() == joinAttribCount.getValue()) ) {
			if (! isPrimary) {
				//TODO add way to skip entries
				entry.setReturnEntry(false);
				return;
				//there's no reason to continue down the chain
			} else {
				//its a primary entry, make sure it passes the original filter
				if (! originalFilter.getRoot().checkEntry(entry.getEntry())) {
					entry.setReturnEntry(false);
					
					return;
					//there's no reason to continue down the chain
				} else {
					//we're done
					entry.setDN(util.getLocalMappedDN(new DN(entry.getEntry().getDN()),this.explodedPrimaryNamespace,this.explodedLocalNameSpace));
					return;
				}
			}
		}
		
		ArrayList<FilterNode> joiningFilterConds = new ArrayList<FilterNode>();
		joiningFilterConds.add(newJoinFilter);
		
		if (isPrimary) {
			
			//joiningFilterConds.add(((Filter) chain.getRequest().get(joinedFilterKey)).getRoot());
			joiningFilterConds.add(jd.joinJoinedFilter.getRoot());
		} else {
			//joiningFilterConds.add(((Filter) chain.getRequest().get(primaryFilterKey)).getRoot());
			joiningFilterConds.add(jd.joinPrimaryFilter.getRoot());
		}
		
		FilterNode finalFilterNode = new FilterNode(FilterType.AND,joiningFilterConds);
		
		Filter finalFilter = new Filter(finalFilterNode);
			
		//DistinguishedName origBase = (DistinguishedName) chain.getRequest().get(baseKey);
		DistinguishedName origBase = jd.joinBase;
		//Int origScope = (Int) chain.getRequest().get(scopeKey);
		Int origScope = jd.joinScope;
		
		if (origScope.getValue() == 0) {
			origScope.setValue(2);
			Vector dns = origBase.getDN().getRDNs();
			if (dns.size() > 0) {
				dns.remove(0);
			}
			
			DN newdn = new DN();
			Enumeration enumer = dns.elements();
			while (enumer.hasMoreElements()) {
				newdn.addRDN((RDN)enumer.nextElement());
			}
			
			origBase.setDN(newdn);
		}
		
		DistinguishedName useBase;
		
		if (isPrimary) {
			//useBase = new DistinguishedName(this.util.getRemoteMappedDN(origBase.getDN(),this.explodedLocalNameSpace,this.explodedJoinedNamespace));
			useBase = new DistinguishedName(new DN(this.joinedNamespace.toString()));
		} else {
			useBase = new DistinguishedName(this.util.getRemoteMappedDN(origBase.getDN(),this.explodedLocalNameSpace,this.explodedPrimaryNamespace));
			
		}
		
		HashMap<DN,DistinguishedName> boundNameSpaces = (HashMap<DN, DistinguishedName>) chain.getSession().get(Joiner.BOUND_DNS + this.name);
		if (boundNameSpaces == null) {
			boundNameSpaces = new HashMap<DN,DistinguishedName>();
		}
		
		
		DistinguishedName dn = null;
		DistinguishedName bindDN = null;
		Int scopeToUse = new Int(0);
		if (isPrimary) {
			dn = boundNameSpaces.get(this.joinedNamespace);
			scopeToUse.setValue(2);
		} else {
			dn = boundNameSpaces.get(this.primaryNamespace);
			scopeToUse.setValue(origScope.getValue());
		}
		
		if (dn == null) {
			bindDN = new DistinguishedName("");
		} else {
			bindDN = new DistinguishedName(dn.toString());
		}
		
		
		
		SearchInterceptorChain searchChain = new SearchInterceptorChain(bindDN,chain.getBindPassword(),ns.getRouter().getGlobalChain().getLength(),ns.getRouter().getGlobalChain(),chain.getSession(),chain.getRequest(),ns.getRouter());
		Results res = new Results(new InsertChain(new Insert[0]),0);
		
		ArrayList<Attribute> attribsToUse;
		
		if (isPrimary) {
			//attribsToUse = (ArrayList<Attribute>) chain.getRequest().get(joinedAttribsKey);
			attribsToUse = jd.joinJoinAttribs;
		} else {
			//attribsToUse = (ArrayList<Attribute>) chain.getRequest().get(primaryAttribsKey);
			attribsToUse = jd.joinPrimaryAttribs;
		}
		searchChain.nextSearch(useBase,scopeToUse,finalFilter,attribsToUse,typesOnly,res,constraints);
		
		res.start();
		boolean first = true;
		
		if (isPrimary) {
			DN origPrimaryName = new DN(entry.getEntry().getDN());
			entry.setDN(util.getLocalMappedDN(new DN(entry.getEntry().getDN()),this.explodedPrimaryNamespace,this.explodedLocalNameSpace));
			entry.getEntry().getAttributeSet().add(new LDAPAttribute(Joiner.PRIMARY_DN,origPrimaryName.toString()));
			entry.getEntry().getAttributeSet().add(new LDAPAttribute(Joiner.PRIMARY_BASE,this.primaryNamespace.toString()));
		}
		
		while (res.hasMore()) {
			Entry jentry = res.next();
			if (! isPrimary) {
				
				LDAPEntry orig = entry.getEntry();
				DN origPrimaryName = new DN(jentry.getEntry().getDN());
				entry.setEntry(new LDAPEntry(util.getLocalMappedDN(new DN(jentry.getEntry().getDN()),this.explodedJoinedNamespace,this.explodedLocalNameSpace).toString(),jentry.getEntry().getAttributeSet()));
				jentry.setEntry(orig);
				entry.getEntry().getAttributeSet().add(new LDAPAttribute(Joiner.PRIMARY_DN,origPrimaryName.toString()));
				entry.getEntry().getAttributeSet().add(new LDAPAttribute(Joiner.PRIMARY_BASE,this.primaryNamespace.toString()));
				res.finish();
			} 
			
			 
			Iterator<String> it = this.joinedAttrbutes.iterator();
			while (it.hasNext()) {
				String name = it.next();
				LDAPAttribute attrib = jentry.getEntry().getAttribute(name);
				if (attrib != null) {
					LDAPAttribute currAttrib = entry.getEntry().getAttributeSet().getAttribute(name);
					
					if (currAttrib != null) {
						byte[][] vals = attrib.getByteValueArray();
						for (int i=0,m=vals.length;i<m;i++) {
							currAttrib.addValue(vals[i]);
						}
						
					} else {
						entry.getEntry().getAttributeSet().add(attrib);
					}
					
				}
			}
			
			LDAPAttribute attrib = entry.getEntry().getAttribute("joinedDNs");
			if (attrib == null) {
				attrib = new LDAPAttribute("joinedDNs");
				entry.getEntry().getAttributeSet().add(attrib);
			}
			attrib.addValue(jentry.getEntry().getDN());
			
			attrib = entry.getEntry().getAttribute("joinedBases");
			if (attrib == null) {
				attrib = new LDAPAttribute("joinedBases");
				entry.getEntry().getAttributeSet().add(attrib);
			}
			attrib.addValue(this.joinedNamespace.toString());
		}
		
		if (! originalFilter.getRoot().checkEntry(entry.getEntry())) {
			//filter doesn't match, lets ditch it
			entry.setReturnEntry(false);
		}
		
		
		
	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		Stack<JoinData> joinStack = (Stack<JoinData>) chain.getRequest().get(this.stackKey);
		if (joinStack != null && joinStack.size() > 0 ) {
			joinStack.pop();
		}

	}
	
	public FilterNode createJoinFilter(FilterNode joinFilter,LDAPEntry entry, Int joinCount, Int noAttribCount) throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (joinFilter.getType()) {
			case PRESENCE :
			case SUBSTR:
				newNode = (FilterNode) joinFilter.clone();
				return newNode;
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				String filterVal = joinFilter.getValue();
				if (filterVal.startsWith("ATTR.")) {
					joinCount.setValue(joinCount.getValue() + 1);
					String attribName = filterVal.substring(filterVal.indexOf('.') + 1);
					LDAPAttribute attrib = entry.getAttribute(attribName);
					if (attrib == null) {
						noAttribCount.setValue(noAttribCount.getValue() + 1);
						//return null;
						return new FilterNode(joinFilter.getType(),joinFilter.getName(),"DOESNOTEXIST");
					}
					
					String val = attrib.getStringValue();
					if (val == null) {
						noAttribCount.setValue(noAttribCount.getValue() + 1);
						return new FilterNode(joinFilter.getType(),joinFilter.getName(),"DOESNOTEXIST");
					}
					newNode = new FilterNode(joinFilter.getType(),joinFilter.getName(),val);
					
				} else {
					newNode = new FilterNode(joinFilter.getType(),joinFilter.getName(),joinFilter.getValue());
				}
				
				return newNode;
				
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = joinFilter.getChildren().iterator();
				while (it.hasNext()) {
					FilterNode node = createJoinFilter(it.next(),entry,joinCount,noAttribCount);
					if (node == null) {
						return null;
					}
					newChildren.add(node);
				}
				
				
				newNode = new FilterNode(joinFilter.getType(),newChildren);
				return newNode;
				
			case NOT:
				FilterNode node = createJoinFilter(joinFilter.getNot(),entry,joinCount,noAttribCount);
				if (node == null) {
					return null;
				}
				return new FilterNode(node);
		}
		
		return null;
	}
	
	public void getFilterAttributes(FilterNode root,ArrayList<Attribute> attribs)  {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
				
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				Attribute attrib = new Attribute(root.getName());
				if (! attribs.contains(attrib)) {
					attribs.add(attrib);
				}
				break;
				
			case AND:
			case OR:
				
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					getFilterAttributes(it.next(),attribs);
				}
				
				break;
				
			case NOT:
				getFilterAttributes(root.getNot(),attribs);
				break;
		}
		
		
	}
	
	
	private void unloadRequest(InterceptorChain chain) {
		chain.getRequest().remove(Joiner.MYVD_JOIN_JATTRIBS + name);
		chain.getRequest().remove(Joiner.MYVD_JOIN_PDN + name);
		chain.getRequest().remove(Joiner.MYVD_JOIN_JDN + name);
	}
	
	private void loadRequest(InterceptorChain chain, DistinguishedName userdn) throws LDAPException {
		SearchInterceptorChain nchain = chain.createSearchChain(chain.getPositionInChain(this));
		Results res = new Results(null,chain.getPositionInChain(this));
		ArrayList<net.sourceforge.myvd.types.Attribute> attribs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
		attribs.add(new Attribute("1.1"));
		nchain.nextSearch(userdn, new Int(0), Joiner.OBJ_CLASS_FILTER, attribs, new Bool(false), res, new LDAPSearchConstraints());
		
		res.start();
		if (! res.hasMore()) {
			res.finish();
			throw new LDAPException("Object not found",LDAPException.NO_SUCH_OBJECT,"");
		}
		
		LDAPEntry entry = res.next().getEntry();
		
		LDAPAttribute pdn = entry.getAttribute("primaryDN");
		chain.getRequest().put(Joiner.MYVD_JOIN_PDN + this.name, new DistinguishedName(pdn.getStringValue()));
		
		ArrayList<DistinguishedName> joinedDns = new ArrayList<DistinguishedName>();
		LDAPAttribute jdn = entry.getAttribute("joinedDns");
		
		String[] vals = jdn.getStringValueArray();
		for (int i=0;i<vals.length;i++) {
			joinedDns.add(new DistinguishedName(vals[i]));
		}
		
		chain.getRequest().put(Joiner.MYVD_JOIN_JDN + this.name, joinedDns);
		
		loadRequestADD(chain);
		
	}

	private void loadRequestADD(InterceptorChain chain) {
		chain.getRequest().put(Joiner.MYVD_JOIN_JATTRIBS + this.name, this.joinedAttrbutes.clone());
	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		
		
	}

	public String getStackKey() {
		return this.stackKey;
	}
}

