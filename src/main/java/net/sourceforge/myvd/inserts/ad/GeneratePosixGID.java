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
package net.sourceforge.myvd.inserts.ad;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;
import java.util.Stack;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

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

public class GeneratePosixGID implements Insert {

	static Logger logger = Logger.getLogger(GeneratePosixGID.class.getName());
	
	public static final String GEN_POSIX_GID = "GEN_POSIX_GID_";
	
	String stackKey;
	
	String name;
	String flag;
	String searchBase;
	
	String userIdAttrib;
	String groupIdAttrib;
	
	String userOc;
	String groupOc;
	
	LDAPAttribute userOcAttrib;
	LDAPAttribute groupOcAttrib;
	
	String userBase;
	String groupBase;

	
	NameSpace ns;
	int chainPos;
	
	String homeDirTemplate;
	String[] homeDirAttribs;
	
	String loginShell;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		if (attrib.getAttribute().getName().equalsIgnoreCase("gidnumber")) {
			String gidNumber = attrib.getAttribute().getName();
			
			
			Results results = retrieveObjectSID(chain, gidNumber);
			Attribute nattrib;
			
			if (results.hasMore()) {
				String primaryGroupID = retrievePrimaryGroupID(results);
				
				nattrib = new Attribute(new LDAPAttribute("primaryGroupID",primaryGroupID));
				
			}  else {
				nattrib = attrib;
			}
				
		
			
			while (results.hasMore()) {
				results.next();
			}
			
			chain.nextCompare(dn, nattrib, constraints);
			
			
		} else {
			chain.nextCompare(dn, attrib, constraints);
		}

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		
		this.stackKey = GEN_POSIX_GID + "stack" + name;
		
		this.flag = GEN_POSIX_GID + name;
		this.searchBase = nameSpace.getBase().getDN().toString();
		this.userIdAttrib = props.getProperty("userIdAttribute","uidNumber");
		this.groupIdAttrib = props.getProperty("groupIdAttribute","gidNumber");
		this.userOc = props.getProperty("userObjectClass","user");
		
		this.groupOc = props.getProperty("groupObjectClass","group");
		this.userBase = props.getProperty("userAddBase","");
		this.groupBase = props.getProperty("groupAddBase","");
		this.ns = nameSpace;
		this.chainPos = ns.getPositionInChain(this);
		
		this.homeDirTemplate = props.getProperty("homeDirTemplate");
		
		logger.info("template : " + this.homeDirTemplate);
		ArrayList<String> attribNames = new ArrayList<String>();
		
		int indexBegin = homeDirTemplate.indexOf('@');
		while (indexBegin > -1) {
			int indexEnd = homeDirTemplate.indexOf('@',indexBegin + 1);
			attribNames.add(homeDirTemplate.substring(indexBegin + 1,indexEnd));
			logger.info("attrib : " + homeDirTemplate.substring(indexBegin + 1,indexEnd));
			indexBegin = homeDirTemplate.indexOf('@',indexEnd + 1);
		}
		
		this.homeDirAttribs = new String[attribNames.size()];
		attribNames.toArray(this.homeDirAttribs);
		
		this.loginShell = props.getProperty("loginShell");

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	public String getName() {
		return this.name;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		Stack<GPDData> stack = (Stack<GPDData>) chain.getRequest().get(this.stackKey);
		if (stack.size() > 0) {
			stack.pop();
		}
		
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);
		
		

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		Stack<GPDData> stack = (Stack<GPDData>) chain.getRequest().get(this.stackKey);
		GPDData data = stack.peek();
		
		
		LDAPAttribute oc = entry.getEntry().getAttribute("objectclass");
		
		
		
		Enumeration<String> enumer = oc.getStringValues();
		
		boolean isUser = false;
		boolean isGroup = false;
		boolean joinedUserOcFound = false;
		boolean joinedGroupOcFound = false;
		
		while (enumer.hasMoreElements()) {
			String objectClass =  enumer.nextElement();
			
			if (objectClass.equalsIgnoreCase("user")) {
				isUser = true;
			} else if (objectClass.equalsIgnoreCase("posixAccount")) {
				joinedUserOcFound = true;
			} else if (objectClass.equalsIgnoreCase("group")) {
				isGroup = true;
			} else if (objectClass.equalsIgnoreCase("posixGroup")) {
				joinedGroupOcFound = true;
			}
			
			
		}
		
		if (isUser && ! joinedUserOcFound) {
			generatePosixUser(chain, entry, attributes, typesOnly, constraints);
			
		} else if (isGroup && ! joinedGroupOcFound) {
			String addBase = "objectguid=" + entry.getEntry().getAttribute("objectguid").getStringValue() + "," + this.groupBase;
			LDAPAttributeSet attribs = new LDAPAttributeSet();
			attribs.add(new LDAPAttribute("objectClass","posixGroup"));
			attribs.add(new LDAPAttribute("objectguid",entry.getEntry().getAttribute("objectguid").getStringValue()));
			chain.createAddChain().nextAdd(new Entry(new LDAPEntry(addBase,attribs)), constraints);
			
			Results res = new Results(this.ns.getChain(),this.chainPos);
			SearchInterceptorChain schain = chain.createSearchChain(this.chainPos);
			schain.nextSearch(new DistinguishedName(entry.getEntry().getDN()), new Int(0), new Filter("(objectClass=*)"), attributes, typesOnly, res, constraints);
			
			
			res.start();
			if (! res.hasMore()) {
				throw new LDAPException("Entry : " + entry.getEntry().getDN() + " does not exist",LDAPException.OPERATIONS_ERROR,"Operations Error");
			}
			
			entry.getEntry().getAttributeSet().clear();
			entry.getEntry().getAttributeSet().addAll(res.next().getEntry().getAttributeSet());
			
			while (res.hasMore()) {
				res.next();
			}
			
			//res.finish();
		}
		
		
		if (data.flag) {
			LDAPAttribute objectSid = entry.getEntry().getAttribute("objectsid");
			LDAPAttribute primaryGroupId = entry.getEntry().getAttribute("primarygroupid");
			
			if (objectSid != null && primaryGroupId != null) {
				String groupSID = objectSid.getStringValue().substring(0,objectSid.getStringValue().lastIndexOf('-') + 1) + primaryGroupId.getStringValue();
				
				Results results = new Results(null,chain.getPositionInChain(this) );
				SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) );
				
				ArrayList<Attribute> searchAttribs = new ArrayList<Attribute>();
				searchAttribs.add(new Attribute("gidnumber"));
				schain.nextSearch(new DistinguishedName(this.searchBase), new Int(2), new Filter("(objectSid=" + groupSID + ")"), searchAttribs, new Bool(false), results, new LDAPSearchConstraints());
				
				results.start();
				
				if (results.hasMore()) {
					Entry res = results.next();
					if (res.getEntry().getAttributeSet().getAttribute("gidnumber") != null) {
						entry.getEntry().getAttributeSet().add(new LDAPAttribute("gidnumber",res.getEntry().getAttribute("gidnumber").getStringValue()));
					}
					
				}
				
				while (results.hasMore()) {
					results.next();
				}
			}
		}

	}

	private void generatePosixUser(PostSearchEntryInterceptorChain chain,
			Entry entry, ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		String addBase = "objectguid=" + entry.getEntry().getAttribute("objectguid").getStringValue() + "," + this.userBase;
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		attribs.add(new LDAPAttribute("objectClass","posixAccount"));
		attribs.add(new LDAPAttribute("objectguid",entry.getEntry().getAttribute("objectguid").getStringValue()));
		attribs.add(new LDAPAttribute("loginShell",this.loginShell));
		
		
		
		ArrayList<Attribute> homeDirAttribs = new ArrayList<Attribute>();
		for (int i=0;i<this.homeDirAttribs.length;i++) {
			
			homeDirAttribs.add(new Attribute(this.homeDirAttribs[i]));
		}
		
		Results res = new Results(this.ns.getChain(),this.chainPos + 1);
		SearchInterceptorChain schain = chain.createSearchChain(this.chainPos + 1);
		schain.nextSearch(new DistinguishedName(entry.getEntry().getDN()), new Int(0), new Filter("(objectClass=*)"), homeDirAttribs, typesOnly, res, constraints);
		
		res.start();
		if (! res.hasMore()) {
			throw new LDAPException("Entry : " + entry.getEntry().getDN() + " does not exist",LDAPException.OPERATIONS_ERROR,"Operations Error");
		}
		
		Entry resEntry = res.next();
		
		String homeDir = this.homeDirTemplate;
		for (int i=0;i<this.homeDirAttribs.length;i++) {
			LDAPAttribute attrib = resEntry.getEntry().getAttributeSet().getAttribute(this.homeDirAttribs[i]); 
			if (attrib == null) {
				logger.warn("User " + entry.getEntry().getDN() + " does not have the attribute " + this.homeDirAttribs[i]);
				homeDir = homeDir.replaceAll("@" + this.homeDirAttribs[i] + "@", "unknown");
			} else {
				String attribName = "@" + this.homeDirAttribs[i] + "@";
				String attribVal = attrib.getStringValue();
				attribVal = attribVal.replace("$", "\\$");
				
				homeDir = homeDir.replaceAll(attribName, attribVal);
				
			}
		}
		
		while (res.hasMore()) {
			res.next();
		}
		
		res.finish();
		
		
		attribs.add(new LDAPAttribute("homeDirectory",homeDir));
		
		
		
		
		chain.createAddChain().nextAdd(new Entry(new LDAPEntry(addBase,attribs)), constraints);
		
		res = new Results(this.ns.getChain(),this.chainPos);
		schain = chain.createSearchChain(this.chainPos);
		schain.nextSearch(new DistinguishedName(entry.getEntry().getDN()), new Int(0), new Filter("(objectClass=*)"), attributes, typesOnly, res, constraints);
		
		
		res.start();
		if (! res.hasMore()) {
			throw new LDAPException("Entry : " + entry.getEntry().getDN() + " does not exist",LDAPException.OPERATIONS_ERROR,"Operations Error");
		}
		
		entry.getEntry().getAttributeSet().clear();
		entry.getEntry().getAttributeSet().addAll(res.next().getEntry().getAttributeSet());
		
		while (res.hasMore()) {
			res.next();
		}
		
		res.finish();
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

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		boolean addAttribs = false;
		boolean objectSidPresent = false;
		boolean primaryGroupIDPresent = false;
		boolean getGid = false;
		boolean addOC = true;
		boolean addIdAttrib = true;
		boolean addObjectGuid = true;
		
		
		Stack<GPDData> stack = (Stack<GPDData>) chain.getRequest().get(this.stackKey);
		if (stack == null) {
			stack = new Stack<GPDData>();
			chain.getRequest().put(this.stackKey, stack);
		}
		
		GPDData data = new GPDData();
		stack.push(data);
		data.flag = false;
		
		if (attributes.size() == 0) {
			getGid = true;
			addOC = false;
			addIdAttrib = false;
			addObjectGuid = false;
		}
		
		Iterator<Attribute> it = attributes.iterator();
		while (it.hasNext()) {
			Attribute attrib = it.next();
			if (attrib.getAttribute().getName().equalsIgnoreCase("gidnumber") || attrib.getAttribute().getName().equalsIgnoreCase("*")) {
				addAttribs = true;
				getGid = true;
				if (attrib.getAttribute().getName().equals("*")) {
					objectSidPresent = true;
					primaryGroupIDPresent = true;
				}
			} else if (attrib.getAttribute().getName().equalsIgnoreCase("objectsid")) {
				objectSidPresent = true;
			} else if (attrib.getAttribute().getName().equalsIgnoreCase("primarygroupid")) {
				primaryGroupIDPresent = true;
			} else if (attrib.getAttribute().getName().equalsIgnoreCase("objectclass") || attrib.getAttribute().getName().equalsIgnoreCase("*")) {
				addOC = false;
			} else if (attrib.getAttribute().getName().equalsIgnoreCase(this.userIdAttrib) || attrib.getAttribute().getName().equalsIgnoreCase(this.groupIdAttrib) || attrib.getAttribute().getName().equalsIgnoreCase("*")) {
				addIdAttrib = false;
			} else if (attrib.getAttribute().getName().equalsIgnoreCase("objectguid") || attrib.getAttribute().getName().equalsIgnoreCase(this.groupIdAttrib) || attrib.getAttribute().getName().equalsIgnoreCase("*")) {
				addObjectGuid = false;
			}
			
					
		}
		
		if (addAttribs) {
			if (! objectSidPresent) {
				attributes.add(new Attribute("objectSID"));
			}
			
			if (! primaryGroupIDPresent) {
				attributes.add(new Attribute("primaryGroupID"));
			}
		}
		
		if (getGid) {
			data.flag = true;
		}
		
		if (addOC) {
			attributes.add(new Attribute("objectClass"));
		}
		
		if (addIdAttrib) {
			attributes.add(new Attribute(this.userIdAttrib));
			attributes.add(new Attribute(this.groupIdAttrib));
		}
		
		if (addObjectGuid) {
			attributes.add(new Attribute("objectguid"));
		}
		
		Filter nfilter = new Filter(filter.getRoot().toString());
		this.setPrimaryGroupID(nfilter.getRoot(), chain);
		
		
		chain.nextSearch(base, scope, nfilter, attributes, typesOnly, results, constraints);

	}

	public void setPrimaryGroupID(FilterNode root,SearchInterceptorChain chain) throws LDAPException  {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
				if (root.getName().equalsIgnoreCase("gidnumber")) {
					root.setName("primaryGroupID");
				}
				break;
			case SUBSTR:
				
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if (root.getName().equalsIgnoreCase("gidnumber")) {
					String gidNumber = root.getValue();
					
					
					Results results = retrieveObjectSID(chain, gidNumber);
					
					if (results.hasMore()) {
						
						
						
						String primaryGroupID = retrievePrimaryGroupID(results);
						
						
						FilterNode node1 = new FilterNode(root.getType(),root.getName(),root.getValue());
						FilterNode node2 = new FilterNode(root.getType(),"primaryGroupID",primaryGroupID);
						
						ArrayList<FilterNode> nor = new ArrayList<FilterNode>();
						nor.add(node1);
						nor.add(node2);
						
						root.setType(FilterType.OR);
						root.setChildren(nor);
						
						
					}
					
					while (results.hasMore()) {
						results.next();
					}
					
					
					
				}
				break;
				
			case AND:
			case OR:
				
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					setPrimaryGroupID(it.next(),chain);
				}
				
				break;
				
			case NOT:
				setPrimaryGroupID(root.getNot(),chain);
				break;
		}
		
		
	}

	private String retrievePrimaryGroupID(Results results) throws LDAPException {
		Entry res = results.next();
		if (res.getEntry().getAttribute("objectsid") != null) {
			String objectsid = res.getEntry().getAttribute("objectsid").getStringValue();
			String primaryGroupID = objectsid.substring(objectsid.lastIndexOf('-') + 1);
			return primaryGroupID;
		} else {
			return "none";
		}
	}

	private Results retrieveObjectSID(InterceptorChain chain,
			String gidNumber) throws LDAPException {
		Results results = new Results(null,chain.getPositionInChain(this) + 1);
		SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
		
		ArrayList<Attribute> searchAttribs = new ArrayList<Attribute>();
		searchAttribs.add(new Attribute("objectSID"));
		schain.nextSearch(new DistinguishedName(this.searchBase), new Int(2), new Filter("(gidnumber=" + gidNumber + ")"), searchAttribs, new Bool(false), results, new LDAPSearchConstraints());
		
		results.start();
		return results;
	}
	
	public void shutdown() {
		

	}

}

class GPDData {
	boolean flag;
}