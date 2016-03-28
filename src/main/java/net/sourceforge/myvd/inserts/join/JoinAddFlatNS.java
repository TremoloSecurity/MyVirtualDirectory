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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Stack;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchCompleteInterceptorChain;
import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.inserts.jdbc.JdbcInsert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.NamingUtils;

public class JoinAddFlatNS implements Insert {

	static Logger logger = Logger.getLogger(JoinAddFlatNS.class);
	
	String name;
	String joinerName;
	
	String joinedObjectClass;
	
	HashSet<String> sharedAttributes;
	
	String[] joinerNamespaceDN;
	String[] primaryNamespaceDN;
	String[] joinedNamespaceDN;
	
	NameSpace ns;
	private Joiner insert;
	private boolean addToJoinedOnly;
	private String stackKey;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		Stack<JoinData> jd = (Stack<JoinData>) chain.getRequest().get(stackKey);
		
		HashSet<String> joinAttribs;
		
		if (jd != null) {
			joinAttribs = jd.peek().joinedAttribsSet;
		} else {
			joinAttribs = (HashSet) chain.getRequest().get(Joiner.MYVD_JOIN_JATTRIBS + this.joinerName);
		}
		LDAPAttributeSet primaryAttribs = new LDAPAttributeSet(),joinedAttribs = new LDAPAttributeSet();
		
		LDAPAttributeSet toadd = entry.getEntry().getAttributeSet();
		
		Iterator it = toadd.iterator();
		
		while (it.hasNext()) {
			LDAPAttribute attrib = (LDAPAttribute) it.next();
			if (! joinAttribs.contains(attrib.getName())) {
				primaryAttribs.add(attrib);
			} else {
				joinedAttribs.add(attrib);
			}
			
			if (attrib.getName().equalsIgnoreCase("objectclass")) {
				attrib.removeValue(joinedObjectClass);
			} else if (sharedAttributes.contains(attrib.getName().toLowerCase())) {
				primaryAttribs.add(attrib);
				joinedAttribs.add(attrib);
			}
			
			
		}
		
		LDAPAttribute oc = new LDAPAttribute("objectClass",joinedObjectClass);
		joinedAttribs.add(oc);
		
		NamingUtils nameutil = new NamingUtils();
		
		DN primaryDN = nameutil.getRemoteMappedDN(new DN(entry.getEntry().getDN()), joinerNamespaceDN, primaryNamespaceDN);
		
		DN joinedDN = nameutil.getRemoteMappedDN(new DN(entry.getEntry().getDN()), joinerNamespaceDN, joinedNamespaceDN);
		
		LDAPEntry primary = new LDAPEntry(primaryDN.toString(),primaryAttribs); 
		LDAPEntry joined  = new LDAPEntry(joinedDN.toString(),joinedAttribs);
		
		AddInterceptorChain nchain = null;
		
		//logger.info("Add to joined only? : " + this.addToJoinedOnly);
		
		if (! this.addToJoinedOnly){
			nchain = new AddInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,new InsertChain(new Insert[0]),chain.getSession(),chain.getRequest(),ns.getRouter());
			nchain.nextAdd(new Entry(primary), constraints);
		}
		
		nchain = new AddInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,new InsertChain(new Insert[0]),chain.getSession(),chain.getRequest(),ns.getRouter());
		nchain.nextAdd(new Entry(joined),constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.ns = nameSpace;
		this.joinerName = props.getProperty("joinerName");
		
		
		for (int i=0;i<nameSpace.getChain().getLength();i++) {
			if (nameSpace.getChain().getInsert(i).getName() != null && nameSpace.getChain().getInsert(i).getName().equals(this.joinerName)) {
				this.insert = (Joiner) nameSpace.getChain().getInsert(i);
				break;
			}
		}
		
		if (this.insert == null) {
			throw new LDAPException("Insert " + this.joinerName + " not found",LDAPException.OPERATIONS_ERROR,"");
		}
		
		this.joinerNamespaceDN = this.insert.explodedLocalNameSpace;
		
		this.primaryNamespaceDN = this.insert.explodedPrimaryNamespace;
		
		this.joinedNamespaceDN = this.insert.explodedJoinedNamespace;
		
		
		this.joinedObjectClass = props.getProperty("joinedObjectClass","NONE");
		
		String attribs = props.getProperty("sharedAttributes","");
		
		StringTokenizer toker = new StringTokenizer(attribs,",",false);
		
		this.sharedAttributes = new HashSet<String>();
		
		while (toker.hasMoreTokens()) {
			this.sharedAttributes.add(toker.nextToken().toLowerCase());
		}

		//logger.info("add to joined only prop? : " + props.getProperty("addToJoinedOnly","false"));
		this.addToJoinedOnly = props.getProperty("addToJoinedOnly","false").equalsIgnoreCase("true");
		this.stackKey = this.insert.getStackKey();
	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public String getName() {
		return this.name;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}
	
	private String combineArray(String[] ar) {
		String ret = "";
		
		for (int i=0;i<ar.length;i++) {
			ret += ret + ",";
		}
		
		return ret.substring(0,ret.lastIndexOf(','));
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
