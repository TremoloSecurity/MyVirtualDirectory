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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;

public class AccessMgmt implements Insert {

	AccessMgr accessMgr;
	String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		accessMgr = new AccessMgr();
		int numAcis = Integer.parseInt(props.getProperty("numACIs","0"));
		
		try {
			for (int i=0;i<numAcis;i++) {
				accessMgr.addACI(new AccessControlItem(i,props.getProperty("aci." + i)));	
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private boolean isNotAllowed(AccessControlItem aci,boolean permision) {
		if (aci == null ||
				(aci.isGrant() && ! permision) ||
				(! aci.isGrant() && permision)
			   ) {
			return true;
		} else {
			return false;
		}
	}
	
	private void checkPermisions(AccessControlItem aci,boolean permision,String errMsg) throws LDAPException {
		if (this.isNotAllowed(aci,permision)) {
			throw new LDAPException(errMsg,LDAPException.INSUFFICIENT_ACCESS_RIGHTS,"");
		}
	}
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		DN dn = new DN(entry.getEntry().getDN());
		AccessControlItem aci = this.accessMgr.getApplicableACI(dn,null,'a',chain);
		
		this.checkPermisions(aci,aci == null ? false : aci.isCreate(),"Can not add entry");
		
		LDAPAttributeSet attribs = entry.getEntry().getAttributeSet();
		Iterator<LDAPAttribute> it = attribs.iterator();
		
		while (it.hasNext()) {
			LDAPAttribute attrib = it.next();
			aci = this.accessMgr.getApplicableACI(dn,attrib.getName(),'w',chain);
			this.checkPermisions(aci,aci.isWrite(),"Could not create attribute : " + attrib.getName());
		}
		
		chain.nextAdd(entry,constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn,pwd,constraints);
	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		AccessControlItem aci = this.accessMgr.getApplicableACI(dn.getDN(),attrib.getAttribute().getName(),'c',chain);
		this.checkPermisions(aci,aci == null ? false : aci.isCompare(),"Could not perform compare");
		
		chain.nextCompare(dn,attrib,constraints);

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		AccessControlItem aci = this.accessMgr.getApplicableACI(dn.getDN(),null,'d',chain);
		this.checkPermisions(aci,aci == null ? false : aci.isDelete(),"Could not perform delete");

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		//TODO figure this one out

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		AccessControlItem aci;
		Iterator<LDAPModification> it = mods.iterator();
		
		while (it.hasNext()) {
			LDAPModification mod = it.next();
			aci = this.accessMgr.getApplicableACI(dn.getDN(),mod.getAttribute().getName(),'w',chain);
			if (mod.getOp() == LDAPModification.ADD || mod.getOp() == LDAPModification.REPLACE) {
				this.checkPermisions(aci,aci == null ? false : aci.isWrite(),"Could not perform mod");
			} else {
				this.checkPermisions(aci,aci == null ? false : aci.isObliterate(),"Could not delete attrbute");
			}
		}
		
		chain.nextModify(dn,mods,constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		checkFilter(base.getDN(),filter.getRoot(),chain);
		
		chain.nextSearch(base,scope,filter,attributes,typesOnly,results,constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		AccessControlItem aci = this.accessMgr.getApplicableACI(dn.getDN(),null,'n',chain);
		this.checkPermisions(aci,aci == null ? false : aci.isRename(),"Could not perform rename");
		
		chain.nextRename(dn,newRdn,deleteOldRdn,constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		
		AccessControlItem aci = this.accessMgr.getApplicableACI(dn.getDN(),null,'n',chain);
		this.checkPermisions(aci,aci == null ? false : aci.isRename(),"Could not perform rename");
		
		chain.nextRename(dn,newRdn,newParentDN,deleteOldRdn,constraints);

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);
		
		AccessControlItem aci;
		DN dn = new DN(entry.getEntry().getDN());
		//first check view
		aci = this.accessMgr.getApplicableACI(dn,null,'v',chain);
		if (this.isNotAllowed(aci,aci == null ? false : aci.isView())) {
			entry.setReturnEntry(false);
		}
		
		LDAPAttributeSet attribs = entry.getEntry().getAttributeSet();
		Iterator<LDAPAttribute> it = attribs.iterator();
		while (it.hasNext()) {
			LDAPAttribute attr = it.next();
			aci = this.accessMgr.getApplicableACI(dn,attr.getName(),'r',chain);
			if (this.isNotAllowed(aci,aci == null ? false : aci.isRead())) {
				it.remove();
			}
		}
		
		

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);

	}
	
	public void checkFilter(DN base,FilterNode root,InterceptorChain chain) throws LDAPException  {
		AccessControlItem aci;
		
		
		switch (root.getType()) {
			case PRESENCE :
				aci = this.accessMgr.getApplicableACI(base,root.getName(),'p',chain);
				this.checkPermisions(aci,aci == null ? false : aci.isPresenceSearch(),"Could not perform presence search on " + root.getName());
				break;
				
			case SUBSTR:
				
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				aci = this.accessMgr.getApplicableACI(base,root.getName(),'s',chain);
				this.checkPermisions(aci,aci == null ? false : aci.isSearch(),"Could not perform search on " + root.getName());
				break;
				
			case AND:
			case OR:
				
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					checkFilter(base,it.next(),chain);
				}
				
				break;
				
			case NOT:
				checkFilter(base,root.getNot(),chain);
				break;
		}
		
		
	}

	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
