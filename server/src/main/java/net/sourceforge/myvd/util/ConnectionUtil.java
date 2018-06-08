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

package net.sourceforge.myvd.util;

import java.util.ArrayList;
import java.util.HashMap;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.types.SessionVariables;

public class ConnectionUtil {
	HashMap<Object,Object> session;
	HashMap<Object,Object> request;
	
	
	NameSpace ns;
	int pos;
	DistinguishedName bindDN;
	Password pass;
	
	public ConnectionUtil(NameSpace ns, int beginPos) {
		this.pos = beginPos;
		this.ns = ns;
		this.session = new HashMap<Object,Object>();
	}
	
	private void initRequest() {
		bindDN = (DistinguishedName) session.get("MYVD_BINDDN");
	    pass = (Password) session.get("MYVD_BINDPASS");
	    
	    if (bindDN == null) {
	    	bindDN = new DistinguishedName("");
	    	pass = new Password();
	    	
	    	
	    	
	    	session.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
	    	session.put("MYVD_BINDDN",new DistinguishedName(""));
	    	session.put("MYVD_BINDPASS",new Password());
	       
	    }
	}
	
	public void bind(DistinguishedName dn, Password pwd,LDAPConstraints constraints) throws LDAPException {
		
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		BindInterceptorChain bindChain;
		
		if (this.ns.isGlobal()) {
			bindChain = new BindInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
		} else {
			bindChain =  new BindInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request);
		}
		
		try {
			bindChain.nextBind(dn, pwd, constraints);
			this.bindDN = dn;
			this.pass = pass;
			session.put("MYVD_BINDDN", this.bindDN);
			session.put("MYVD_BINDPASS", this.pass);
		} catch (LDAPException e) {
			this.bindDN = new DistinguishedName("");;
			this.pass = new Password();
			session.put("MYVD_BINDDN", this.bindDN);
			session.put("MYVD_BINDPASS", this.pass);
			
			throw e;
		}
		
		
	}
	
	public void add(Entry entry,LDAPConstraints constraints) throws LDAPException {
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		AddInterceptorChain addChain;
		
		if (this.ns.isGlobal()) {
			addChain = new AddInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
		} else {
			addChain = new AddInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request);
		}
		
		addChain.nextAdd(entry, constraints);
	}
	
	public void compare(DistinguishedName dn,Attribute attrib,LDAPConstraints constraints) throws LDAPException {
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		CompareInterceptorChain compareChain;
		
		if (this.ns.isGlobal()) {
			compareChain = new CompareInterceptorChain(this.bindDN,this.pass,pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
		} else {
			compareChain = new CompareInterceptorChain(this.bindDN,this.pass,pos,this.ns.getChain(),this.session,this.request);
		}
		
		compareChain.nextCompare(dn, attrib, constraints);
		
	}
	
	public void modify(DistinguishedName dn,ArrayList<LDAPModification> mods,LDAPConstraints constraints) throws LDAPException {
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		ModifyInterceptorChain modifyChain;
		
		if (this.ns.isGlobal()) {
			modifyChain = new ModifyInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
		} else {
			modifyChain = new ModifyInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request);
		}
	}
	
	public void delete(DistinguishedName dn,LDAPConstraints constraints) throws LDAPException {
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		DeleteInterceptorChain deleteChain;
		
		if (this.ns.isGlobal()) {
			deleteChain = new DeleteInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
		} else {
			deleteChain = new DeleteInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request);
		}
		
		deleteChain.nextDelete(dn, constraints);
	}
	
	public void rename(DistinguishedName dn,DistinguishedName newRdn,Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		RenameInterceptorChain renameChain;
		
		if (this.ns.isGlobal()) {
			renameChain = new RenameInterceptorChain(this.bindDN,this.pass,pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
		} else {
			renameChain = new RenameInterceptorChain(this.bindDN,this.pass,pos,this.ns.getChain(),this.session,this.request);
		}
		
		renameChain.nextRename(dn, newRdn, deleteOldRdn, constraints);
	}
	
	public void nextRename(DistinguishedName dn,DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		RenameInterceptorChain renameChain;
		
		if (this.ns.isGlobal()) {
			renameChain = new RenameInterceptorChain(this.bindDN,this.pass,pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
		} else {
			renameChain = new RenameInterceptorChain(this.bindDN,this.pass,pos,this.ns.getChain(),this.session,this.request);
		}
		
		renameChain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);
	}
	
	public void extendedOperations(ExtendedOperation op,LDAPConstraints constraints) throws LDAPException {
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		ExetendedOperationInterceptorChain extChain;
		
		if (this.ns.isGlobal()) {
			extChain = new ExetendedOperationInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
		} else {
			extChain = new ExetendedOperationInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request);
		}
		
		extChain.nextExtendedOperations(op, constraints);
	}
	
	public Results  search(DistinguishedName base,Int scope,Filter filter,ArrayList<Attribute> attributes,Bool typesOnly,LDAPSearchConstraints constraints) throws LDAPException {
		this.initRequest();
		this.request = new HashMap<Object,Object>();
		
		SearchInterceptorChain searchChain;
		Results results;
		
		if (this.ns.isGlobal()) {
			searchChain = new SearchInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request,this.ns.getRouter());
			results = new Results(this.ns.getChain(),this.pos);
		} else {
			searchChain = new SearchInterceptorChain(this.bindDN,this.pass,this.pos,this.ns.getChain(),this.session,this.request);
			results = new Results(null,this.pos);
		}
		
		searchChain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);
		
		return results; 
	}
	
	
}
