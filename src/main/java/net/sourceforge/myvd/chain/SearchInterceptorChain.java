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
package net.sourceforge.myvd.chain;

import java.util.ArrayList;
import java.util.HashMap;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.EntrySet;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchConstraints;

public class SearchInterceptorChain extends InterceptorChain {
	
	
	
	public SearchInterceptorChain(DistinguishedName dn, Password pass,int startPos,InsertChain chain,HashMap<Object,Object> session,HashMap<Object,Object> request,Router router) {
		super(dn, pass,startPos,chain,session,request,router);
		// TODO Auto-generated constructor stub
	}

	public SearchInterceptorChain(DistinguishedName dn, Password pass,int startPos,InsertChain chain,HashMap<Object,Object> session,HashMap<Object,Object> request) {
		super(dn, pass,startPos,chain,session,request);
		// TODO Auto-generated constructor stub
	}

	public void addResult(Results results,EntrySet entrySet,DistinguishedName base,Int scope,Filter filter,ArrayList<Attribute> attributes,Bool typesOnly,LDAPSearchConstraints constraints) {
		results.addResult(this,entrySet,base,scope,filter,attributes,typesOnly,constraints,super.chain);
	}
	
	public void nextSearch(DistinguishedName base,Int scope,Filter filter,ArrayList<Attribute> attributes,Bool typesOnly,Results results,LDAPSearchConstraints constraints) throws LDAPException {
		Insert next = this.getNext();
		if (next != null) {
			next.search(this,base,scope,filter,attributes,typesOnly,results,constraints);
		} else {
			if (router != null) {
				router.search(this,base,scope,filter,attributes,typesOnly,results,constraints);
			}
		}
	}
}
