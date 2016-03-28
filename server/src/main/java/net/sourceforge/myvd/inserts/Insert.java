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
package net.sourceforge.myvd.inserts;

import java.util.ArrayList;
import java.util.Properties;

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

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

public interface Insert {
	
	public String getName();
	
	/**
	 * Called to configure the current interceptor
	 * @param name
	 * @param props
	 * @throws LDAPException
	 */
	public void configure(String name,Properties props,NameSpace nameSpace) throws LDAPException;
	
	
	/**
	 * Performs the LDAP "add" operation
	 * @param entry The entry to be added
	 * @param constraints Any controls
	 * @throws LDAPException
	 */
	public void add(AddInterceptorChain chain,Entry entry,LDAPConstraints constraints) throws LDAPException;
	
	/**
	 * Performs the LDAP "bind" operation 
	 * @param chain The current chain
	 * @param dn The user's DN
	 * @param pwd The User's Password
	 * @param constraints Any Controls
	 * @throws LDAPException
	 */
	public void bind(BindInterceptorChain chain,DistinguishedName dn,Password pwd,LDAPConstraints constraints) throws LDAPException;
	
	/**
	 * Performs the LDAP "compare" operation
	 * @param chain The current chain
	 * @param dn The dn of the object to perform the compare on
	 * @param attrib The attribute which represents the name and value of the attribute being compared
	 * @param constraints Any controls
	 */
	public void compare(CompareInterceptorChain chain,DistinguishedName dn,Attribute attrib,LDAPConstraints constraints) throws LDAPException;
	
	/**
	 * Performs the LDAP "Delete" operation
	 * @param chain The current chain
	 * @param dn The object to be deleted 
	 * @param constraints Any controls
	 */
	public void delete(DeleteInterceptorChain chain,DistinguishedName dn,LDAPConstraints constraints) throws LDAPException;

	/**
	 * Performs and LDAP "extended operation"
	 * @param chain The current chain
	 * @param op The current Operation
	 * @param constraints Any Constrols
	 * @throws LDAPException
	 */
	public void extendedOperation(ExetendedOperationInterceptorChain chain,ExtendedOperation op,LDAPConstraints constraints) throws LDAPException;
	
	/**
	 * Performs the LDAP "modify" operation
	 * @param chain The current chain
	 * @param dn The object to be modified
	 * @param mods The modifications
	 * @param constraints Any controls
	 */
	public void modify(ModifyInterceptorChain chain,DistinguishedName dn,ArrayList<LDAPModification> mods,LDAPConstraints constraints) throws LDAPException;
	
	
	/**
	 * Performs the LDAP "search" operation
	 * @param chain The current chain
	 * @param base The search base
	 * @param scope The scope of the search
	 * @param filter The search filter
	 * @param attributes The attributes to return
	 * @param typesOnly Return only types
	 * @param results All results
	 * @param constraints Any controls
	 * @throws LDAPException
	 */
	public void search(SearchInterceptorChain chain,DistinguishedName base,Int scope,Filter filter,ArrayList<Attribute> attributes,Bool typesOnly,Results results,LDAPSearchConstraints constraints) throws LDAPException;
	
	public void rename(RenameInterceptorChain chain,DistinguishedName dn,DistinguishedName newRdn,Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException;
	
	public void rename(RenameInterceptorChain chain,DistinguishedName dn,DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException;
	
	public void postSearchEntry(PostSearchEntryInterceptorChain chain,Entry entry,DistinguishedName base,Int scope,Filter filter,ArrayList<Attribute> attributes,Bool typesOnly,LDAPSearchConstraints constraints) throws LDAPException;
	
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,DistinguishedName base,Int scope,Filter filter,ArrayList<Attribute> attributes,Bool typesOnly,LDAPSearchConstraints constraints) throws LDAPException;
	
	public void shutdown();
	
	
}
