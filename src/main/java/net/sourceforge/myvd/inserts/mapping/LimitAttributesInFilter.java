/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package net.sourceforge.myvd.inserts.mapping;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

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

public class LimitAttributesInFilter implements Insert {
	
	static Logger logger = Logger.getLogger(LimitAttributesInFilter.class);
	
	HashSet<String> allowedAttributes;
	
	String name;

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		StringTokenizer toker = new StringTokenizer(props.getProperty("attributes"),",",false);
		this.allowedAttributes = new HashSet<String>();
		while (toker.hasMoreTokens()) {
			this.allowedAttributes.add(toker.nextToken().toLowerCase());
		}

	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn, Password pwd, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn, Attribute attrib,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);

	}

	@Override
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain chain, ExtendedOperation op,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	@Override
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn, ArrayList<LDAPModification> mods,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		Filter newFilter = new Filter(filter.getRoot().toString());
		
		
		
		if (this.cleanFilter(newFilter.getRoot())) {
			
			chain.getRequest().put("myvd.attributefilter.original." + this.name, filter);
			
			chain.nextSearch(base, scope, newFilter, attributes, typesOnly, results, constraints);
		} 
		
		
		

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn,
			DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(newParentDN, newRdn, deleteOldRdn, constraints);

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		
		
		
		
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		Filter originalFilter = (Filter) chain.getRequest().get("myvd.attributefilter.original." + this.name);
		
		if (originalFilter != null) {
			entry.setReturnEntry(originalFilter.getRoot().checkEntry(entry.getEntry()));
		}
		
		

	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
			throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);

	}

	@Override
	public void shutdown() {
		

	}
	
	
	private boolean cleanFilter(FilterNode root) {
        FilterType op;
        //filter.append('(');
        String comp = null;
        ArrayList<FilterNode> children;
        Iterator<FilterNode> filterIt;
        String attribName = null;
        
        boolean isFirst = true;
        
        
                op = root.getType();
                switch (op){
                    case AND:
                    case OR:
                    		ArrayList<FilterNode> toRemove = new ArrayList<FilterNode>();
                    	
                    		children = root.getChildren();
                    		for (FilterNode node : children) {
                    			if (! cleanFilter(node)) {
                    				toRemove.add(node);
                    			}
                    		}
                    		
                    		if (! toRemove.isEmpty()) {
                    			children.removeAll(toRemove);
                    		}
                    		
                    		return ! children.isEmpty();
                        
                        
                    		
                        
                        
                        
                    
                    		
                                                
                       
                        
                    case NOT:
                        
                    	return cleanFilter(root.getNot());
                        
                    case PRESENCE:
                    case GREATER_THEN:
                    case LESS_THEN:
                    case SUBSTR:
                    case EQUALS:{
                    		if (! this.allowedAttributes.contains(root.getName().toLowerCase())) {
                    			return false;
                    		} 
                        
                        
                        
                        break;
                    }
                    
                    
                    
                }
            
        
        
        return true;
        
        
    }

}
