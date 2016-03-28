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
package net.sourceforge.myvd.inserts.composite;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

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
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public abstract class CompositeInsert implements Insert {

	
	
	String name;
	
	
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
		
		chain.nextCompare(dn, attrib, constraints);

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		
		this.name = name;
		
		
		
		ArrayList<String> inserts = new ArrayList<String>();
		Properties localProps = new Properties();
		
		this.generateConfig(inserts, localProps,props,nameSpace);
		
		Iterator<String> it = inserts.iterator();
		
		
		int index = 0;
		
		
		Insert[] chain = new Insert[inserts.size()];
		
		String[] insertNames = new String[inserts.size()];
		HashMap<String,Properties> insertPropsMap = new HashMap<String,Properties>(); 
		
		while (it.hasNext()) {
			String insertName = it.next();
			
			
			Properties insertProps = new Properties();
			String className = localProps.getProperty(insertName + ".className");
			
			Iterator<Object> propsIt = localProps.keySet().iterator();
			
			while (propsIt.hasNext()) {
				String propName = (String) propsIt.next();
				if (propName.startsWith(insertName + ".config.")) {
					String propConfigName = propName.substring(propName.lastIndexOf('.') + 1);
					String propConfigVal = localProps.getProperty(propName);
					
					insertProps.put(propConfigName, propConfigVal);
				}
			}
			
			try {
				chain[index] = (Insert) Class.forName(className).newInstance();
			} catch (Exception e) {
				getLogger().error(e.toString(),e);
			}
			
			
			//chain[index].configure(insertName, insertProps, nameSpace);
			insertPropsMap.put(insertName, insertProps);
			insertNames[index] = insertName;
			index++;
			
		}
		
		nameSpace.getChain().insertIntoChain(chain,insertPropsMap,insertNames);
		
		/*this.chain[this.chain.length - 1] = new InsertEndPoint();
		this.chain[this.chain.length - 1].configure(name + "EndPoint", new Properties(), nameSpace);
		
		this.iep = (InsertEndPoint) this.chain[this.chain.length - 1];
		
		nameSpace.setChain(origChain);
		*/
		

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
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);
		

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);

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
		chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);

	}

	public void shutdown() {
		

	}
	
	/**
	 * Generates the configuration for the child inserts
	 * @param insertNames List of insert names in order
	 * @param props Properties in the same format as the configuration file.
	 */
	public abstract void generateConfig(ArrayList<String> insertNames, Properties props,Properties compositeProps,NameSpace ns);
	
	public abstract Logger getLogger();

}
