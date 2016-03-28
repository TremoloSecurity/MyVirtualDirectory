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
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;



import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.apache.log4j.Priority;

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

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

public class DumpTransaction implements Insert {

	public static final String LOG_LEVEL = "logLevel";
	public static final String LABEL = "label";
	Priority logLevel;
	
	Logger logger;
	String label;
	String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.logger = Logger.getLogger(DumpTransaction.class);
		String tmpLogLevel = props.getProperty(LOG_LEVEL,"debug");
		tmpLogLevel = tmpLogLevel.toUpperCase();
		Class cls = Priority.class;
		try {
			this.logLevel = (Priority) cls.getField(tmpLogLevel).get(null);
		} catch (IllegalArgumentException e) {
			logger.error("Unable to configure DumpTransaction", e);
		} catch (SecurityException e) {
			logger.error("Unable to configure DumpTransaction", e);
		} catch (IllegalAccessException e) {
			logger.error("Unable to configure DumpTransaction", e);
		} catch (NoSuchFieldException e) {
			logger.error("Unable to configure DumpTransaction", e);
		}

		this.label = "[" + props.getProperty(DumpTransaction.LABEL,"Default") + "] ";
	}
	
	private void log(String val) {
		logger.log(logLevel, label + val);
	}
	
	private void log(String val,Throwable t) {
		logger.log(logLevel, label + val,t);
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		
		
		StringBuffer ldif = new StringBuffer();
		ldif.append("dn : ").append(entry.getEntry().getDN()).append('\n');
		Iterator it = entry.getEntry().getAttributeSet().iterator();
		while (it.hasNext()) {
			LDAPAttribute attrib = (LDAPAttribute) it.next();
			for (int i=0,m=attrib.size();i<m;i++) {
				ldif.append(attrib.getBaseName()).append(" : ").append(attrib.getStringValueArray()[i]).append('\n');
			}
		}
		
		log("Begin Add : \n" + ldif.toString());
		
		try {
			chain.nextAdd(entry,constraints);
		} catch (Throwable t) {
			log("Error Running Add",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Add Complete");
		}

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		log("Begin Bind : " + dn.getDN().toString());
		
		try {
			chain.nextBind(dn, pwd, constraints);
		} catch (Throwable t) {
			log("Error Running Bind",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Bind Complete");
		}

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		log("Begin Compare : [" + dn.getDN().toString() + "] " + attrib.getAttribute().getName() + "=" + attrib.getAttribute().getStringValue());
		
		try {
			chain.nextCompare(dn, attrib, constraints);
		} catch (Throwable t) {
			
			
			if (! (t instanceof LDAPException) && ((LDAPException) t).getResultCode() != LDAPException.COMPARE_FALSE) {
				log("Error Running Compare",t);
			}
			
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Compare Complete");
		}

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		log("Begin Delete : " + dn.getDN().toString());
		
		try {
			chain.nextDelete(dn, constraints);
		} catch (Throwable t) {
			log("Error Running Delete",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		}
		
		log("Delete Complete");

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		log("Begin Extended Operation : " + op.getDn().toString());
		
		try {
			chain.nextExtendedOperations(op, constraints);
		} catch (Throwable t) {
			log("Error Running Extended Operation",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Extended Operation Complete");
		}

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		StringBuffer buf = new StringBuffer();
		
		buf.append("dn: ").append(dn.getDN().toString()).append('\n');
		buf.append("changeType : modify\n");
		
		Iterator<LDAPModification> it = mods.iterator();
		while (it.hasNext()) {
			LDAPModification mod = it.next();
			
			switch (mod.getOp()) {
				case LDAPModification.ADD : buf.append("add: ").append(mod.getAttribute().getName()).append("\n"); break;
				case LDAPModification.REPLACE : buf.append("replace: ").append(mod.getAttribute().getName()).append("\n"); break;
				case LDAPModification.DELETE : buf.append("delete: ").append(mod.getAttribute().getName()).append("\n"); break;
			}
			
			Enumeration enumer = mod.getAttribute().getStringValues();
			
			while (enumer.hasMoreElements()) {
				buf.append(mod.getAttribute().getName()).append(": ").append(enumer.nextElement().toString()).append('\n');
			}
			
			buf.append("-\n");
			
		}
		
		log("Begin Modify \n" + buf.toString());
		
		try {
			chain.nextModify(dn, mods, constraints);
		} catch (Throwable t) {
			log("Error Running Modify",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Modify Complete");
		}

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		StringBuffer buf = new StringBuffer();
		Iterator<Attribute> it = attributes.iterator();
		while (it.hasNext()) {
			buf.append(it.next().getAttribute().getName()).append(' ');
		}
		
		log("Begin Seach - Filter=" + filter.getValue() + ";Base=" + base.toString() + ";Scope=" + scope.getValue() + ";Attributes=" + buf.toString());
		
		try {
			chain.nextSearch(base,scope,filter,attributes,typesOnly,results,constraints);
		} catch (Throwable t) {
			log("Error Running Search",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Seach submitted");
		}
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		log("Begin Rename - dn=" + dn.toString() + ";newRdn=" + newRdn.toString() + ";deleteOldRdn=" + deleteOldRdn.toString());
		try {
			chain.nextRename(dn, newRdn, deleteOldRdn, constraints);
		} catch (Throwable t) {
			log("Rename Error",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Rename Complete");
		}

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		log("Begin Rename - dn=" + dn.toString() + ";newRdn=" + newRdn.toString() + ";deleteOldRdn=" + deleteOldRdn.toString() + ";newParentDN=" + newParentDN.toString());
		
		try {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);
		} catch (Throwable t) {
			log("Rename Error",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Rename Complete");
		}

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		
		StringBuffer ldif = new StringBuffer();
		ldif.append("dn : ").append(entry.getEntry().getDN()).append('\n');
		Iterator it = entry.getEntry().getAttributeSet().iterator();
		while (it.hasNext()) {
			LDAPAttribute attrib = (LDAPAttribute) it.next();
			for (int i=0,m=attrib.size();i<m;i++) {
				ldif.append(attrib.getBaseName()).append(" : ").append(attrib.getStringValueArray()[i]).append('\n');
			}
		}
		ldif.append("myVdReturnEntry: " + entry.isReturnEntry());
		
		log("Begin Post Search Entry - Filter=" + filter.getValue() + ";Base=" + base.toString() + ";Scope=" + scope.getValue() + ";Attributes=" + attributes  + "\n" + ldif.toString());
		
		try {
			chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);
		} catch (Throwable t) {
			log("Post Search Entry Error",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
		
			ldif = new StringBuffer();
			ldif.append("dn : ").append(entry.getEntry().getDN()).append('\n');
			it = entry.getEntry().getAttributeSet().iterator();
			while (it.hasNext()) {
				LDAPAttribute attrib = (LDAPAttribute) it.next();
				for (int i=0,m=attrib.size();i<m;i++) {
					ldif.append(attrib.getBaseName()).append(" : ").append(attrib.getStringValueArray()[i]).append('\n');
				}
			}
			ldif.append("myVdReturnEntry: " + entry.isReturnEntry());
			
			log("Post Seach Entry Complete\n" + ldif.toString());
		}
	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		log("Begin Post Search Complete - Filter=" + filter.getValue() + ";Base=" + base.toString() + ";Scope=" + scope.getValue() + ";Attributes=" + attributes);
		
		try {
		chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);
		} catch (Throwable t) {
			log("Post Search Complete Error",t);
			if (t instanceof LDAPException) {
				throw ((LDAPException) t);
			} else {
				throw new RuntimeException(t);
			}
		} finally {
			log("Post Search Complete Complete");
		}

	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
