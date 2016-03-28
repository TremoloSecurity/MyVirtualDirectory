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
import java.util.StringTokenizer;

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
import net.sourceforge.myvd.util.IteratorEntrySet;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

public class RootDSE implements Insert {

	
	LDAPAttribute supportedFeatures;
	LDAPAttribute namingContexts;
	LDAPAttribute supportedControls;
	LDAPAttribute supportedSaslMechs;
	LDAPAttribute supportedExtension;
	LDAPAttribute subSchemaSubEntry;
	LDAPAttribute supportedLDAPVersions;
	
	String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		
		this.supportedFeatures = new LDAPAttribute("supportedFeatures");
		loadProps(props,this.supportedFeatures,"supportedFeatures",",");
		if (this.supportedFeatures.size() == 0) {
			this.supportedFeatures = null;
		}
		
		this.namingContexts = new LDAPAttribute("namingContexts");
		this.loadProps(props,namingContexts,"namingContexts","|");
		if (this.namingContexts.size() == 0) {
			this.namingContexts = null;
		}
		
		
		this.supportedControls = new LDAPAttribute("supportedControls");
		this.loadProps(props,this.supportedControls,"supportedControls",",");
		if (this.supportedControls.size() == 0) {
			this.supportedControls = null;
		}
		
		
		this.supportedSaslMechs = new LDAPAttribute("supportedSaslMechanisms");
		this.loadProps(props,this.supportedSaslMechs,"supportedSaslMechanisms",",");
		if (this.supportedSaslMechs.size() == 0) {
			this.supportedSaslMechs = null;
		}
		
		this.supportedExtension = new LDAPAttribute("supportedExtension");
		this.loadProps(props,this.supportedExtension,"supportedExtension",",");
		if (this.supportedExtension.size() == 0) {
			this.supportedExtension = null;
		}
		
		this.subSchemaSubEntry = new LDAPAttribute("subSchemaSubEntry",props.getProperty("subSchemaSubEntry","cn=schema"));
		
		this.supportedLDAPVersions = new LDAPAttribute("supportedLDAPVersion");
		this.supportedLDAPVersions.addValue("2");
		this.supportedLDAPVersions.addValue("3");
		
		this.name = name;

	}

	private void loadProps(Properties props,LDAPAttribute repos, String attribName, String delim) {
		StringTokenizer toker;
		toker = new StringTokenizer(props.getProperty(attribName,""),delim);
		while (toker.hasMoreTokens()) {
			repos.addValue(toker.nextToken());
		}
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		if (scope.getValue() != 0) {
			throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");
		}
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		boolean allAttribs = attributes.size() == 0 || attributes.contains(new Attribute("*")) || attributes.contains(new Attribute("+"));
		
		if (supportedFeatures != null && (allAttribs || attributes.contains(new Attribute("supportedFeatures")))) {
			attribs.add(this.supportedFeatures);
		}
		
		if (namingContexts != null && (allAttribs || attributes.contains(new Attribute("namingContexts")))) {
			attribs.add(this.namingContexts);
		}
		
		if (supportedControls != null && (allAttribs || attributes.contains(new Attribute("supportedControls")))) {
			attribs.add(this.supportedControls);
		}
		
		if (supportedSaslMechs != null && (allAttribs || attributes.contains(new Attribute("supportedSASLMechanisms")))) {
			attribs.add(this.supportedSaslMechs);
		}
		
		if (supportedExtension != null && (allAttribs || attributes.contains(new Attribute("supportedExtensions")))) {
			attribs.add(this.supportedExtension);
		}
		
		if (supportedLDAPVersions != null && (allAttribs || attributes.contains(new Attribute("supportedLDAPVersion")))) {
			attribs.add(this.supportedLDAPVersions);
		}
		
		if (allAttribs || attributes.contains(new Attribute("subSchemaSubEntry"))) {
			attribs.add(this.subSchemaSubEntry);
		}
		
		LDAPEntry rootEntry = new LDAPEntry("",attribs);
		ArrayList<Entry> list = new ArrayList<Entry>();
		list.add(new Entry(rootEntry));
		
		chain.addResult(results,new IteratorEntrySet(list.iterator()),base,scope,filter,attributes,typesOnly,constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Root is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}
}
