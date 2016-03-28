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

package net.sourceforge.myvd.inserts.setrdn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

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

public class SetRDN implements Insert {
	
	static Logger logger = Logger.getLogger(SetRDN.class.getName());
	
	String name;
	String internalRDN;
	String externalRDN;
	
	String objectClass;
	
	
	HashMap<String,String> in2out, out2in;
	HashSet<String> toIgnore;
	
	ArrayList<String> dnAttributes;
	HashSet<String> dnAttrNames;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		
		
		entry.setEntry(new LDAPEntry(this.getInternalDN(new DN(entry.getEntry().getDN()),chain,entry.getEntry()).toString(),entry.getEntry().getAttributeSet()));
		chain.nextAdd(entry, constraints);
		
		

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		if (dn.getDN() == null || dn.getDN().getRDNs().size() == 0) {
			chain.nextBind(dn, pwd, constraints);
			
		} else {
			chain.nextBind(new DistinguishedName(this.getInternalDN(dn.getDN(), chain)), pwd, constraints);
		}

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(new DistinguishedName(this.getInternalDN(dn.getDN(), chain)), attrib, constraints);

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = nameSpace.getLabel();

		this.in2out = new HashMap<String,String>();
		this.out2in = new HashMap<String,String>();
		
		this.internalRDN = props.getProperty("internalRDN");
		this.externalRDN = props.getProperty("externalRDN");
		this.objectClass = props.getProperty("objectClass");
		
		if (this.objectClass == null) {
			this.objectClass = "inetOrgPerson";
		}
		
		this.toIgnore = new HashSet<String>();
		
		this.dnAttributes = new ArrayList<String>();
		this.dnAttrNames = new HashSet<String>();
		String dnAttrs = props.getProperty("dnattributes");
		if (dnAttrs != null) {
			StringTokenizer toker = new StringTokenizer(dnAttrs,",",false);
			while (toker.hasMoreTokens()) {
				String attrName = toker.nextToken();
				this.dnAttributes.add(attrName);
				this.dnAttrNames.add(attrName.toLowerCase());
			}
		}
	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(new DistinguishedName(this.getInternalDN(dn.getDN(), chain)), constraints);

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
		chain.nextModify(new DistinguishedName(this.getInternalDN(dn.getDN(), chain)), mods, constraints);

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

		this.setExternalDN(entry);
		this.mapAttributes(entry.getEntry(), chain);
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		//chain.nextRename(dn, newRdn, deleteOldRdn, constraints);
		
		ModifyInterceptorChain mod = chain.createModifyChain(chain.getPositionInChain(this));
		ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
		RDN rdn = (RDN) newRdn.getDN().getRDNs().get(0);
		
		mods.add(new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute(rdn.getType(),rdn.getValue())));
		
		mod.nextModify(new DistinguishedName(this.getInternalDN(dn.getDN(), chain)), mods, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		
		ModifyInterceptorChain mod = chain.createModifyChain(chain.getPositionInChain(this));
		ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
		RDN rdn = (RDN) newRdn.getDN().getRDNs().get(0);
		
		mods.add(new LDAPModification(LDAPModification.REPLACE,new LDAPAttribute(rdn.getType(),rdn.getValue())));
		
		DistinguishedName ndn = new DistinguishedName(this.getInternalDN(dn.getDN(), chain));
		
		mod.nextModify(ndn, mods, constraints);
		
		chain.nextRename(ndn, newRdn, deleteOldRdn, constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		Filter newFilter = new Filter(filter.getRoot().toString());
		mapFilter(newFilter.getRoot(),chain);
		
		DN internalBase = this.getInternalDN(base.getDN(), chain);
		ArrayList<Attribute> attribs = this.createNewAttribs(attributes);
		chain.nextSearch(new DistinguishedName(internalBase), scope, newFilter, attribs, typesOnly, results, constraints);

	}
	
	private void mapFilter(FilterNode node,InterceptorChain chain) throws LDAPException {
		switch (node.getType()) {
			case EQUALS :
			case GREATER_THEN:
			case LESS_THEN:
				if (this.dnAttrNames.contains(node.getName().toLowerCase())) {
					String externalDN = node.getValue();
					String internalDN = this.getInternalAttrDN(externalDN, chain);
					node.setValue(internalDN);
				}
				break;
			case PRESENCE:
			case SUBSTR:
				//do nothing
				break;
			case AND:
			case OR:
				for (FilterNode child : node.getChildren()) {
					mapFilter(child,chain);
				}
				break;
			case NOT: mapFilter(node.getNot(),chain);
			
		}
	}
	
	private void setExternalDN(Entry entry) {
		
		/*if (this.toIgnore.contains(entry.getEntry().getDN())) {
			//we know to ignore
			return;
		}*/
		
		boolean ocFound = false;
		if (entry.getEntry().getAttribute("OBJECTCLASS") != null) {
			for (String oc : entry.getEntry().getAttribute("OBJECTCLASS").getStringValueArray()) {
				if (oc.equalsIgnoreCase(this.objectClass)) {
					ocFound = true;
					break;
				}
			}
		}
		
		if (! ocFound) {
			this.toIgnore.add(entry.getEntry().getDN());
			return;
		}
		
		
		DN dn = new DN(entry.getEntry().getDN());
		Vector<RDN> rdns = dn.getRDNs();
		if (rdns.size() == 0 || ! rdns.get(0).getType().equalsIgnoreCase(this.internalRDN)) {
			return;
		}
		
		String dnlower = entry.getEntry().getDN().toLowerCase();
		String strdn = null;//this.in2out.get(dnlower);
		
		if (strdn != null) {
			entry.setEntry(new LDAPEntry(strdn,entry.getEntry().getAttributeSet()));
			return;
		}
		
		if ( entry.getEntry().getAttributeSet().getAttribute(this.externalRDN) == null) {
			return;
		}
		
		String val = entry.getEntry().getAttributeSet().getAttribute(this.externalRDN).getStringValue();
		DN newdn = new DN();
		RDN rdn = new RDN();
		rdn.add(this.externalRDN, val, val);
		newdn.addRDN(rdn);
		
		for (int i=1,m=rdns.size();i<m;i++) {
			newdn.addRDNToBack(rdns.elementAt(i));
		}
		
		this.in2out.put(dnlower, newdn.toString());
		
		entry.setEntry(new LDAPEntry(newdn.toString(),entry.getEntry().getAttributeSet()));
		
		
		
		
	}
	
	private void mapAttributes(LDAPEntry entry,PostSearchEntryInterceptorChain chain) throws LDAPException {
		for (String attrName : this.dnAttributes) {
			LDAPAttribute attr = entry.getAttribute(attrName);
			
			
			if (attr != null) {
				ArrayList<String> vals = new ArrayList<String>();
				ArrayList<String> origVals = new ArrayList<String>();
				
				for (String val : attr.getStringValueArray()) {
					String nval = this.getExternalAttrDN(val, chain);
					vals.add(nval);
					origVals.add(val);
				}
				
				for (String val : origVals) {
					attr.removeValue(val);
				}
				
				for (String val : vals) {
					attr.addValue(val);
				}
				
			}
		}
	}
	
	private DN getInternalDN(DN externalDN,InterceptorChain chain) throws LDAPException {
		DN dn = this.getInternalDN(externalDN, chain,null);
		if (dn != null) {
			return dn;
		} else {
			return new DN(externalDN.toString());
		}
	}
	
	
	private String getExternalAttrDN(String internalDN,InterceptorChain chain) throws LDAPException {
		/*if (this.toIgnore.contains(internalDN)) {
			return internalDN;
		}*/
		
		String externalDN = null;//this.in2out.get(internalDN.toLowerCase());
		if (externalDN != null) {
			return externalDN;
		}
		
		
		DN internalDNdn = new DN(internalDN);
		Vector rdns = internalDNdn.getRDNs();
		DN base = new DN();
		for (int i=1;i<rdns.size();i++) {
			base.addRDNToBack((RDN) rdns.get(i));
		}
		
		String internalRDNVal = ((RDN) rdns.get(0)).getValue();
		String internalRDNName = ((RDN) rdns.get(0)).getType();
		
		ArrayList<Attribute> attributes = new ArrayList<Attribute>();
		attributes.add(new Attribute(this.externalRDN));
		attributes.add(new Attribute(this.objectClass));
		
		StringBuffer b = new StringBuffer();
		b.append("(&(objectClass=").append(this.objectClass).append(")(").append(internalRDNName).append('=').append(internalRDNVal).append("))");
		//b.append('(').append(this.externalRDN).append('=').append(externalRDNs.get(0).getValue()).append(')');
		Filter filter = new Filter(b.toString());
		
		
		Results results = new Results(null,chain.getPositionInChain(this) + 1);
		SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
		
		
		logger.info("Base : '" + base + "'" );
		
		schain.nextSearch(new DistinguishedName(base), new Int(1), filter, attributes, new Bool(false), results, new LDAPSearchConstraints());
		
		results.start();
		
		
		Entry entry = null;
		
		if (results.hasMore()) {
			entry = results.next();
		} else {
			results.finish();
			//Assume this isn't the correct obectClass
			this.toIgnore.add(internalDN.toString());
			return internalDN;
		}
		
		String val = entry.getEntry().getAttribute(this.externalRDN).getStringValue();
		
		DN newExternal = new DN();
		b.setLength(0);
		b.append(this.externalRDN).append('=').append(val);
		RDN rdn = new RDN(b.toString());
		
		newExternal.addRDN(rdn);
		
		for (int i=1;i<rdns.size();i++) {
			newExternal.addRDNToBack((RDN) rdns.get(i));
		}
		
		this.in2out.put(internalDN.toLowerCase() , newExternal.toString().toLowerCase());
		return newExternal.toString();
		
	}
	
	private String getInternalAttrDN(String externalDN,InterceptorChain chain) throws LDAPException {
		/*if (this.toIgnore.contains(externalDN)) {
			return externalDN;
		}*/
		
		String internalDN = null;//this.out2in.get(externalDN.toLowerCase());
		if (internalDN != null) {
			return internalDN;
		}
		
		
		DN externalDNdn = new DN(externalDN);
		Vector rdns = externalDNdn.getRDNs();
		DN base = new DN();
		for (int i=1;i<rdns.size();i++) {
			base.addRDNToBack((RDN) rdns.get(i));
		}
		
		String externalRDNVal = ((RDN) rdns.get(0)).getValue();
		String externalRDNName = ((RDN) rdns.get(0)).getType();
		
		ArrayList<Attribute> attributes = new ArrayList<Attribute>();
		attributes.add(new Attribute(this.internalRDN));
		attributes.add(new Attribute(this.objectClass));
		
		StringBuffer b = new StringBuffer();
		b.append("(&(objectClass=").append(this.objectClass).append(")(").append(externalRDNName).append('=').append(externalRDNVal).append("))");
		//b.append('(').append(this.externalRDN).append('=').append(externalRDNs.get(0).getValue()).append(')');
		Filter filter = new Filter(b.toString());
		
		
		Results results = new Results(null,chain.getPositionInChain(this) + 1);
		SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
		
		schain.nextSearch(new DistinguishedName(base), new Int(1), filter, attributes, new Bool(false), results, new LDAPSearchConstraints());
		
		results.start();
		
		
		Entry entry = null;
		
		if (results.hasMore()) {
			entry = results.next();
		} else {
			results.finish();
			//Assume this isn't the correct obectClass
			this.toIgnore.add(externalDN.toString());
			return externalDN;
		}
		
		String val = entry.getEntry().getAttribute(this.internalRDN).getStringValue();
		
		DN newInternal = new DN();
		b.setLength(0);
		b.append(this.internalRDN).append('=').append(val);
		RDN rdn = new RDN(b.toString());
		
		newInternal.addRDN(rdn);
		
		for (int i=1;i<rdns.size();i++) {
			newInternal.addRDNToBack((RDN) rdns.get(i));
		}
		
		this.out2in.put(externalDN.toLowerCase() , newInternal.toString().toLowerCase());
		return newInternal.toString();
		
	}
	
	private DN getInternalDN(DN externalDN,InterceptorChain chain,LDAPEntry toadd) throws LDAPException {
		Vector<RDN> externalRDNs =  externalDN.getRDNs();
		
		//first see if we can ignore
		/*if (this.toIgnore.contains(externalDN.toString())) {
			return externalDN;
		}*/
		
		//check to make sure we need to do the mapping
		if (externalRDNs.size() == 0 || ! externalRDNs.get(0).getType().equalsIgnoreCase(this.externalRDN)) {
			return externalDN;
		}
		
		
		//check to see if we have it cached
		String dnstr = null;//this.out2in.get(externalDN.toString().toLowerCase());
		
		if (dnstr != null) {
			return new DN(dnstr);
		}
		
		//we need to retrieve the attribute via a search
		Results results = new Results(null,chain.getPositionInChain(this) + 1);
		SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
		DN base = new DN();
		for (int i=1,m=externalRDNs.size();i<m;i++) {
			base.addRDNToBack(externalRDNs.get(i));
		}
		
		String val = "";
		
		if (toadd == null) {
			ArrayList<Attribute> attributes = new ArrayList<Attribute>();
			attributes.add(new Attribute(this.internalRDN));
			attributes.add(new Attribute(this.objectClass));
			
			StringBuffer b = new StringBuffer();
			b.append("(&(objectClass=").append(this.objectClass).append(")(").append(this.externalRDN).append('=').append(externalRDNs.get(0).getValue()).append("))");
			//b.append('(').append(this.externalRDN).append('=').append(externalRDNs.get(0).getValue()).append(')');
			Filter filter = new Filter(b.toString());
			
			schain.nextSearch(new DistinguishedName(base), new Int(1), filter, attributes, new Bool(false), results, new LDAPSearchConstraints());
			
			results.start();
			
			
			Entry entry = null;
			
			if (results.hasMore()) {
				entry = results.next();
			} else {
				results.finish();
				//Assume this isn't the correct obectClass
				this.toIgnore.add(externalDN.toString());
				return externalDN;
			}
			
			val = entry.getEntry().getAttribute(this.internalRDN).getStringValue();

		} else {
			val = toadd.getAttribute(this.internalRDN).getStringValue();
		}
		
		DN internalDN = new DN();
		RDN rdn = new RDN();
		rdn.add(this.internalRDN, val, val);
		internalDN.addRDN(rdn);
		for (int i=1,m=externalRDNs.size();i<m;i++) {
			internalDN.addRDNToBack(externalRDNs.get(i));
		}
		
		this.out2in.put(externalDN.toString().toLowerCase(), internalDN.toString());
		return internalDN;
	}
	
	private ArrayList<Attribute> createNewAttribs(ArrayList<Attribute> attributes) {
		ArrayList<Attribute> newAttribs = new ArrayList<Attribute>();
		
		
		boolean foundWC = false;
		boolean foundOC = false;
		boolean foundExternalRDN = false;
		
		for (Attribute attrib : attributes) {
			if (attrib.getAttribute().equals(this.externalRDN)) {
				foundExternalRDN = true;
				
			} else if (attrib.getAttribute().getName().equals("*")) {
				foundWC = true;
			} else if (attrib.getAttribute().getName().equalsIgnoreCase("objectClass")) {
				foundOC = true;
			} 
			
			newAttribs.add(new Attribute(attrib.getAttribute().getName()));
			
		}
		
		if (! (newAttribs.size() == 0 || foundWC)) {
			if (! foundExternalRDN) {
				newAttribs.add(new Attribute(this.externalRDN));
			}
			
			if (! foundOC) {
				newAttribs.add(new Attribute(this.objectClass));
			}
		}
		
		
		
		return newAttribs;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
