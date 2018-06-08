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
import java.util.Iterator;
import java.util.Properties;
import java.util.Vector;

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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class SetRDN implements Insert {
	
	String name;
	String internalRDN;
	String externalRDN;
	
	HashMap<String,String> in2out, out2in;

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		
		
		entry.setEntry(new LDAPEntry(this.getInternalDN(new DN(entry.getEntry().getDN()),chain,entry.getEntry()).toString(),entry.getEntry().getAttributeSet()));
		chain.nextAdd(entry, constraints);
		
		

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(new DistinguishedName(this.getInternalDN(dn.getDN(), chain)), pwd, constraints);

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
		
		
		DN internalBase = this.getInternalDN(base.getDN(), chain);
		ArrayList<Attribute> attribs = this.createNewAttribs(attributes);
		chain.nextSearch(new DistinguishedName(internalBase), scope, filter, attribs, typesOnly, results, constraints);

	}
	
	
	private void setExternalDN(Entry entry) {
		DN dn = new DN(entry.getEntry().getDN());
		Vector<RDN> rdns = dn.getRDNs();
		if (rdns.size() == 0 || ! rdns.get(0).getType().equalsIgnoreCase(this.internalRDN)) {
			return;
		}
		
		String dnlower = entry.getEntry().getDN().toLowerCase();
		String strdn = this.in2out.get(dnlower);
		
		if (strdn != null) {
			entry.setEntry(new LDAPEntry(strdn,entry.getEntry().getAttributeSet()));
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
	
	private DN getInternalDN(DN externalDN,InterceptorChain chain) throws LDAPException {
		return this.getInternalDN(externalDN, chain,null);
	}
	
	private DN getInternalDN(DN externalDN,InterceptorChain chain,LDAPEntry toadd) throws LDAPException {
		Vector<RDN> externalRDNs =  externalDN.getRDNs();
		
		//check to make sure we need to do the mapping
		if (externalRDNs.size() == 0 || ! externalRDNs.get(0).getType().equalsIgnoreCase(this.externalRDN)) {
			return externalDN;
		}
		
		
		//check to see if we have it cached
		String dnstr = this.out2in.get(externalDN.toString().toLowerCase());
		
		if (dnstr != null) {
			return new DN(dnstr);
		}
		
		//we need to retrieve the attribute via a search
		Results results = new Results(null,chain.getPositionInChain(this));
		SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this));
		DN base = new DN();
		for (int i=1,m=externalRDNs.size();i<m;i++) {
			base.addRDNToBack(externalRDNs.get(i));
		}
		
		String val = "";
		
		if (toadd == null) {
			ArrayList<Attribute> attributes = new ArrayList<Attribute>();
			attributes.add(new Attribute(this.internalRDN));
			
			Filter filter = new Filter("(" + this.externalRDN + "=" + externalRDNs.get(0).getValue() +")");
			
			schain.nextSearch(new DistinguishedName(base), new Int(1), filter, attributes, new Bool(false), results, new LDAPSearchConstraints());
			
			results.start();
			
			
			Entry entry = null;
			
			if (results.hasMore()) {
				entry = results.next();
			} else {
				results.finish();
				throw new LDAPException("No Such Object",LDAPException.NO_SUCH_OBJECT,"No Such Object");
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
		Iterator<Attribute> it = attributes.iterator();
		
		while (it.hasNext()) {
			Attribute attrib = it.next();
			if (attrib.getAttribute().equals(this.externalRDN)) {
				continue;
			} else {
				newAttribs.add(new Attribute(attrib.getAttribute().getName()));
			}
		}
		
		if (newAttribs.size() != 0) {
			
			newAttribs.add(new Attribute(this.externalRDN));
		}
		return newAttribs;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
