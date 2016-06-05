package net.sourceforge.myvd.inserts.mapping;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;


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

public class Dn2Attribute implements Insert {
	
	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(Dn2Attribute.class.getName());
	
	String sourceAttribute;
	String newValueAttribute;
	
	HashMap<String,String> dn2attr;
	HashMap<String,String> attr2dn;
	String searchBase;
	String name;
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.dn2attr = new HashMap<String,String>();
		this.attr2dn =  new HashMap<String,String>();
		
		this.name = name;
		this.newValueAttribute = props.getProperty("newValueAttribute");
		this.sourceAttribute = props.getProperty("sourceAttribute");
		this.searchBase = nameSpace.getBase().toString();
		
	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry, LDAPConstraints constraints) throws LDAPException {
		//TODO we should support add
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
		//TODO should support
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
		//TODO support
		chain.nextModify(dn, mods, constraints);

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly, Results results, LDAPSearchConstraints constraints)
					throws LDAPException {
		
		
		Filter newfilter = new Filter(filter.getRoot().toString());
		this.mapFilter(newfilter.getRoot(), chain);
		chain.nextSearch(base, scope, newfilter, attributes, typesOnly, results, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn,
			DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope,
			Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints)
					throws LDAPException {
		
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		LDAPAttribute attr = entry.getEntry().getAttribute(this.sourceAttribute);
		if (attr != null) {
			LDAPAttribute nattr = new LDAPAttribute(this.sourceAttribute);
			String[] dns = attr.getStringValueArray();
			for (String dn : dns) {
				nattr.addValue(this.dn2attr(dn, chain));
			}
			entry.getEntry().getAttributeSet().remove(this.sourceAttribute);
			entry.getEntry().getAttributeSet().add(nattr);
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
	
	private void mapFilter(FilterNode node,InterceptorChain chain) throws LDAPException {
		switch (node.getType()) {
			case EQUALS :
			case GREATER_THEN:
			case LESS_THEN:
				if (node.getName().equalsIgnoreCase(this.sourceAttribute)) {
					String val = this.attr2dn(node.getValue(), chain);
					if (val != null) {
						node.setValue(val);
					}
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
	
	private String dn2attr(String dn,InterceptorChain chain) throws LDAPException {
		String dnlcase = dn.toLowerCase();
		String attr = this.dn2attr.get(dnlcase);
		
		if (attr != null) {
			return attr;
		} else {
			Filter filter = new Filter("(objectClass=*)");
			
			
			Results results = new Results(null,chain.getPositionInChain(this) + 1);
			SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
			ArrayList<Attribute> attributes = new ArrayList<Attribute>();
			attributes.add(new Attribute(this.newValueAttribute));
			
			
			schain.nextSearch(new DistinguishedName(dn), new Int(0), filter, attributes, new Bool(false), results, new LDAPSearchConstraints());
			
			results.start();
			
			if (! results.hasMore()) {
				logger.warn("DN does not exist : " + dn);
				results.finish();
				return null;
			} else {
				Entry entry = results.next();
				LDAPAttribute valAttr = entry.getEntry().getAttribute(newValueAttribute);
				
				if (valAttr == null) {
					logger.warn("Attribute " + this.newValueAttribute + " does not exist");
					results.finish();
					return null;
				} else {
					this.dn2attr.put(dnlcase, valAttr.getStringValue());
					results.finish();
					return valAttr.getStringValue();
				}
			}
			
		}
	}
	
	private String attr2dn(String attr,InterceptorChain chain) throws LDAPException {
		String attrlcase = attr.toLowerCase();
		String dn = this.attr2dn.get(attrlcase);
		
		if (dn != null) {
			return dn;
		} else {
			Filter filter = new Filter(equal(this.newValueAttribute,attr).toString());
			
			
			Results results = new Results(null,chain.getPositionInChain(this) + 1);
			SearchInterceptorChain schain = chain.createSearchChain(chain.getPositionInChain(this) + 1);
			ArrayList<Attribute> attributes = new ArrayList<Attribute>();
			attributes.add(new Attribute(this.newValueAttribute));
			
			
			schain.nextSearch(new DistinguishedName(this.searchBase), new Int(2), filter, attributes, new Bool(false), results, new LDAPSearchConstraints());
			
			results.start();
			
			if (! results.hasMore()) {
				logger.warn("Entry does not exist for : " + attr);
				results.finish();
				return null;
			} else {
				Entry entry = results.next();
				
				this.attr2dn.put(attrlcase, entry.getEntry().getDN());
				results.finish();
				return entry.getEntry().getDN();
				
			}
			
		}
	}

}
