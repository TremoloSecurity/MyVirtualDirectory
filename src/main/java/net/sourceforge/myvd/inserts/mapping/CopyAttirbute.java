package net.sourceforge.myvd.inserts.mapping;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;
import java.util.regex.Pattern;

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

public class CopyAttirbute implements Insert {

	String name;
	String sourceAttribute;
	String targetAttribute;
	String singleMapRegEx;
	Pattern singleMap;
	
	
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
		this.name = name;
		this.sourceAttribute = props.getProperty("sourceAttribute");
		this.targetAttribute = props.getProperty("targetAttribute");
		
		this.singleMapRegEx = props.getProperty("sinleMapRegEx");
		if (this.singleMapRegEx != null) {
			this.singleMap = Pattern.compile(singleMapRegEx);
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
		this.renameFilter(newFilter.getRoot());
		
		boolean found = false;
		boolean all = false;
		
		if (attributes.size() == 0) {
			all = true;
		}
		
		for (Attribute attr : attributes) {
			if (attr.getAttribute().getName().equalsIgnoreCase("*")) {
				all = true;
			} else if (attr.getAttribute().getName().equalsIgnoreCase(this.targetAttribute)) {
				found = true;
			}
		}
		
		if (!all && found) {
			ArrayList<Attribute> nattrs = new ArrayList<Attribute>();
			nattrs.addAll(attributes);
			nattrs.add(new Attribute(this.sourceAttribute));
			attributes = nattrs;
		}
		
		chain.nextSearch(base, scope, newFilter, attributes, typesOnly, results, constraints);
		
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
		
		if (entry.getEntry().getAttribute(this.targetAttribute) == null) {
			entry.renameAttribute(sourceAttribute, targetAttribute);
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

	
	private void renameFilter(FilterNode node) {
		String name;
		String newName;
		String value;
		FilterType type;
		switch (node.getType()) {
			case SUBSTR	: 
			case EQUALS 	  :
			case GREATER_THEN :
			case LESS_THEN:
			case PRESENCE : 
							
				
							name = node.getName().toLowerCase();
							if (name.equalsIgnoreCase(targetAttribute)) {
								
								if (this.singleMap != null) {
									if (this.singleMap.matcher(node.getValue()).matches()) {
										node.setName(this.sourceAttribute);
									} 
								} else {
									doubleMap(node, name);
								}
								
								
							}
							
							break;
			case AND:
			case OR:
							Iterator<FilterNode> it = node.getChildren().iterator();
							while (it.hasNext()) {
								renameFilter(it.next());
							}
							break;
			case NOT :		renameFilter(node.getNot());
		}
		
		
	}

	private void doubleMap(FilterNode node, String name) {
		String value;
		FilterType type;
		value = node.getValue();
		type = node.getType();
		
		node.setName(null);
		node.setValue(null);
		node.setType(FilterType.OR);
		node.setChildren(new ArrayList<FilterNode>());
		node.addNode(new FilterNode(type,name,value));
		node.addNode(new FilterNode(type,this.sourceAttribute,value));
	}
}
