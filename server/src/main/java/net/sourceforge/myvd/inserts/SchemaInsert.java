package net.sourceforge.myvd.inserts;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
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
import net.sourceforge.myvd.util.IteratorEntrySet;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.util.LDIFReader;

public class SchemaInsert implements Insert {

	LDAPEntry schemaEntry;
	String name;
	
	public static  Attribute ALL_ATTRIBS = new Attribute("*");
	
	
	@Override
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Schema is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Schema is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Schema is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		LDIFReader reader = null;
		
		try {
			reader = new LDIFReader(new FileInputStream(new File(props.getProperty("schemaLDIF"))));
			this.schemaEntry = ((LDAPSearchResult) reader.readMessage()).getEntry();
		} catch (Exception e) {
			throw new LDAPException("Could not start Schema insert",LDAPException.OPERATIONS_ERROR,e.toString(),e);
		}
	
		this.name = name;
		

	}

	@Override
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Schema is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Schema is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Schema is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		

	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		throw new LDAPException("Schema is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		throw new LDAPException("Schema is search only",LDAPException.LDAP_NOT_SUPPORTED,"");

	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		LDAPAttributeSet attribs = new LDAPAttributeSet();
		LDAPAttributeSet ldifAttribs = this.schemaEntry.getAttributeSet();
		
		boolean allAttribs = attributes.size() == 0 || attributes.contains(ALL_ATTRIBS);
		
		Iterator<LDAPAttribute> it = ldifAttribs.iterator();
		while (it.hasNext()) {
			LDAPAttribute ldifAttrib = it.next();
			Attribute attribName = new Attribute(ldifAttrib.getName());
			if (allAttribs || attributes.contains(attribName)) {
				LDAPAttribute newAttrib = new LDAPAttribute(ldifAttrib.getName());
				Enumeration enumer = ldifAttrib.getByteValues();
				while (enumer.hasMoreElements()) {
					byte[] val = (byte[]) enumer.nextElement();
					newAttrib.addValue(val);
				}
				
				attribs.add(newAttrib);
			}
		}
		
		LDAPEntry toret = new LDAPEntry(this.schemaEntry.getDN(),attribs);
		ArrayList<Entry> list = new ArrayList<Entry>();
		list.add(new Entry(toret));
		
		chain.addResult(results,new IteratorEntrySet(list.iterator()),base,scope,filter,attributes,typesOnly,constraints);

	}

	@Override
	public void shutdown() {
		

	}

}
