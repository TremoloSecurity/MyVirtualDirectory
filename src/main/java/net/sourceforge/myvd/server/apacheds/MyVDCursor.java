package net.sourceforge.myvd.server.apacheds;

import net.sourceforge.myvd.types.Results;

import org.apache.directory.api.ldap.model.cursor.AbstractCursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.TremoloEntry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;

import java.util.LinkedList;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.util.ByteArray;

public class MyVDCursor extends AbstractCursor<Entry> {

	
	
	private Results res;
	LdapException le;
	boolean first;
	
	net.sourceforge.myvd.types.Entry buffer;
	private SchemaManager schemaManager;

	public MyVDCursor(Results res,SchemaManager schemaManager) {
		this.res = res;
		le = null;
		first = true;
		buffer = null;
		this.schemaManager = schemaManager;
		
	}
	
	@Override
	public void after(Entry arg0) throws LdapException, CursorException {
		//Do nothing
		System.out.println();
	}

	@Override
	public void afterLast() throws LdapException, CursorException {
		
		if (le != null) {
			throw le;
		}
		
		try {
			while (res.hasMore()) res.next();
			le = null;
		} catch (LDAPException e) {
			throw MyVDInterceptor.generateException(e);
		}
		
	}

	@Override
	public boolean available() {
		try {
			return res.hasMore();
		} catch (LDAPException e) {
			this.le =  MyVDInterceptor.generateException(e);
			return true;
		}
	}

	@Override
	public void before(Entry arg0) throws LdapException, CursorException {
		System.out.println();
		
	}

	@Override
	public void beforeFirst() throws LdapException, CursorException {
		System.out.println();
		
	}

	@Override
	public boolean first() throws LdapException, CursorException {
		return this.first;
	}

	@Override
	public Entry get() throws CursorException {
		
		try {
			LDAPEntry nentry = null;
			
			if (buffer != null) {
				nentry = buffer.getEntry();
				buffer = null;
			} else {
				net.sourceforge.myvd.types.Entry entry = res.next();
				if (entry == null) {
					return null;
				} else {
					nentry = entry.getEntry();
				}
				
			}
			
			Entry entry = new TremoloEntry();
			
			entry.setDn(nentry.getDN());
			LDAPAttributeSet attrs = nentry.getAttributeSet();
			for (Object o : attrs) {
				LDAPAttribute a = (LDAPAttribute) o;
				String oid = "";
				
				AttributeType at;
				
				
				
				
				
				
				DefaultAttribute attr = new DefaultAttribute(a.getName());
				LinkedList<ByteArray> vals = a.getAllValues();
				for (ByteArray b : vals) {
					attr.add(b.getValue());
				}
				
				
				entry.add(attr);
				
			}
			
			return entry;
		} catch (Exception e) {
			throw new CursorException(e);
		} 
		
	}

	private String generateRandomOID() {
		String base ="9.8.7.6.5.";
		int num = (int) (Math.random() * 5000);
		
		StringBuffer b = new StringBuffer(base);
		b.append(num);
		
		if (this.schemaManager.getAttributeType(b.toString()) == null ) {
			return b.toString();
		} else {
			return generateRandomOID();
		}
	}

	@Override
	public boolean last() throws LdapException, CursorException {
		
		try {
			while (res.hasMore()) {
				buffer = res.next();
			}
			return true;
		} catch (LDAPException e) {
			throw MyVDInterceptor.generateException(e);
		}
	}

	@Override
	public boolean next() throws LdapException, CursorException {
		try {
			return res.hasMore();
		} catch (LDAPException e) {
			throw MyVDInterceptor.generateException(e);
		}
	}

	@Override
	public boolean previous() throws LdapException, CursorException {
		
		return false;
	}

}
