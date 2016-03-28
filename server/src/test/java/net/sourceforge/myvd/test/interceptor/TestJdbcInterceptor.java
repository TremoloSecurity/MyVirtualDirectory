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
package net.sourceforge.myvd.test.interceptor;


import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Properties;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;




import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Properties;

import junit.framework.TestCase;
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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

public class TestJdbcInterceptor extends TestCase implements Insert {
	
	public void testdonothing() {
		
	}

	String name;
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		// TODO Auto-generated method stub
		this.name = name;
	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		if (attributes.contains(new Attribute("add"))) {
			try {
				PreparedStatement ps = chain.createJdbcLdapConnection().prepareStatement("INSERT INTO cn=testadd,o=mycompany,c=us (objectClass,cn,sn) VALUES ('inetOrgPerson','testadd','add')");
				ps.execute();
			} catch (SQLException e) {
				throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
			}
			
		} else if (attributes.contains(new Attribute("update"))) {
			try {
				PreparedStatement ps = chain.createJdbcLdapConnection().prepareStatement("INSERT INTO cn=testadd,o=mycompany,c=us (objectClass,cn,sn) VALUES ('inetOrgPerson','testadd','add')");
				ps.execute();
				ps = chain.createJdbcLdapConnection().prepareStatement("UPDATE subTreeScope;o=mycompany,c=us SET sn=sntest WHERE cn='testadd'");
				ps.execute();
				
			} catch (SQLException e) {
				throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
			}
			
		} else if (attributes.contains(new Attribute("updateentry"))) {
			try {
				PreparedStatement ps = chain.createJdbcLdapConnection().prepareStatement("INSERT INTO cn=testadd,o=mycompany,c=us (objectClass,cn,sn) VALUES ('inetOrgPerson','testadd','add')");
				ps.execute();
				ps = chain.createJdbcLdapConnection().prepareStatement("UPDATE ENTRY subTreeScope;o=mycompany,c=us DO ADD SET uid=testuid WHERE cn='testadd'");
				ps.execute();
				
			} catch (SQLException e) {
				throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
			}
			
		} else if (attributes.contains(new Attribute("delete"))) {
			try {
				PreparedStatement ps = chain.createJdbcLdapConnection().prepareStatement("INSERT INTO cn=testadd,o=mycompany,c=us (objectClass,cn,sn) VALUES ('inetOrgPerson','testadd','add')");
				ps.execute();
				ps = chain.createJdbcLdapConnection().prepareStatement("INSERT INTO cn=testadd1,o=mycompany,c=us (objectClass,cn,sn) VALUES ('inetOrgPerson','testadd1','add')");
				ps.execute();
				ps = chain.createJdbcLdapConnection().prepareStatement("DELETE FROM cn=testadd1,o=mycompany,c=us");
				ps.execute();
			} catch (SQLException e) {
				throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
			}
			
		} else if (attributes.contains(new Attribute("search"))) {
			try {
				PreparedStatement ps = chain.createJdbcLdapConnection().prepareStatement("INSERT INTO cn=testadd,o=mycompany,c=us (objectClass,cn,sn) VALUES ('inetOrgPerson','testadd','add')");
				ps.execute();
				ps = chain.createJdbcLdapConnection().prepareStatement("SELECT cn FROM subTreeScope;o=mycompany,c=us WHERE cn='testadd'");
				ResultSet rs = ps.executeQuery();
				if (! rs.next()) {
					throw new LDAPException("Entry not retrieved",LDAPException.OPERATIONS_ERROR,"");
				}
				
				if (! rs.getString("cn").equals("testadd")) {
					throw new LDAPException("Invalid results : " + rs.getString("cn"),LDAPException.OPERATIONS_ERROR,"");
				}
				
			} catch (SQLException e) {
				throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
			}
			
		}
		
		
		chain.getRequest().remove(ExceptionInterceptor.FLAG);
		chain.nextSearch(base,scope,filter,attributes,typesOnly,results,constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

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
