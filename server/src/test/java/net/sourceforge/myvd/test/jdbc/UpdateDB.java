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
package net.sourceforge.myvd.test.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import junit.framework.TestCase;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.RDN;

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
import net.sourceforge.myvd.inserts.jdbc.JdbcInsert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;

public class UpdateDB extends TestCase implements Insert {
	
	public void testdonothing() {
		
	}
	
	String name ;
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		Connection con = (Connection) chain.getRequest().get(JdbcInsert.MYVD_DB_CON + "LDAPBaseServer");
		
		if (con == null) {
			throw new LDAPException("Operations Error",LDAPException.OPERATIONS_ERROR,"No Database Connection");
		}
		
		try {
			// begin the transaction
			con.setAutoCommit(false);
			
			HashMap<String,String> db2ldap = (HashMap<String, String>) chain.getRequest().get(JdbcInsert.MYVD_DB_DB2LDAP + "LDAPBaseServer");
			
			PreparedStatement ps = con.prepareStatement("INSERT INTO USERS (id,firstname,lastname,username) VALUES (?,?,?,?)");
			ps.setInt(1, 5); //this is horrible practice
			ps.setString(2, entry.getEntry().getAttribute(db2ldap.get("firstname")).getStringValue());
			ps.setString(3, entry.getEntry().getAttribute(db2ldap.get("lastname")).getStringValue());
			ps.setString(4, entry.getEntry().getAttribute(db2ldap.get("username")).getStringValue());
			
			ps.executeUpdate();
			
			ps.close();
			
			ps = con.prepareStatement("SELECT id FROM LOCATIONS WHERE name=?");
			PreparedStatement inst = con.prepareStatement("INSERT INTO LOCATIONMAP (person,location) VALUES (?,?)");
			LDAPAttribute l = entry.getEntry().getAttribute(db2ldap.get("name"));
			
			if (l == null) {
				con.rollback();
				throw new LDAPException("Location is required",LDAPException.OBJECT_CLASS_VIOLATION,"Location is required");
			}
			
			String[] vals = l.getStringValueArray();
			for (int i=0;i<vals.length;i++) {
				ps.setString(1, vals[i]);
				ResultSet rs = ps.executeQuery();
				if (! rs.next()) {
					con.rollback();
					throw new LDAPException("Location " + vals[i] + " does not exist",LDAPException.OBJECT_CLASS_VIOLATION,"Location " + vals[i] + " does not exist");
				}
				
				inst.setInt(1, 5);
				inst.setInt(2, rs.getInt("id"));
				
				inst.executeUpdate();
			}
			
			ps.close();
			inst.close();
			
			con.commit();
		
		} catch (SQLException e) {
			try {
				con.rollback();
				
			} catch (SQLException e1) {
				throw new LDAPException("Could not add entry or rollback transaction",LDAPException.OPERATIONS_ERROR,e.toString(),e);
			}
			throw new LDAPException("Could not add entry",LDAPException.OPERATIONS_ERROR,e.toString(),e);
		}
		
		

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		Connection con = (Connection) chain.getRequest().get(JdbcInsert.MYVD_DB_CON + "LDAPBaseServer");
		
		if (con == null) {
			throw new LDAPException("Operations Error",LDAPException.OPERATIONS_ERROR,"No Database Connection");
		}
		
		try {
			// begin the transaction
			con.setAutoCommit(false);
			int id = getId(dn,con);
			HashMap<String,String> db2ldap = (HashMap<String, String>) chain.getRequest().get(JdbcInsert.MYVD_DB_DB2LDAP + "LDAPBaseServer");
			
			PreparedStatement ps = con.prepareStatement("DELETE FROM users WHERE id=?");
			ps.setInt(1, id);
			ps.executeUpdate();
			
			ps = con.prepareStatement("DELETE FROM locationmap WHERE person=?");
			ps.setInt(1, id);
			ps.executeUpdate();
			
			ps.close();
			
			con.commit();
		} catch (SQLException e) {
			try {
				con.rollback();
				
			} catch (SQLException e1) {
				throw new LDAPException("Could not delete entry or rollback transaction",LDAPException.OPERATIONS_ERROR,e.toString(),e);
			}
			throw new LDAPException("Could not delete entry",LDAPException.OPERATIONS_ERROR,e.toString(),e);
		}

	}

	private int getId(DistinguishedName dn, Connection con) throws SQLException, LDAPException {
		PreparedStatement ps = con.prepareStatement("SELECT id FROM USERS WHERE username=?");
		String uid = ((RDN) dn.getDN().getRDNs().get(0)).getValue();
		ps.setString(1, uid);
		ResultSet rs = ps.executeQuery();
		if (! rs.next()) {
			throw new LDAPException("User " + uid + " not found",LDAPException.NO_SUCH_OBJECT,"No such object");
		}
		int id = rs.getInt("id");
		rs.close();
		ps.close();
		
		return id;
	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		
		
		Connection con = (Connection) chain.getRequest().get(JdbcInsert.MYVD_DB_CON + "LDAPBaseServer");
		
		if (con == null) {
			throw new LDAPException("Operations Error",LDAPException.OPERATIONS_ERROR,"No Database Connection");
		}
		
		try {
			// begin the transaction
			con.setAutoCommit(false);
			HashMap<String,String> db2ldap = (HashMap<String, String>) chain.getRequest().get(JdbcInsert.MYVD_DB_DB2LDAP + "LDAPBaseServer");
			
			Iterator<LDAPModification> it = mods.iterator();
			String uid = ((RDN) dn.getDN().getRDNs().get(0)).getValue();
			int id = this.getId(dn, con);
			while (it.hasNext()) {
				LDAPModification mod = it.next();
				if (mod.getOp() == LDAPModification.REPLACE) {
					String attributeName = mod.getAttribute().getName();
					if (attributeName.equals(db2ldap.get("first")) || attributeName.equals(db2ldap.get("last"))) {
						PreparedStatement ps = con.prepareStatement("UPDATE USERS SET " + (attributeName.equals(db2ldap.get("first")) ? "first" : "last") + "=? WHERE username=?");
						ps.setString(1, mod.getAttribute().getStringValue());
						ps.setString(2, uid);
						ps.executeUpdate();
						ps.close();
					} else if (attributeName.equals(db2ldap.get("username"))) {
						throw new LDAPException("Can not modify the rdn",LDAPException.NOT_ALLOWED_ON_RDN,"Can not perform modify");	
					} else if (attributeName.equals(db2ldap.get("name"))) {
						
						PreparedStatement ps = con.prepareStatement("DELETE FROM locationmap WHERE person=?");
						ps.setInt(1,id);
						ps.executeUpdate();
						ps.close();
						
						ps = con.prepareStatement("INSERT INTO locationmap (person,location) VALUES (?,?)");
						PreparedStatement pssel = con.prepareStatement("SELECT id FROM LOCATIONS WHERE name=?");
						
						String[] vals = mod.getAttribute().getStringValueArray();
						for (int i=0;i<vals.length;i++) {
							pssel.setString(1, vals[i]);
							ResultSet rs = pssel.executeQuery();
							if (! rs.next()) {
								con.rollback();
								throw new LDAPException("Location " + vals[i] + " does not exist",LDAPException.OBJECT_CLASS_VIOLATION,"Location " + vals[i] + " does not exist");
							}
							int lid = rs.getInt("id");
							ps.setInt(1,id);
							ps.setInt(2,lid);
							ps.executeUpdate();
							
						}
						
						ps.close();
						pssel.close();
					}
				} else if (mod.getOp() == LDAPModification.DELETE) {
					if (mod.getAttribute().getName().equals(db2ldap.get("name"))) {
						String[] vals = mod.getAttribute().getStringValueArray();
						if (vals.length == 0) {
							PreparedStatement  ps = con.prepareStatement("DELETE FROM locationmap WHERE person=?");
							ps.setInt(1, id);
							ps.executeUpdate();
							ps.close();
						} else {
							PreparedStatement ps = con.prepareStatement("DELETE FROM locationmap WHERE person=? and location=?");
							PreparedStatement pssel = con.prepareStatement("SELECT id FROM LOCATIONS WHERE name=?");
							
							
							for (int i=0;i<vals.length;i++) {
								pssel.setString(1, vals[i]);
								ResultSet rs = pssel.executeQuery();
								if (! rs.next()) {
									con.rollback();
									throw new LDAPException("Location " + vals[i] + " does not exist",LDAPException.OBJECT_CLASS_VIOLATION,"Location " + vals[i] + " does not exist");
								}
								int lid = rs.getInt("id");
								ps.setInt(1,id);
								ps.setInt(2,lid);
								ps.executeUpdate();
								
							}
							
							ps.close();
							pssel.close();
						}
					} else {
						throw new LDAPException("Can not delete attribute " + mod.getAttribute().getName(),LDAPException.INVALID_ATTRIBUTE_SYNTAX,"");
					}
				}  else if (mod.getOp() == LDAPModification.ADD) {
					if (mod.getAttribute().getName().equals(db2ldap.get("name"))) {
						String[] vals = mod.getAttribute().getStringValueArray();
						
							PreparedStatement ps = con.prepareStatement("INSERT INTO locationmap (person,location) VALUES (?,?)");
							PreparedStatement pssel = con.prepareStatement("SELECT id FROM LOCATIONS WHERE name=?");
							
							
							for (int i=0;i<vals.length;i++) {
								pssel.setString(1, vals[i]);
								ResultSet rs = pssel.executeQuery();
								if (! rs.next()) {
									con.rollback();
									throw new LDAPException("Location " + vals[i] + " does not exist",LDAPException.OBJECT_CLASS_VIOLATION,"Location " + vals[i] + " does not exist");
								}
								int lid = rs.getInt("id");
								ps.setInt(1,id);
								ps.setInt(2,lid);
								ps.executeUpdate();
								
							}
							
							ps.close();
							pssel.close();
						
					} else {
						throw new LDAPException("Can not delete attribute " + mod.getAttribute().getName(),LDAPException.INVALID_ATTRIBUTE_SYNTAX,"");
					}
				}
			} 
			
		  con.commit();
		} catch (SQLException e) {
			try {
				con.rollback();
				
			} catch (SQLException e1) {
				throw new LDAPException("Could not delete entry or rollback transaction",LDAPException.OPERATIONS_ERROR,e.toString(),e);
			}
			throw new LDAPException("Could not delete entry",LDAPException.OPERATIONS_ERROR,e.toString(),e);
		}

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		// TODO Auto-generated method stub

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

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}
}
