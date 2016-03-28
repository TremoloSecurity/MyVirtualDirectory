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
package net.sourceforge.myvd.inserts.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
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

public class DBAddOnModify implements Insert {

	protected static Logger logger = Logger.getLogger(DBAddOnModify.class.getName());
	
	public static final String ADD_OR_MOD_FLAG = "DB_ADD_OR_MOD_FLAG";
	public static final String ADD_FLAG = "ADD";
	public static final String MOD_FLAG = "MOD";
	private static final String DB_ADD_ON_MOD_ID = "DB_ADD_ON_MOD_ID_";
	
	String tableName;
	String dbInsertName;
	JdbcInsert insert;
	
	ArrayList<String> fields;
	String rdnField;
	
	String name;
	
	String insertSQL;
	String deleteSQL;
	String idField;
	String idAttribute;
	
	boolean hasIdField;
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		Connection con = (Connection) chain.getRequest().get(JdbcInsert.MYVD_DB_CON + this.dbInsertName);
		
		if (con == null) {
			throw new LDAPException("Operations Error",LDAPException.OPERATIONS_ERROR,"No Database Connection");
		}
		
		addEntry(chain, entry, con);

	}

	private void addEntry(InterceptorChain chain, Entry entry, Connection con)
			throws LDAPException {
		try {
			// begin the transaction
			
			HashMap<String,String> db2ldap = (HashMap<String, String>) chain.getRequest().get(JdbcInsert.MYVD_DB_DB2LDAP + this.dbInsertName);
			String uid = ((RDN) (new DN(entry.getEntry().getDN())).getRDNs().get(0)).getValue();
			
		
			
			insertRecord(entry.getEntry().getAttributeSet(), con, db2ldap, uid,false);
		} catch (SQLException e) {
			try {
				con.rollback();
				
			} catch (SQLException e1) {
				throw new LDAPException("Could not delete entry or rollback transaction",LDAPException.OPERATIONS_ERROR,e.toString(),e);
			}
			throw new LDAPException("Could not delete entry",LDAPException.OPERATIONS_ERROR,e.toString(),e);
		}
	}

	private int insertRecord(LDAPAttributeSet attribs, Connection con,HashMap<String, String> db2ldap, String uid,boolean returnId) throws SQLException {
		con.setAutoCommit(false);
		PreparedStatement ps = con.prepareStatement(this.insertSQL);
		
		//logger.info(attribs);
		
		int ii = 0;
		
		for (int i=0;i<this.fields.size();i++) {
			String field = this.fields.get(i);
			//logger.info("Field : " + field + "; " + db2ldap.get(field));
			if (! field.equalsIgnoreCase(this.idField)) {
				if (field.equals(this.rdnField)) {
					ps.setString(ii + 1, uid);
				} else {
					//logger.info("field : " + field);
					String sdb2ldap = db2ldap.get(field);
					//logger.info("db2ldap : " + sdb2ldap);
					LDAPAttribute attrib = attribs.getAttribute(sdb2ldap);
					//logger.info("attrib : " + attrib);
					ps.setString(ii + 1, attrib.getStringValue());
				}
				
				ii++;
			} 
			
		}
		
		
		ps.executeUpdate();
		
		con.commit();
		
		if (returnId) {
			ResultSet keys = ps.getGeneratedKeys();
	        keys.next();
	        int key = keys.getInt(1);
	        
	        return key;
		} else {
			
			return -1;
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
		this.name = name;
		this.tableName = props.getProperty("tableName");
		this.dbInsertName = props.getProperty("dbInsertName");
		
		
		
		for (int i=0;i<nameSpace.getChain().getLength();i++) {
			if (nameSpace.getChain().getInsert(i).getName().equals(this.dbInsertName)) {
				this.insert = (JdbcInsert) nameSpace.getChain().getInsert(i);
				break;
			}
		}
		
		if (this.insert == null) {
			throw new LDAPException("Insert " + this.dbInsertName + " not found",LDAPException.OPERATIONS_ERROR,"");
		}
		
		
		HashMap db2ldap = this.insert.getDB2LDAPMap();
		this.rdnField =   this.insert.getLDAP2DBMap().get(this.insert.getRDNField());
		
		this.fields = new ArrayList<String>();
		
		fields.addAll(db2ldap.keySet());
		
		this.idField = props.getProperty("idField","");
		
		
		String fieldsString = "";
		this.hasIdField = false;
		
		Iterator<String> it = fields.iterator();
		while (it.hasNext()) {
			String fieldName = it.next();
			if (! fieldName.equalsIgnoreCase(this.idField)) {
				fieldsString += fieldName + ",";
			} else {
				this.hasIdField = true;
			}
		}

		fieldsString = fieldsString.substring(0,fieldsString.lastIndexOf(','));
		
		this.insertSQL = "INSERT INTO " + this.tableName + " (" + fieldsString + ") VALUES (";
		
		int count = fields.size();
		if (this.hasIdField) {
			count--;
		}
		
		for (int i=0;i<count;i++) {
			this.insertSQL += "?,";
		}
		
		this.insertSQL = this.insertSQL.substring(0,this.insertSQL.lastIndexOf(','));
		
		this.insertSQL += ")";
		
		//logger.info("insert sql : " + this.insertSQL);
		
		this.deleteSQL = "DELETE FROM " + this.tableName + " WHERE " + this.rdnField + "=?";
		
		

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		Connection con = (Connection) chain.getRequest().get(JdbcInsert.MYVD_DB_CON + this.dbInsertName);
		
		if (con == null) {
			throw new LDAPException("Operations Error",LDAPException.OPERATIONS_ERROR,"No Database Connection");
		}
		
		try {
			// begin the transaction
			con.setAutoCommit(false);
			String uid = ((RDN) dn.getDN().getRDNs().get(0)).getValue();
			
			PreparedStatement ps = con.prepareStatement(this.deleteSQL);
			ps.setString(1, uid);
			ps.executeUpdate();
			
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

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		// TODO Auto-generated method stub

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		Connection con = (Connection) chain.getRequest().get(JdbcInsert.MYVD_DB_CON + this.dbInsertName);
		
		if (con == null) {
			throw new LDAPException("Operations Error",LDAPException.OPERATIONS_ERROR,"No Database Connection");
		}
		
		if (! chain.getRequest().containsKey(DBAddOnModify.ADD_OR_MOD_FLAG) || chain.getRequest().get(DBAddOnModify.ADD_OR_MOD_FLAG).equals(MOD_FLAG)) {
			modifyEntry(chain, dn, mods, con);
		} else {
			LDAPAttributeSet attribs = new LDAPAttributeSet();
			HashMap<String,String> ldap2db = (HashMap<String, String>) chain.getRequest().get(JdbcInsert.MYVD_DB_LDAP2DB + this.dbInsertName);
			HashMap<String,String> db2ldap = (HashMap<String, String>) chain.getRequest().get(JdbcInsert.MYVD_DB_DB2LDAP + this.dbInsertName);
			
			Iterator<LDAPModification> it = mods.iterator();
			while (it.hasNext()) {
				LDAPModification mod = it.next();
				attribs.add(new LDAPAttribute(mod.getAttribute().getName(),mod.getAttribute().getStringValue()));
			}
			
			try {
				
				int id = this.insertRecord(attribs, con, db2ldap, null, true);
				chain.getRequest().put(DB_ADD_ON_MOD_ID + this.name, id);
			} catch (SQLException e) {
				try {
					con.rollback();
					
				} catch (SQLException e1) {
					throw new LDAPException("Could not delete entry or rollback transaction",LDAPException.OPERATIONS_ERROR,e.toString(),e);
				}
				throw new LDAPException("Could not delete entry",LDAPException.OPERATIONS_ERROR,e.toString(),e);
			}
		}
	}

	private void modifyEntry(ModifyInterceptorChain chain,
			DistinguishedName dn, ArrayList<LDAPModification> mods,
			Connection con) throws LDAPException {
		try {
			// begin the transaction
			con.setAutoCommit(false);
			HashMap<String,String> ldap2db = (HashMap<String, String>) chain.getRequest().get(JdbcInsert.MYVD_DB_LDAP2DB + this.dbInsertName);
			
			Iterator<LDAPModification> it = mods.iterator();
			
			String sql = "UPDATE " + this.tableName + " SET ";
			
			
			
			while (it.hasNext()) {
				LDAPModification mod = it.next();
				if (mod.getOp() != LDAPModification.REPLACE) {
					throw new LDAPException("Only modify replace allowed",LDAPException.OBJECT_CLASS_VIOLATION,"");
				}
				sql += ldap2db.get( mod.getAttribute().getName()) + "=? ";
			}
			
			sql += " WHERE " + this.rdnField + "=?";
			
			PreparedStatement ps = con.prepareStatement(sql);
			
			
			
			it = mods.iterator();
			int i=1;
			while (it.hasNext()) {
				LDAPModification mod = it.next();
				ps.setString(i, mod.getAttribute().getStringValue());
				i++;
			}
			
			String uid = ((RDN) dn.getDN().getRDNs().get(0)).getValue();
			
			ps.setString(i, uid);
			
			ps.executeUpdate();
			
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
