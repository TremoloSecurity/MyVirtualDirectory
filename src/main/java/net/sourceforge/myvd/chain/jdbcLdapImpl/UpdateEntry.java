/* **************************************************************************
 *
 * Copyright (C) 2002-2005 Octet String, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND
 * TREATIES. USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT
 * TO VERSION 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS
 * AVAILABLE AT HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE"
 * IN THE TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION
 * OF THIS WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP
 * PUBLIC LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM OCTET STRING, INC., 
 * COULD SUBJECT THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
 ******************************************************************************/
package net.sourceforge.myvd.chain.jdbcLdapImpl;

import java.util.*;

import java.sql.*;

import net.sourceforge.myvd.chain.InterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.types.DistinguishedName;

import com.octetstring.jdbcLdap.backend.DirectoryRetrieveResults;
import com.octetstring.jdbcLdap.backend.DirectoryUpdateEntry;
import com.octetstring.jdbcLdap.jndi.JndiLdapConnection;
import com.octetstring.jdbcLdap.jndi.SQLNamingException;
import com.octetstring.jdbcLdap.sql.statements.*;
import com.octetstring.jdbcLdap.util.*;
import com.novell.ldap.*;

/**
 * @author mlb
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class UpdateEntry implements ChainedImpl,DirectoryUpdateEntry {
	
	InterceptorChain chain;
	
	
	/* (non-Javadoc)
	 * @see com.octetstring.jdbcLdap.jndi.DirectoryUpdateEntry#doUpdateEntryJldap(com.octetstring.jdbcLdap.sql.statements.JdbcLdapUpdateEntry)
	 */
	public int doUpdateEntryJldap(JdbcLdapUpdateEntry stmt) throws SQLException {
		DirectoryRetrieveResults res = (DirectoryRetrieveResults) stmt.getJDBCConnection().getImplClasses().get(JndiLdapConnection.IMPL_RETRIEVE_RESULTS);
		int argPos = 0;
		StringBuffer dn = new StringBuffer();
		
		
		
		Iterator icmds = stmt.getCmds().iterator();
		UpdateSet us;
		ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
		int paramnum = 0;
		while (icmds.hasNext()) {
			us = (UpdateSet) icmds.next();
			
			
			int modtype;
			
			if (us.getCmd().equalsIgnoreCase(JdbcLdapUpdateEntry.ADD)) {
				modtype = LDAPModification.ADD;
			}
			else if (us.getCmd().equalsIgnoreCase(JdbcLdapUpdateEntry.DELETE)) {
				modtype = LDAPModification.DELETE;
			}
			else {
				modtype = LDAPModification.REPLACE;
			}
			
			
			
			//ModificationItem[] mods = new ModificationItem[stmt.getAttribs().size()];
			Pair p;
			String val,name;
			Iterator it = us.getAttribs().iterator();
			int i = 0;
			ArrayList al = new ArrayList();
			while (it.hasNext()) {
				if (modtype == LDAPModification.ADD || modtype == LDAPModification.REPLACE) {
					p = (Pair) it.next();
					name = p.getName();
					
					if (p.getValue().equals("?")) {
						////System.out.println("paramnum : " + paramnum);
						////System.out.println("val : " + stmt.getArgVals()[paramnum]);
						val = stmt.getArgVals()[paramnum];
						paramnum++;
						//i++;
					}
					else {
						val = p.getValue();
					}
					
					
					////System.out.println("moditem : " + modtype + ", " + name + "=" + val);
					mods.add(new LDAPModification(modtype,new LDAPAttribute(name,val)));
				}
				else {
					name = (String) it.next();
					////System.out.println("moditem : " + modtype + ", " + name);
					mods.add(new LDAPModification(modtype,new LDAPAttribute(name)));
				}
				i++;
			}
		}
		
		Object[] toCopy = mods.toArray();
		
		
		LDAPEntry entry;
		StringBuffer buf = new StringBuffer();
		String name;
		try {
			int count = 0;
			if (stmt.getSearchScope() != 0) {
				LDAPSearchResults enumer = res.searchUpInsJldap(stmt);
				while (enumer.hasMore()) {
					entry = enumer.next();
					buf.setLength(0);
					
					name = entry.getDN();
					
					ModifyInterceptorChain modChain = this.chain.createModifyChain();
					modChain.nextModify(new DistinguishedName(name),mods,new LDAPConstraints());
					
					
					count++;
					////System.out.println("count : " + count);
				
				}
			} else {
				ModifyInterceptorChain modChain = this.chain.createModifyChain();
				modChain.nextModify(new DistinguishedName(stmt.getBaseContext()),mods,new LDAPConstraints());
				
				count++;
			}
			
			
			////System.out.println("final count : " + count);
			return count;
			//stmt.getContext().modifyAttributes(dn.toString(),doMods);
		} catch (LDAPException ne) {
			throw new SQLNamingException(ne);
		}
	}


	public InterceptorChain getChain() {
		return chain;
	}


	public void setChain(InterceptorChain chain) {
		this.chain = chain;
	}

}
