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

/*
 * Delete.java
 *
 * Created on March 13, 2002, 5:50 PM
 */

package net.sourceforge.myvd.chain.jdbcLdapImpl;


import com.octetstring.jdbcLdap.backend.DirectoryDelete;
import com.octetstring.jdbcLdap.backend.DirectoryRetrieveResults;
import com.octetstring.jdbcLdap.jndi.JndiLdapConnection;
import com.octetstring.jdbcLdap.jndi.SQLNamingException;
import com.octetstring.jdbcLdap.sql.statements.*;
import com.octetstring.jdbcLdap.sql.*;

import java.sql.*;

import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.InterceptorChain;
import net.sourceforge.myvd.types.DistinguishedName;

import com.novell.ldap.*;
/**
 *Deletes an entry
 *@author Marc Boorshtein, OctetString
 */
public class Delete implements DirectoryDelete, ChainedImpl {
	
	InterceptorChain chain;

	
	public int doDeleteJldap(JdbcLdapDelete del) throws SQLException {
		DirectoryRetrieveResults res = (DirectoryRetrieveResults) del.getCon().getImplClasses().get(JndiLdapConnection.IMPL_RETRIEVE_RESULTS);
		
		
		StringBuffer buf = new StringBuffer();
		SqlStore store = del.getSqlStore();
		int count = 0;
		////System.out.println("from : " + store.getFrom());
		if (store.getSimple()) {
			try {
				
				DeleteInterceptorChain delChain = this.chain.createDeleteChain();
				delChain.nextDelete(new DistinguishedName(JndiLdapConnection.getRealBase(del)),new LDAPConstraints());
			}
			catch (LDAPException ne) {
				throw new SQLNamingException(ne);
			}
			
			return 1;
		}
		else {
			try {
				
				LDAPSearchResults enumer = res.searchUpInsJldap(del);
				while (enumer.hasMore()) {
					LDAPEntry entry = enumer.next(); 
					DeleteInterceptorChain delChain = this.chain.createDeleteChain();
					delChain.nextDelete(new DistinguishedName(entry.getDN()),new LDAPConstraints());
					count++;
				}
				
				
				
				return count;
			}
			catch (LDAPException ne) {
				throw new SQLNamingException(ne);
			}
		}
	}


	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.chain.jdbcLdapImpl.ChainedImpl#getChain()
	 */
	public InterceptorChain getChain() {
		return chain;
	}


	/* (non-Javadoc)
	 * @see net.sourceforge.myvd.chain.jdbcLdapImpl.ChainedImpl#setChain(net.sourceforge.myvd.chain.InterceptorChain)
	 */
	public void setChain(InterceptorChain chain) {
		this.chain = chain;
	}
}
