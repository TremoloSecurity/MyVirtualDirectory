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
package net.sourceforge.myvd.chain;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;

import net.sourceforge.myvd.chain.jdbcLdapImpl.ChainedImpl;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Password;

import com.octetstring.jdbcLdap.jndi.JndiLdapConnection;

public class InterceptorChain {
	static Logger logger = Logger.getLogger(InterceptorChain.class);
	InsertChain chain;
	int pos;
	
	
	DistinguishedName bindDN;
	Password password;
	
	HashMap<Object,Object> session;
	HashMap<Object,Object> request;
	Router router;
	
	JndiLdapConnection jdbcCon;
	
	protected Insert getNext() {
		if (pos < chain.getLength()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Chain Position : " + pos);
				logger.debug("Insert : " + chain.getInsert(pos).toString());
			}
			return chain.getInsert(pos++);
		} else {
			logger.debug("Chain Completed");
			return null;
		}
	}
	
	public InterceptorChain(DistinguishedName dn,Password pass,int startPos,InsertChain chain,HashMap<Object,Object> session,HashMap<Object,Object> request,Router router) {
		this(dn,pass,startPos,chain,session,request);
		this.router = router;
	}
	
	public InterceptorChain(DistinguishedName dn,Password pass,int startPos,InsertChain chain,HashMap<Object,Object> session,HashMap<Object,Object> request) {
		this.bindDN = dn;
		this.password = pass;
		this.chain = chain;
		this.pos = startPos;
		
		this.request = request;
		this.session = session;
		
		this.router = null;
	}
	
	//Common methods
	public DistinguishedName getBindDN() {
		if (this.bindDN == null) {
			return new DistinguishedName("");
		} else {
			return bindDN;
		}
	}
	
	public Password getBindPassword() {
		return password;
	}
	
	public HashMap<Object,Object> getSession() {
		return this.session;
	}
	
	public HashMap<Object,Object> getRequest() {
		return this.request;
	}
	
	public AddInterceptorChain createAddChain() {
		if (this.router != null) {
			return new AddInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request,this.router);
		} else {
			return new AddInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request);
		}
	}
	
	public AddInterceptorChain createAddChain(int pos) {
		if (this.router != null) {
			return new AddInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request,this.router);
		} else {
			return new AddInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request);
		}
	}
	
	public BindInterceptorChain createBindChain() {
		if (this.router != null) {
			return new BindInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request,this.router);
		} else {
			return new BindInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request);
		}
	}
	
	public BindInterceptorChain createBindChain(int pos) {
		if (this.router != null) {
			return new BindInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request,this.router);
		} else {
			return new BindInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request);
		}
	}
	
	public CompareInterceptorChain createCompareChain(int pos) {
		if (this.router != null) {
			return new CompareInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request,this.router);
		} else {
			return new CompareInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request);
		}
	}
	
	public CompareInterceptorChain createCompareChain() {
		if (this.router != null) {
			return new CompareInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request,this.router);
		} else {
			return new CompareInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request);
		}
	}
	
	public ModifyInterceptorChain createModifyChain() {
		if (this.router != null) {
			return new ModifyInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request,this.router);
		} else {
			return new ModifyInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request);
		}
	}
	
	public ModifyInterceptorChain createModifyChain(int pos) {
		if (this.router != null) {
			return new ModifyInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request,this.router);
		} else {
			return new ModifyInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request);
		}
	}
	
	public DeleteInterceptorChain createDeleteChain() {
		if (this.router != null) {
			return new DeleteInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request,this.router);
		} else {
			return new DeleteInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request);
		}
	}
	
	public DeleteInterceptorChain createDeleteChain(int pos) {
		if (this.router != null) {
			return new DeleteInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request,this.router);
		} else {
			return new DeleteInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request);
		}
	}
	
	public RenameInterceptorChain createRenameChain() {
		if (this.router != null) {
			return new RenameInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request,this.router);
		} else {
			return new RenameInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request);
		}
	}
	
	public RenameInterceptorChain createRenameChain(int pos) {
		if (this.router != null) {
			return new RenameInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request,this.router);
		} else {
			return new RenameInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request);
		}
	}
	
	public ExetendedOperationInterceptorChain createExtendedOpChain() {
		if (this.router != null) {
			return new ExetendedOperationInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request,this.router);
		} else {
			return new ExetendedOperationInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request);
		}
	}
	
	public ExetendedOperationInterceptorChain createExtendedOpChain(int pos) {
		if (this.router != null) {
			return new ExetendedOperationInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request,this.router);
		} else {
			return new ExetendedOperationInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request);
		}
	}
	
	public SearchInterceptorChain createSearchChain() {
		if (this.router != null) {
			return new SearchInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request,this.router);
		} else {
			return new SearchInterceptorChain(this.bindDN,this.password,this.pos,this.chain,this.session,this.request);
		}
	}
	
	public SearchInterceptorChain createSearchChain(int pos) {
		if (this.router != null) {
			return new SearchInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request,this.router);
		} else {
			return new SearchInterceptorChain(this.bindDN,this.password,pos,this.chain,this.session,this.request);
		}
	}
	
	public int getPositionInChain(Insert insert) {
		return this.chain.getPositionInChain(insert);
	}
	

	public InsertChain getInterceptors() {
		return this.chain;
	}
	
	public int getPos() {
		return this.pos;
	}
	
	
	
	public void setBindDN(DistinguishedName dn) {
		this.bindDN = dn;
	}
	
	public Connection createJdbcLdapConnection() throws SQLException {
		
		
		String url = "ldap://nohost:0/?NO_CONNECTION:=true,BACKEND_PACKAGE:=net.sourceforge.myvd.chain.jdbcLdapImpl";
		Properties props = new Properties();
		props.setProperty(JndiLdapConnection.BACKEND_PACKAGE,"net.sourceforge.myvd.chain.jdbcLdapImpl");
		props.setProperty(JndiLdapConnection.NO_CONNECTION,"true");
		JndiLdapConnection con = new JndiLdapConnection(url,props);
		Iterator<String> it = con.getImplClasses().keySet().iterator();
		while (it.hasNext()) {
			((ChainedImpl) con.getImplClasses().get(it.next())).setChain(this);
		}
		return con;
	}
}
