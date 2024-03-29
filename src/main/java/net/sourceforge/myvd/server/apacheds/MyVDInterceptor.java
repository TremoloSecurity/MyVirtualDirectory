/*
 * Copyright 2022 Tremolo Security, Inc. 
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

package net.sourceforge.myvd.server.apacheds;

import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.ConnectionEventLogger;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.types.SessionVariables;
import net.sourceforge.myvd.types.TlsParameters;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.TremoloEntry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.AssertionType;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.ExtensibleNode;
import org.apache.directory.api.ldap.model.filter.FilterEncoder;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.filter.LessEqNode;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.filter.ObjectClassNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.filter.SubstringNode;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.AttributeTypeOptions;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.StringConstants;
import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.BaseInterceptor;
import org.apache.directory.server.core.api.interceptor.context.AbstractOperationContext;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.api.interceptor.context.CompareOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.GetRootDseOperationContext;
import org.apache.directory.server.core.api.interceptor.context.HasEntryOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveAndRenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveOperationContext;
import org.apache.directory.server.core.api.interceptor.context.RenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.api.interceptor.context.UnbindOperationContext;
import org.apache.directory.server.core.shared.DefaultCoreSessionImpl;
import org.apache.logging.log4j.Logger;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.ssl.SslFilter;
import org.apache.directory.server.core.shared.DefaultCoreSession;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.ByteArray;

public class MyVDInterceptor extends BaseInterceptor {

	public static final Object USER_SESSION = "MYVD_USER_SESSION";

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(MyVDInterceptor.class.getName());
	
	InsertChain globalChain;
	Router router;
	SchemaManager schemaManager;
	HashSet<String> binaryAttrs;
	
	ConnectionEventLogger conLogger;
	
	public MyVDInterceptor(InsertChain globalChain,Router router,SchemaManager schemaManager,HashSet<String> binaryAttrs) {
		this.globalChain = globalChain;
		this.router = router;
		this.schemaManager = schemaManager;
		this.binaryAttrs = binaryAttrs;
		
		
		String className = System.getProperty("myvd.connectionLogger");
		if (className != null) {
			logger.info("Connection logger : '" + className + "'");
			try {
				this.conLogger = (ConnectionEventLogger) Class.forName(className).newInstance();
			} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
				logger.warn("Could not load the event logger",e);
			}
		} else {
			logger.info("No connection event logger");
		}
	}
	
	
	private HashMap<Object,Object> getUserSession(AbstractOperationContext op) {
		
		if (op instanceof BindOperationContext) {
			BindOperationContext bind = (BindOperationContext) op;
			HashMap<Object,Object> userSession = (HashMap<Object, Object>) bind.getIoSession().getAttribute(MyVDInterceptor.USER_SESSION);
			
			if (userSession == null) {
				userSession = new HashMap<Object,Object>();
				bind.getIoSession().setAttribute(MyVDInterceptor.USER_SESSION, userSession);
				userSession.put("LDAP_CONNECTION_NUMBER", bind.getIoSession().getId());
			}
			
			return userSession;
		} else {
			HashMap<Object,Object> userSession = (HashMap<Object, Object>) ((DefaultCoreSession)op.getSession()).getIoSession().getAttribute(MyVDInterceptor.USER_SESSION);
			
			if (userSession == null) {
				userSession = new HashMap<Object,Object>();
				((DefaultCoreSession)op.getSession()).getIoSession().setAttribute(MyVDInterceptor.USER_SESSION, userSession);
				userSession.put("LDAP_CONNECTION_NUMBER", ((DefaultCoreSession)op.getSession()).getIoSession().getId());
			}
			
			return userSession;
		}
		
		
		
	}
	
	@Override
	public void add(AddOperationContext add) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(add);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
			
			
		}
		
		synchronized(userSession) {
		
		
			setTLSSessionParams(userSession,add.getSession());
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (add.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(add.getSession().getAuthenticatedPrincipal().getDn().getName());
				if (userSession.get("MYVD_BINDPASS") != null) {
					password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
				} else {
					password = null;
				}
			}
			
			Password pass = new Password(password);
			
			AddInterceptorChain chain = new AddInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
			
			
			LDAPAttributeSet attrs = new LDAPAttributeSet();
			for (Attribute attr : add.getEntry().getAttributes()) {
				
				LDAPAttribute lattr = attrs.getAttribute(attr.getAttributeType().getName());
				if (lattr == null) {
					lattr = new LDAPAttribute(attr.getAttributeType().getName());
					attrs.add(lattr);
				}
				
				
				
				if (attr.isHumanReadable()) {
					for (Value v : attr) {
						lattr.addValue(v.getString());
					}
				} else {
					for (Value v : attr) {
						lattr.addValue(v.getBytes());
					}
				}
				
			}
			
			LDAPEntry nentry = new LDAPEntry(add.getEntry().getDn().getName(),attrs);
			
			LDAPConstraints cons = new LDAPConstraints();
			
			
			
			try {
				chain.nextAdd(new net.sourceforge.myvd.types.Entry(nentry),cons);
			} catch (LDAPException e) {
				throw generateException(e);
				
			}
		}
	}

	private void setTLSSessionParams(HashMap<Object, Object> userSession,
			CoreSession session) {
		this.setTLSSessionParams(userSession, ((DefaultCoreSession)session).getIoSession());
		
	}

	private void setTLSSessionParams(HashMap<Object, Object> userSession,
			IoSession ioSession) {
		
		
		SslFilter filter = null;
		
		if (ioSession != null) { 
			filter = (SslFilter) ioSession.getFilterChain().get("sslFilter");
		}
		
		if (filter != null) {
			SSLSession tlssession =  filter.getSslSession(ioSession);
			if (tlssession != null) {
				try {
					TlsParameters tlsParams = new TlsParameters(tlssession.getCipherSuite(),(java.security.cert.X509Certificate[]) tlssession.getPeerCertificates());
					userSession.put(SessionVariables.TLS_PARAMS, tlsParams);
				} catch (SSLPeerUnverifiedException e) {
					//no need to log this
					//logger.warn("Could not get TLS information",e);
					
				}
			}
		}
		
		
	}

	@Override
	public void bind(BindOperationContext bindContext) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(bindContext);
		synchronized (userSession) {
			bindContext.getIoSession().setAttribute("MYVD_USER_SESSION", userSession);
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (bindContext.getSession() == null) {
				//userSession = new HashMap<Object,Object>();
				//bindContext.getIoSession().setAttribute("MYVD_USER_SESSION", userSession);
				
				bindDN = new DistinguishedName("");
				password = null;
				
				
				
			} else {
				//userSession = bindContext.getSession().getUserSession();*/
				
			
				if (bindContext.getSession().isAnonymous()) {
					bindDN = new DistinguishedName("");
					password = null;
				} else {
					bindDN = new DistinguishedName(bindContext.getSession().getAuthenticatedPrincipal().getDn().getName());
					if (bindContext.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
						password = bindContext.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
					} else {
						password = null;
					}
				}
			}
			
			
			if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
				userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			}
			
			setTLSSessionParams(userSession,bindContext.getIoSession());
			
			
			
			Password pass = new Password(password);
			
			/*StringBuffer sb = new StringBuffer();
			
			
			for (Rdn rdn : bindContext.getDn().getRdns()) {
				sb.append(rdn.getAva().getAttributeType().getNames().get(0)).append('=').append(rdn.getValue().getString()).append(',');
			}
			
			sb.setLength(sb.length() - 1);*/
			
			DistinguishedName newBindDN = new DistinguishedName(bindContext.getDn().toString());
	        Password newPass = new Password(bindContext.getCredentials());
	        
	        try {
	        	BindInterceptorChain chain = new BindInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,router);
	        	chain.nextBind(newBindDN,newPass,new LDAPConstraints());
	        } catch (LDAPException e) {
	        	throw MyVDInterceptor.generateException(e);
	        }
	        
	        userSession.put("MYVD_BINDDN",newBindDN);
	        userSession.put("MYVD_BINDPASS",newPass);
	        
	        LdapPrincipal principal = new LdapPrincipal(this.schemaManager,bindContext.getDn(),AuthenticationLevel.SIMPLE,  bindContext.getCredentials());
	        
	        IoSession session = bindContext.getIoSession();
	
	        if ( session != null )
	        {
	            SocketAddress clientAddress = session.getRemoteAddress();
	            principal.setClientAddress( clientAddress );
	            SocketAddress serverAddress = session.getServiceAddress();
	            principal.setServerAddress( serverAddress );
	        }
	        
	     
	
	        LdapPrincipal clonedPrincipal = null;
			try {
				clonedPrincipal = ( LdapPrincipal ) ( principal.clone() );
			} catch (CloneNotSupportedException e) {
				//not possible
			}
	
	        // remove creds so there is no security risk
	        bindContext.setCredentials( null );
	        clonedPrincipal.setUserPassword( new byte[0] );
	
	        // authentication was successful
	        CoreSession csession = new DefaultCoreSessionImpl( clonedPrincipal, directoryService );
	        bindContext.setSession( csession );
		}
	}

	@Override
	public boolean compare(CompareOperationContext compareContext)
			throws LdapException {
		
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();

		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(compareContext);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
		}
		
		synchronized (userSession) {
		
			setTLSSessionParams(userSession,compareContext.getSession());
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (compareContext.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(compareContext.getSession().getAuthenticatedPrincipal().getDn().getName());
				if (userSession.get("MYVD_BINDPASS") != null) {
					password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
				} else {
					password = null;
				}
			}
			
			Password pass = new Password(password);
			
			SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
			Results res = new Results(this.globalChain);
			
			String compareFilter = FilterBuilder.equal(compareContext.getOid(),compareContext.getValue().getString()).toString();
	
			try {
				chain.nextSearch(new DistinguishedName(compareContext.getDn().toString()), new Int(0), new Filter(compareFilter), new ArrayList<net.sourceforge.myvd.types.Attribute>(), new Bool(false), res, new LDAPSearchConstraints());
				res.start();
				if (res.hasMore()) {
					res.next();
					while (res.hasMore()) res.next();
					res.finish();
					return true;
				} else {
					res.finish();
					return false;
				}
				
			} catch (LDAPException e) {
				throw generateException(e);
			}

		}

	}

	@Override
	public void delete(DeleteOperationContext del)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(del);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
		}
		
		synchronized(userSession) {
		
			setTLSSessionParams(userSession,del.getSession());
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (del.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(del.getSession().getAuthenticatedPrincipal().getDn().getName());
				if (userSession.get("MYVD_BINDPASS") != null) {
					password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
				} else {
					password = null;
				}
			}
			
			Password pass = new Password(password);
			
			
			
			
			
			DeleteInterceptorChain dchain = new DeleteInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
			LDAPConstraints cons = new LDAPConstraints();
			
			try {
				dchain.nextDelete(new DistinguishedName(del.getDn().getName()), cons);
			} catch (LDAPException e) {
				throw generateException(e);
			}
		
		}
	}

	@Override
	public boolean hasEntry(HasEntryOperationContext has)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(has);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
		}
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (has.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(has.getSession().getAuthenticatedPrincipal().getDn().getName());
			if (userSession.get("MYVD_BINDPASS") != null) {
				password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
			} else {
				password = null;
			}
		}
		
		Password pass = new Password(password);
		
		
		SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		Results res = new Results(this.globalChain);
		Entry entry = new TremoloEntry();
		try {
			ArrayList<net.sourceforge.myvd.types.Attribute> attrs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
			net.sourceforge.myvd.types.Attribute none = new net.sourceforge.myvd.types.Attribute("1.1");
			attrs.add(none);
			chain.nextSearch(new DistinguishedName(has.getDn().getName()), new Int(0), new Filter("(objectClass=*)"), attrs, new Bool(false), res, new LDAPSearchConstraints());
			
			boolean more = res.hasMore();
			
			if (more) {
				res.next();
				while (res.hasMore()) res.next();
				return true;
			} else {
				return false;
			}
			
		} catch (LDAPException e1) {
			if (e1.getResultCode() == 32) {
				return false;
			} else {
				throw generateException(e1);
			}
		}
	}

	@Override
	public Entry lookup(LookupOperationContext lookup)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(lookup);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
		}
		
		synchronized (userSession) {
		
			setTLSSessionParams(userSession,lookup.getSession());
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (lookup.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(lookup.getSession().getAuthenticatedPrincipal().getDn().getName());
				if (userSession.get("MYVD_BINDPASS") != null) {
					password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
				} else {
					password = null;
				}
			}
			
			Password pass = new Password(password);
			
			
			SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
			Results res = new Results(this.globalChain);
			Entry entry = new TremoloEntry();
			try {
				chain.nextSearch(new DistinguishedName(lookup.getDn().getName()), new Int(0), new Filter("(objectClass=*)"), new ArrayList<net.sourceforge.myvd.types.Attribute>(), new Bool(false), res, new LDAPSearchConstraints());
				res.start();
				if (res.hasMore()) {
					LDAPEntry nentry = res.next().getEntry();
					
					
					
					entry.setDn(nentry.getDN());
					LDAPAttributeSet attrs = nentry.getAttributeSet();
					for (Object o : attrs) {
						LDAPAttribute a = (LDAPAttribute) o;
						
						LinkedList<ByteArray> vals = a.getAllValues();
						for (ByteArray val : vals) {
							entry.add(a.getName(),val.getValue());
						}
					}
					
					while (res.hasMore()) res.next();
					return entry;
				} else {
					return null;
				}
				
			} catch (LDAPException e1) {
				if (e1.getResultCode() == 32) {
					return null;
				} else {
					throw generateException(e1);
				}
				
				
			}
		}
	}

	@Override
	public void modify(ModifyOperationContext mod)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(mod);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
		}
		
		synchronized (userSession) {
			setTLSSessionParams(userSession,mod.getSession());
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (mod.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(mod.getSession().getAuthenticatedPrincipal().getDn().getName());
				/*if (mod.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
					password = mod.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
				} else {
					password = null;
				}*/
	
				if (userSession.get("MYVD_BINDPASS") != null) {
					password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
				} else {
					password = null;
				}
			}
			
			Password pass = new Password(password);
			
			ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
			
			for (Modification modification : mod.getModItems()) {
				LDAPModification ldapMod = new LDAPModification(modification.getOperation().getValue(),new LDAPAttribute(modification.getAttribute().getAttributeType().getName()));
				
				if (modification.getAttribute().isHumanReadable()) {
					for (Value s : modification.getAttribute()) {
						ldapMod.getAttribute().addValue(s.getString());
					}
				} else {
					for (Value s : modification.getAttribute()) {
						ldapMod.getAttribute().addValue(s.getBytes());
					}
				}
				
				mods.add(ldapMod);
			}
			
			ModifyInterceptorChain chain = new ModifyInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
			LDAPConstraints cons = new LDAPConstraints();
			
			try {
				chain.nextModify(new DistinguishedName(mod.getDn().getName()), mods, cons);
			} catch (LDAPException e) {
				throw generateException(e);
			}
		}
	}

	@Override
	public void move(MoveOperationContext move) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(move);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
		}
		
		synchronized (userSession) {
			setTLSSessionParams(userSession,move.getSession());
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (move.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
				if (userSession.get("MYVD_BINDPASS") != null) {
					password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
				} else {
					password = null;
				}
			}
			
			Password pass = new Password(password);
			
			
			
			RenameInterceptorChain chain = new RenameInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
			LDAPConstraints cons = new LDAPConstraints();
			
			try {
				chain.nextRename(new DistinguishedName(move.getDn().getName()), new DistinguishedName(move.getRdn().getName()), new DistinguishedName(move.getNewSuperior().getName()), new Bool(true), cons);
			} catch (LDAPException e) {
				throw generateException(e);
			}
		}
	}

	@Override
	public void moveAndRename(MoveAndRenameOperationContext move)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(move);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
		}
		
		synchronized (userSession) {
		
			setTLSSessionParams(userSession,move.getSession());
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (move.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
				if (userSession.get("MYVD_BINDPASS") != null) {
					password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
				} else {
					password = null;
				}
			}
			
			Password pass = new Password(password);
			
			
			
			RenameInterceptorChain chain = new RenameInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
			LDAPConstraints cons = new LDAPConstraints();
			
			try {
				chain.nextRename(new DistinguishedName(move.getDn().getName()), new DistinguishedName(move.getNewRdn().getName()), new DistinguishedName(move.getNewSuperiorDn().getName()), new Bool(true), cons);
			} catch (LDAPException e) {
				throw generateException(e);
			}
		}
	}

	@Override
	public void rename(RenameOperationContext move)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = this.getUserSession(move);
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
			
		}
		
		synchronized (userSession) {
			setTLSSessionParams(userSession,move.getSession());
			
			DistinguishedName bindDN;
			byte[] password;
			
			if (move.getSession().isAnonymous()) {
				bindDN = new DistinguishedName("");
				password = null;
			} else {
				bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
				if (userSession.get("MYVD_BINDPASS") != null) {
					password = ((Password) userSession.get("MYVD_BINDPASS")).getValue();
				} else {
					password = null;
				}
			}
			
			Password pass = new Password(password);
			
			
			
			RenameInterceptorChain chain = new RenameInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
			LDAPConstraints cons = new LDAPConstraints();
			
			try {
				chain.nextRename(new DistinguishedName(move.getDn().getName()), new DistinguishedName(move.getNewRdn().getName()), new Bool(true), cons);
				
			} catch (LDAPException e) {
				throw generateException(e);
			}
		}
	}

	@Override
	public EntryFilteringCursor search(SearchOperationContext search)
			throws LdapException {
				// ignore all requests from the system user
				if (search.getSession().getAuthenticatedPrincipal().getDn().toString().equalsIgnoreCase("uid=admin,ou=system")) {
					Results res = new Results(this.globalChain);
					return new MyVDBaseCursor(new MyVDCursor(res,this.schemaManager),search,this.schemaManager);
				}
				
				
				HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
				
				//how to track?
				HashMap<Object,Object> userSession = this.getUserSession(search);
				if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
					userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
					
				}
				
				synchronized (userSession) {

					Password currentSessionPassword = (Password) userSession.get("MYVD_BINDPASS");
					
					setTLSSessionParams(userSession,search.getSession());
					
					DistinguishedName bindDN;
					byte[] password;
					
					if (search.getSession().isAnonymous()) {
						bindDN = new DistinguishedName("");
						password = null;
					} else {
						bindDN = new DistinguishedName(search.getSession().getAuthenticatedPrincipal().getDn().getName());
						if (currentSessionPassword != null) {
							password = currentSessionPassword.getValue();
						} else {
							password = null;
						}
					}
					
					Password pass = new Password(password);
					
					
					SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
					Results res = new Results(this.globalChain);
					
					ArrayList<net.sourceforge.myvd.types.Attribute> attrs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
					
					if (! search.isNoAttributes()) {
					
						if (search.getReturningAttributes() != null) {
							for (AttributeTypeOptions attrType : search.getReturningAttributes()) {
								attrs.add(new net.sourceforge.myvd.types.Attribute(attrType.getAttributeType().getName()));
							}
						}
					} else {
						attrs.add(new net.sourceforge.myvd.types.Attribute("1.1"));
					}
					
					/*StringBuffer sb = new StringBuffer();
					
					
					for (Rdn rdn : search.getDn().getRdns()) {
						sb.append(rdn.getAva().getAttributeType().getNames().get(0)).append('=').append(rdn.getValue().getString()).append(',');
					}
					
					sb.setLength(sb.length() - 1);*/
					
					
					
					Filter filter = this.generateMyVDFilter(search.getFilter());
					
					if (filter == null) {
						throw new LdapInvalidSearchFilterException("Unable to parse filter : '" + search.getFilter().toString() + "'");
					}
					
					try {
						
						StringBuffer newdn = new StringBuffer();
						boolean indq = false;
						char last = 0;
						for (char c : search.getDn().toString().toCharArray()) {
							if (c == '"') {
								indq = !indq;
							} else if (c == ',') {
								if (indq) {
									
									newdn.append("\\,");
									
								} else {
									newdn.append(',');
								}
							} else {
								newdn.append(c);
							}
							
							last = c;
						}
						
						LDAPSearchConstraints ldapsc = new LDAPSearchConstraints();
						ldapsc.setMaxResults((int)search.getSizeLimit());
						ldapsc.setTimeLimit(search.getTimeLimit());
						
						
						
						chain.nextSearch(new DistinguishedName(newdn.toString()), new Int(search.getScope().getScope()), filter, attrs, new Bool(search.isTypesOnly()), res, ldapsc);
						res.start();
					} catch (LDAPException e) {
						logger.error("Error Searching",e);
						
						throw this.generateException(e);
					} catch (Throwable t) {
						logger.error("Throwable Searching",t);
						throw new org.apache.directory.api.ldap.model.exception.LdapOperationErrorException(t.getMessage(), t);
					}
					
					return new MyVDBaseCursor(new MyVDCursor(res,this.schemaManager),search,this.schemaManager);
				}
	}

	@Override
	public void unbind(UnbindOperationContext unbindContext)
			throws LdapException {
		if (this.conLogger != null) {
			conLogger.unbind(((DefaultCoreSession)unbindContext.getSession()).getIoSession());
		}
		super.unbind(unbindContext);
	}
	
private Filter generateMyVDFilter(ExprNode root) {
		
		FilterNode myvdroot = copyNode(root);
		
		if (myvdroot == null) {
			return null;
		} else { 
			return new Filter(myvdroot);
		}
		
	}

	private FilterNode copyNode(ExprNode root) {
		if (root instanceof PresenceNode) {
			PresenceNode n = (PresenceNode) root;
			return new FilterNode(FilterType.PRESENCE,n.getAttribute(),"*");
		} else if (root instanceof ObjectClassNode) {
			return new FilterNode(FilterType.PRESENCE,"objectClass","*");
		} else if (root instanceof EqualityNode) {
			EqualityNode n = (EqualityNode) root;
			AttributeType at = n.getAttributeType();
			
			boolean isBinary = false;
			
			if (at == null) {
				
				
				try {
					String oid = this.schemaManager.getAttributeTypeRegistry().getOidByName(n.getAttribute());
					
					at = this.schemaManager.getAttributeType(oid);
					isBinary = ! at.getSyntax().isHumanReadable();
				} catch (LdapException e) {
					isBinary = this.binaryAttrs.contains(n.getAttribute().toLowerCase());
				}
			} else {
				isBinary = ! at.getSyntax().isHumanReadable();
			}
			
			if (isBinary) {
				byte[] enc = n.getValue().getBytes();
				
				StringBuilder sb = new StringBuilder(enc.length * 2);
				
				for (int i=0; i< enc.length; i++)
	    			
    			{
    			
    			sb.append(String.format("\\%02x", enc[i]));
    			
    			}
				
				return new FilterNode(FilterType.EQUALS,n.getAttribute(),sb.toString());
				
			} else {
				return new FilterNode(FilterType.EQUALS,n.getAttribute(),n.getValue().getString());
			}
			
		} else if (root instanceof GreaterEqNode) {
			GreaterEqNode n = (GreaterEqNode) root;
			return new FilterNode(FilterType.GREATER_THEN,n.getAttribute(),n.getValue().getString());
		} else if (root instanceof LessEqNode) {
			LessEqNode n = (LessEqNode) root;
			return new FilterNode(FilterType.LESS_THEN,n.getAttribute(),n.getValue().getString());
		} else if (root instanceof NotNode) {
			NotNode n = (NotNode) root;
			FilterNode not = copyNode(n.getFirstChild());
			
			return new FilterNode(not);
		} else if (root instanceof AndNode) {
			AndNode n = (AndNode) root;
			ArrayList<FilterNode> children = new ArrayList<FilterNode>();
			for (ExprNode node : n.getChildren()) {
				children.add(copyNode(node));
			}
			
			return new FilterNode(FilterType.AND,children);
		} else if (root instanceof OrNode) {
			OrNode n = (OrNode) root;
			ArrayList<FilterNode> children = new ArrayList<FilterNode>();
			for (ExprNode node : n.getChildren()) {
				children.add(copyNode(node));
			}
			
			return new FilterNode(FilterType.OR,children);
		} else if (root instanceof SubstringNode) {
			return new FilterNode(FilterType.SUBSTR,((SubstringNode) root).getAttribute(),getSubStrFilterText((SubstringNode) root));
		} else if (root instanceof ExtensibleNode) {
			ExtensibleNode enode = (ExtensibleNode) root;
			return new FilterNode(FilterType.EXT,enode.getAttribute() + ":" + enode.getMatchingRuleId(),enode.getValue().getString());
		}
		
		
		else return null;
	}
	
	private String getSubStrFilterText(SubstringNode node)
    {
        StringBuilder buf = new StringBuilder();

        

        if ( null != node.getInitial() )
        {
            buf.append( escapeFilterValue( new Value( node.getInitial() ) ) ).append( '*' );
        }
        else
        {
            buf.append( '*' );
        }

        if ( null != node.getAny() )
        {
            for ( String any : node.getAny() )
            {
                buf.append( escapeFilterValue( new Value( any ) ) );
                buf.append( '*' );
            }
        }

        if ( null != node.getFinal() )
        {
            buf.append( escapeFilterValue( new Value( node.getFinal() ) ) );
        }

        

        return buf.toString();
    }
	
	/**
     * Handles the escaping of special characters in LDAP search filter assertion values using the
     * &lt;valueencoding&gt; rule as described in
     * <a href="http://www.ietf.org/rfc/rfc4515.txt">RFC 4515</a>. Needed so that
     * {@link ExprNode#printToBuffer(StringBuffer)} results in a valid filter string that can be parsed
     * again (as a way of cloning filters).
     *
     * @param value Right hand side of "attrId=value" assertion occurring in an LDAP search filter.
     * @return Escaped version of <code>value</code>
     */
    protected Value escapeFilterValue( Value value )
    {
        if ( value.isNull() )
        {
            return value;
        }

        StringBuilder sb = null;
        String val;

        if ( !value.isHumanReadable() )
        {
            sb = new StringBuilder( value.getBytes().length * 3 );

            for ( byte b : value.getBytes() )
            {
                if ( ( b < 0x7F ) && ( b >= 0 ) )
                {
                    switch ( b )
                    {
                        case '*':
                            sb.append( "\\2A" );
                            break;

                        case '(':
                            sb.append( "\\28" );
                            break;

                        case ')':
                            sb.append( "\\29" );
                            break;

                        case '\\':
                            sb.append( "\\5C" );
                            break;

                        case '\0':
                            sb.append( "\\00" );
                            break;

                        default:
                            sb.append( ( char ) b );
                    }
                }
                else
                {
                    sb.append( '\\' );
                    String digit = Integer.toHexString( b & 0x00FF );

                    if ( digit.length() == 1 )
                    {
                        sb.append( '0' );
                    }

                    sb.append( digit.toUpperCase() );
                }
            }

            return new Value( sb.toString() );
        }

        val = ( ( Value ) value ).getString();
        String encodedVal = FilterEncoder.encodeFilterValue( val );
        if ( val.equals( encodedVal ) )
        {
            return value;
        }
        else
        {
            return new Value( encodedVal );
        }
    }
    
    public static LdapException generateException(LDAPException e) {
		LdapException ex;
		
		
		if (logger.isDebugEnabled()) {
			logger.debug("Exception: '" + e.getMessage() + " / " + e.getLDAPErrorMessage() + "/" + e.getMatchedDN(),e);
		}
		
		String errMsg = String.format("%s / %s / %s", e.getMessage(),e.getLDAPErrorMessage(),e.getMatchedDN());
		
		switch (e.getResultCode()) {
		
			
		
			case 1 : ex = new org.apache.directory.api.ldap.model.exception.LdapOperationErrorException(errMsg, e); break;
			case 2 : ex = new org.apache.directory.api.ldap.model.exception.LdapProtocolErrorException(errMsg, e); break;
			case 3 : ex = new org.apache.directory.api.ldap.model.exception.LdapTimeLimitExceededException(errMsg); break;
			case 4 : ex = new org.apache.directory.api.ldap.model.exception.LdapSizeLimitExceededException(errMsg); break;
			case 48:
			case 7 : ex = new org.apache.directory.api.ldap.model.exception.LdapAuthenticationNotSupportedException(ResultCodeEnum.AUTH_METHOD_NOT_SUPPORTED); break;
			case 8 : ex = new org.apache.directory.api.ldap.model.exception.LdapStrongAuthenticationRequiredException(errMsg); break;
			case 11 : ex = new org.apache.directory.api.ldap.model.exception.LdapAdminLimitExceededException(errMsg); break;
			case 53 :
			case 12 : ex = new org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException(errMsg); break;
			case 13 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoPermissionException(errMsg); break;
			case 16 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(errMsg); break;
			case 17 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(errMsg); break;
			case 18 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException(errMsg); break;
			case 21:
			case 19 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException(ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, errMsg);
			case 20 : ex = new org.apache.directory.api.ldap.model.exception.LdapAttributeInUseException(errMsg); break;
			case 32 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException(errMsg); break;
			case 34 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidDnException(errMsg); break;
			case 49 : ex = new org.apache.directory.api.ldap.model.exception.LdapAuthenticationException(errMsg); break;
			case 50 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoPermissionException(errMsg); break;
			case 52 :
			case 51 : ex = new org.apache.directory.api.ldap.model.exception.LdapServiceUnavailableException(ResultCodeEnum.UNAVAILABLE); break;
			case 54 : ex = new org.apache.directory.api.ldap.model.exception.LdapLoopDetectedException(errMsg);
			case 64 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidDnException(errMsg); break;
			case 65 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(errMsg); break;
			case 66 : ex = new org.apache.directory.api.ldap.model.exception.LdapContextNotEmptyException(errMsg); break;
			case 69 :
			case 67 : ex = new org.apache.directory.api.ldap.model.exception.LdapSchemaException(errMsg); break;
			case 68 : ex = new org.apache.directory.api.ldap.model.exception.LdapEntryAlreadyExistsException(errMsg); break;
			case 71 : ex = new org.apache.directory.api.ldap.model.exception.LdapAffectMultipleDsaException(errMsg); break;
			case 80 : ex = new org.apache.directory.api.ldap.model.exception.LdapOtherException(errMsg); break;
		    		
			default : ex = new org.apache.directory.api.ldap.model.exception.LdapOperationErrorException(errMsg, e); break;
		}
		
		ex.setStackTrace(e.getStackTrace());
		return ex;
	}

	@Override
	public Entry getRootDse(GetRootDseOperationContext getRootDseContext)
			throws LdapException {
		// TODO Auto-generated method stub
		return super.getRootDse(getRootDseContext);
	}

}
