package net.sourceforge.myvd.server.apacheds;

import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
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

import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.AssertionType;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
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
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.BaseInterceptor;
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
import org.apache.directory.server.core.shared.DefaultCoreSession;
import org.apache.mina.core.session.IoSession;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

public class MyVDInterceptor extends BaseInterceptor {

	InsertChain globalChain;
	Router router;
	SchemaManager schemaManager;
	HashSet<String> binaryAttrs;
	
	public MyVDInterceptor(InsertChain globalChain,Router router,SchemaManager schemaManager,HashSet<String> binaryAttrs) {
		this.globalChain = globalChain;
		this.router = router;
		this.schemaManager = schemaManager;
		this.binaryAttrs = binaryAttrs;
	}
	
	@Override
	public void add(AddOperationContext add) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = add.getSession().getUserSession();
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		}
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (add.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(add.getSession().getAuthenticatedPrincipal().getDn().getName());
			if (add.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
				password = add.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
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
				for (Value<?> v : attr) {
					lattr.addValue(v.getString());
				}
			} else {
				for (Value<?> v : attr) {
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

	@Override
	public void bind(BindOperationContext bindContext) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = null;
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (bindContext.getSession() == null) {
			userSession = new HashMap<Object,Object>();
			bindContext.getIoSession().setAttribute("MYVD_USER_SESSION", userSession);
			
			bindDN = new DistinguishedName("");
			password = null;
			
		} else {
			userSession = bindContext.getSession().getUserSession();
			
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
        clonedPrincipal.setUserPassword( StringConstants.EMPTY_BYTES );

        // authentication was successful
        CoreSession csession = new DefaultCoreSession( clonedPrincipal, directoryService );
        bindContext.setSession( csession );
	}

	@Override
	public boolean compare(CompareOperationContext compareContext)
			throws LdapException {
		// TODO Auto-generated method stub
		return super.compare(compareContext);
	}

	@Override
	public void delete(DeleteOperationContext del)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = del.getSession().getUserSession();
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		}
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (del.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(del.getSession().getAuthenticatedPrincipal().getDn().getName());
			if (del.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
				password = del.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
			} else {
				password = null;
			}
		}
		
		Password pass = new Password(password);
		
		
		/*SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		Results res = new Results(this.globalChain);
		Entry entry = new DefaultEntry();
		try {
			chain.nextSearch(new DistinguishedName(del.getDn().getName()), new Int(0), new Filter("(objectClass=*)"), new ArrayList<net.sourceforge.myvd.types.Attribute>(), new Bool(false), res, new LDAPSearchConstraints());
			res.next();
			res.hasMore();
			LDAPEntry nentry = res.next().getEntry();
			
			
			entry.setDn(nentry.getDN());
			LDAPAttributeSet attrs = nentry.getAttributeSet();
			for (Object o : attrs) {
				LDAPAttribute a = (LDAPAttribute) o;
				byte[][] vals = a.getByteValueArray();
				for (int i=0;i<vals.length;i++) {
					entry.add(a.getName(),vals[i]);
				}
			}
		} catch (LDAPException e1) {
			throw generateException(e1);
		}*/
		
		
		DeleteInterceptorChain dchain = new DeleteInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		LDAPConstraints cons = new LDAPConstraints();
		
		try {
			dchain.nextDelete(new DistinguishedName(del.getDn().getName()), cons);
		} catch (LDAPException e) {
			throw generateException(e);
		}
		
		
	}

	@Override
	public boolean hasEntry(HasEntryOperationContext has)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = has.getSession().getUserSession();
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
			if (has.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
				password = has.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
			} else {
				password = null;
			}
		}
		
		Password pass = new Password(password);
		
		
		SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		Results res = new Results(this.globalChain);
		Entry entry = new DefaultEntry();
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
		HashMap<Object,Object> userSession = lookup.getSession().getUserSession();
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		}
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (lookup.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(lookup.getSession().getAuthenticatedPrincipal().getDn().getName());
			if (lookup.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
				password = lookup.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
			} else {
				password = null;
			}
		}
		
		Password pass = new Password(password);
		
		
		SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
		Results res = new Results(this.globalChain);
		Entry entry = new DefaultEntry();
		try {
			chain.nextSearch(new DistinguishedName(lookup.getDn().getName()), new Int(0), new Filter("(objectClass=*)"), new ArrayList<net.sourceforge.myvd.types.Attribute>(), new Bool(false), res, new LDAPSearchConstraints());
			res.start();
			if (res.hasMore()) {
				LDAPEntry nentry = res.next().getEntry();
				
				
				
				entry.setDn(nentry.getDN());
				LDAPAttributeSet attrs = nentry.getAttributeSet();
				for (Object o : attrs) {
					LDAPAttribute a = (LDAPAttribute) o;
					byte[][] vals = a.getByteValueArray();
					for (int i=0;i<vals.length;i++) {
						entry.add(a.getName(),vals[i]);
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

	@Override
	public void modify(ModifyOperationContext mod)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = mod.getSession().getUserSession();
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		}
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (mod.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(mod.getSession().getAuthenticatedPrincipal().getDn().getName());
			if (mod.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
				password = mod.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
			} else {
				password = null;
			}
		}
		
		Password pass = new Password(password);
		
		ArrayList<LDAPModification> mods = new ArrayList<LDAPModification>();
		
		for (Modification modification : mod.getModItems()) {
			LDAPModification ldapMod = new LDAPModification(modification.getOperation().getValue(),new LDAPAttribute(modification.getAttribute().getAttributeType().getName()));
			
			if (modification.getAttribute().isHumanReadable()) {
				for (Value<?> s : modification.getAttribute()) {
					ldapMod.getAttribute().addValue(s.getString());
				}
			} else {
				for (Value<?> s : modification.getAttribute()) {
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

	@Override
	public void move(MoveOperationContext move) throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = move.getSession().getUserSession();
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		}
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (move.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
			if (move.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
				password = move.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
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

	@Override
	public void moveAndRename(MoveAndRenameOperationContext move)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = move.getSession().getUserSession();
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		}
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (move.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
			if (move.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
				password = move.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
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

	@Override
	public void rename(RenameOperationContext move)
			throws LdapException {
		HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
		
		//how to track?
		HashMap<Object,Object> userSession = move.getSession().getUserSession();
		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
		}
		
		DistinguishedName bindDN;
		byte[] password;
		
		if (move.getSession().isAnonymous()) {
			bindDN = new DistinguishedName("");
			password = null;
		} else {
			bindDN = new DistinguishedName(move.getSession().getAuthenticatedPrincipal().getDn().getName());
			if (move.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
				password = move.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
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
				HashMap<Object,Object> userSession = search.getSession().getUserSession();
				if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
					userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
				}
				
				DistinguishedName bindDN;
				byte[] password;
				
				if (search.getSession().isAnonymous()) {
					bindDN = new DistinguishedName("");
					password = null;
				} else {
					bindDN = new DistinguishedName(search.getSession().getAuthenticatedPrincipal().getDn().getName());
					if (search.getSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
						password = search.getSession().getAuthenticatedPrincipal().getUserPasswords()[0];
					} else {
						password = null;
					}
				}
				
				Password pass = new Password(password);
				
				
				SearchInterceptorChain chain = new SearchInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,this.router);
				Results res = new Results(this.globalChain);
				
				ArrayList<net.sourceforge.myvd.types.Attribute> attrs = new ArrayList<net.sourceforge.myvd.types.Attribute>();
				
				if (! search.isNoAttributes()) {
				
					if (search.getOriginalAttributes() != null) {
						for (String attrName : search.getOriginalAttributes()) {
							attrs.add(new net.sourceforge.myvd.types.Attribute(attrName));
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
					chain.nextSearch(new DistinguishedName(search.getDn().toString()), new Int(search.getScope().getScope()), filter, attrs, new Bool(search.isTypesOnly()), res, new LDAPSearchConstraints());
					res.start();
				} catch (LDAPException e) {
					throw this.generateException(e);
				}
				
				return new MyVDBaseCursor(new MyVDCursor(res,this.schemaManager),search,this.schemaManager);
	}

	@Override
	public void unbind(UnbindOperationContext unbindContext)
			throws LdapException {
		// TODO Auto-generated method stub
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
		} else return null;
	}
	
	private String getSubStrFilterText(SubstringNode node)
    {
        StringBuilder buf = new StringBuilder();

        

        if ( null != node.getInitial() )
        {
            buf.append( escapeFilterValue( new StringValue( node.getInitial() ) ) ).append( '*' );
        }
        else
        {
            buf.append( '*' );
        }

        if ( null != node.getAny() )
        {
            for ( String any : node.getAny() )
            {
                buf.append( escapeFilterValue( new StringValue( any ) ) );
                buf.append( '*' );
            }
        }

        if ( null != node.getFinal() )
        {
            buf.append( escapeFilterValue( new StringValue( node.getFinal() ) ) );
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
    protected Value<?> escapeFilterValue( Value<?> value )
    {
        if ( value.isNull() )
        {
            return value;
        }

        StringBuilder sb = null;
        String val;

        if ( !value.isHumanReadable() )
        {
            sb = new StringBuilder( ( ( BinaryValue ) value ).getReference().length * 3 );

            for ( byte b : ( ( BinaryValue ) value ).getReference() )
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

            return new StringValue( sb.toString() );
        }

        val = ( ( StringValue ) value ).getString();
        String encodedVal = FilterEncoder.encodeFilterValue( val );
        if ( val.equals( encodedVal ) )
        {
            return value;
        }
        else
        {
            return new StringValue( encodedVal );
        }
    }
    
    public static LdapException generateException(LDAPException e) {
		LdapException ex;
		
		switch (e.getResultCode()) {
		
			
			case 1 : ex = new org.apache.directory.api.ldap.model.exception.LdapOperationErrorException(e.getMessage(), e); break;
			case 2 : ex = new org.apache.directory.api.ldap.model.exception.LdapProtocolErrorException(e.getMessage(), e); break;
			case 3 : ex = new org.apache.directory.api.ldap.model.exception.LdapTimeLimitExceededException(e.getMessage()); break;
			case 4 : ex = new org.apache.directory.api.ldap.model.exception.LdapSizeLimitExceededException(e.getMessage()); break;
			case 48:
			case 7 : ex = new org.apache.directory.api.ldap.model.exception.LdapAuthenticationNotSupportedException(ResultCodeEnum.AUTH_METHOD_NOT_SUPPORTED); break;
			case 8 : ex = new org.apache.directory.api.ldap.model.exception.LdapStrongAuthenticationRequiredException(e.getMessage()); break;
			case 11 : ex = new org.apache.directory.api.ldap.model.exception.LdapAdminLimitExceededException(e.getMessage()); break;
			case 53 :
			case 12 : ex = new org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException(e.getMessage()); break;
			case 13 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoPermissionException(e.getMessage()); break;
			case 16 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(e.getMessage()); break;
			case 17 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(e.getMessage()); break;
			case 18 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException(e.getMessage()); break;
			case 21:
			case 19 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException(ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, e.getMessage());
			case 20 : ex = new org.apache.directory.api.ldap.model.exception.LdapAttributeInUseException(e.getMessage()); break;
			case 32 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException(e.getMessage()); break;
			case 34 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidDnException(e.getMessage()); break;
			case 49 : ex = new org.apache.directory.api.ldap.model.exception.LdapAuthenticationException(e.getMessage()); break;
			case 50 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoPermissionException(e.getMessage()); break;
			case 52 :
			case 51 : ex = new org.apache.directory.api.ldap.model.exception.LdapServiceUnavailableException(ResultCodeEnum.UNAVAILABLE); break;
			case 54 : ex = new org.apache.directory.api.ldap.model.exception.LdapLoopDetectedException(e.getMessage());
			case 64 : ex = new org.apache.directory.api.ldap.model.exception.LdapInvalidDnException(e.getMessage()); break;
			case 65 : ex = new org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException(e.getMessage()); break;
			case 66 : ex = new org.apache.directory.api.ldap.model.exception.LdapContextNotEmptyException(e.getMessage()); break;
			case 69 :
			case 67 : ex = new org.apache.directory.api.ldap.model.exception.LdapSchemaException(e.getMessage()); break;
			case 68 : ex = new org.apache.directory.api.ldap.model.exception.LdapEntryAlreadyExistsException(e.getMessage()); break;
			case 71 : ex = new org.apache.directory.api.ldap.model.exception.LdapAffectMultipleDsaException(e.getMessage()); break;
			case 80 : ex = new org.apache.directory.api.ldap.model.exception.LdapOtherException(e.getMessage()); break;
		    		
			default : ex = new org.apache.directory.api.ldap.model.exception.LdapOperationErrorException(e.getMessage(), e); break;
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
