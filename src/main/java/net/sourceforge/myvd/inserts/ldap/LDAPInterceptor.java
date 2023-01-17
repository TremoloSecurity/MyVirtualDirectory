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
package net.sourceforge.myvd.inserts.ldap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

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
import net.sourceforge.myvd.inserts.ldap.pool2.InspectCheckedoutConnections;
import net.sourceforge.myvd.inserts.ldap.pool2.LdapPool;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.types.SessionVariables;
import net.sourceforge.myvd.util.NamingUtils;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPLocalException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.util.DN;

import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.logging.log4j.Logger;

public class LDAPInterceptor implements Insert {

    public static final String NO_MAP_BIND_DN = "NO_MAP_BIND_DN_";
    static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LDAPInterceptor.class);
    String host;
    int port;
    String name;
    DN remoteBase;
    String[] explodedRemoteBase;
    String[] explodedLocalBase;

    String proxyDN;
    byte[] proxyPass;

    LDAPConnectionType type;

    String spmlImpl;

    boolean isSoap;

    boolean passThroughBindOnly;
    boolean ignoreRefs;

    boolean usePaging;
    int pageSize;

    NamingUtils utils;

    //LDAPConnectionPool pool;
    LDAPSocketFactory socketFactory;

    String noMapBindFlag;

    long maxIdleTime;
    private int maxOpMillis;
    private long maxStaleTime;
    private DistinguishedName localBase;

    private long heartbeatIntervalMinis;

    private LDAPHeartBeat heartBeat;
    public boolean useSrvDNS;
    
    int maxOpsPerCon;
    long maxCheckoutTimePerCon;
    
    int cleanupDelay;
	private ConnectionCleanupPool cleanup;
	private int maxConnections;
	private int minConnections;
	
	LdapPool pool;
	private int maxRetries;
	
	InspectCheckedoutConnections inspector;

    public void configure(String name, Properties props, NameSpace nameSpace) throws LDAPException {
        this.name = name;
        this.host = props.getProperty("host");
        this.port = Integer.parseInt(props.getProperty("port"));
        this.remoteBase = new DN(props.getProperty("remoteBase"));
        this.explodedRemoteBase = this.remoteBase.explodeDN(false);
        this.explodedLocalBase = nameSpace.getBase().getDN().explodeDN(false);
        this.localBase = nameSpace.getBase();

        this.usePaging = Boolean.parseBoolean(props.getProperty("usePaging", "false"));
        if (this.usePaging) {
            this.pageSize = Integer.parseInt(props.getProperty("pageSize", "500"));
        }

        logger.info("usePaging - '" + this.usePaging + "'");
        logger.info("pageSize - '" + this.pageSize + "'");

        this.proxyDN = (String) props.getProperty("proxyDN", "");

        this.proxyPass = props.getProperty("proxyPass", "").getBytes();
        
        
        
        String type = props.getProperty("type", "LDAP");

        if (type.equalsIgnoreCase("LDAP")) {
            this.type = LDAPConnectionType.LDAP;
        } else if (type.equalsIgnoreCase("DSMLV2")) {
            this.type = LDAPConnectionType.DSMLV2;
            this.isSoap = props.getProperty("useSOAP", "true").equalsIgnoreCase("true");
        } else if (type.equalsIgnoreCase("SPML")) {
            this.type = LDAPConnectionType.SPML;
            this.spmlImpl = props.getProperty("spmlImpl", "com.novell.ldap.spml.NoAuthImpl");

        } else if (type.equalsIgnoreCase("ldaps")) {
            this.type = LDAPConnectionType.LDAPS;
        } else {
            throw new LDAPLocalException("Unrecognized ldap interceptor type : " + type, LDAPException.OPERATIONS_ERROR);
        }

        String socketFactoryClassName = props.getProperty("sslSocketFactory");

        if (socketFactoryClassName != null) {
            try {
                this.socketFactory = (LDAPSocketFactory) Class.forName(socketFactoryClassName).newInstance();
            } catch (Exception e) {
                throw new LDAPException("Could not initiate socket factory", LDAPException.OPERATIONS_ERROR, "Operations Error", e);
            }
        } else {
            this.socketFactory = null;
        }

        this.maxIdleTime = Long.parseLong(props.getProperty("maxIdle", "0"));

        this.maxOpMillis = Integer.parseInt(props.getProperty("maxMillis", "30000"));

        logger.info("Maximum Operations Time (millis); " + this.maxOpMillis);

        this.maxStaleTime = Long.parseLong(props.getProperty("maxStaleTimeMillis", "60000"));
        logger.info("Maximum stale connection time in millis : " + this.maxStaleTime);

        this.useSrvDNS = props.getProperty("useSrvDNS", "false").equalsIgnoreCase("true");

        
        this.maxConnections = Integer.parseInt(props.getProperty("maximumConnections", "30"));
        this.minConnections = Integer.parseInt(props.getProperty("minimumConnections", "5"));
        this.maxRetries = Integer.parseInt(props.getProperty("maximumRetries", "100"));
        
        //this.pool = new LDAPConnectionPool(this, , , ), this.type, this.spmlImpl, this.isSoap);

        this.passThroughBindOnly = props.getProperty("passBindOnly", "false").equalsIgnoreCase("true");
        this.ignoreRefs = props.getProperty("ignoreRefs", "false").equalsIgnoreCase("true");

        this.utils = new NamingUtils();

        this.noMapBindFlag = LDAPInterceptor.NO_MAP_BIND_DN + this.name;

        this.heartbeatIntervalMinis = Long.parseLong(props.getProperty("heartbeatIntervalMillis", "0"));
        logger.info("Heartbeat Interval in Milliseconds : '" + this.heartbeatIntervalMinis + "'");

        if (this.heartbeatIntervalMinis > 0) {
            this.heartBeat = new LDAPHeartBeat(this);
            new Thread(this.heartBeat).start();
        }
        
        this.maxOpsPerCon = Integer.parseInt(props.getProperty("maxOpsPerCon","0"));
        logger.info(String.format("Max Ops Per Con : %d",this.maxOpsPerCon));
        
        this.maxCheckoutTimePerCon = Long.parseLong(props.getProperty("maxCheckoutTimePerCon","1000"));
        logger.info(String.format("Max Millis Checkout Time %d", this.maxCheckoutTimePerCon));
        
        this.cleanupDelay = Integer.parseInt(props.getProperty("cleanupDelayMillis","10000"));
        
        this.cleanup = new ConnectionCleanupPool(this.cleanupDelay);
		new Thread(this.cleanup).start();
        
        this.pool = new LdapPool(this);
        if (this.maxCheckoutTimePerCon > 0) {
        	this.inspector = new InspectCheckedoutConnections(this);
        	new Thread(inspector).start();
        }

    }
    
    public void closeConnection(LDAPConnection con) {
    	this.cleanup.closeConnection(con);
    }

    private LDAPConnection getConnection(DN bindDN, Password pass, boolean force, DN base, HashMap<Object, Object> session) throws LDAPException {
        return this.getConnection(bindDN, pass, force, base, session, false);
    }

    private LDAPConnection getConnection(DN bindDN, Password pass, boolean force, DN base, HashMap<Object, Object> session, boolean forceBind) throws LDAPException {
        
        LDAPConnection ldap = null;
        
        if (logger.isDebugEnabled()) {
            logger.debug("Bound inserts : " + session.get(SessionVariables.BOUND_INTERCEPTORS));
        }

        if (this.passThroughBindOnly && !force) {
            //wrapper = pool.getConnection(new DN(this.proxyDN), new Password(this.proxyPass), force);
        	ldap = this.pool.checkOut(this.proxyDN, this.proxyPass, force, this.maxRetries);
        	
            
        } else if (forceBind || (!this.passThroughBindOnly && ((ArrayList<String>) session.get(SessionVariables.BOUND_INTERCEPTORS)).contains(this.name))) {
            //wrapper = pool.getConnection(bindDN, pass, force);
        	ldap = pool.checkOut(bindDN != null ? bindDN.toString() : null, pass != null ? pass.getValue() : null, force, this.maxRetries);
        } else {
            //wrapper = pool.getConnection(new DN(this.proxyDN), new Password(this.proxyPass), force);
        	ldap = pool.checkOut(this.proxyDN,this.proxyPass,force,this.maxRetries);
        }

        if (ldap == null) {

            throw new LDAPException("Could not get remote connection", LDAPException.SERVER_DOWN, base.toString());
        } else {
            return ldap;
        }
    }

    

    protected DN getRemoteMappedDN(DN dn) {

        //if ((dn.getRDNs().size() < this.explodedLocalBase.length) || (dn.equals(this.localBase.getDN()) || dn.isDescendantOf(this.localBase.getDN()))) {
        return utils.getRemoteMappedDN(dn, explodedLocalBase, explodedRemoteBase);
        //} else {
        //	return dn;
        //}
    }

    protected DN getLocalMappedDN(DN dn) {
        return utils.getLocalMappedDN(dn, explodedRemoteBase, explodedLocalBase);

    }

    public void add(AddInterceptorChain chain, Entry entry,
                    LDAPConstraints constraints) throws LDAPException {

        LDAPConnection ldap;

        if (chain.getSession().containsKey(noMapBindFlag)) {
            ldap = this.getConnection(chain.getBindDN().getDN(), chain.getBindPassword(), false, new DN(entry.getEntry().getDN()), chain.getSession());
        } else {
            ldap = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()), chain.getBindPassword(), false, new DN(entry.getEntry().getDN()), chain.getSession());
        }

       

        try {
            LDAPEntry remoteEntry = new LDAPEntry(this.getRemoteMappedDN(new DN(entry.getEntry().getDN())).toString(), entry.getEntry().getAttributeSet());

            if (this.maxOpMillis > 0) {
                if (constraints == null) {
                    constraints = new LDAPConstraints();
                }
                constraints.setTimeLimit(this.maxOpMillis);
            }

            ldap.add(remoteEntry, constraints);
        } finally {
            ldap.disconnect();
        }

        //TODO -- Add way to continue down the chain?
    }

    public void bind(BindInterceptorChain chain, DistinguishedName dn,
                     Password pwd, LDAPConstraints constraints) throws LDAPException {

        DN mappedDN;

        if (chain.getSession().containsKey(noMapBindFlag)) {
            mappedDN = dn.getDN();
        } else {
            mappedDN = this.getRemoteMappedDN(dn.getDN());
        }

        
        LDAPConnection ldap = null;
        

        try {
        	ldap = this.getConnection(null, null, true, dn.getDN(), chain.getSession(), true);
            
        	if (this.maxOpMillis > 0) {
                if (constraints == null) {
                    constraints = new LDAPConstraints();
                }
                constraints.setTimeLimit(this.maxOpMillis);
            }
        	
        	ldap.bind(3, mappedDN.toString(),pwd.getValue());
        	
        	ArrayList<String> bound = (ArrayList<String>) chain.getSession().get(SessionVariables.BOUND_INTERCEPTORS);
            bound.add(this.name);
        } finally {
            if (ldap != null) ldap.disconnect();
        }

    }

    public void compare(CompareInterceptorChain chain, DistinguishedName dn,
                        Attribute attrib, LDAPConstraints constraints) throws LDAPException {

        LDAPConnection ldap = null;

        if (chain.getSession().containsKey(noMapBindFlag)) {
            ldap = this.getConnection(chain.getBindDN().getDN(), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        } else {
            ldap = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        }

        

        try {
            if (this.maxOpMillis > 0) {
                if (constraints == null) {
                    constraints = new LDAPConstraints();
                }
                constraints.setTimeLimit(this.maxOpMillis);
            }
            ldap.compare(this.getRemoteMappedDN(dn.getDN()).toString(), attrib.getAttribute(), constraints);
        } finally {
            ldap.disconnect();
        }

    }

    public void delete(DeleteInterceptorChain chain, DistinguishedName dn, LDAPConstraints constraints) throws LDAPException {

        LDAPConnection ldap = null;

        if (chain.getSession().containsKey(noMapBindFlag)) {
            ldap = this.getConnection(chain.getBindDN().getDN(), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        } else {
            ldap = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        }

        try {

            

            if (this.maxOpMillis > 0) {
                constraints.setTimeLimit(this.maxOpMillis);
            }

            ldap.delete(this.getRemoteMappedDN(dn.getDN()).toString(), constraints);
        } finally {
            ldap.disconnect();
        }

    }

    public void extendedOperation(ExetendedOperationInterceptorChain chain,
                                  ExtendedOperation op, LDAPConstraints constraints)
            throws LDAPException {

        LDAPConnection ldap = null;
        
        if (chain.getSession().containsKey(noMapBindFlag)) {
            ldap = this.getConnection(chain.getBindDN().getDN(), chain.getBindPassword(), false, op.getDn().getDN(), chain.getSession());
        } else {

            ldap = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()), chain.getBindPassword(), false, op.getDn().getDN(), chain.getSession());
        }
        

        try {
            if (this.maxOpMillis > 0) {
                if (constraints == null) {
                    constraints = new LDAPConstraints();
                }
                constraints.setTimeLimit(this.maxOpMillis);
            }

            ldap.extendedOperation(op.getOp(), constraints);
        } finally {
            ldap.disconnect();
        }

    }

    public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
                       ArrayList<LDAPModification> mods, LDAPConstraints constraints) throws LDAPException {

        LDAPModification[] ldapMods = new LDAPModification[mods.size()];
        System.arraycopy(mods.toArray(), 0, ldapMods, 0, ldapMods.length);

        LDAPConnection ldap = null;
        
        if (chain.getSession().containsKey(noMapBindFlag)) {
            ldap = this.getConnection(chain.getBindDN().getDN(), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        } else {
            ldap = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        }
        
        try {
            if (this.maxOpMillis > 0) {
                if (constraints == null) {
                    constraints = new LDAPConstraints();
                }
                constraints.setTimeLimit(this.maxOpMillis);
            }

            ldap.modify(this.getRemoteMappedDN(dn.getDN()).toString(), ldapMods, constraints);
            
            for (LDAPModification mod : mods) {
            	if (mod.getAttribute().getName().equalsIgnoreCase("userPassword")) {
            		DN bindDN = chain.getBindDN().getDN();
            		DN opDN = dn.getDN();
            		
            		if (bindDN.equals(opDN)) {
            			// we've updated the current connection's password, let's reset it
            			chain.getBindPassword().setValue(mod.getAttribute().getByteValue());
            			chain.getSession().put("MYVD_BINDPASS", new Password(chain.getBindPassword().getValue()));
            		}
            	}
            }
            
        } finally {
            ldap.disconnect();
        }

    }

    public void search(SearchInterceptorChain chain, DistinguishedName base,
                       Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly,
                       Results results, LDAPSearchConstraints constraints) throws LDAPException {

        String[] attribs = new String[attributes.size()];

        Iterator<Attribute> it = attributes.iterator();
        for (int i = 0, m = attribs.length; i < m; i++) {
            it.hasNext();
            attribs[i] = it.next().getAttribute().getName();
        }

        LDAPConnection ldap = null;
        
        if (chain.getSession().containsKey(noMapBindFlag)) {
            ldap = this.getConnection(chain.getBindDN().getDN(), chain.getBindPassword(), false, base.getDN(), chain.getSession());
        } else {
            ldap = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()), chain.getBindPassword(), false, base.getDN(), chain.getSession());
        }
        
        boolean searchSubmitted = false;
        
        try {
            String remoteBase = this.getRemoteMappedDN(base.getDN()).toString();
            if (remoteBase == null) {
                remoteBase = "";
            }

            if (this.usePaging) {
                if (constraints != null) {

                    LDAPSearchConstraints lc = (LDAPSearchConstraints) constraints.clone();
                    constraints = lc;

                    if (constraints.getControls() == null) {
                        LDAPControl[] controls = new LDAPControl[1];
                        controls[0] = new LDAPPagedResultsControl(this.pageSize, true);
                        constraints.setControls(controls);
                    } else {
                        LDAPControl[] controls = new LDAPControl[constraints.getControls().length + 1];
                        for (int i = 0; i < constraints.getControls().length; i++) {
                            controls[i] = constraints.getControls()[i];
                        }

                        controls[constraints.getControls().length] = new LDAPPagedResultsControl(this.pageSize, true);
                        constraints.setControls(controls);
                    }

                } else {
                    constraints = new LDAPSearchConstraints();
                    LDAPControl[] controls = new LDAPControl[1];
                    controls[0] = new LDAPPagedResultsControl(this.pageSize, true);
                    constraints.setControls(controls);
                }
            }

            String filterVal = filter.getValue();
            String convertedFilter = convertFilter(filter.getRoot()).toString();
            
            //filterVal = filterVal.replace("\\", "\\5C");
            

            
            
            
           /* if (filterVal.contains("\\")) {
                filterVal = filterVal.replace("\\", "\\5C");

            }*/

            if (this.maxOpMillis > 0) {
                if (constraints == null) {
                    constraints = new LDAPSearchConstraints();
                }
                constraints.setTimeLimit(this.maxOpMillis);
            }

            LDAPSearchResults res = ldap.search(remoteBase, scope.getValue(), convertedFilter, attribs, typesOnly.getValue(), constraints);
            chain.addResult(results, new LDAPEntrySet(this, ldap, res, remoteBase, scope.getValue(), filter.getValue(), attribs, typesOnly.getValue(), constraints), base, scope, filter, attributes, typesOnly, constraints);
            searchSubmitted = true;
        } finally {
        	if (! searchSubmitted) {
        		ldap.disconnect();
        	}
            
        }

    }
    

    FilterBuilder convertFilter(FilterNode root) {
    	switch (root.getType()) {
    		case EQUALS: return FilterBuilder.equal(root.getName(), root.getValue());
    		case PRESENCE: return FilterBuilder.present(root.getName());
    		case LESS_THEN: return FilterBuilder.lessThanOrEqual(root.getName(), root.getValue());
    		case GREATER_THEN: return FilterBuilder.greaterThanOrEqual(root.getName(), root.getValue());
    		case NOT: return FilterBuilder.not(convertFilter(root.getNot()));
    		case AND:
    			List<FilterBuilder> ands = new ArrayList<FilterBuilder>();
    			
    			
    			for (FilterNode child : root.getChildren()) {
    				ands.add(convertFilter(child));
    			}
    			
    			return FilterBuilder.and( ands.toArray(new FilterBuilder[ands.size()]));
    		case OR:
    			List<FilterBuilder> ors = new ArrayList<FilterBuilder>();
    			
    			
    			for (FilterNode child : root.getChildren()) {
    				ors.add(convertFilter(child));
    			}
    			
    			return FilterBuilder.or(ors.toArray(new FilterBuilder[ors.size()]));
    		case SUBSTR:
    			
    			boolean startsWith = root.getValue().endsWith("*");
    			boolean endsWith = root.getValue().startsWith("*");
    			
    			StringTokenizer toker = new StringTokenizer(root.getValue(),"*",false);
    			List<String> parts = new ArrayList<String>();
    			while (toker.hasMoreTokens()) {
    				parts.add(toker.nextToken());
    			}
    			
    			if (startsWith && ! endsWith) {
    				return FilterBuilder.startsWith(root.getName(),parts.toArray(new String[parts.size()]));
    			} else if (endsWith && ! startsWith) {
    				return FilterBuilder.endsWith(root.getName(),parts.toArray(new String[parts.size()]));
    			} else if (startsWith && endsWith) {
    				return FilterBuilder.contains(root.getName(),parts.toArray(new String[parts.size()]));
    			} else {
    				return FilterBuilder.substring(root.getName(),parts.toArray(new String[parts.size()]));
    			}
    			
    			
    			
    		case EXT:
    			return FilterBuilder.extensible(root.getName(),root.getValue());
    		default: return null;

    	}
    	
    }

    public String getHost() {
        return host;
    }

    public String getName() {
        return name;
    }

    public int getPort() {
        return port;
    }

    public DN getRemoteBase() {
        return remoteBase;
    }

    public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {

        String oldDN = this.getRemoteMappedDN(dn.getDN()).toString();

        LDAPConnection ldap = null;
        if (chain.getSession().containsKey(noMapBindFlag)) {
            ldap = this.getConnection(chain.getBindDN().getDN(), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        } else {
            ldap = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        }
        

        try {
            if (this.maxOpMillis > 0) {
                if (constraints == null) {
                    constraints = new LDAPConstraints();
                }
                constraints.setTimeLimit(this.maxOpMillis);
            }

            ldap.rename(oldDN, newRdn.getDN().toString(), deleteOldRdn.getValue());
        } finally {
            ldap.disconnect();
        }

    }

    public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn, LDAPConstraints constraints) throws LDAPException {
        String oldDN = this.getRemoteMappedDN(dn.getDN()).toString();
        String newPDN = this.getRemoteMappedDN(newParentDN.getDN()).toString();

        LDAPConnection ldap = null;
        if (chain.getSession().containsKey(noMapBindFlag)) {
            ldap = this.getConnection(chain.getBindDN().getDN(), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        } else {
            ldap = this.getConnection(this.getRemoteMappedDN(chain.getBindDN().getDN()), chain.getBindPassword(), false, dn.getDN(), chain.getSession());
        }
        

        try {

            if (this.maxOpMillis > 0) {
                if (constraints == null) {
                    constraints = new LDAPConstraints();
                }
                constraints.setTimeLimit(this.maxOpMillis);
            }

            ldap.rename(oldDN, newRdn.getDN().toString(), newPDN, deleteOldRdn.getValue());
        } finally {
            ldap.disconnect();
        }

    }

    public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
        // TODO Auto-generated method stub

    }

    public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
        // TODO Auto-generated method stub

    }

    public boolean isIgnoreRefs() {
        return this.ignoreRefs;
    }

    public void shutdown() {
        if (this.heartBeat != null) {
            this.heartBeat.stop();
        }
        
        if (this.inspector != null) {
        	this.inspector.stopInspector();
        }

        logger.info("Closing down all pools...");
        this.pool.shutDownPool();
        this.cleanup.stopRunning();
        logger.info("Pool shutdown...");

    }

    public LDAPSocketFactory getSocketFactory() {
        return this.socketFactory;
    }

    public long getMaxIdleTime() {
        return maxIdleTime;
    }

    public void setMaxIdleTime(long maxIdleTime) {
        this.maxIdleTime = maxIdleTime;
    }

    public boolean isUsePaging() {
        return usePaging;
    }

    public void setUsePaging(boolean usePaging) {
        this.usePaging = usePaging;
    }

    public int getPageSize() {
        return pageSize;
    }

    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
    }

    public int getMaxTimeoutMillis() {
        return this.maxOpMillis;
    }

    public long getMaxStailTime() {
        return this.maxStaleTime;
    }

    

    public long getHeartBeatMillis() {
        return this.heartbeatIntervalMinis;
    }



	public long getMaxCheckoutTimePerCon() {
		return maxCheckoutTimePerCon;
	}

	public int getMaxOpsPerCon() {
		return maxOpsPerCon;
	}
	
	public int getCleanupDelay() {
		return this.cleanupDelay;
	}

	public int getMaxConnections() {
		return this.maxConnections;
	}

	public String getBindDN() {
		return this.proxyDN;
	}

	public byte[] getBindPassword() {
		return this.proxyPass;
	}

	public LDAPConnectionType getType() {
		return this.type;
	}

	public int getMinConnections() {
		return this.minConnections;
	}

	public LdapPool getConnectionPool() {
		return this.pool;
	}

    
}
