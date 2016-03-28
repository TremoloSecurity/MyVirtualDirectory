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
package net.sourceforge.myvd.router;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.TreeMap;

import javax.naming.NameNotFoundException;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

import net.sourceforge.myvd.chain.AddInterceptorChain;
import net.sourceforge.myvd.chain.BindInterceptorChain;
import net.sourceforge.myvd.chain.CompareInterceptorChain;
import net.sourceforge.myvd.chain.DeleteInterceptorChain;
import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.chain.InterceptorChain;
import net.sourceforge.myvd.chain.ModifyInterceptorChain;
import net.sourceforge.myvd.chain.RenameInterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DNComparer;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.RequestVariables;
import net.sourceforge.myvd.types.Results;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;



public class Router {
	static Logger logger = Logger.getLogger(Router.class);
	
	/** the backends keyed by normalized suffix strings */
    LinkedHashMap<String,NameSpace> backends = new LinkedHashMap<String,NameSpace>();
	
    /** Contains a mapping from a name to available contexts */
    TreeMap<DN,Level> subtree;
    
    
    boolean writeAll;
    InsertChain globalChain;
    
    NameSpace rootNS;
    
    boolean searchAll;
    
    
    public Router(InsertChain globalChain) {
    	this.subtree = new TreeMap<DN,Level>(new DNComparer());
    	this.globalChain = globalChain;
    }
    
    
    public void add(AddInterceptorChain chain,Entry entry,LDAPConstraints constraints) throws LDAPException {
    	NameSpace curr = null;
    	curr = getLocalBackendsWrite(chain, entry.getEntry().getDN());
    	
    	if (curr == null) {
    		throw new LDAPException("No namespaces for " + entry.getEntry().getDN().toString(),LDAPException.NO_SUCH_OBJECT,entry.getEntry().getDN().toString());
    	}
    	
		AddInterceptorChain localChain = new AddInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,curr.getChain(),chain.getSession(),chain.getRequest());
		localChain.nextAdd(entry,constraints);
    		
    		
    	
    }


    private NameSpace getLocalBackendsWrite(InterceptorChain chain, String dn) throws LDAPException {
    	return this.getLocalBackendsWrite(chain,dn,false);
    }
    
	private NameSpace getLocalBackendsWrite(InterceptorChain chain, String dn, boolean isRename) throws LDAPException {
		NameSpace curr;
		String key = null;
		
		if (isRename) {
			key = RequestVariables.ROUTE_NAMESPACE_RENAME;
		} else {
			key = RequestVariables.ROUTE_NAMESPACE;
		}
		
		if (! chain.getRequest().containsKey(key)) {
			
    		
			//logger.info("DN : " + dn);
			Level level = this.getLevel(new DN(dn));
        	
        	if (level == null) {
        		throw new LDAPException(LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT),LDAPException.NO_SUCH_OBJECT,"");
        	}
        	
        	Iterator<NameSpace> it = level.backends.iterator();
        	
    		curr = it.next();
    	} else {
    		curr = this.backends.get(chain.getRequest().get(key));
    	}
		return curr;
	}
    
    public void bind(BindInterceptorChain chain,DistinguishedName dn,Password pwd,LDAPConstraints constraints) throws LDAPException {
    	
    	
    	//check for an anonymouse user
    	if (pwd.getValue().length == 0) {
    		//user has not bind DN
    		dn.setDN(new DN(""));
    		return;
    	}
    	
    	ArrayList<NameSpace> localBackends = getLocalLevels(chain, dn);
    	int num = 0;
    	
    	Iterator<NameSpace> it = localBackends.iterator();
    	while (it.hasNext()) {
    		NameSpace curr = it.next();
    		BindInterceptorChain localChain = new BindInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,curr.getChain(),chain.getSession(),chain.getRequest());
    		try {
    			localChain.nextBind(dn,pwd,constraints);
    		} catch (LDAPException e) {
    			if (e.getResultCode() == LDAPException.INVALID_CREDENTIALS || e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
    				num++;
    			} else {
    				throw e;
    			}
    		}
    		
    		if (num == localBackends.size()) {
    			throw new LDAPException("Could not bind to any services",LDAPException.INVALID_CREDENTIALS,dn.getDN().toString());
    		}
    	}
    }


	private ArrayList<NameSpace> getLocalLevels(InterceptorChain chain, DistinguishedName dn) throws LDAPException {
		ArrayList<NameSpace> localBackends;
    	
		logger.debug("Is set namespace?");
    	if (chain.getRequest().containsKey(RequestVariables.ROUTE_NAMESPACE)) {
    		logger.debug("namespace manually set");
    		Object obj = chain.getRequest().get(RequestVariables.ROUTE_NAMESPACE);
    		if (obj instanceof ArrayList) {
    			ArrayList<String> list = (ArrayList<String>) obj;
    			localBackends = new ArrayList<NameSpace>();
    			Iterator<String> it = list.iterator();
    			while (it.hasNext()) {
    				NameSpace lns = this.backends.get(it.next());
    				
    				if (lns.getBase().getDN().isDescendantOf(dn.getDN()) || dn.getDN().equals(lns.getBase().getDN()) || dn.getDN().isDescendantOf(lns.getBase().getDN())) {
    					localBackends.add(lns);
    				}
    				
    				
    			}
    		} else if (obj instanceof String) {
    			localBackends = new ArrayList<NameSpace>();
    			localBackends.add(this.backends.get((String) obj));
    		} else {
    			throw new LDAPException("Invalid routing type",LDAPException.OPERATIONS_ERROR,"");
    		}
    	} else {
    		logger.debug("namespace set by router");
    		Level level = this.getLevel(dn.getDN());
    		logger.debug("namespace levels determined");
    	
	    	if (level == null) {
	    		logger.debug("no levels found");
	    		throw new LDAPException(LDAPException.resultCodeToString(LDAPException.NO_SUCH_OBJECT),LDAPException.NO_SUCH_OBJECT,"");
	    	}
	    	
	    	localBackends = level.backends;
    	}
		return localBackends;
	}
    
    public void compare(CompareInterceptorChain chain,DistinguishedName dn,Attribute attrib,LDAPConstraints constraints) throws LDAPException {
    	ArrayList<NameSpace> localBackends = getLocalLevels(chain, dn);
    	
    	int num = 0;
    	
    	Iterator<NameSpace> it = localBackends.iterator();
    	while (it.hasNext()) {
    		NameSpace curr = it.next();
    		CompareInterceptorChain localChain = new CompareInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,curr.getChain(),chain.getSession(),chain.getRequest());
    		try {
    			localChain.nextCompare(dn,attrib,constraints);
    		} catch (LDAPException e) {
    			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
    				num++;
    			} else if (e.getResultCode() == LDAPException.COMPARE_TRUE) {
    				continue;
    			} else {
    				throw e;
    			}
    		}
    		
    		if (num == localBackends.size()) {
    			throw new LDAPException("Could not compare on any services",LDAPException.NO_SUCH_OBJECT,dn.getDN().toString());
    		}
    	}
    }
    
    public void delete(DeleteInterceptorChain chain,DistinguishedName dn,LDAPConstraints constraints) throws LDAPException {
    	NameSpace curr = null;
    	curr = getLocalBackendsWrite(chain, dn.getDN().toString());
    	
    	DeleteInterceptorChain localChain = new DeleteInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,curr.getChain(),chain.getSession(),chain.getRequest());
    	
    	localChain.nextDelete(dn,constraints);
    	
    		
    		
    }
    
    public void extendedOperation(ExetendedOperationInterceptorChain chain,ExtendedOperation op,LDAPConstraints constraints) throws LDAPException {
    	Iterator<NameSpace> itBase = null;
    	Iterator<java.util.Map.Entry<String, NameSpace>> itNoBase = null;
    	Iterator<?> it;
    	
    	if (op.getDn() != null || chain.getRequest().containsKey(RequestVariables.ROUTE_NAMESPACE)) {
    		if (chain.getRequest().containsKey(RequestVariables.ROUTE_NAMESPACE)) {
    			itBase = this.getLocalLevels(chain,op.getDn()).iterator();
    		} else {
    			itBase = this.getLevel(op.getDn().getDN()).backends.iterator();
    		}
    		
    		it = itBase;
    		
    	} else {
    		itNoBase = this.backends.entrySet().iterator();
    		it = itNoBase;
    	}
    	
    	
    	int num = 0;
    	
    	 
    	while (it.hasNext()) {
    		NameSpace curr = null;
    		
    		if (itBase != null) {
    			curr = itBase.next();
    		} else {
    			curr = itNoBase.next().getValue();
    		}
    		
    		
    		ExetendedOperationInterceptorChain localChain = new ExetendedOperationInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,curr.getChain(),chain.getSession(),chain.getRequest());
    		try {
    			localChain.nextExtendedOperations(op,constraints);
    		} catch (LDAPException e) {
    			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
    				num++;
    			} 
    		}
    		
    		if (! this.writeAll) {
    			continue;
    		}
    		
    		if (num == this.backends.size()) {
    			throw new LDAPException("Could not compare on any services",LDAPException.NO_SUCH_OBJECT,"");
    		}
    	}
    }
    
    public void modify(ModifyInterceptorChain chain,DistinguishedName dn,ArrayList<LDAPModification> mods,LDAPConstraints constraints) throws LDAPException {
    	NameSpace curr = this.getLocalBackendsWrite(chain,dn.getDN().toString());
    	ModifyInterceptorChain localChain = new ModifyInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,curr.getChain(),chain.getSession(),chain.getRequest());
    	localChain.nextModify(dn,mods,constraints);
    	
    }
    
    
    
    public void search(SearchInterceptorChain chain,DistinguishedName base,Int scope,Filter filter,ArrayList<Attribute> attributes,Bool typesOnly,Results results,LDAPSearchConstraints constraints) throws LDAPException {
		
		logger.debug("Entering router search");
		
		int notFounds = 0;
		HashSet<String> toExclude = (HashSet<String>) chain.getRequest().get(RequestVariables.ROUTE_NAMESPACE_EXCLUDE);
		
		
		logger.debug("Determining local levels");
		ArrayList<NameSpace> localBackends = this.getLocalLevels(chain,base);
		logger.debug("Determined local levels");
		Iterator<NameSpace> it = localBackends.iterator();
		
		logger.debug("Iterate over levels");
		while (it.hasNext()) {
		
			NameSpace holder = it.next(); 
			
			if (toExclude != null  && toExclude.contains(holder.getLabel())) {
				continue;
			}
			
			DN parentDN = holder.getBase().getDN().getParent();
			
			
			DN reqDN = new DN(base.toString());
			
			
			DistinguishedName searchBase = new DistinguishedName(reqDN.toString());
			
			logger.debug("Determine scope");
			Int localScope = new Int(scope.getValue());
			if (scope.getValue() != 0) {
				if (scope.getValue() == 1) {
					if (holder.getBase().getDN().countRDNs() - searchBase.getDN().countRDNs() == 1) {
						localScope.setValue(0);
						searchBase = new DistinguishedName(holder.getBase().getDN().toString());
					} else if (holder.getBase().getDN().countRDNs() - searchBase.getDN().countRDNs() > 0) {
						continue;
					}
				} else {
					searchBase = base;
				}
			}
			logger.debug("Base determined");
			
			
			try {
				logger.debug("create local chain");
				SearchInterceptorChain localChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,holder.getChain(),chain.getSession(),chain.getRequest());
				logger.debug("Begin Local Chain");
				localChain.nextSearch(searchBase,localScope,filter,attributes,typesOnly,results,constraints);
				logger.debug("chain complete");
			} catch (LDAPException e) {
				logger.error("Error running search",e);
				if (e.getResultCode() == 32) {
					notFounds++;
				} else {
					throw e;
				}
			} 
			
			if (scope.getValue() == 0) {
				break;
			}
			
			
		}
		
		if (notFounds == localBackends.size()) {
			throw new LDAPException("Could not find base",LDAPException.NO_SUCH_OBJECT,"");
		}
		
		
	}
    
    
    
    public void addBackend(String label,DN name, NameSpace namespace) {
    	namespace.setRouter(this);
    	this.backends.put(label,namespace);
    	
    	if (name.countRDNs() == 0) {
    		this.rootNS = namespace;
    		return;
    	}
    	
		DN curr = new DN(name.toString());
		Level level;
		for (int i=0,m=name.countRDNs();i<m;i++) {
			level = this.subtree.get(curr);
			if (level == null) {
				level = new Level();
				this.subtree.put(curr,level);
			}
			
			if (! level.backends.contains(namespace)) {
				//level.backends.add(backend);
				
				if (level.backends.size() == 0) {
					level.backends.add(namespace);
				} else {
				
					//this needs to be sorted, most exact to least
					boolean found = false;
					for (int j=0;j<level.backends.size();j++) {
						NameSpace part =  level.backends.get(j);
						
						/*
						 * If the namespace added 
						 */
						if (newNamespaceProceedsCurrent(namespace, part)) {
							
							if (namespace.getBase().getDN().countRDNs() < part.getBase().getDN().countRDNs() || checkWeighting(namespace, part)) {
								level.backends.add(j,namespace);
								found = true;
								break;
							}
						} 
					}
					
					if (! found) {
						level.backends.add(namespace);
					}
				}
				
			}
			
			
			
			curr = curr.getParent();
			
		}
		
	}
    
    public Level getLevel(DN name) {
    	
    	if (name.countRDNs() == 0) {
    		Level level = new Level();
    		level.backends.add(this.rootNS);
    		return level;
    	}
    	
    	Level level = null;
    	DN curr = new DN(name.toString());
    	for (int i=0,m=name.countRDNs();i<m;i++) {
    		level = (Level) subtree.get(curr);
    		if (level != null) {
    			return level;
    		}
    		
    		curr = curr.getParent(); 
		}
    	
    	return null;
    }

	private boolean checkWeighting(NameSpace namespace, NameSpace part) {
		return (this.newNamespaceEqualsCurrent(namespace,part) && namespace.getWeight() > part.getWeight());
	}

	private boolean newNamespaceProceedsCurrent(NameSpace namespace, NameSpace part) {
		return part.getBase().getDN().countRDNs() >= namespace.getBase().getDN().countRDNs();
	}
	
	private boolean newNamespaceEqualsCurrent(NameSpace namespace, NameSpace part) {
		return part.getBase().getDN().countRDNs() == namespace.getBase().getDN().countRDNs();
	}

	public TreeMap<DN, Level> getSubtree() {
		return subtree;
	}
	
	public void rename(RenameInterceptorChain chain,DistinguishedName dn,DistinguishedName newRdn,Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		DN oldDN = new DN(dn.getDN().toString());
		
		
		NameSpace ns = this.getLocalBackendsWrite(chain,dn.getDN().toString());
		
		RenameInterceptorChain newChain = new RenameInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,ns.getChain(),chain.getSession(),chain.getRequest());
		
		newChain.nextRename(dn,newRdn,deleteOldRdn,constraints);
		
		
	}
	
	public void rename(RenameInterceptorChain chain,DistinguishedName dn,DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		DN oldDN = new DN(dn.getDN().toString());
		DN newPDN = new DN(newParentDN.getDN().toString());
		
		
		
		
		
		NameSpace oldNs = this.getLocalBackendsWrite(chain,dn.getDN().toString());
		NameSpace newNs = this.getLocalBackendsWrite(chain,newPDN.toString(),true);
		
		if (oldNs == newNs) {
			RenameInterceptorChain newChain = new RenameInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,oldNs.getChain(),chain.getSession(),chain.getRequest());
			newChain.nextRename(dn,newRdn,newParentDN,deleteOldRdn,constraints);
		} else {
			
			SearchInterceptorChain searchChain = new SearchInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,oldNs.getChain(),chain.getSession(),chain.getRequest());
			Results results = new Results(globalChain);
			searchChain.nextSearch(new DistinguishedName(dn.getDN().toString()),new Int(0),new Filter("(objectClass=*)"),new ArrayList<Attribute>(),new Bool(false),results,new LDAPSearchConstraints());
			
			results.start();
			if (! results.hasMore()) {
				throw new LDAPException("Old entry not found",LDAPException.NO_SUCH_OBJECT,"");
			}
			
			Entry entry = results.next();
			
			results.finish();
			
			AddInterceptorChain addChain = new AddInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,newNs.getChain(),chain.getSession(),chain.getRequest());
			LDAPEntry newEntry = new LDAPEntry(newRdn.getDN().toString() + "," + newParentDN.getDN().toString(),entry.getEntry().getAttributeSet());
			RDN rdn = new RDN(newRdn.getDN().toString());
			RDN oldRDN = (RDN) dn.getDN().getRDNs().get(0);
			
			 
			
			newEntry.getAttributeSet().getAttribute(rdn.getType()).removeValue(oldRDN.getValue());
			newEntry.getAttributeSet().getAttribute(rdn.getType()).addValue(rdn.getValue());
			
			entry = new Entry(newEntry);
			
			addChain.nextAdd(entry,new LDAPConstraints());
			
			if (deleteOldRdn.getValue()) {
				DeleteInterceptorChain delChain = new DeleteInterceptorChain(chain.getBindDN(),chain.getBindPassword(),0,oldNs.getChain(),chain.getSession(),chain.getRequest());
				delChain.nextDelete(dn,new LDAPConstraints());
			}
			
			
		}
		
		
	}
	
	public InsertChain getGlobalChain() {
		return this.globalChain;
	}
	
	public void shutDownRouter() {
		
		logger.info("Shutting down the Global Chain...");
		
		shutdownChain(this.globalChain);
		
		logger.info("Global Chain shut down complete");
		
		Iterator<NameSpace> it = this.backends.values().iterator();
		while(it.hasNext()) {
			NameSpace ns = it.next();
			logger.info("Shutting down namespace " + ns.getLabel() + "...");
			shutdownChain(ns.getChain());
			logger.info(ns.getLabel() + " shut down complete");
		}
		
	}


	private void shutdownChain(InsertChain chain) {
		
		chain.shutdownChain();
		
	}


	public void load(Router router) {
		this.backends = router.backends;
		this.globalChain = router.globalChain;
		this.rootNS = router.rootNS;
		this.searchAll = router.searchAll;
		this.subtree = router.subtree;
		this.writeAll = router.writeAll;
		
	}
}

