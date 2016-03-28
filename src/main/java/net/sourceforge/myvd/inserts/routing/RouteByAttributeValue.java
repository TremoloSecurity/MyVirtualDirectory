package net.sourceforge.myvd.inserts.routing;

import java.util.ArrayList;
import java.util.Properties;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;

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
import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.RequestVariables;
import net.sourceforge.myvd.types.Results;

public class RouteByAttributeValue implements Insert {

	static Logger logger = Logger.getLogger(RouteByAttributeValue.class.getName());
	
	String name;
	ArrayList<RouteMap> maps;
	String defaultRoute;
	boolean useDefault;
	String attrName;
	Pattern ignore;

	private boolean ignoreNegative;
	
	
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.maps = new ArrayList<RouteMap>();
		
		this.attrName = props.getProperty("attributeName","").toLowerCase();
		logger.info("Attribute name to check : '" + this.attrName + "'");
		
		
		this.useDefault = Boolean.parseBoolean(props.getProperty("useDefault","true"));
		if (! this.useDefault) {
			this.defaultRoute = null;
			logger.info("No default route");
		} else {
			this.defaultRoute = props.getProperty("defaultNameSpace");
			logger.info("Default route : '" + this.defaultRoute + "'");
		}
		
		int num = Integer.parseInt(props.getProperty("numRoutes","0"));
		
		logger.info("Number of routes : " + num);
		
		for (int i=0;i<num;i++) {
			String val = props.getProperty("route." + i);
			if (val == null) {
				throw new LDAPException("route." + i + " is missing",LDAPException.OPERATIONS_ERROR,"Error");
			}
			
			String ns = val.substring(0,val.indexOf('='));
			String pattern = val.substring(val.indexOf('=') + 1);
			
			logger.info("Route #" + i + ": Pattern='" + pattern + "', NameSpace='" + ns + "'");
			
			RouteMap rm = new RouteMap();
			rm.name = ns;
			rm.p = Pattern.compile(pattern);
			this.maps.add(rm);
		}
		
		String ignorePattern = props.getProperty("ignorePattern");;
		if (ignorePattern == null) {
			this.ignore = null;
		} else {
			logger.info("Ignore Pattern : '" + ignorePattern + "'");
			this.ignore = Pattern.compile(ignorePattern);
			
			String ignoreNeg = props.getProperty("ignoreNegative");
			if (ignoreNeg == null) {
				this.ignoreNegative = false;
			} else {
				this.ignoreNegative = ignoreNeg.equalsIgnoreCase("true");
			}
		}
		
		 
		
		
	}

	@Override
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);
		
	}

	@Override
	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn, pwd, constraints);
		
	}

	@Override
	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);
		
	}

	@Override
	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn, constraints);
		
	}

	@Override
	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextExtendedOperations(op, constraints);
		
	}

	@Override
	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn, mods, constraints);
		
	}

	@Override
	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		
		ArrayList<String> routes = new ArrayList<String>();
		
		checkRoutes(filter.getRoot(),routes);
		
		if (routes.size() > 0) {
			chain.getRequest().put(RequestVariables.ROUTE_NAMESPACE,routes);
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("Routes : '" + routes + "'");
		}
		
		chain.nextSearch(base, scope, filter, attributes, typesOnly, results, constraints);
		
	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);
		
	}

	@Override
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);
		
	}

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
	}

	@Override
	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);
		
	}

	@Override
	public void shutdown() {
		
		
	}
	
	private void checkRoutes(FilterNode node,ArrayList<String> routes) {
		switch (node.getType()) {
			case AND:
			case OR:
			case NOT:
				
				for (FilterNode val : node.getChildren()) {
					checkRoutes(val,routes);
				}
				
				break;
			case EQUALS:
				if (node.getName().equalsIgnoreCase(this.attrName)) {
					boolean found = false;
					
					for (RouteMap rm : this.maps) {
						if (logger.isDebugEnabled()) {
							logger.debug("Checking filter - '" + node.toString() + "', pattern='" + rm.p.toString() + "', matches=" + rm.p.matcher(node.getValue()).matches());
						}
						if (rm.p.matcher(node.getValue()).matches()) {
							if (logger.isDebugEnabled()) {
								logger.debug("Adding " + rm.name);
							}
							
							routes.add(rm.name);
							found = true;
						}
					}
					
					if (! found) {
						if (this.useDefault) {
							if (logger.isDebugEnabled()) {
								logger.debug("Default route being used : '" + this.defaultRoute + "'");
							}
							
							
							if (ignore == null) {
								routes.add(this.defaultRoute);
							} else {
								boolean matches = ignore.matcher(node.getValue()).matches();
								if (this.ignoreNegative && matches) {
									routes.add(defaultRoute);
								} else if (! this.ignoreNegative && ! matches) {
									routes.add(defaultRoute);
								}
							}
							
							
							
							
							
							
							
							
						}
					}
					
					
				}
		}
	}

}

class RouteMap {
	String name;
	Pattern p;
}