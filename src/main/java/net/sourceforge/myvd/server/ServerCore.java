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

package net.sourceforge.myvd.server;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.util.SchemaUtil;

import com.novell.ldap.LDAPException;
import com.novell.ldap.util.DN;

public class ServerCore {
	static Logger logger = Logger.getLogger(ServerCore.class);
	
	Properties props;
	private InsertChain globalChain;
	private Router router;
	


	private NameSpace globalNS;


	
	public ServerCore(Properties props) {
		this.props = props;
	}

	public InsertChain getGlobalChain() {
		return globalChain;
	}

	public Properties getProps() {
		return props;
	}

	public Router getRouter() {
		return router;
	}

	
	
	

	private void configureChain(String prefix,ArrayList<String> links,InsertChain chain,NameSpace ns) throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		Iterator<String> it = links.iterator();
		int i=0;
		
		while (it.hasNext()) {
			String name = it.next();
			chain.setInsert(i, chain.getInsertConfig(name,prefix +  name + ".",chain,i));
			
			i++;
		}
		
		chain.configureChain();
	}
	
	private void buildGlobalChain() throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		String links = props.getProperty("server.globalChain");
		ArrayList<String> linkList = new ArrayList<String>();
		
		StringTokenizer toker = new StringTokenizer(links,",");
		
		while (toker.hasMoreTokens()) {
			linkList.add(toker.nextToken());
		}
		
		Insert[] tchain = new Insert[linkList.size()];
		InsertChain chain = new InsertChain(tchain);
		this.globalNS = new NameSpace("globalChain",new DistinguishedName("cn=root"),0,chain,false);
		chain.setNameSpace(this.globalNS);
		chain.setProps(this.props);
		
		this.configureChain("server.globalChain.",linkList,chain,this.globalNS);
		
		this.globalChain = chain;
		
		
		
	}
	
	private void buildNamespaces() throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		String nss = props.getProperty("server.nameSpaces");
		StringTokenizer toker = new StringTokenizer(nss,",");
		Router router = new Router(this.globalChain);

		
		
		while (toker.hasMoreTokens()) {
			
			
			String nsName = toker.nextToken();
			
			
			
			logger.debug("Loading namespace : " + nsName);
			
			String prefix = "server." + nsName + ".";
			int weight = Integer.parseInt(props.getProperty(prefix + "weight","0"));
			String nsBase = props.getProperty(prefix + "nameSpace");
			
			boolean enabled = props.getProperty(prefix + "enabled","true").equalsIgnoreCase("true");
			
			if (! enabled) {
				logger.warn("Namespace " + nsName + " disabled");
				
			} else {
			
				String nsChain = props.getProperty(prefix + "chain");
				StringTokenizer chainToker = new StringTokenizer(nsChain,",");
				
				ArrayList<String> chainList = new ArrayList<String>();
				
				while (chainToker.hasMoreTokens()) {
					chainList.add(chainToker.nextToken());
				}
				
				Insert[] tchain = new Insert[chainList.size()];
				InsertChain chain = new InsertChain(tchain);
				chain.setProps(props);
				
				NameSpace ns = new NameSpace(nsName,new DistinguishedName(nsBase),weight,chain,false);
				chain.setNameSpace(ns);
				
				this.configureChain(prefix,chainList,chain,ns);
				
				router.addBackend(nsName,new DN(nsBase),ns);
			}
		}
		
		
		
		
		this.router = router;
	}
	
	public void startService() throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		logger.debug("Initializing Server wide config...");
		this.buildServerWideConfig();
		logger.debug("Loading global chain...");
		this.buildGlobalChain();
		logger.debug("Global chain loaded");
		logger.debug("Loading local chain...");
		this.buildNamespaces();
		logger.debug("Local chain loaded");
	}

	private void buildServerWideConfig() {
		String binaryAttrs = props.getProperty("server.binaryAttributes","objectguid,orclguid,entryuuid");
		StringTokenizer toker = new StringTokenizer(binaryAttrs,",",false);
		while (toker.hasMoreTokens()) {
			SchemaUtil.getSchemaUtil().addBinaryAttribute(toker.nextToken().toLowerCase());
		}
		
		
		
	}
	
	
}
