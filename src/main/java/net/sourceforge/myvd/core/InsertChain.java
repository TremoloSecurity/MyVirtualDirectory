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
package net.sourceforge.myvd.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.ListIterator;
import java.util.Properties;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPException;

import net.sourceforge.myvd.inserts.Insert;

public class InsertChain {
	static Logger logger = Logger.getLogger(InsertChain.class.getName());
	
	Insert[] chain;
	Properties props;
	HashMap<String,Properties> propsMap;
	ArrayList<String> initialInserts;
	
	NameSpace ns;
	
	int configIndex;
	
	public InsertChain(Insert[] chain) {
		this.chain = chain;
		this.propsMap = new HashMap<String,Properties>();
		this.initialInserts = new ArrayList<String>();
	}
	
	public Insert getInsert(int index) {
		return this.chain.clone()[index];
	}
	
	public void setProps(Properties props) {
		this.props = props;
	}
	
	public void setNameSpace(NameSpace ns) {
		this.ns = ns;
	}
	
	public int getLength() {
		return this.chain.length;
	}
	
	public int getPositionInChain(Insert insert) {
		for (int i=0;i<this.chain.length;i++) {
			if (this.chain[i] == insert) {
				return i;
			}
		}
		
		return -1;
	}
	
	public void setInsert(int index,Insert insert) {
		this.chain[index] = insert;
	}
	
	public void shutdownChain() {
		
		for (int i=0;i<chain.length;i++) {
			logger.info("Shutting down insert " + chain[i].getName() + "...");
			chain[i].shutdown();
			logger.info(chain[i].getName() + " shut down complete");
		}
		
	}

	public void insertIntoChain(Insert[] insertChain, HashMap<String,Properties> insertProps, String[] insertNames) throws LDAPException {
		Insert[] newChain = new Insert[this.chain.length + insertChain.length];
		
		//first set the old inserts
		for (int i=0;i<=this.configIndex;i++) {
			newChain[i] = this.chain[i];
		}
		
		//add the new chain
		for (int i=this.configIndex + 1,m=0;m<insertChain.length;i++,m++) {
			newChain[i] = insertChain[m];
			this.initialInserts.add(i, insertNames[m]);
			
		}
		
		//add the rest
		for (int i=this.configIndex + 1 + insertChain.length,m=this.configIndex + 1;m<this.chain.length;i++,m++) {
			newChain[i] = this.chain[m];
		}
		
		this.chain = newChain;
		
		
		
		this.propsMap.putAll(insertProps);
		
	}
	
	public Insert getInsertConfig(String name,String prefix,InsertChain chain,int pos) throws InstantiationException, IllegalAccessException, ClassNotFoundException, LDAPException {
		logger.debug("Insert : " + name + "; " + prefix);
		
		String className = props.getProperty(prefix + "className");
		
		logger.debug("Insert Class Name : " + className);
		
		String cfgPrefix = prefix + "config.";
		Insert insert;
		
		insert = (Insert) Class.forName(className).newInstance();
		String propName;
		Properties localProps = new Properties();
		Iterator it = props.keySet().iterator();
		while (it.hasNext()) {
			propName = (String) it.next();
			if (propName.startsWith(cfgPrefix)) {
				String localPropName = propName.substring(cfgPrefix.length());
				String localVal = props.getProperty(propName);
				localVal = envVars(localVal);
				logger.debug("Config : " + localPropName + "=" + localVal);
				localProps.setProperty(localPropName,localVal);
			}
		}
		
		
		
		chain.setInsert(pos, insert);
		
		this.propsMap.put(name, localProps);
		this.initialInserts.add(name);
		
		//interceptor.configure(name,localProps,ns);
		
		
		
		return insert;
		
		
	}
	
	private String envVars(String localVal) {
		int start = localVal.indexOf('%');
		
		int last = 0;
		if (start == -1) {
			return localVal;
		}
		
		
		
		StringBuffer buf = new StringBuffer();
		
		while (start != -1) {
			int end = localVal.indexOf('%',start + 1);
			if (end == -1) {
				return localVal;
			}
			buf.append(localVal.substring(last,start));
			buf.append(System.getenv().get(localVal.substring(start + 1,end)));
			last = end + 1;
			start = localVal.indexOf('%',last);
		}
		
		buf.append(localVal.substring(last));
		
		return buf.toString();
	}
	
	public void configureChain() throws LDAPException {
		this.configIndex = 0;
		
		
		for (int i = 0;i<this.chain.length;i++) {
			String insertName = this.initialInserts.get(i);
			Properties props = this.propsMap.get(insertName);
			this.chain[configIndex].configure(insertName, props, ns);
			this.configIndex++;
		}
		
	}

	public void load(InsertChain globalChain) {
		this.chain = globalChain.chain;
		this.configIndex = globalChain.configIndex;
		this.initialInserts = globalChain.initialInserts;
		this.ns = globalChain.ns;
		this.props = globalChain.props;
		this.propsMap = globalChain.propsMap;
		
	}
}
