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
package net.sourceforge.myvd.inserts.ad;

import java.util.ArrayList;
import java.util.Properties;

import org.apache.log4j.Logger;

import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchConstraints;

import net.sourceforge.myvd.chain.PostSearchEntryInterceptorChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.composite.CompositeInsert;
import net.sourceforge.myvd.types.Attribute;
import net.sourceforge.myvd.types.Bool;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.Entry;
import net.sourceforge.myvd.types.Filter;
import net.sourceforge.myvd.types.Int;

public class ADPosixJoiner extends CompositeInsert {

	@Override
	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
	}




	Logger logger;
	
	@Override
	public void generateConfig(ArrayList<String> insertNames, Properties props,Properties compositeProps,NameSpace ns) {
		
		//Attribute Cleaner
		insertNames.add("attributeCleaner");
		props.setProperty("attributeCleaner.className", "net.sourceforge.myvd.inserts.mapping.AttributeCleaner");
		
		//Map the objectclass
		insertNames.add("objmap");
		props.setProperty("objmap.className", "net.sourceforge.myvd.inserts.mapping.AttributeValueMapper");
		props.setProperty("objmap.config.mapping", "objectClass.posixAccount=user,objectClass.posixGroup=group");
		
		//Map attributes names
		insertNames.add("membertrans");
		props.setProperty("membertrans.className", "net.sourceforge.myvd.inserts.mapping.AttributeMapper");
		props.setProperty("membertrans.config.mapping", "uniqueMember=member,uid=samAccountName");
		
		//Map dns
		insertNames.add("mapdns");
		props.setProperty("mapdns.className", "net.sourceforge.myvd.inserts.mapping.DNAttributeMapper");
		props.setProperty("mapdns.config.remoteBase", compositeProps.getProperty("activeDirectoryBase"));
		props.setProperty("mapdns.config.localBase", ns.getBase().toString());
		props.setProperty("mapdns.config.dnAttribs", compositeProps.getProperty("dnAttribs","uniqueMember,member,memberOf,distinguishedname,objectcategory"));
		

		
		//Generate Posix ID
		insertNames.add("posixgroupid");
		props.setProperty("posixgroupid.className", "net.sourceforge.myvd.inserts.ad.GeneratePosixGID");
		props.setProperty("posixgroupid.config.userAddBase", compositeProps.getProperty("userAddBase") + "," + ns.getBase().toString());
		props.setProperty("posixgroupid.config.groupAddBase", compositeProps.getProperty("groupAddBase") + "," + ns.getBase().toString());
		props.setProperty("posixgroupid.config.homeDirTemplate", compositeProps.getProperty("homeDirTemplate"));
		props.setProperty("posixgroupid.config.loginShell", compositeProps.getProperty("loginShell"));
		
		
		this.getLogger();
		logger.info("User Base : " + props.getProperty("posixgroupid.config.userAddBase"));
		logger.info("Group Base : " + props.getProperty("posixgroupid.config.groupAddBase"));
		
		/*insertNames.add("dumpjoin");
		props.setProperty("dumpjoin.className", "net.sourceforge.myvd.inserts.DumpTransaction");
		props.setProperty("dumpjoin.config.logLevel", "info");
		props.setProperty("dumpjoin.config.label", "joiner");*/
		
		
		//The joiner
		insertNames.add("joiner");
		props.setProperty("joiner.className", "net.sourceforge.myvd.inserts.join.Joiner");
		props.setProperty("joiner.config.primaryNamespace", compositeProps.getProperty("activeDirectoryBase"));
		props.setProperty("joiner.config.joinedNamespace", compositeProps.getProperty("dbBase"));
		props.setProperty("joiner.config.joinedAttributes", "uidNumber,gid,homeDirectory,gidnumber,loginShell");
		props.setProperty("joiner.config.joinFilter", "(objectguid=ATTR.objectguid)");
		
		
		
		
		//For creating db entries
		insertNames.add("joinadd");
		props.setProperty("joinadd.className", "net.sourceforge.myvd.inserts.join.JoinAddFlatNS");
		props.setProperty("joinadd.config.joinerName", "joiner");
		props.setProperty("joinadd.config.joinedObjectClass", "posixUser");
		props.setProperty("joinadd.config.sharedAttributes", "objectguid,homeDirectory,loginShell");
		props.setProperty("joinadd.config.addToJoinedOnly", "true");
		
		
		
		

	}

	
	
	
	@Override
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		// TODO Auto-generated method stub
		super.configure(name, props, nameSpace);
	}




	@Override
	public Logger getLogger() {
		if (logger == null) {
			logger = Logger.getLogger(ADPosixJoiner.class.getName());
		}
		
		return this.logger;
	}

}
