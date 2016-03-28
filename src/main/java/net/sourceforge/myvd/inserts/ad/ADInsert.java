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

import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.composite.CompositeInsert;

public class ADInsert extends CompositeInsert {

	@Override
	public void generateConfig(ArrayList<String> insertNames, Properties props,
			Properties compositeProps, NameSpace ns) {
		
		String adbase;
		String remoteBase = compositeProps.getProperty("remoteBase");
		String proxyDN;
		String searchDN;
		
		
		if (compositeProps.getProperty("ADBase","").equalsIgnoreCase("")) {
			adbase = ns.getBase().toString();
		} else {
			adbase = compositeProps.getProperty("ADBase") + ns.getBase().toString();
		}
		
		if (compositeProps.getProperty("proxyDN","").length() > 0) {
			proxyDN = compositeProps.getProperty("proxyDN","") + "," + remoteBase;
			searchDN = compositeProps.getProperty("proxyDN","") + "," + ns.getBase().toString();
		} else {
			proxyDN = "";
			searchDN = "";
		}
			
		
		
		
		
		
		//first the embedded groups insert
		insertNames.add("embed");
		props.setProperty("embed.className", "net.sourceforge.myvd.inserts.ldap.EmbeddedGroups");
		props.setProperty("embed.config.staticAttribute", "member");
		props.setProperty("embed.config.groupSearchBase", adbase);
		props.setProperty("embed.config.staticObjectClass", "group");
		props.setProperty("embed.config.userDN", searchDN);
		props.setProperty("embed.config.userPwd", compositeProps.getProperty("proxyPass"));
		props.setProperty("embed.config.useSync", "false");
		
		//dynamic groups
		insertNames.add("dyngroups");
		props.setProperty("dyngroups.className","net.sourceforge.myvd.inserts.ldap.DynamicGroups");
		props.setProperty("dyngroups.config.urlAttribute", "memberURL");
		props.setProperty("dyngroups.config.staticAttribute", "member");
		props.setProperty("dyngroups.config.staticObjectClass", "group");
		props.setProperty("dyngroups.config.dynamicObjectClass", "groupOfUrls");
		props.setProperty("dyngroups.config.mapObjectClass", "false");
		
		//primary group
		insertNames.add("primarygroup");
		props.setProperty("primarygroup.className", "net.sourceforge.myvd.inserts.ad.PrimaryGroup");
		props.setProperty("primarygroup.config.searchBase", adbase);
		props.setProperty("primarygroup.config.groupObjectClass", "group");
		
		//dn attribute mapper
		insertNames.add("mapdns");
		props.setProperty("mapdns.className", "net.sourceforge.myvd.inserts.mapping.DNAttributeMapper");
		props.setProperty("mapdns.config.dnAttribs", "uniqueMember,member,memberOf,distinguishedname,objectcategory");
		props.setProperty("mapdns.config.remoteBase", compositeProps.getProperty("remoteBase"));
		props.setProperty("mapdns.config.localBase", ns.getBase().toString());
		
		
		insertNames.add("mapguid");
		props.setProperty("mapguid.className", "net.sourceforge.myvd.inserts.ad.ObjectGuidToString");
		
		String useKerb = compositeProps.getProperty("useKerberos","false");
		
		if (useKerb.equalsIgnoreCase("true")) {
			insertNames.add("kerberos");
			props.setProperty("kerberos.className", "net.sourceforge.myvd.inserts.kerberos.ADKerberosInsert");
			props.setProperty("kerberos.config.host", compositeProps.getProperty("host"));
			props.setProperty("kerberos.config.port", compositeProps.getProperty("kerbPort","88"));
		}
		
		
		//LDAP insert
		insertNames.add("ldap");
		props.setProperty("ldap.className", "net.sourceforge.myvd.inserts.ldap.LDAPInterceptor");
		props.setProperty("ldap.config.host", compositeProps.getProperty("host"));
		props.setProperty("ldap.config.port", compositeProps.getProperty("port"));
		props.setProperty("ldap.config.type", compositeProps.getProperty("type","ldap"));
		props.setProperty("ldap.config.passBindOnly", compositeProps.getProperty("passBindOnly","true"));
		props.setProperty("ldap.config.proxyDN", proxyDN);
		props.setProperty("ldap.config.proxyPass", compositeProps.getProperty("proxyPass"));
		props.setProperty("ldap.config.remoteBase", compositeProps.getProperty("remoteBase"));
		props.setProperty("ldap.config.ignoreRefs", compositeProps.getProperty("ignoreRefs","true"));
		
		

	}

	@Override
	public Logger getLogger() {
		// TODO Auto-generated method stub
		return null;
	}

}
