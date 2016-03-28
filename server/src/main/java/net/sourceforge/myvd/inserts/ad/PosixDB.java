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

public class PosixDB extends CompositeInsert {

	private Logger logger;

	@Override
	public void generateConfig(ArrayList<String> insertNames, Properties props,
			Properties compositeProps, NameSpace ns) {
		String table = compositeProps.getProperty("tableName");
		String type = compositeProps.getProperty("type","user");
		
		//map the obejct class for consistancy
		insertNames.add("mapoc");
		props.setProperty("mapoc.className","net.sourceforge.myvd.inserts.jdbc.MapDBObjectClass");
		if (type.equalsIgnoreCase("user")) {
			props.setProperty("mapoc.config.inboundObjectClasses","user,person,organizationalPerson");
		} else {
			props.setProperty("mapoc.config.inboundObjectClasses","group");
		}
		
		//the actual db insert
		insertNames.add("dbserver");
		props.setProperty("dbserver.className", "net.sourceforge.myvd.inserts.jdbc.JdbcInsert");
		props.setProperty("dbserver.config.driver", compositeProps.getProperty("driver"));
		props.setProperty("dbserver.config.url", compositeProps.getProperty("url"));
		props.setProperty("dbserver.config.user", compositeProps.getProperty("user"));
		props.setProperty("dbserver.config.password", compositeProps.getProperty("password"));
		props.setProperty("dbserver.config.maxCons", compositeProps.getProperty("maxCons"));
		props.setProperty("dbserver.config.maxConsIdle", compositeProps.getProperty("maxConsIdle"));
		props.setProperty("dbserver.config.rdn", "objectguid");
		props.setProperty("dbserver.config.addBaseToFilter", "false");
		props.setProperty("dbserver.config.useSimple", "true");
		
		
		
		if (type.equalsIgnoreCase("user")) {
			props.setProperty("dbserver.config.objectClass", "posixAccount");
			props.setProperty("dbserver.config.sql", "SELECT id,objectguid,homeDirectory,loginShell FROM " + table);
			props.setProperty("dbserver.config.mapping", "uidnumber=id,objectguid=objectguid,homeDirectory=homeDirectory,loginShell=loginShell");
		} else {
			props.setProperty("dbserver.config.objectClass", "posixGroup");
			props.setProperty("dbserver.config.sql", "SELECT id,objectguid FROM " + table);
			props.setProperty("dbserver.config.mapping", "gidnumber=id,objectguid=objectguid");
		}
		
		//db update insert
		insertNames.add("updateDB");
		props.setProperty("updateDB.className", "net.sourceforge.myvd.inserts.jdbc.DBAddOnModify");
		props.setProperty("updateDB.config.tableName",table);
		props.setProperty("updateDB.config.dbInsertName","dbserver");
		props.setProperty("updateDB.config.idField", "id");
		
		

	}

	@Override
	public Logger getLogger() {
		if (logger == null) {
			logger = Logger.getLogger(ADPosixJoiner.class.getName());
		}
		
		return this.logger;
	}

}
