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
package net.sourceforge.myvd.types;

import java.util.ArrayList;

import net.sourceforge.myvd.chain.InterceptorChain;
import net.sourceforge.myvd.chain.SearchInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;



import com.novell.ldap.LDAPSearchConstraints;

public class Result {
	public EntrySet entrySet;
	public DistinguishedName base;
	public Int scope;
	public Filter filter;
	public Bool typesOnly;
	public ArrayList<Attribute> attribs;
	public LDAPSearchConstraints constraints;
	
	public InsertChain localSource;
	public InsertChain globalSource;
	public SearchInterceptorChain chain;
}
