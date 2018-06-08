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
package net.sourceforge.myvd.test.chain;

import java.util.ArrayList;

import net.sourceforge.myvd.types.FilterNode;
import net.sourceforge.myvd.types.FilterType;


import junit.framework.TestCase;

public class TestFilter extends TestCase {

	
	public void testPresenceToString() {
		FilterNode node = new FilterNode(FilterType.PRESENCE,"objectClass","");
		
		if (! node.toString().equals("(objectClass=*)")) {
			fail("invalid filter : " + node.toString());
		}
		
		
	}
	
	public void testEqualsToString() {
		FilterNode node = new FilterNode(FilterType.EQUALS,"objectClass","inetOrgPerson");
		
		if (! node.toString().equals("(objectClass=inetOrgPerson)")) {
			fail("invalid filter : " + node.toString());
		}
		
		
	}
	
	public void testLessThenToString() {
		FilterNode node = new FilterNode(FilterType.LESS_THEN,"objectClass","LT");
		
		if (! node.toString().equals("(objectClass<=LT)")) {
			fail("invalid filter : " + node.toString());
		}
		
		
	}
	
	public void testGreaterThenToString() {
		FilterNode node = new FilterNode(FilterType.GREATER_THEN,"objectClass","GT");
		
		if (! node.toString().equals("(objectClass>=GT)")) {
			fail("invalid filter : " + node.toString());
		}
		
	}
	
	public void testNotToString() {
		
		FilterNode nnode = new FilterNode(FilterType.PRESENCE,"objectClass","");
		FilterNode node = new FilterNode(nnode);
		
		if (! node.toString().equals("(!(objectClass=*))")) {
			fail("invalid filter : " + node.toString());
		}
		
		
	}
	
	public void testAndToString() {
		
		ArrayList<FilterNode> parts = new ArrayList<FilterNode>();
		parts.add(new FilterNode(FilterType.PRESENCE,"objectClass","*"));
		parts.add(new FilterNode(FilterType.EQUALS,"cn","Test User"));
		parts.add(new FilterNode(FilterType.EQUALS,"sn","User"));
		
		FilterNode node = new FilterNode(FilterType.AND,parts);
		
		if (! node.toString().equals("(&(objectClass=*)(cn=Test User)(sn=User))")) {
			fail("invalid filter : " + node.toString());
		}
		
		
	}
	
	public void testOrToString() {
		
		ArrayList<FilterNode> parts = new ArrayList<FilterNode>();
		parts.add(new FilterNode(FilterType.PRESENCE,"objectClass","*"));
		parts.add(new FilterNode(FilterType.EQUALS,"cn","Test User"));
		parts.add(new FilterNode(FilterType.EQUALS,"sn","User"));
		
		FilterNode node = new FilterNode(FilterType.OR,parts);
		
		if (! node.toString().equals("(|(objectClass=*)(cn=Test User)(sn=User))")) {
			fail("invalid filter : " + node.toString());
		}
		
		
	}
}
