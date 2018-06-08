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
import java.util.Enumeration;
import java.util.Iterator;


import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;

public class FilterNode implements Cloneable {
	FilterType type;
	String name;
	String value;
	FilterNode not;
	ArrayList<FilterNode> children;
	FilterNode parent;
	
	public FilterNode(FilterType type,String name,String value) {
		this.type = type;
		this.name = name;
		this.value = value;
		this.not = null;
		this.children = null;
	}
	
	public FilterNode(FilterType type,ArrayList<FilterNode> children) {
		this.type = type;
		this.children = children;
		this.name = null;
		this.value = null;
		this.not = null;
	}
	
	public FilterNode(FilterNode not) {
		this.type = FilterType.NOT;
		this.not = not;
		this.children = null;
		this.name = null;
		this.value = null;
	}

	public ArrayList<FilterNode> getChildren() {
		return children;
	}

	public void setChildren(ArrayList<FilterNode> children) {
		this.children = children;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public FilterNode getNot() {
		return not;
	}

	public void setNot(FilterNode not) {
		this.not = not;
	}

	public FilterType getType() {
		return type;
	}

	public void setType(FilterType type) {
		this.type = type;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public @Override Object clone() throws CloneNotSupportedException {
		FilterNode newNode;
		
		switch (this.type) {
			case PRESENCE :
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
			case SUBSTR:
				newNode = new FilterNode(this.type,this.name,this.value);
				return newNode;
			
			case AND:
			case OR:
				ArrayList<FilterNode> newChildren = new ArrayList<FilterNode>();
				Iterator<FilterNode> it = this.children.iterator();
				while (it.hasNext()) {
					newChildren.add((FilterNode) it.next().clone());
				}
				
				
				newNode = new FilterNode(this.type,newChildren);
				return newNode;
				
			case NOT:
				return new FilterNode((FilterNode) this.not.clone());
		}
		
		return null;
	}
	
	public void readFromNode(FilterNode node) throws LDAPException {
		this.type = node.type;
		this.name = node.name;
		this.value = node.value;
		
		if (node.not != null) {
			try {
				this.not = (FilterNode) node.not.clone();
			} catch (CloneNotSupportedException e) {
				throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
			}
		}
		
		
		if (node.children != null) {
			this.children = new ArrayList<FilterNode>();
			Iterator<FilterNode> it = node.children.iterator();
			while (it.hasNext()) {
				try {
					node.children.add((FilterNode) it.next().clone());
				} catch (CloneNotSupportedException e) {
					throw new LDAPException(e.toString(),LDAPException.OPERATIONS_ERROR,"");
				}
			}
		}
	}
	
	public String toString() {
		StringBuffer buf = new StringBuffer();
		this.toString(buf);
		return buf.toString();
	}
	
	protected void toString(StringBuffer buf) {
		Iterator<FilterNode> it;
		
		switch (this.type) {
			case PRESENCE : buf.append('(').append(this.name).append("=*)"); break;
			case SUBSTR:
			case EQUALS : buf.append('(').append(this.name).append('=').append(this.value).append(')'); break;
			case GREATER_THEN : buf.append('(').append(this.name).append(">=").append(this.value).append(')'); break;
			case LESS_THEN : buf.append('(').append(this.name).append("<=").append(this.value).append(')'); break;
			case AND : buf.append("(&");
					   it = this.children.iterator();
					   while (it.hasNext()) {
						   it.next().toString(buf);
					   }
					   buf.append(')');
					   break;
					   
			case OR :  buf.append("(|");
					   it = this.children.iterator();
					   while (it.hasNext()) {
						   it.next().toString(buf);
					   }
					   buf.append(')');
					   break;
			
			case NOT : buf.append("(!");
					   this.not.toString(buf);
					   buf.append(')');
					   break;
					   
		}
	}

	public void addNode(FilterNode node) {
		if (this.type == FilterType.AND || this.type == FilterType.OR) {
			this.children.add(node);
		} else {
			this.not = node;
		}
		
	}
	
	
	
	public boolean checkEntry(LDAPEntry entry) {
		Iterator<FilterNode> it;
		LDAPAttributeSet attribs;
		LDAPAttribute attrib;
		Enumeration enumer;
		
		switch (this.type) {
			case PRESENCE : return entry.getAttributeSet().getAttribute(this.name) != null;
			case SUBSTR: 
					   attribs = entry.getAttributeSet();
					   attrib = attribs.getAttribute(this.name);
					   
					   if (attrib == null) {
						   return false;
					   }
					   
					   enumer = attrib.getStringValues();
					   String compval = this.value.replaceAll("\\*", ".*");
					   while (enumer.hasMoreElements()) {
						   if (enumer.nextElement().toString().matches(compval)) {
							   return true;
						   }
					   }
					   
					   return false;
				   
			case EQUALS :  attribs = entry.getAttributeSet();
						   attrib = attribs.getAttribute(this.name);
						   
						   if (attrib == null) {
							   return false;
						   }
						   
						   enumer = attrib.getStringValues();
						   while (enumer.hasMoreElements()) {
							   if (enumer.nextElement().toString().equalsIgnoreCase(this.value)) {
								   return true;
							   }
						   }
						   
						   return false;
			case GREATER_THEN : attribs = entry.getAttributeSet();
								   attrib = attribs.getAttribute(this.name);
								   
								   if (attrib == null) {
									   return false;
								   }
								   
								   enumer = attrib.getStringValues();
								   while (enumer.hasMoreElements()) {
									   if (enumer.nextElement().toString().compareToIgnoreCase(this.value) > 0) {
										   return true;
									   }
								   }
								   
								   return false;
			case LESS_THEN : attribs = entry.getAttributeSet();
							   attrib = attribs.getAttribute(this.name);
							   
							   if (attrib == null) {
								   return false;
							   }
							   
							   enumer = attrib.getStringValues();
							   while (enumer.hasMoreElements()) {
								   if (enumer.nextElement().toString().compareToIgnoreCase(this.value) < 0) {
									   return true;
								   }
							   }
							   
							   return false;
			case AND : 
					   it = this.children.iterator();
					   while (it.hasNext()) {
						   if (! it.next().checkEntry(entry)) {
							   return false;
						   }
					   }
					   return true;
					   
			case OR :  it = this.children.iterator();
					   while (it.hasNext()) {
						   if (it.next().checkEntry(entry)) {
							   return true;
						   }
					   }
					   return false;
					   
			
			case NOT : return ! this.not.checkEntry(entry);
					   
		}
		
		return false;
	}
	
	public int getWeight() {
		Iterator<FilterNode> it;
		LDAPAttributeSet attribs;
		LDAPAttribute attrib;
		Enumeration enumer;
		int w = 0;
		int sum = 0;
		int curw = 0;
		
		switch (this.type) {
			case PRESENCE : return 1;
			case SUBSTR: return 2;
			case EQUALS :  return 3;
			case GREATER_THEN : return 2;
			case LESS_THEN : return 2;
			case AND : 
					   it = this.children.iterator();
					   while (it.hasNext()) {
						   sum += it.next().getWeight();
					   }
					   return sum;
					   
			case OR :  it = this.children.iterator();
					   while (it.hasNext()) {
						   curw = it.next().getWeight();
						   if (curw == 0 || curw > w) {
							   w = curw;
						   }
					   }
					   return w;
					   
			
			case NOT : return 4 - this.not.getWeight();
					   
		}
		
		return 0;
	}

	public FilterNode getParent() {
		return parent;
	}

	public void setParent(FilterNode parent) {
		this.parent = parent;
	}
	
	protected int computeLength() {
		return 0;
		/*
		int length;
		switch (this.type) {
		case AND :
		case OR:
			length = this.computeFilterSetLength();
			break;
		case NOT:
			length = this.not.computeLength();
			break;
		case GREATER_THEN:
		case LESS_THEN:
		case EQUALS:
			length = this.computeAVALength();
			break;
		case PRESENCE:
			length = this.computePresenceLength();
			break;
		case EXT:
			length = 0; //this isn't going to fly
			break;
		case SUBSTR:
			
		
			
			
		}*/
	}
	

	

}
