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
import java.util.Iterator;

import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchRequest;
import com.novell.ldap.rfc2251.RfcFilter;

public class Filter {
	
	private FilterNode root;
	
	public Filter(String val) throws LDAPException {
		RfcFilter rfcFilter = new RfcFilter(val.trim());
		this.root = createFilter(rfcFilter.getFilterIterator(),null);
	}
	
	public Filter(FilterNode root) {
		
		this.root = root;
	}
	
	public void setValue(String val) throws LDAPException {
		RfcFilter rfcFilter = new RfcFilter(val.trim());
		this.root = createFilter(rfcFilter.getFilterIterator(),null);
	}
	
	public String getValue() {
		return this.root.toString();
	}
	
	
	private  FilterNode createFilter(Iterator itr,FilterNode parent) {
        int op=-1;
        //filter.append('(');
        String comp = null;
        
        boolean isFirst = true;
        
        FilterNode ret = null;
        
        while (itr.hasNext()){
            Object filterpart = itr.next();
            if (filterpart instanceof Integer){
                op = ((Integer)filterpart).intValue();
                switch (op){
                    case LDAPSearchRequest.AND:
                    	
                        ret = new FilterNode(FilterType.AND,new ArrayList<FilterNode>());
                        if (parent != null) {
                    		parent.addNode(ret);
                    	}
                        break;
                    case LDAPSearchRequest.OR:
                    	ret = new FilterNode(FilterType.OR,new ArrayList<FilterNode>());
                        if (parent != null) {
                    		parent.addNode(ret);
                    	}
                        break;
                    case LDAPSearchRequest.NOT:
                    	ret = new FilterNode(null);
                        if (parent != null) {
                    		parent.addNode(ret);
                    	}
                        break;
                    case LDAPSearchRequest.EQUALITY_MATCH:{
                    	ret = new FilterNode(FilterType.EQUALS,(String)itr.next(),new String((byte[])itr.next()));
                    	if (parent != null) {
                    		if (parent.getType() == FilterType.NOT) {
                    			parent.setNot(ret);
                    		} else {
                    			parent.getChildren().add(ret);
                    		}
                    	}
                    	break;
                    }
                    case LDAPSearchRequest.GREATER_OR_EQUAL:{
                    	ret = new FilterNode(FilterType.GREATER_THEN,(String)itr.next(),new String((byte[])itr.next()));
                    	if (parent != null) {
                    		if (parent.getType() == FilterType.NOT) {
                    			parent.setNot(ret);
                    		} else {
                    			parent.getChildren().add(ret);
                    		}
                    	}
                    	break;
                    }
                    case LDAPSearchRequest.LESS_OR_EQUAL:{
                    	ret = new FilterNode(FilterType.LESS_THEN,(String)itr.next(),new String((byte[])itr.next()));
                    	if (parent != null) {
                    		if (parent.getType() == FilterType.NOT) {
                    			parent.setNot(ret);
                    		} else {
                    			parent.getChildren().add(ret);
                    		}
                    	}
                    	break;
                    }
                    case LDAPSearchRequest.PRESENT:
                    	ret = new FilterNode(FilterType.PRESENCE,(String)itr.next(),"");
                    	if (parent != null) {
                    		if (parent.getType() == FilterType.NOT) {
                    			parent.setNot(ret);
                    		} else {
                    			parent.getChildren().add(ret);
                    		}
                    	}
                    	break;
                    case LDAPSearchRequest.APPROX_MATCH:
                    	ret = new FilterNode(FilterType.EQUALS,(String)itr.next(),new String((byte[])itr.next()));
                    	if (parent != null) {
                    		if (parent.getType() == FilterType.NOT) {
                    			parent.setNot(ret);
                    		} else {
                    			parent.getChildren().add(ret);
                    		}
                    	}
                    	break;
                    case LDAPSearchRequest.EXTENSIBLE_MATCH:
                    	ret = new FilterNode(FilterType.EXT,(String)itr.next(),new String((byte[])itr.next()));
                    	if (parent != null) {
                    		if (parent.getType() == FilterType.NOT) {
                    			parent.setNot(ret);
                    		} else {
                    			parent.getChildren().add(ret);
                    		}
                    	}
                    	break;
                    case LDAPSearchRequest.SUBSTRINGS:{
                    	StringBuffer val = new StringBuffer();
                        String name = (String)itr.next();
                    	
                        
                        boolean noStarLast = true;
                        while (itr.hasNext()){
                            op = ((Integer)itr.next()).intValue();
                            switch(op){
                                case LDAPSearchRequest.INITIAL:
                                    val.append((String)itr.next());
                                    val.append('*');
                                    noStarLast = false;
                                    break;
                                case LDAPSearchRequest.ANY:
                                    if( noStarLast)
                                        val.append('*');
                                    val.append((String)itr.next());
                                    val.append('*');
                                    noStarLast = false;
                                    break;
                                case LDAPSearchRequest.FINAL:
                                    if( noStarLast)
                                        val.append('*');
                                    
                                    val.append((String)itr.next());
                                    break;
                            }
                            
                            
                        }
                        
                        ret = new FilterNode(FilterType.SUBSTR,name,val.toString());
                        if (parent != null) {
                    		if (parent.getType() == FilterType.NOT) {
                    			parent.setNot(ret);
                    		} else {
                    			parent.getChildren().add(ret);
                    		}
                    	}
                        break;
                    }
                }
            } else if (filterpart instanceof Iterator){
            	createFilter((Iterator)filterpart, ret);
            }
            
            
        }
        
        return ret;
    }
	
	public FilterNode getRoot() {
		return this.root;
	}
	
	public ArrayList<FilterNode> listNodes(String attributeName) {
		ArrayList<FilterNode> results = new ArrayList<FilterNode>();
		this.findNodes(this.root,attributeName,results);
		return results;
	}
	
	private void findNodes(FilterNode root,String attributeName,ArrayList<FilterNode> res) {
		Iterator<FilterNode> it;
		
		switch (root.getType()) {
			case PRESENCE : 
			case SUBSTR:
			case EQUALS : 
			case GREATER_THEN : 
			case LESS_THEN : if (root.getName().equalsIgnoreCase(attributeName)) {
							 	res.add(root);
							 	return;
							 }
							 break;
			case AND : it = root.getChildren().iterator();
					   while (it.hasNext()) {
						   findNodes(it.next(),attributeName,res);
					   }
					   break;
					   
			case OR :  it = root.getChildren().iterator();
					   while (it.hasNext()) {
						   findNodes(it.next(),attributeName,res);
					   }
					   break;
			
			case NOT : findNodes(root.getNot(),attributeName,res);
					   break;
					   
		}
	}
	
	private int computeLength() {
		return this.root.computeLength();
	}
}
