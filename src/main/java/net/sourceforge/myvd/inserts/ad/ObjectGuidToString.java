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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import com.novell.ldap.LDAPAttribute;
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
import net.sourceforge.myvd.types.Results;

public class ObjectGuidToString implements Insert {

	String name;
	
	HashMap<String,String> binaryToString;
	
	
	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry, constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn, pwd, constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn, attrib, constraints);

	}

	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.name = name;
		this.binaryToString = new HashMap<String,String>();

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn, constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextExtendedOperations(op, constraints);

	}

	public String getName() {
		return this.name;
	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn, mods, constraints);

	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain,
			DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base, scope, filter, attributes, typesOnly, constraints);

	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain,
			Entry entry, DistinguishedName base, Int scope, Filter filter,
			ArrayList<Attribute> attributes, Bool typesOnly,
			LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry, base, scope, filter, attributes, typesOnly, constraints);
		
		LDAPAttribute attrib = entry.getEntry().getAttribute("objectguid");
		
		if (attrib != null) {
			byte[] bytes = attrib.getByteValue();
			StringBuffer byteStr = new StringBuffer();
			
			for (int i = 0; i < bytes.length; i++) {
				byteStr.append("\\").append(byteToHex(bytes[i]));
			}
			
			StringBuffer buf = new StringBuffer();
			buf.append(byteToHex(bytes[3]));
			buf.append(byteToHex(bytes[2]));
			buf.append(byteToHex(bytes[1]));
			buf.append(byteToHex(bytes[0]));
			buf.append('-');
			buf.append(byteToHex(bytes[5]));
			buf.append(byteToHex(bytes[4]));
			buf.append('-');
			buf.append(byteToHex(bytes[7]));
			buf.append(byteToHex(bytes[6]));
			buf.append('-');
			buf.append(byteToHex(bytes[8]));
			buf.append(byteToHex(bytes[9]));
			buf.append('-');
			buf.append(byteToHex(bytes[10]));
			buf.append(byteToHex(bytes[11]));
			buf.append(byteToHex(bytes[12]));
			buf.append(byteToHex(bytes[13]));
			buf.append(byteToHex(bytes[14]));
			buf.append(byteToHex(bytes[15]));
			
			attrib.removeValue(bytes);
			attrib.addValue(buf.toString());
			
			this.binaryToString.put(buf.toString(), byteStr.toString());
		}
		
		attrib = entry.getEntry().getAttribute("objectsid");
		
		if (attrib != null) {
			byte[] sidBytes = attrib.getByteValue();
			attrib.removeValue(sidBytes);
			
			String strSid = this.getSIDasStringOfBytes(sidBytes);
			attrib.addValue(strSid);
			
			
		}

	}

	private String objectguidh2b(String objectguid) {
		StringBuffer byteStr = new StringBuffer();
		
		char c;
		
		//first 4 bytes
		byteStr.append("\\");
		c = objectguid.charAt(6);
		byteStr.append(c);
		c = objectguid.charAt(7);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(4);
		byteStr.append(c);
		c = objectguid.charAt(5);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(2);
		byteStr.append(c);
		c = objectguid.charAt(3);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(0);
		byteStr.append(c);
		c = objectguid.charAt(1);
		byteStr.append(c);
		
		//2 bytes
		byteStr.append("\\");
		c = objectguid.charAt(11);
		byteStr.append(c);
		c = objectguid.charAt(12);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(9);
		byteStr.append(c);
		c = objectguid.charAt(10);
		byteStr.append(c);
		
		//2 bytes
		byteStr.append("\\");
		c = objectguid.charAt(16);
		byteStr.append(c);
		c = objectguid.charAt(17);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(14);
		byteStr.append(c);
		c = objectguid.charAt(15);
		byteStr.append(c);
		
		//2 bytes
		byteStr.append("\\");
		c = objectguid.charAt(19);
		byteStr.append(c);
		c = objectguid.charAt(20);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(21);
		byteStr.append(c);
		c = objectguid.charAt(22);
		byteStr.append(c);
		
		//6 bytes
		byteStr.append("\\");
		c = objectguid.charAt(24);
		byteStr.append(c);
		c = objectguid.charAt(25);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(26);
		byteStr.append(c);
		c = objectguid.charAt(27);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(28);
		byteStr.append(c);
		c = objectguid.charAt(29);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(30);
		byteStr.append(c);
		c = objectguid.charAt(31);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(32);
		byteStr.append(c);
		c = objectguid.charAt(33);
		byteStr.append(c);
		
		byteStr.append("\\");
		c = objectguid.charAt(34);
		byteStr.append(c);
		c = objectguid.charAt(35);
		byteStr.append(c);
		
		this.binaryToString.put(objectguid, byteStr.toString());
		return byteStr.toString();
	}
	
	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, Bool deleteOldRdn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn, newRdn, deleteOldRdn, constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn,
			DistinguishedName newRdn, DistinguishedName newParentDN,
			Bool deleteOldRdn, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextRename(dn, newRdn, newParentDN, deleteOldRdn, constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		
		Filter newFilter = new Filter(filter.getRoot().toString());
		this.replaceGUID(newFilter.getRoot());
		
		chain.nextSearch(base, scope, newFilter, attributes, typesOnly, results, constraints);
		
		

	}

	public void shutdown() {
		

	}
	
	/**
	* Convenience method to convert a byte array to a hex string.
	*
	* @param data the byte[] to convert
	* @return String the converted byte[]
	*/
	public  String bytesToHex(byte[] data) {
		StringBuffer buf = new StringBuffer();
		for ( int i = 0; i < data.length; i++ ) {
			buf.append( byteToHex(data[i]) );
		}
		return(buf.toString());
	}
	
	/**
	* Convenience method to convert a byte to a hex string.
	*
	* @param data the byte to convert
	* @return String the converted byte
	*/
	public  String byteToHex(byte data)
	{
		StringBuffer buf = new StringBuffer();
		buf.append(toHexChar((data>>>4)&0x0F));
		buf.append(toHexChar(data&0x0F));
		return buf.toString();
	}
	
	 /**
	* Convenience method to convert an int to a hex char.
	*
	* @param i the int to convert
	* @return char the converted char
	*/
	public  char toHexChar(int i)
	{
		if ((0 <= i) && (i <= 9 ))
			return (char)('0' + i);
		else
			return (char)('a' + (i-10));
	}
	
	public void replaceGUID(FilterNode root)  {
		FilterNode newNode;
		
		switch (root.getType()) {
			case PRESENCE :
			case SUBSTR:
				
			case EQUALS :
			case LESS_THEN :
			case GREATER_THEN :
				if (root.getName().equalsIgnoreCase("objectguid")) {
					String curVal = root.getValue();
					String byteVal = this.binaryToString.get(curVal);
					if (byteVal == null) {
						byteVal = this.objectguidh2b(curVal);
					}
					
					
					root.setValue(byteVal);
				} else if (root.getName().equalsIgnoreCase("objectsid")) {
					String curVal = root.getValue();
					String byteVal = this.binaryToString.get(curVal);
					if (byteVal == null) {
						byteVal = this.objectsidh2b(curVal);
					} 
					
					
					root.setValue(byteVal);
					
				}
				break;
				
			case AND:
			case OR:
				
				Iterator<FilterNode> it = root.getChildren().iterator();
				while (it.hasNext()) {
					replaceGUID(it.next());
				}
				
				break;
				
			case NOT:
				replaceGUID(root.getNot());
				break;
		}
		
		
	}
	
	
	
	public  String getSIDasStringOfBytes(byte[] sid) {
		
		if (sid.length < 28) {
			return "";
		}
		
		StringBuffer byteString = new StringBuffer();
		StringBuffer strSID = new StringBuffer();
		
		for (int i=0;i<sid.length;i++) {
			byteString.append("\\").append(this.byte2hex(sid[i]));
		}
		
		
		int version;
		long authority;
		int count;
		String rid = "";
		strSID.append("S");
    
		 // get version
		version = sid[0];
		strSID = strSID.append('-').append(Integer.toString(version));
		for (int i=6; i>0; i--) {
			rid += byte2hex(sid[i]);

		}
    
		// get authority
		authority = Long.parseLong(rid);
		
		strSID.append('-').append(Long.toString(authority));
 
		//next byte is the count of sub-authorities
		count = sid[7]&0xFF;
		
 
		//iterate all the sub-auths
		for (int i=0;i<count;i++) {
			rid = "";
			for (int j=11; j>7; j--) {
				rid += byte2hex(sid[j+(i*4)]);
			}
			
		
			
			
			strSID.append('-').append(Long.parseLong(rid,16));
		}
		
		
		
		
		this.binaryToString.put(strSID.toString(), byteString.toString());
		
		return strSID.toString();    
	}
	
	private String objectsidh2b(String objectSID) {
		
		StringBuffer byteStr = new StringBuffer();
		StringBuffer tmp = new StringBuffer();
		StringBuffer authorities = new StringBuffer();
		
		//version
		int begin = objectSID.indexOf('-') + 1;
		int end = objectSID.indexOf('-',begin);
		String version = objectSID.substring(begin,end);
		byteStr.append('\\');
		if (version.length() == 1) {
			byteStr.append('0');
		}
		byteStr.append(version);
		
		
		
		////System.out.println("version : " + version);
		
		begin = objectSID.indexOf('-',end) + 1;
		end = objectSID.indexOf('-',begin);
		
		String part2 = objectSID.substring(begin,end);
		for (int i=part2.length();i<12;i++) {
			tmp.append('0');
		}
		
		tmp.append(part2);
		
		
		
		for (int i=11;i>0;i-=2) {
			byteStr.append('\\').append(tmp.charAt(i - 1)).append(tmp.charAt(i));
		}
		
		
		
		tmp.setLength(0);
		
		byte num = 0;
		
		boolean done = false;
		String subauth;
		
		while (! done) {
			begin = objectSID.indexOf('-',end) + 1;
			end = objectSID.indexOf('-',begin);
			
			
			
			num++;
			
			if (end == -1) {
				done = true;
				subauth = objectSID.substring(begin);
			} else {
				subauth = objectSID.substring(begin,end);
			}
			
			
			Long l = Long.parseLong(subauth);
			String hexstr = Long.toHexString(l);
			tmp.setLength(0);
			for (int i=hexstr.length();i<8;i++) {
				tmp.append('0');
			}
			tmp.append(hexstr);
			
			for (int i=7;i>0;i-=2) {
				authorities.append('\\').append(tmp.charAt(i - 1)).append(tmp.charAt(i));
			}
			
			
		}
		
		byteStr.append('\\').append(byte2hex(num)).append(authorities);
		
		
		
		return byteStr.toString();
		
		
	}
	
	public  String byte2hex(byte b) {
		String ret = Integer.toHexString((int)b&0xFF);
		if (ret.length()<2) ret = "0"+ret;
		return ret;
	}

}
