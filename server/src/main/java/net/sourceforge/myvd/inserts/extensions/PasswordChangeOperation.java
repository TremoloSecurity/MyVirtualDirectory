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
package net.sourceforge.myvd.inserts.extensions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

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
import net.sourceforge.myvd.types.Int;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.Results;
import net.sourceforge.myvd.util.NamingUtils;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.asn1.ASN1Identifier;
import com.novell.ldap.asn1.ASN1OctetString;
import com.novell.ldap.asn1.ASN1Sequence;
import com.novell.ldap.asn1.ASN1Tagged;
import com.novell.ldap.asn1.LBERDecoder;
import com.novell.ldap.asn1.LBEREncoder;
import com.novell.ldap.util.DN;

public class PasswordChangeOperation implements Insert {

	private static final String PASSWD_CHANGE_OP = "1.3.6.1.4.1.4203.1.11.1";
	DN remoteBase;
	String[] explodedRemoteBase;
	String[] explodedLocalBase;
	NamingUtils utils;
	String name;
	
	public void configure(String name, Properties props, NameSpace nameSpace)
			throws LDAPException {
		this.remoteBase = new DN(props.getProperty("remoteBase"));
		this.explodedRemoteBase = this.remoteBase.explodeDN(false);
		if (nameSpace != null && props.getProperty("localBase") == null) {
			this.explodedLocalBase =   nameSpace.getBase().getDN().explodeDN(false);
		} else {
			this.explodedLocalBase =   new DN(props.getProperty("localBase","")).explodeDN(false);
		}
		
		utils = new NamingUtils();

	}

	public void add(AddInterceptorChain chain, Entry entry,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextAdd(entry,constraints);

	}

	public void bind(BindInterceptorChain chain, DistinguishedName dn,
			Password pwd, LDAPConstraints constraints) throws LDAPException {
		chain.nextBind(dn,pwd,constraints);

	}

	public void compare(CompareInterceptorChain chain, DistinguishedName dn,
			Attribute attrib, LDAPConstraints constraints) throws LDAPException {
		chain.nextCompare(dn,attrib,constraints);

	}

	public void delete(DeleteInterceptorChain chain, DistinguishedName dn,
			LDAPConstraints constraints) throws LDAPException {
		chain.nextDelete(dn,constraints);

	}

	public void extendedOperation(ExetendedOperationInterceptorChain chain,
			ExtendedOperation op, LDAPConstraints constraints)
			throws LDAPException {
		
		if (op.getOp().getID().equals(PasswordChangeOperation.PASSWD_CHANGE_OP)) {
		
			LBERDecoder decoder = new LBERDecoder();
			ASN1Sequence opSeq = (ASN1Sequence) decoder.decode(op.getOp().getValue());
			ASN1Tagged[] seq = new ASN1Tagged[3];
			
			seq[0] = (ASN1Tagged) opSeq.get(0);
			seq[1] = (ASN1Tagged) opSeq.get(1);
			seq[2] = (ASN1Tagged) opSeq.get(2);
			
			String userDN = ((ASN1OctetString) seq[0].taggedValue()).stringValue();
			String oldPwd = ((ASN1OctetString) seq[1].taggedValue()).stringValue();
			String newPwd = ((ASN1OctetString) seq[2].taggedValue()).stringValue();
			
			userDN = utils.getRemoteMappedDN(new DN(userDN),this.explodedLocalBase,this.explodedRemoteBase).toString();
			
			//reconstruct the operation
			ByteArrayOutputStream encodedData = new ByteArrayOutputStream();
	        LBEREncoder encoder  = new LBEREncoder();
	        seq = new ASN1Tagged[3];
	        seq[0] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,false,0),new ASN1OctetString(userDN),false);
	        seq[1] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,false,1),new ASN1OctetString(oldPwd),false);
	        seq[2] = new ASN1Tagged(new ASN1Identifier(ASN1Identifier.CONTEXT,false,2),new ASN1OctetString(newPwd),false);
	
	        opSeq = new ASN1Sequence(seq,3);
	        try {
				opSeq.encode(encoder,encodedData);
			} catch (IOException e) {
				throw new LDAPException("Could not encode request",LDAPException.OPERATIONS_ERROR,userDN);
			}
	        
	        LDAPExtendedOperation localOp = new LDAPExtendedOperation(PASSWD_CHANGE_OP,encodedData.toByteArray());
	        op.setDn(new DistinguishedName(userDN));
	        op.setOp(localOp);
	        op.setWrite(true);
		}
		
		chain.nextExtendedOperations(op,constraints);
		

	}

	public void modify(ModifyInterceptorChain chain, DistinguishedName dn,
			ArrayList<LDAPModification> mods, LDAPConstraints constraints)
			throws LDAPException {
		chain.nextModify(dn,mods,constraints);

	}

	public void search(SearchInterceptorChain chain, DistinguishedName base,
			Int scope, Filter filter, ArrayList<Attribute> attributes,
			Bool typesOnly, Results results, LDAPSearchConstraints constraints)
			throws LDAPException {
		chain.nextSearch(base,scope,filter,attributes,typesOnly,results,constraints);

	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn,newRdn,deleteOldRdn,constraints);
		
	}

	public void rename(RenameInterceptorChain chain, DistinguishedName dn, DistinguishedName newRdn, DistinguishedName newParentDN, Bool deleteOldRdn,LDAPConstraints constraints) throws LDAPException {
		chain.nextRename(dn,newRdn,newParentDN,deleteOldRdn,constraints);
	}

	public void postSearchEntry(PostSearchEntryInterceptorChain chain, Entry entry, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchEntry(entry,base,scope,filter,attributes,typesOnly,constraints);
		
	}

	public void postSearchComplete(PostSearchCompleteInterceptorChain chain, DistinguishedName base, Int scope, Filter filter, ArrayList<Attribute> attributes, Bool typesOnly, LDAPSearchConstraints constraints) throws LDAPException {
		chain.nextPostSearchComplete(base,scope,filter,attributes,typesOnly,constraints);
		
	}
	
	public String getName() {
		return this.name;
	}

	public void shutdown() {
		// TODO Auto-generated method stub
		
	}

}
