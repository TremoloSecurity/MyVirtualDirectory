package net.sourceforge.myvd.server.apacheds;

import java.util.Map;

import org.apache.directory.api.ldap.model.message.AbstractExtendedResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;

import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;

public class MyVDExtendedResponse  extends AbstractExtendedResponse implements ExtendedResponse  {

	public MyVDExtendedResponse(int id) {
		super(id);
		
	}
	
	public MyVDExtendedResponse(int id,String name) {
		super(id,name);
		
	}
	
	public MyVDExtendedResponse(String name) {
		super(name);
		
	}
	
	

	
}
