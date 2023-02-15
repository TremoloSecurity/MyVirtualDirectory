package net.sourceforge.myvd.server.apacheds;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Iterator;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;

public class MyVDApacheDSAttribute implements org.apache.directory.api.ldap.model.entry.Attribute {

	@Override
	public Iterator<Value> iterator() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public int add(String... vals) throws LdapInvalidAttributeValueException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int add(byte[]... vals) throws LdapInvalidAttributeValueException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int add(Value... val) throws LdapInvalidAttributeValueException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void clear() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean contains(String... vals) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean contains(byte[]... vals) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean contains(Value... vals) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public AttributeType getAttributeType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void apply(AttributeType attributeType) throws LdapInvalidAttributeValueException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isInstanceOf(AttributeType attributeType) throws LdapInvalidAttributeValueException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Value get() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] getBytes() throws LdapInvalidAttributeValueException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getId() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUpId() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isHumanReadable() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getString() throws LdapInvalidAttributeValueException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean remove(String... vals) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean remove(byte[]... val) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean remove(Value... vals) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setUpId(String upId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setUpId(String upId, AttributeType attributeType) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public int size() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean isValid(AttributeType attributeType) throws LdapInvalidAttributeValueException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String toString(String tabs) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean equals(Object obj) {
		// TODO Auto-generated method stub
		return super.equals(obj);
	}

	@Override
	public Attribute clone()  {
		// TODO Auto-generated method stub
		return null;
	}
	
	

}
