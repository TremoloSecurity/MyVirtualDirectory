package net.sourceforge.myvd.server.apacheds;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;

public final class MyVDApacheDSEntry implements org.apache.directory.api.ldap.model.entry.Entry {

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void clear() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Entry shallowClone() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Dn getDn() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean hasObjectClass(String... objectClasses) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean hasObjectClass(Attribute... objectClasses) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Attribute get(String alias) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute get(AttributeType attributeType) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Attribute> getAttributes() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setDn(Dn dn) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setDn(String dn) throws LdapInvalidDnException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Iterator<Attribute> iterator() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(Attribute... attributes) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(AttributeType attributeType, byte[]... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(AttributeType attributeType, String... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(AttributeType attributeType, Value... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(String upId, AttributeType attributeType, byte[]... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(String upId, AttributeType attributeType, String... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(String upId, AttributeType attributeType, Value... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(String upId, String... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(String upId, byte[]... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Entry add(String upId, Value... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<Attribute> put(Attribute... attributes) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(AttributeType attributeType, byte[]... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(AttributeType attributeType, String... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(AttributeType attributeType, Value... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(String upId, AttributeType attributeType, byte[]... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(String upId, AttributeType attributeType, String... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(String upId, AttributeType attributeType, Value... values) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(String upId, byte[]... values) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(String upId, String... values) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attribute put(String upId, Value... values) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean remove(AttributeType attributeType, byte[]... values) throws LdapException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean remove(AttributeType attributeType, String... values) throws LdapException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean remove(AttributeType attributeType, Value... values) throws LdapException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public List<Attribute> remove(Attribute... attributes) throws LdapException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void removeAttributes(AttributeType... attributes) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean remove(String upId, byte[]... values) throws LdapException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean remove(String upId, String... values) throws LdapException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean remove(String upId, Value... values) throws LdapException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void removeAttributes(String... attributes) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean contains(AttributeType attributeType, byte[]... values) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean contains(AttributeType attributeType, String... values) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean contains(AttributeType attributeType, Value... values) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean containsAttribute(AttributeType attributeType) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean contains(Attribute... attributes) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean contains(String upId, byte[]... values) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean contains(String upId, String... values) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean contains(String upId, Value... values) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean containsAttribute(String... attributes) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public int size() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean isSchemaAware() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String toString(String tabs) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
    public Entry clone()
    {
		return null;
    }
	

}
