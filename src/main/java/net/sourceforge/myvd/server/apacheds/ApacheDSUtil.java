package net.sourceforge.myvd.server.apacheds;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ApacheDSUtil {
	
	private static final Logger LOG = LoggerFactory.getLogger( ApacheDSUtil.class );
	
    public static String generateRandomOID(SchemaManager schemaManager) {
		String base ="1.2.840.113556.1.4.";
		int num = (int) (Math.random() * 5000);
		
		StringBuffer b = new StringBuffer(base);
		b.append(num);
		
		if (schemaManager.getAttributeType(b.toString()) == null ) {
			return b.toString();
		} else {
			return generateRandomOID(schemaManager);
		}
	}
    
    public static AttributeType addAttributeToSchema(Attribute attribute,SchemaManager schemaManager) throws LdapException {
    	String newOID = generateRandomOID(schemaManager);
    	MutableAttributeType at = new MutableAttributeType(newOID);
    	
    	// base new attributes on uid
    	AttributeType uidAT = schemaManager.getAttributeType("0.9.2342.19200300.100.1.1");
    	at.setNames(attribute.getId());
    	at.setSyntax(uidAT.getSyntax());
    	at.setSingleValued(false);
    	at.setEquality(uidAT.getEquality());
    	
    	at.setSubstring(uidAT.getSubstring());
    	at.setSchemaName(uidAT.getSchemaName());
    	at.setSpecification(uidAT.getSpecification());
    	at.setUsage(uidAT.getUsage());
    	
    	LOG.warn("Creating dynamic schema entry : '{}' {}", at.getName(), at.getOid());
    	
    	schemaManager.add(at);
    	return at;
    }
    
    public static AttributeType addBinaryAttributeToSchema(Attribute attribute,SchemaManager schemaManager) throws LdapException {
    	String newOID = generateRandomOID(schemaManager);
    	MutableAttributeType at = new MutableAttributeType(newOID);
    	
    	// base new attributes on javaSerializedData
    	AttributeType uidAT = schemaManager.getAttributeType("1.3.6.1.4.1.42.2.27.4.1.8");
    	at.setNames(attribute.getId());
    	at.setSyntax(uidAT.getSyntax());
    	at.setSingleValued(false);
    	
    	at.setSchemaName(uidAT.getSchemaName());
    	at.setSpecification(uidAT.getSpecification());
    	at.setUsage(uidAT.getUsage());
    	
    	LOG.warn("Creating dynamic schema entry : '{}' {}", at.getName(), at.getOid());
    	
    	schemaManager.add(at);
    	return at;
    }
}
