package net.sourceforge.myvd.util;

import java.util.HashSet;

public class SchemaUtil {
	static SchemaUtil schemaUtil;
	
	HashSet<String> binaryAttribs;
	
	private SchemaUtil() {
		this.binaryAttribs = new HashSet<String>();
	}
	
	public static SchemaUtil getSchemaUtil() {
		if (schemaUtil == null) {
			schemaUtil = new SchemaUtil();
		}
		
		return schemaUtil;
	}
	
	public boolean isBinary(String name) {
		return this.binaryAttribs.contains(name.toLowerCase());
	}
	
	public void addBinaryAttribute(String name) {
		this.binaryAttribs.add(name.toLowerCase());
	}
}
