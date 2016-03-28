package net.sourceforge.myvd.inserts.jdbc;

import java.sql.Connection;
import java.sql.SQLException;

public interface JdbcPool {
	public Connection getCon() throws InstantiationException, IllegalAccessException, ClassNotFoundException, SQLException;
	
	public void returnCon(Connection con);
}
