package net.sourceforge.myvd.server.apacheds;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.ReferralManager;
import org.apache.directory.server.core.shared.ReferralManagerImpl;

public class MyVDReferalManager implements ReferralManager {

	@Override
	public void lockRead() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void lockWrite() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void unlock() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isReferral(Dn dn) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean hasParentReferral(Dn dn) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Entry getParentReferral(Dn dn) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void addReferral(Entry entry) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeReferral(Entry entry) throws LdapException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void init(DirectoryService directoryService, String... suffixes)
			throws Exception {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void remove(DirectoryService directoryService, Dn suffix)
			throws Exception {
		// TODO Auto-generated method stub
		
	}

}
