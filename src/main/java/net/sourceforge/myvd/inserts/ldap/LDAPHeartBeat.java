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

package net.sourceforge.myvd.inserts.ldap;

import org.apache.log4j.Logger;

public class LDAPHeartBeat implements Runnable {

	static Logger logger = Logger.getLogger(LDAPHeartBeat.class.getName());
	
	boolean stillRunning;

	private LDAPInterceptor insert;
	
	public LDAPHeartBeat(LDAPInterceptor ldapInterceptor) {
		this.stillRunning = true;
		this.insert = ldapInterceptor;
	}

	@Override
	public void run() {
		try {
			Thread.sleep(insert.getHeartBeatMillis());
		} catch (InterruptedException e1) {
			//do nothing
		}
		
		while (stillRunning) {
			this.insert.getConnectionPool().executeHeartBeat();
			try {
				Thread.sleep(insert.getHeartBeatMillis());
			} catch (InterruptedException e) {
				//do nothing
			}
		}

	}
	
	public void stop() {
		this.stillRunning = false;
	}

}
