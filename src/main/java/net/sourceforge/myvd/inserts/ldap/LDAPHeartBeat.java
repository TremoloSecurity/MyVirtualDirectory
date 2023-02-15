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

import org.apache.logging.log4j.Logger;

public class LDAPHeartBeat implements Runnable {

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(LDAPHeartBeat.class.getName());
	
	boolean stillRunning;

	private LDAPInterceptorExperimental insert;
	private LDAPInterceptor legacy;
	
	public LDAPHeartBeat(LDAPInterceptorExperimental ldapInterceptor) {
		this.stillRunning = true;
		this.insert = ldapInterceptor;
		this.legacy = null;
	}
	
	public LDAPHeartBeat(LDAPInterceptor ldapInterceptor) {
		this.stillRunning = true;
		this.insert = null;
		this.legacy = ldapInterceptor;
	}

	@Override
	public void run() {
		try {
			if (this.insert != null) {
				Thread.sleep(insert.getHeartBeatMillis());
			} else {
				Thread.sleep(legacy.getHeartBeatMillis());
			}
			
		} catch (InterruptedException e1) {
			//do nothing
		}
		
		while (stillRunning) {
			if (this.insert != null) {
				this.insert.getConnectionPool().executeHeartBeat();
			} else {
				this.legacy.getConnectionPool().executeHeartBeat();
			}
			try {
				if (this.insert != null) {
					Thread.sleep(insert.getHeartBeatMillis());
				} else {
					Thread.sleep(this.legacy.getHeartBeatMillis());
				}
				
			} catch (InterruptedException e) {
				//do nothing
			}
		}

	}
	
	public void stop() {
		this.stillRunning = false;
	}

}
