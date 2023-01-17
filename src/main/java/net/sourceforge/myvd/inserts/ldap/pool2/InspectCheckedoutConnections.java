/*******************************************************************************
 * Copyright (c) 2023 Tremolo Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package net.sourceforge.myvd.inserts.ldap.pool2;

import net.sourceforge.myvd.inserts.ldap.LDAPInterceptor;

public class InspectCheckedoutConnections implements Runnable {

	boolean keepRunning;
	
	LDAPInterceptor interceptor;
	
	public InspectCheckedoutConnections(LDAPInterceptor interceptor) {
		this.interceptor = interceptor;
		this.keepRunning = true;
	}
	
	@Override
	public void run() {
		
		while (this.keepRunning) {
			
			this.interceptor.getConnectionPool().checkCheckedoutConnections();
			
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				
			}
		}
		
	}
	
	public void stopInspector() {
		this.keepRunning = false;
	}

}
