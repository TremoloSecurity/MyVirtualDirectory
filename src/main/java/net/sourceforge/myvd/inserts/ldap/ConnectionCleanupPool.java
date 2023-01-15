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
package net.sourceforge.myvd.inserts.ldap;

import java.util.HashSet;
import java.util.LinkedList;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import com.novell.ldap.LDAPConnection;

public class ConnectionCleanupPool implements Runnable {
	
	static Logger logger = Logger.getLogger(ConnectionCleanupPool.class);
	
	HashSet<ConnectionToClose> queue;
	boolean keepRunning;
	int timeToClose;
	
	public ConnectionCleanupPool(int timeToClose) {
		this.queue = new HashSet<ConnectionToClose>();
		this.keepRunning = true;
		this.timeToClose = timeToClose;
	}

	@Override
	public void run() {
		while (keepRunning) {
			logger.info(String.format("Beginning run, checking %d connecitions",queue.size()));
			HashSet<ConnectionToClose> toRemove = new HashSet<ConnectionToClose>();
			
			for (ConnectionToClose c : this.queue) {
				synchronized(c.con) {
					if (DateTime.now().minusMillis(this.timeToClose).isAfter(c.enqueued)  ) {
						logger.info(String.format("Closing connection enqued at %s", c.enqueued.toString()));
						try {
							c.con.disconnect();
						} catch (Throwable t) {
							//do nothing
						}
						toRemove.add(c);
					}
					
				}
			}
			
			for (ConnectionToClose c : toRemove) {
				synchronized(queue) {
					this.queue.remove(c);
				}
			}
			
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
				logger.warn("Interupdated, stopping thread");
				this.keepRunning = false;
			}
				
		}

	}
	
	public void closeConnection(LDAPConnection con) {
		ConnectionToClose c = new ConnectionToClose();
		c.con = con;
		c.enqueued = DateTime.now();
		synchronized(this.queue) {
			this.queue.add(c);
		}
	}
	
	public void stopRunning() {
		this.keepRunning = false;
	}

}

class ConnectionToClose {
	LDAPConnection con;
	DateTime enqueued;
}
