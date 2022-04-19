/*
 * Copyright 2022 Marc Boorshtein 
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

package net.sourceforge.myvd.server;

import java.util.Map;

import org.apache.log4j.Logger;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.service.IoServiceListener;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;

public class IdleIoServiceListener implements IoServiceListener {

	static Logger logger = Logger.getLogger(IdleIoServiceListener.class);
	long maxIdleTime;
	CheckIdleThread idleCheck;
	
	public IdleIoServiceListener(long maxIdleTime) {
		this.maxIdleTime = maxIdleTime;
	}
	
	@Override
	public void serviceActivated(IoService service) throws Exception {
		
		
		this.idleCheck = new CheckIdleThread(service.getManagedSessions(),maxIdleTime);
		new Thread(this.idleCheck).start();

	}

	@Override
	public void serviceIdle(IoService service, IdleStatus idleStatus) throws Exception {
		
		
		
		

	}

	@Override
	public void serviceDeactivated(IoService service) throws Exception {
		logger.info("Service being destroyed");
		this.idleCheck.stopChecks();

	}

	@Override
	public void sessionCreated(IoSession session) throws Exception {
		if (logger.isDebugEnabled()) {
			logger.debug(new StringBuilder().append("Session '").append(session.getRemoteAddress()).append("' created"));
		}

	}

	@Override
	public void sessionClosed(IoSession session) throws Exception {
		if (logger.isDebugEnabled()) {
			logger.debug(new StringBuilder().append("Session '").append(session.getRemoteAddress()).append("' closed"));
		}

	}

	@Override
	public void sessionDestroyed(IoSession session) throws Exception {
		if (logger.isDebugEnabled()) {
			logger.debug(new StringBuilder().append("Session '").append(session.getRemoteAddress()).append("' destroyed"));
		}
		

	}

}

class CheckIdleThread implements Runnable {
	
	boolean keepRunning;
	Map<Long,IoSession> sessions;
	long maxIdleTime;
	

	CheckIdleThread(Map<Long,IoSession> sessions,long maxIdleTime) {
		this.sessions = sessions;
		this.maxIdleTime = maxIdleTime;
		this.keepRunning = true;
	}
	
	public void stopChecks() {
		this.keepRunning = false;
	}
	
	@Override
	public void run() {
		while (keepRunning) {
			for (long key : sessions.keySet()) {
				IoSession session = sessions.get(key);
				synchronized (session) {
					
					if (System.currentTimeMillis() - session.getLastIoTime() >= this.maxIdleTime ) {
						if (IdleIoServiceListener.logger.isDebugEnabled()) {
							IdleIoServiceListener.logger.debug(new StringBuilder().append("Session from '").append(session.getRemoteAddress()).append("' must be closed due to inactivity").toString());
						}
						session.closeNow();

					}
				}
			}
			
			
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				
			}
		}
		
	}
	
}
