/*******************************************************************************
 * Copyright 2021 Tremolo Security, Inc.
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
package org.apache.directory.server.core;

import org.apache.log4j.Logger;
import org.apache.mina.core.filterchain.IoFilter;
import org.apache.mina.core.filterchain.IoFilterAdapter;
import org.apache.mina.core.filterchain.IoFilterChain;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.WriteRequest;

import net.sourceforge.myvd.core.ConnectionEventLogger;

public class LoggingFilter extends IoFilterAdapter {
	
	ConnectionEventLogger eventLogger;
	
	boolean isTls;
	
	static Logger logger = Logger.getLogger(LoggingFilter.class);
	
	public LoggingFilter(boolean isTls) {
		this.isTls = isTls;
		
		String className = System.getProperty("myvd.connectionLogger");
		if (className != null) {
			logger.info("Connection logger : '" + className + "'");
			try {
				this.eventLogger = (ConnectionEventLogger) Class.forName(className).newInstance();
			} catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
				logger.warn("Could not load the event logger",e);
			}
		} else {
			logger.info("No connection event logger");
		}
	}

	@Override
	public void sessionOpened(NextFilter nextFilter, IoSession session) throws Exception {
		if (eventLogger != null) {
			eventLogger.onNewSession(session, isTls);
		}
		
		super.sessionOpened(nextFilter, session);
	}

	@Override
	public void sessionClosed(NextFilter nextFilter, IoSession session) throws Exception {
		if (eventLogger != null) {
			eventLogger.onCloseSession(session, isTls);
		}
		super.sessionClosed(nextFilter, session);
	}
	
	
	

	/*
	@Override
	public void destroy() throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void exceptionCaught(NextFilter nextFilter, IoSession ioSession, Throwable cause) throws Exception {
		nextFilter.exceptionCaught(ioSession, cause);

	}

	@Override
	public void filterClose(NextFilter nextFilter, IoSession ioSession) throws Exception {
		nextFilter.filterClose(ioSession);

	}

	@Override
	public void filterWrite(NextFilter nextFilter, IoSession ioSession, WriteRequest writeRequest) throws Exception {
		nextFilter.filterClose(ioSession);

	}

	@Override
	public void init() throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void inputClosed(NextFilter nextFilter, IoSession ioSession) throws Exception {
		nextFilter.inputClosed(ioSession);

	}

	@Override
	public void messageReceived(NextFilter nextFilter, IoSession ioSession, Object message) throws Exception {
		nextFilter.messageReceived(ioSession, message);

	}

	@Override
	public void messageSent(NextFilter nextFilter, IoSession ioSession, WriteRequest writeRequest) throws Exception {
		nextFilter.messageSent(ioSession, writeRequest);

	}

	@Override
	public void onPostAdd(IoFilterChain ioFilterChain, String arg1, NextFilter nextFilter) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void onPostRemove(IoFilterChain ioFilterChain, String arg1, NextFilter nextFilter) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void onPreAdd(IoFilterChain ioFilterChain, String arg1, NextFilter nextFilter) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void onPreRemove(IoFilterChain ioFilterChain, String arg1, NextFilter nextFilter) throws Exception {
		// TODO Auto-generated method stub

	}

	@Override
	public void sessionClosed(NextFilter nextFilter, IoSession ioSession) throws Exception {
		nextFilter.sessionClosed(ioSession);

	}

	@Override
	public void sessionCreated(NextFilter nextFilter, IoSession ioSession) throws Exception {
		nextFilter.sessionCreated(ioSession);

	}

	@Override
	public void sessionIdle(NextFilter nextFilter, IoSession ioSession, IdleStatus idelStatus) throws Exception {
		nextFilter.sessionIdle(ioSession, idelStatus);

	}

	@Override
	public void sessionOpened(NextFilter nextFilter, IoSession ioSession) throws Exception {
		nextFilter.sessionOpened(ioSession);

	}*/

}
