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
package net.sourceforge.myvd.inserts.kerberos;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;



public class KerbHandler implements CallbackHandler {

	String user;
	char[] password;
	
	public KerbHandler(String user,byte[] pwd) {
		this.user = user;
		try {
			this.password = new String(pwd,"UTF-8").toCharArray();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		ConfirmationCallback confirmation = null;

		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof NameCallback) {
		 		NameCallback nc = (NameCallback) callbacks[i];

				

				String result = getName();
				if (result.equals("")) {
				    result = nc.getDefaultName();
				}

				nc.setName(result);
		 
			} else if (callbacks[i] instanceof PasswordCallback) {
		 		PasswordCallback pc = (PasswordCallback) callbacks[i];

		 		

		 		pc.setPassword(getPassword());
		  
			    } else if (callbacks[i] instanceof ConfirmationCallback) {
				confirmation = (ConfirmationCallback) callbacks[i];

		 	    } else {
		 		throw new UnsupportedCallbackException(
				    callbacks[i], "Unrecognized Callback");
		 	    }
			
			
			
		}

	}

	private char[] getPassword() {
		return this.password;
	}

	private String getName() {
		return this.user;
	}

}
