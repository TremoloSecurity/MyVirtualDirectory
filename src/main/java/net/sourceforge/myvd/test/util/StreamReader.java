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
package net.sourceforge.myvd.test.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class StreamReader extends Thread {
	InputStream in;
	boolean debug;
	boolean done;
	
	public StreamReader(InputStream in,boolean debug ) {
		this.in = in;
		this.debug = debug;
		done = false;
	}
	
	public void run() {
		BufferedReader in = new BufferedReader(new InputStreamReader(this.in));
		
		String line;
		try {
			while ((line = in.readLine()) != null) {
				if (debug) {
					System.out.println(line);
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
		}
		
		done = true;
		
	}
	
	public boolean isDone() {
		return this.done;
	}
}

