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
import java.io.PrintWriter;

public class StreamWriter extends Thread {
	InputStream in;
	PrintWriter out;
	boolean debug;
	
	public StreamWriter(InputStream in,PrintWriter out) {
		this.in = in;
		this.out = out;
		
	}
	
	public void run() {
		BufferedReader in = new BufferedReader(new InputStreamReader(this.in));
		BufferedReader sin = new BufferedReader(new InputStreamReader(System.in));
		int num = 0;
		String line;
		
		try {
			while ((line = in.readLine()) != null ) {
				//System.out.println(line);
				System.out.flush();
				/*if (line.trim().endsWith(":")) {
					//System.out.print(line);
					String fromc = sin.readLine();
					out.println(fromc);
				} else {
					//System.out.println(line);
				}*/
				
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
		}
		
	}
}

