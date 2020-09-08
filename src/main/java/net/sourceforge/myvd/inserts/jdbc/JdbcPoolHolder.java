/*******************************************************************************
 * Copyright 2020 Tremolo Security, Inc.
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
package net.sourceforge.myvd.inserts.jdbc;

import com.mchange.v2.c3p0.ComboPooledDataSource;

public class JdbcPoolHolder {
	int count;
	ComboPooledDataSource ds;
	String key;
	
	public JdbcPoolHolder(String key) {
		this.key = key;
		this.count = 0;
	}
	
	
	public synchronized void upCount() {
		count++;
	}
	
	public synchronized boolean downCount() {
		count--;
		if (count <= 0) {
			ds.close();
			return true;
		} else {
			return false;
		}
	}

	public ComboPooledDataSource getDs() {
		return ds;
	}

	public void setDs(ComboPooledDataSource ds) {
		this.ds = ds;
	}
	
	public void close() {
		this.ds.close();
	}


	public String getKey() {
		return key;
	}
	
	
}
