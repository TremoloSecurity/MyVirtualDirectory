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
package net.sourceforge.myvd.test.Server;

import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPSearchResults;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class TestRootBase {

    private static StartOpenLDAP baseServer;
    private static StartOpenLDAP internalServer;
    private static StartOpenLDAP externalServer;
    private static StartMyVD server;

    @BeforeClass
    public static void setUp() throws Exception {
        OpenLDAPUtils.killAllOpenLDAPS();
        baseServer = new StartOpenLDAP();
        baseServer.startServer(System.getenv("PROJ_DIR") + "/test/Base", 10983, "cn=admin,dc=domain,dc=com", "manager");

        internalServer = new StartOpenLDAP();
        internalServer.startServer(System.getenv("PROJ_DIR") + "/test/InternalUsers", 11983,
                                   "cn=admin,ou=internal,dc=domain,dc=com", "manager");

        externalServer = new StartOpenLDAP();
        externalServer.startServer(System.getenv("PROJ_DIR") + "/test/ExternalUsers", 12983,
                                   "cn=admin,ou=external,dc=domain,dc=com", "manager");

        server = new StartMyVD();
        server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/testconfig-rootbase.props", 50983);

        System.setProperty("javax.net.ssl.trustStore", System.getenv("PROJ_DIR") + "/test/TestServer/testconfig.jks");
    }

    @After
    public void after() throws Exception {
        baseServer.reloadAllData();
        internalServer.reloadAllData();
        externalServer.reloadAllData();
    }

    @Test
    public void testRootBaseSearch() throws Exception {
        LDAPConnection con = new LDAPConnection();
        try {
            con.connect("127.0.0.1", 50983);

            boolean fromInternal = false;
            boolean fromExternal = false;

            LDAPSearchResults res = con.search("dn=root", 2, "(objectClass=*)", new String[0], false);
            while (res.hasMore()) {
                String dn = res.next().getDN();

                if ("ou=internal,o=mycompany,c=us".equals(dn)) {
                    fromInternal = true;
                }
                if ("ou=external,o=mycompany,c=us".equals(dn)) {
                    fromExternal = true;
                }
            }

            assertTrue("Internal should be searched.", fromInternal);
            assertTrue("External should be searched.", fromExternal);

        } finally {
            con.disconnect();
        }
    }

    @AfterClass
    public static void tearDown() throws Exception {

        baseServer.stopServer();
        internalServer.stopServer();
        externalServer.stopServer();
        server.stopServer();
    }
}
