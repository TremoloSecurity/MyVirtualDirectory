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

import java.nio.charset.Charset;

import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.fail;

public class TestStartServerAuthRequired {

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
        server.startServer(System.getenv("PROJ_DIR") + "/test/TestServer/testconfig-required-auth.props", 50983);

        System.setProperty("javax.net.ssl.trustStore", System.getenv("PROJ_DIR") + "/test/TestServer/testconfig.jks");
    }

    @After
    public void after() throws Exception {
        baseServer.reloadAllData();
        internalServer.reloadAllData();
        externalServer.reloadAllData();
    }

    @Test
    public void testStartServer_BindWithCredentialsShouldPass() throws Exception {
        LDAPConnection con = new LDAPConnection();
        try {
            con.connect("127.0.0.1", 50983);

            con.bind(3, "cn=admin,ou=internal,o=mycompany,c=us", "manager".getBytes(Charset.forName("UTF-8")));

            LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
            while (res.hasMore()) {
                System.out.println(res.next().getDN());
            }

        } finally {
            con.disconnect();
        }
    }

    @Test
    public void testStartServer_BindWithInvalidPasswordShouldFail() throws Exception {
        LDAPConnection con = new LDAPConnection();
        try {
            con.connect("127.0.0.1", 50983);

            con.bind(3, "cn=admin,ou=internal,o=mycompany,c=us", "xxx".getBytes(Charset.forName("UTF-8")));

            LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
            while (res.hasMore()) {
                System.out.println(res.next().getDN());
            }
        } catch (LDAPException e) {
            if (e.getResultCode() != 49) {
                fail();
            }
        } finally {
            con.disconnect();
        }
    }

    @Test
    public void testStartServer_BindWithInvalidUserShouldFail() throws Exception {
        LDAPConnection con = new LDAPConnection();
        try {
            con.connect("127.0.0.1", 50983);

            con.bind(3, "cn=xxx,ou=internal,o=mycompany,c=us", "xxx".getBytes(Charset.forName("UTF-8")));

            LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
            while (res.hasMore()) {
                System.out.println(res.next().getDN());
            }
        } catch (LDAPException e) {
            if (e.getResultCode() != 49) {
                fail();
            }
        } finally {
            con.disconnect();
        }
    }

    @Test
    public void testStartServer_BindWithoutCredentialsShouldFail() throws Exception {
        LDAPConnection con = new LDAPConnection();
        try {
            con.connect("127.0.0.1", 50983);

            con.bind(3, null, new byte[0]);

            LDAPSearchResults res = con.search("ou=internal,o=mycompany,c=us", 2, "(objectClass=*)", new String[0], false);
            while (res.hasMore()) {
                System.out.println(res.next().getDN());
            }
        } catch (LDAPException e) {
            if (e.getResultCode() != 49) {
                fail();
            }
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