package net.sourceforge.myvd.test.router;

import com.novell.ldap.*;
import com.novell.ldap.util.LDIFReader;
import net.sourceforge.myvd.test.util.OpenLDAPUtils;
import net.sourceforge.myvd.test.util.StartMyVD;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import net.sourceforge.myvd.test.util.Util;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.FileInputStream;

import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertNull;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;

public class TestSearchOverlap {

    private static StartOpenLDAP internalServer;
    private static  StartOpenLDAP externalServer;
    private static StartMyVD server;

    @BeforeClass
    public static void setupClass() throws Exception {
        OpenLDAPUtils.killAllOpenLDAPS();
        internalServer = new StartOpenLDAP();
        internalServer.startServer(System.getenv("PROJ_DIR")
                        + "/test/InternalUsers", 11983,
                "cn=admin,ou=internal,dc=domain,dc=com", "manager");

        externalServer = new StartOpenLDAP();
        externalServer.startServer(System.getenv("PROJ_DIR")
                        + "/test/ExternalUsers", 12983,
                "cn=admin,ou=external,dc=domain,dc=com", "manager");

        server = new StartMyVD();
        server.startServer(System.getenv("PROJ_DIR")
                + "/test/TestServer/ldap-overlapp-test.conf", 50983);

    }

    @AfterClass
    public static void shutdownClass() throws Exception {
        server.stopServer();
        externalServer.stopServer();
        internalServer.stopServer();
    }

    @Test
    public void testOneLevelFromRootObjectSuccess() throws Exception {
        LDAPConnection con = new LDAPConnection();
        con.connect("localhost",50983);
        LDIFReader testDataReader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/test-data/ldap-overlap/onelevel-from-root.ldif"));
        LDAPSearchResults res = con.search("dc=local,dc=com",1,"(objectClass=*)",new String[]{},false);

        while (res.hasMore()) {
            LDAPEntry fromSearch = res.next();
            LDAPMessage msg = testDataReader.readMessage();
            assertNotNull(msg);
            LDAPEntry fromLDIF = ((LDAPSearchResult) msg).getEntry();
            assertTrue("entries match",Util.compareEntry(fromSearch,fromLDIF));
        }

        LDAPMessage msg = testDataReader.readMessage();
        assertNull(msg);
    }

    @Test
    public void testOneLevelFromOpenLDAPRootSuccess() throws Exception {
        LDAPConnection con = new LDAPConnection();
        con.connect("localhost",50983);
        LDIFReader testDataReader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/test-data/ldap-overlap/onelevel-from-openldap-ou.ldif"));
        LDAPSearchResults res = con.search("ou=internal,dc=local,dc=com",1,"(objectClass=*)",new String[]{},false);

        while (res.hasMore()) {
            LDAPEntry fromSearch = res.next();
            LDAPMessage msg = testDataReader.readMessage();
            assertNotNull(msg);
            LDAPEntry fromLDIF = ((LDAPSearchResult) msg).getEntry();
            assertTrue("entries match",Util.compareEntry(fromSearch,fromLDIF));
        }

        LDAPMessage msg = testDataReader.readMessage();
        assertNull(msg);
    }

    @Test
    public void testSubtreeFromOpenLDAPRootSuccess() throws Exception {
        LDAPConnection con = new LDAPConnection();
        con.connect("localhost",50983);
        LDIFReader testDataReader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/test-data/ldap-overlap/subtree-from-openldap-ou.ldif"));
        LDAPSearchResults res = con.search("ou=internal,dc=local,dc=com",2,"(objectClass=*)",new String[]{},false);

        while (res.hasMore()) {
            LDAPEntry fromSearch = res.next();
            LDAPMessage msg = testDataReader.readMessage();
            assertNotNull(msg);
            LDAPEntry fromLDIF = ((LDAPSearchResult) msg).getEntry();
            assertTrue("entries match",Util.compareEntry(fromSearch,fromLDIF));
        }

        LDAPMessage msg = testDataReader.readMessage();
        assertNull(msg);
    }

    @Test
    public void testOneLevelFromOverlapRootSuccess() throws Exception {
        LDAPConnection con = new LDAPConnection();
        con.connect("localhost",50983);
        LDIFReader testDataReader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/test-data/ldap-overlap/onelevel-from-overlap-ou.ldif"));
        LDAPSearchResults res = con.search("dc=domain,dc=local,dc=com",1,"(objectClass=*)",new String[]{},false);

        while (res.hasMore()) {
            LDAPEntry fromSearch = res.next();
            LDAPMessage msg = testDataReader.readMessage();
            assertNotNull(msg);
            LDAPEntry fromLDIF = ((LDAPSearchResult) msg).getEntry();
            assertTrue("entries match",Util.compareEntry(fromSearch,fromLDIF));
        }

        LDAPMessage msg = testDataReader.readMessage();
        assertNull(msg);
    }

    @Test
    public void testSubtreeFromOverlapRootSuccess() throws Exception {
        LDAPConnection con = new LDAPConnection();
        con.connect("localhost",50983);
        LDIFReader testDataReader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/test-data/ldap-overlap/subtree-from-overlap-ou.ldif"));
        LDAPSearchResults res = con.search("dc=domain,dc=local,dc=com",2,"(objectClass=*)",new String[]{},false);

        while (res.hasMore()) {
            LDAPEntry fromSearch = res.next();
            LDAPMessage msg = testDataReader.readMessage();
            assertNotNull(msg);
            LDAPEntry fromLDIF = ((LDAPSearchResult) msg).getEntry();
            assertTrue("entries match",Util.compareEntry(fromSearch,fromLDIF));
        }

        LDAPMessage msg = testDataReader.readMessage();
        assertNull(msg);
    }

    @Test
    public void testSubtreeLevelFromRootRootSuccess() throws Exception {
        LDAPConnection con = new LDAPConnection();
        con.connect("localhost",50983);
        LDIFReader testDataReader = new LDIFReader(new FileInputStream(System.getenv("PROJ_DIR") + "/test/test-data/ldap-overlap/subtree-root.ldif"));
        LDAPSearchResults res = con.search("dc=local,dc=com",2,"(objectClass=*)",new String[]{},false);

        while (res.hasMore()) {
            LDAPEntry fromSearch = res.next();
            LDAPMessage msg = testDataReader.readMessage();
            assertNotNull(msg);
            LDAPEntry fromLDIF = ((LDAPSearchResult) msg).getEntry();
            assertTrue("entries match",Util.compareEntry(fromSearch,fromLDIF));
        }

        LDAPMessage msg = testDataReader.readMessage();
        assertNull(msg);
    }
}
