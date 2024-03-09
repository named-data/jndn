package src.net.named_data.jndn.tests.integration_tests;

import net.named_data.jndn.*;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.Tlv0_3WireFormat;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;

public class TestLpHeaderField {
    Face faceIn;
    Face faceOut;
    KeyChain keyChain;
    Name certificateName;

    @Before
    public void setUp() throws SecurityException {
        Name[] localCertificateName = new Name[1];
        keyChain = IntegrationTestsCommon.buildKeyChain(localCertificateName);
        certificateName = localCertificateName[0];

        faceIn = IntegrationTestsCommon.buildFaceWithKeyChain
                ("localhost", keyChain, certificateName);
        faceOut = IntegrationTestsCommon.buildFaceWithKeyChain
                ("localhost", keyChain, certificateName);
    }

    @Test
    public void testFields() throws IOException, SecurityException {
        WireFormat.setDefaultWireFormat(new Tlv0_3WireFormat());
        Name registerPrefix = new Name("/test");
        final long[] congestionMarkFieldValue = {0};
        final long[] incomingFaceIdFieldValue = {-1};
        final int[] interestCallbackCount = new int[]{0};
        final int[] failedCallbackCount = new int[]{0};
        faceIn.registerPrefix(registerPrefix, new OnInterestCallback() {
            @Override
            public void onInterest(Name prefix, Interest interest, Face face, long interestFilterId, InterestFilter filter) {
                interestCallbackCount[0]++;
                congestionMarkFieldValue[0] = interest.getCongestionMark();
                incomingFaceIdFieldValue[0] = interest.getIncomingFaceId();
                Data data = new Data(interest.getName());
                data.setCongestionMark(1);
                data.setContent(new Blob("SUCCESS"));

                try {
                    keyChain.sign(data, certificateName);
                } catch (SecurityException ex) {
                    logger.log(Level.SEVERE, null, ex);
                }
                try {
                    face.putData(data);
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, null, ex);
                }
            }
        }, new OnRegisterFailed() {
            @Override
            public void onRegisterFailed(Name prefix) {
                failedCallbackCount[0]++;
            }
        });

        // Give the "server" time to register the interest.
        double timeout = 1000;
        double startTime = getNowMilliseconds();
        while (getNowMilliseconds() - startTime < timeout) {
            try {
                faceIn.processEvents();
            } catch (IOException | EncodingException ex) {
                logger.log(Level.SEVERE, null, ex);
                break;
            }

            try {
                // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
                Thread.sleep(10);
            } catch (InterruptedException ex) {
                logger.log(Level.SEVERE, null, ex);
                break;
            }
        }

        final int[] dataCallbackCount = new int[]{0};
        final int[] timeoutCallbackCount = new int[]{0};
        final Data[] receivedData = new Data[1];

        Name interestName = registerPrefix.append("hello" + getNowMilliseconds());
        Interest interest = new Interest(interestName);
        interest.setCongestionMark(1);
        faceOut.expressInterest(interest, new OnData() {
            @Override
            public void onData(Interest interest, Data data) {
                dataCallbackCount[0]++;
                receivedData[0] = data;
            }
        }, new OnTimeout() {
            @Override
            public void onTimeout(Interest interest) {
                timeoutCallbackCount[0]++;
            }
        });

        // Process events for the in and out faces.
        timeout = 10000;
        startTime = getNowMilliseconds();
        while (getNowMilliseconds() - startTime < timeout) {
            try {
                faceIn.processEvents();
                faceOut.processEvents();
            } catch (IOException | EncodingException ex) {
                logger.log(Level.SEVERE, null, ex);
                break;
            }

            boolean done = true;
            if (interestCallbackCount[0] == 0 && failedCallbackCount[0] == 0)
                // Still processing faceIn.
                done = false;
            if (dataCallbackCount[0] == 0 && timeoutCallbackCount[0] == 0)
                // Still processing face_out.
                done = false;

            if (done)
                break;

            try {
                // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
                Thread.sleep(10);
            } catch (InterruptedException ex) {
                logger.log(Level.SEVERE, null, ex);
                break;
            }
        }

        assertEquals("Failed to register prefix at all",
                0, failedCallbackCount[0]);
        assertEquals("Expected 1 onInterest callback",
                1, interestCallbackCount[0]);
        assertEquals("Expected 1 onData callback",
                1, dataCallbackCount[0]);

        assertEquals("Expected Interest's CongestionMark value is 1", 1L, congestionMarkFieldValue[0]);

        assertEquals("Expected Data's CongestionMark value is 1", 1L, receivedData[0].getCongestionMark());
    }

    public static double
    getNowMilliseconds() {
        return Common.getNowMilliseconds();
    }

    private static final Logger logger = Logger.getLogger
            (TestFaceCallRegisterMethods.class.getName());
}