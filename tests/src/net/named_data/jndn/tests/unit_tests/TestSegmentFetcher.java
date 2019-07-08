package net.named_data.jndn.tests.unit_tests;


import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import net.named_data.jndn.*;
import net.named_data.jndn.security.v2.ValidationPolicyAcceptAll;
import net.named_data.jndn.security.v2.Validator;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.SegmentFetcher;
import src.net.named_data.jndn.tests.integration_tests.ValidatorFixture;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * Test sending interests and receiving segmented data
 *
 * @author Ritik Kumar <ritikkne@gmail.com>
 */


public class TestSegmentFetcher {

    public final ValidatorFixture.TestFace face_ = new ValidatorFixture.TestFace();
    private ConcurrentHashMap<String, ArrayList<Data>> cacheMap_;
    private Name name_ = new Name("/localhost/nfd/location/%FD%00/%00%00");
    private int nSegments_ = 10;

    @Before
    public void setUp() throws Exception {

        cacheMap_ = new ConcurrentHashMap<>();

        final ArrayList<Data> data = new ArrayList<>();

        cacheMap_.put("key", data);
        byte[] segment_buffer = new byte[200];
        MetaInfo meta_info = new MetaInfo();
        Name.Component finalBlockId = Name.Component.fromSegment(nSegments_-1);
        meta_info.setFinalBlockId(finalBlockId);

        for (int i = 0; i < nSegments_ ; i++){
            Data d = new Data(name_.getPrefix(-1).appendSegment(i));
            d.setMetaInfo(meta_info);
            d.setContent(new Blob(segment_buffer));

            data.add(d);
        }

        face_.processInterest_ = new ValidatorFixture.TestFace.ProcessInterest() {
            public void processInterest
                    (final Interest interest, final OnData onData, OnTimeout onTimeout,
                     OnNetworkNack onNetworkNack) {
                if (cacheMap_.containsKey("key")){
                    Thread th = new Thread(){
                        @Override
                        public void run() {
                            try {
                                Thread.sleep(30);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                            for(Data d: data){
                                if (interest.matchesName(d.getName())){
                                    onData.onData(interest, d);
                                }
                            }
                        }
                    };

                    th.start();
                }
            }
        };
    }

    @Test
    public void fetch() {
        Interest baseInterest = new Interest(name_);

        SegmentFetcher.OnComplete onComplete = new SegmentFetcher.OnComplete() {
            @Override
            public void onComplete(Blob content) {
                assertEquals(content.size(), 200 * nSegments_);
            }
        };

        SegmentFetcher.OnError onError = new SegmentFetcher.OnError() {
            @Override
            public void onError(SegmentFetcher.ErrorCode errorCode, String message) {
                System.out.println("onError:  " + message);
            }
        };

        SegmentFetcher.VerifySegment verifySegment = new SegmentFetcher.VerifySegment() {
            @Override
            public boolean verifySegment(Data data) {
                return true;
            }
        };

        SegmentFetcher.fetch(face_, baseInterest, new Validator(new ValidationPolicyAcceptAll()), onComplete, onError);
    }
}