/**
 * Copyright (C) 2015-2019 Regents of the University of California.
 *
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: Ritik Kumar <rkumar1@cs.iitr.ac.in>
 * @author: From ndn-cxx util/segment-fetcher https://github.com/named-data/ndn-cxx
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

package net.named_data.jndn.util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.OnDataValidationFailed;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.ValidatorConfigError;
import net.named_data.jndn.security.v2.*;

/**
 * SegmentFetcher is a utility class to fetch the latest version of segmented data.
 *
 * SegmentFetcher assumes that segments in the object are named `/{prefix}/{version}/{segment}`,
 * where:
 * - `{prefix}` is the specified prefix,
 * - `{version}` is an unknown version that needs to be discovered, and
 * - `{segment}` is a segment number (the number of segments in the object is unknown until a Data
 *   packet containing the `FinalBlockId` field is received).
 *
 * SegmentFetcher implements the following logic:
 *
 * 1. Express an Interest to discover the latest version of the object:
 *
 *    Interest: `/{prefix}?ndn.CanBePrefix=true,ndn.MustBeFresh=true`
 *
 * 2. Infer the latest version of the object: `{version} = Data.getName().get(-2)`
 *
 * 3. Keep sending Interests for future segments until an error occurs or the number of segments
 *    indicated by the FinalBlockId in a received Data packet is reached. This retrieval will start
 *    at segment 1 if segment 0 was received in response to the Interest expressed in step 2;
 *    otherwise, retrieval will start at segment 0. By default, congestion control will be used to
 *    manage the Interest window size. Interests expressed in this step will follow this Name
 *    format:
 *
 *    Interest: `/{prefix}/{version}/{segment=(N)}`
 *
 * 4. Call the OnComplete callback with a blob that concatenates the content
 *    from all the segmented objects.
 *
 * If an error occurs during the fetching process, the OnError callback is called
 * with a proper error code.  The following errors are possible:
 *
 * - `INTEREST_TIMEOUT`: if any of the Interests times out
 * - `DATA_HAS_NO_SEGMENT`: if any of the retrieved Data packets don't have a segment
 *   as the last component of the name (not counting the implicit digest)
 * - `SEGMENT_VERIFICATION_FAILED`: if any retrieved segment fails
 *   the user-provided VerifySegment callback or KeyChain verifyData.
 * - `IO_ERROR`: for I/O errors when sending an Interest.
 * - 'NACK_ERROR': unknown/unhandled NACK received.
 *
 * In order to validate individual segments, a KeyChain needs to be supplied.
 * If verifyData fails, the fetching process is aborted with
 * SEGMENT_VERIFICATION_FAILED. If data validation is not required, pass
 * (KeyChain)null.
 *
 * Example:
 *     Interest interest = new Interest(new Name("/data/prefix"));
 *     interest.setInterestLifetimeMilliseconds(1000);
 *
 *     SegmentFetcher.fetch
 *       (face, interest, 0, new SegmentFetcher.OnComplete() {
 *          public void onComplete(Blob content) {
 *            ...
 *          }},
 *        new SegmentFetcher.OnError() {
 *          public void onError(SegmentFetcher.ErrorCode errorCode, String message) {
 *            ...
 *          }});
 */
public class SegmentFetcher implements OnData, OnDataValidationFailed, OnTimeout, OnNetworkNack {

    public static class Options {

        /** if true, window size is kept at `initCwnd`
         */
        public boolean useConstantCwnd = false;
        /** lifetime of sent Interests in milliseconds - independent of Interest timeout
         */
        public int interestLifetime = 4000;
        /** initial congestion window size
         */
         public double initCwnd = 1.0;
        /** maximum allowed time between successful receipt of segments in millisecond
         */
        public int maxTimeout = 60000;
        /** initial slow start threshold
         */
        public double initSsthresh = Double.MAX_VALUE;
        /** additive increase step (in segments)
         */
        public double aiStep = 1.0;
        /** multiplicative decrease coefficient
         */
        public double mdCoef = 0.5;
        /** interval for checking retransmission timer in millisecond
         */
        public int rtoCheckInterval = 10;
        /** disable Conservative Window Adaptation
         */
        public boolean disableCwa = false;
        /** reduce cwnd_ to initCwnd when loss event occurs
         */
        public boolean resetCwndToInit = false;
        /** disable window decrease after congestion mark received
         */
        public boolean ignoreCongMarks = false;
        /** max window size for sending interests
         */
        public int maxWindowSize = Integer.MAX_VALUE;
        /** if true, Interest timeout is kept at `maxTimeout`
         */
        public boolean useConstantInterestTimeout = false;
        /** options for RTT estimator
         */
        public RttEstimator.Options rttOptions = new RttEstimator.Options();

    }

    private enum SegmentState {
        /** the first Interest for this segment has been sent
         */
        FirstInterest,
        /** the segment is awaiting Interest retransmission
         */
        InRetxQueue,
        /** one or more retransmitted Interests have been sent for this segment
         */
        Retransmitted
    }

    class PendingSegment {

        public SegmentState state;
        public long sendTime;
        public long rto;

        public PendingSegment(SegmentState state, long sendTime, long rto) {
            this.state = state;
            this.sendTime = sendTime;
            this.rto = rto;
        }
    }

    public enum ErrorCode {
        INTEREST_TIMEOUT,
        DATA_HAS_NO_SEGMENT,
        SEGMENT_VERIFICATION_FAILED,
        IO_ERROR,
        NACK_ERROR
    }

    public interface OnComplete {
        void onComplete(Blob content);
    }

    public interface VerifySegment {
        boolean verifySegment(Data data);
    }

    public interface OnError {
        void onError(SegmentFetcher.ErrorCode errorCode, String message);
    }

    /**
     * DontVerifySegment may be used in fetch to skip validation of Data packets.
     */
    public static final SegmentFetcher.VerifySegment DontVerifySegment = new SegmentFetcher.VerifySegment() {
        public boolean verifySegment(Data data) {
            return true;
        }
    };

    /**
     * Initiate segment fetching. For more details, see the documentation for
     * the class.
     * @param face This calls face.expressInterest to fetch more segments.
     * @param baseInterest Interest for the initial segment of requested data.
     * This interest may include a custom InterestLifetime and parameters that
     * will propagate to all subsequent Interests. The only exception is that the
     * initial Interest will be forced to include the "CanBePrefix=true" and
     * "MustBeFresh=true" parameters, which will not be included in subsequent
     * interests.
     * @param options A set of options to control the sending and receiving of packets
     * in the AIMD pipelining.
     * @param verifySegment When a Data packet is received this calls
     * verifySegment.verifySegment(data). If it returns false then abort fetching
     * and call onError.onError with ErrorCode.SEGMENT_VERIFICATION_FAILED. If
     * data validation is not required, use DontVerifySegment.
     * NOTE: The library will log any exceptions thrown by this callback, but for
     * better error handling the callback should catch and properly handle any
     * exceptions.
     * @param onComplete When all segments are received, call
     * onComplete.onComplete(content) where content is the concatenation of the
     * content of all the segments.
     * NOTE: The library will log any exceptions thrown by this callback, but for
     * better error handling the callback should catch and properly handle any
     * exceptions.
     * @param onError Call onError.onError(errorCode, message) for timeout or an
     * error processing segments.
     * NOTE: The library will log any exceptions thrown by this callback, but for
     * better error handling the callback should catch and properly handle any
     * exceptions.
     */
    public static void fetch
    (Face face, Interest baseInterest, Options options, SegmentFetcher.VerifySegment verifySegment,
     SegmentFetcher.OnComplete onComplete, SegmentFetcher.OnError onError) {
        new SegmentFetcher(face, baseInterest, null, options, null,
                verifySegment, onComplete, onError)
                .run();
    }

    public static void fetch
    (Face face, Interest baseInterest, SegmentFetcher.VerifySegment verifySegment,
     SegmentFetcher.OnComplete onComplete, SegmentFetcher.OnError onError) {
        fetch(face, baseInterest, new Options(), verifySegment, onComplete, onError);
    }

    /**
     * Initiate segment fetching. For more details, see the documentation for
     * the class.
     * @param face This calls face.expressInterest to fetch more segments.
     * @param baseInterest Interest for the initial segment of requested data.
     * This interest may include a custom InterestLifetime and parameters that
     * will propagate to all subsequent Interests. The only exception is that the
     * initial Interest will be forced to include the "CanBePrefix=true" and
     * "MustBeFresh=true" parameters, which will not be included in subsequent
     * interests.
     * @param options A set of options to control the sending and receiving of packets
     * in the AIMD pipelining.
     * @param validatorKeyChain When a Data packet is received this calls
     * validatorKeyChain.verifyData(data). If validation fails then abort
     * fetching and call onError with SEGMENT_VERIFICATION_FAILED. This does not
     * make a copy of the KeyChain; the object must remain valid while fetching.
     * If validatorKeyChain is null, this does not validate the data packet.
     * @param onComplete When all segments are received, call
     * onComplete.onComplete(content) where content is the concatenation of the
     * content of all the segments.
     * NOTE: The library will log any exceptions thrown by this callback, but for
     * better error handling the callback should catch and properly handle any
     * exceptions.
     * @param onError Call onError.onError(errorCode, message) for timeout or an
     * error processing segments.
     * NOTE: The library will log any exceptions thrown by this callback, but for
     * better error handling the callback should catch and properly handle any
     * exceptions.
     */
    public static void fetch
    (Face face, Interest baseInterest, Options options, KeyChain validatorKeyChain,
     SegmentFetcher.OnComplete onComplete, SegmentFetcher.OnError onError) {
        new SegmentFetcher(face, baseInterest, validatorKeyChain, options, null,
                DontVerifySegment, onComplete, onError)
                .run();
    }

    public static void fetch
    (Face face, Interest baseInterest, KeyChain validatorKeyChain,
     SegmentFetcher.OnComplete onComplete, SegmentFetcher.OnError onError) {
        fetch(face, baseInterest, new Options(), validatorKeyChain, onComplete,
                onError);
    }

    /**
     * Initiate segment fetching. For more details, see the documentation for
     * the class.
     * @param face This calls face.expressInterest to fetch more segments.
     * @param baseInterest Interest for the initial segment of requested data.
     * This interest may include a custom InterestLifetime and parameters that
     * will propagate to all subsequent Interests. The only exception is that the
     * initial Interest will be forced to include the "CanBePrefix=true" and
     * "MustBeFresh=true" parameters, which will not be included in subsequent
     * interests.
     * @param options A set of options to control the sending and receiving of packets
     * in the AIMD pipelining.
     * @param validator The Validator, the fetcher will use to validate data.
     * The caller must ensure the validator remains valid until either #onComplete
     * or #onError has been signaled.
     * @param onComplete When all segments are received, call
     * onComplete.onComplete(content) where content is the concatenation of the
     * content of all the segments.
     * NOTE: The library will log any exceptions thrown by this callback, but for
     * better error handling the callback should catch and properly handle any
     * exceptions.
     * @param onError Call onError.onError(errorCode, message) for timeout or an
     * error processing segments.
     * NOTE: The library will log any exceptions thrown by this callback, but for
     * better error handling the callback should catch and properly handle any
     * exceptions.
     */
    public static void fetch
    (Face face, Interest baseInterest, Options options, Validator validator,
     SegmentFetcher.OnComplete onComplete, SegmentFetcher.OnError onError) {
        new SegmentFetcher(face, baseInterest,null, options, validator,
                DontVerifySegment, onComplete, onError)
                .run();
    }

    public static void fetch
    (Face face, Interest baseInterest, Validator validator,
     SegmentFetcher.OnComplete onComplete, SegmentFetcher.OnError onError) {
        new SegmentFetcher(face, baseInterest, null, new Options(), validator,
                DontVerifySegment, onComplete, onError)
                .run();
    }

    /**
     * Create a new SegmentFetcher to use the Face. See the static fetch method
     * for details. If validatorKeyChain is not null, use it and ignore
     * verifySegment. After creating the SegmentFetcher, call fetchFirstSegment.
     *
     * @param face              This calls face.expressInterest to fetch more segments.
     * @param validatorKeyChain If this is not null, use its verifyData instead of
     *                          the verifySegment callback.
     * @param verifySegment     When a Data packet is received this calls
     *                          verifySegment.verifySegment(data). If it returns false then abort fetching
     *                          and call onError.onError with ErrorCode.SEGMENT_VERIFICATION_FAILED.
     * @param onComplete        When all segments are received, call
     *                          onComplete.onComplete(content) where content is the concatenation of the
     *                          content of all the segments.
     * @param onError           Call onError.onError(errorCode, message) for timeout or an
     *                          error processing segments.
     */
    private SegmentFetcher
    (Face face, Interest baseInterest, KeyChain validatorKeyChain, Options options, Validator validator,
     SegmentFetcher.VerifySegment verifySegment, SegmentFetcher.OnComplete onComplete,
     SegmentFetcher.OnError onError) {
        this.options_ = options;
        face_ = face;
        validator_ = validator;
        validatorKeyChain_ = validatorKeyChain;
        verifySegment_ = verifySegment;
        onComplete_ = onComplete;
        onError_ = onError;

        rttEstimator_ = new RttEstimator(options_.rttOptions);
        cwnd_ = options_.initCwnd;
        ssThresh_ = options_.initSsthresh;
        timeLastSegmentReceived_ = System.currentTimeMillis();
        baseInterest_ = baseInterest;
    }

    private void run() {
        fetchFirstSegment(false);

        face_.callLater(options_.rtoCheckInterval, rtoTimeoutRunnable_);
    }

    private void fetchFirstSegment(boolean isRetransmission) {
        Interest interest = new Interest(baseInterest_);
        interest.setCanBePrefix(true);
        interest.setMustBeFresh(true);
        interest.setInterestLifetimeMilliseconds(options_.interestLifetime);
        if (isRetransmission) {
            interest.refreshNonce();
        }

        try {
            sendInterest(0, interest, isRetransmission);

        } catch (IOException ex) {
            try {
                onError_.onError
                        (SegmentFetcher.ErrorCode.IO_ERROR, "I/O error fetching the first segment " + ex);
            } catch (Throwable exception) {
                logger_.log(Level.SEVERE, "Error in onError", exception);
            }
        }
    }

    private void fetchSegmentsInWindow() {
        if (checkAllSegmentsReceived()) {
            // All segments have been retrieved
            finalizeFetch();
            return;
        }

        double availableWindowSize = cwnd_ - nSegmentsInFlight_;
        Map<Long, Boolean> segmentsToRequest = new HashMap(); // The boolean indicates whether a retx or not

        while (availableWindowSize > 0) {

            if (!retxQueue_.isEmpty()) {
                Long key = retxQueue_.element();
                retxQueue_.remove();
                segmentsToRequest.put(key, true);
            } else if (nSegments_ == -1 || nextSegmentNum_ < nSegments_) {
                if (receivedSegments_.containsKey(nextSegmentNum_)) {
                    // Don't request a segment a second time if received in response to first "discovery" Interest
                    nextSegmentNum_++;
                    continue;
                }
                segmentsToRequest.put(nextSegmentNum_++, false);
            } else {
                break;
            }
            availableWindowSize--;
        }

        for (Map.Entry<Long, Boolean> segment : segmentsToRequest.entrySet()) {
            // Start with the original Interest to preserve any special selectors.
            Interest interest = new Interest(baseInterest_);
            interest.setName(versionedDataName_.getPrefix(-1).appendSegment(segment.getKey()));
            interest.setCanBePrefix(false);
            interest.setMustBeFresh(false);
            interest.setInterestLifetimeMilliseconds(options_.interestLifetime);
            interest.refreshNonce();

            try {
                sendInterest(segment.getKey(), interest, segment.getValue());
            } catch (IOException ex) {
                try {
                    onError_.onError
                            (SegmentFetcher.ErrorCode.IO_ERROR, "I/O error fetching the next segment " + ex);
                } catch (Throwable exception) {
                    logger_.log(Level.SEVERE, "Error in onError", exception);
                }
            }
        }
    }

    private void sendInterest(long segmentNum, final Interest interest, boolean isRetransmission) throws IOException {
        int timeout = options_.useConstantInterestTimeout ? options_.maxTimeout : getEstimatedRto();

        if (isRetransmission) {
            PendingSegment pendingSegmentIt = pendingSegments_.get(segmentNum);
            if (pendingSegmentIt == null) return;
            pendingSegmentIt.state = SegmentState.Retransmitted;
            pendingSegmentIt.sendTime = System.currentTimeMillis();
            pendingSegmentIt.rto = timeout;
        }else {
            pendingSegments_.put(segmentNum, new PendingSegment(SegmentState.FirstInterest,
                    System.currentTimeMillis(), timeout));
            highInterest_ = segmentNum;
        }

        face_.expressInterest(interest, this, this, this);
        ++nSegmentsInFlight_;

    }

    private int getEstimatedRto() {
        // We don't want an Interest timeout greater than the maximum allowed timeout between the
        // successful receipt of segments
        return Math.min(options_.maxTimeout, (int) rttEstimator_.getEstimatedRto());
    }

    private Long findFirstEntry() {
        Map.Entry<Long, Long> o = (Map.Entry<Long, Long>) pendingSegments_.entrySet().toArray()[0];
        return o.getKey();
    }

    private boolean checkAllSegmentsReceived() {
        boolean haveReceivedAllSegments = false;

        if (nSegments_ != -1 && receivedSegments_.size() >= nSegments_) {
            haveReceivedAllSegments = true;
            // Verify that all segments in window have been received. If not, send Interests for missing segments.
            for (long i = 0; i < nSegments_; i++) {
                if (!receivedSegments_.containsKey(i)) {
                    retxQueue_.offer(i);
                    return false;
                }
            }
        }
        return haveReceivedAllSegments;
    }

    private void finalizeFetch() {
        // We are finished.
        // Get the total size and concatenate to get content.
        int totalSize = 0;
        for (long i = 0; i < nSegments_; ++i) {
            totalSize += (receivedSegments_.get(i)).size();
        }

        ByteBuffer content = ByteBuffer.allocate(totalSize);
        for (long i = 0; i < nSegments_; ++i) {
            if (receivedSegments_.get(i).size() != 0)
                content.put((receivedSegments_.get(i)).buf());
        }
        content.flip();
        stop();
        clean();

        try {
            onComplete_.onComplete(new Blob(content, false));
        } catch (Throwable ex) {
            logger_.log(Level.SEVERE, "Error in onComplete", ex);
        }
    }

    public void onData(final Interest originalInterest, Data data) {
        if (shouldStop()) return;

        nSegmentsInFlight_--;
        Name.Component currentSegmentComponent = data.getName().get(-1);
        if (!currentSegmentComponent.isSegment()) {
            onError_.onError
                    (SegmentFetcher.ErrorCode.DATA_HAS_NO_SEGMENT, "Data Name has no segment number");
            return;
        }

        long segmentNum;
        try {
            segmentNum = currentSegmentComponent.toSegment();
        } catch (EncodingException e) {
            onError_.onError
                    (SegmentFetcher.ErrorCode.DATA_HAS_NO_SEGMENT,
                            "Error decoding the name segment number " +
                                    data.getName().get(-1).toEscapedString() + ": " + e);
            e.printStackTrace();
            return;
        }

        // The first received Interest could have any segment ID
        final long pendingSegmentIt;
        if (receivedSegments_.size() > 0) {
            if (receivedSegments_.containsKey(segmentNum) || !pendingSegments_.containsKey(segmentNum))
                return;
            pendingSegmentIt = segmentNum;
        } else {
            pendingSegmentIt = findFirstEntry();
        }

        if (validatorKeyChain_ != null) {
            try {
                final SegmentFetcher thisSegmentFetcher = this;
                validatorKeyChain_.verifyData
                        (data, new OnVerified() {
                                    public void onVerified(Data localData) {
                                        thisSegmentFetcher.onVerified(localData, originalInterest, pendingSegmentIt);
                                    }
                                },
                                this);
            } catch (Throwable ex) {
                onDataValidationFailed(data, "Error in KeyChain.verifyData " + ex.getMessage());
            }
        } else if(validator_ != null){
            try {
                validator_.validate(data, new DataValidationSuccessCallback() {
                    public void successCallback(Data data) {
                        onVerified(data, originalInterest, pendingSegmentIt);
                    }
                }, new DataValidationFailureCallback() {
                    public void failureCallback(Data data, ValidationError error) {
                        onDataValidationFailed(data, error.toString());
                    }
                });
            } catch (CertificateV2.Error | ValidatorConfigError error) {
                onDataValidationFailed(data, "Error in KeyChain.verifyData " + error.getMessage());
            }
        }
        else {
            boolean verified = false;
            try {
                verified = verifySegment_.verifySegment(data);
            } catch (Throwable ex) {
                logger_.log(Level.SEVERE, "Error in verifySegment", ex);
            }
            if (!verified) {
                onDataValidationFailed(data, "User verification failed");
                return;
            }
            onVerified(data, originalInterest, pendingSegmentIt);
        }
    }

    private void onVerified(Data data, Interest originalInterest, long pendingSegmentIt) {
        if (shouldStop()) return;

        if (!endsWithSegmentNumber(data.getName())) {
            // We don't expect a name without a segment number.  Treat it as a bad packet.
            try {
                onError_.onError
                        (SegmentFetcher.ErrorCode.DATA_HAS_NO_SEGMENT,
                                "Got an unexpected packet without a segment number: " + data.getName().toUri());
            } catch (Throwable ex) {
                logger_.log(Level.SEVERE, "Error in onError", ex);
            }
        } else {
            long segmentNum;
            try {
                // It was verified in onData that the last Data name component is a segment number
                segmentNum = data.getName().get(-1).toSegment();
            } catch (EncodingException ex) {
                try {
                    onError_.onError
                            (SegmentFetcher.ErrorCode.DATA_HAS_NO_SEGMENT,
                                    "Error decoding the name segment number " +
                                            data.getName().get(-1).toEscapedString() + ": " + ex);
                } catch (Throwable exception) {
                    logger_.log(Level.SEVERE, "Error in onError", exception);
                }
                return;
            }

            // We update the last receive time here instead of in the segment received callback so that the
            // transfer will not fail to terminate if we only received invalid Data packets.
            timeLastSegmentReceived_ = System.currentTimeMillis();

            if (pendingSegments_.get(pendingSegmentIt).state == SegmentState.FirstInterest) {
                rttEstimator_.addMeasurement(
                        timeLastSegmentReceived_ - pendingSegments_.get(pendingSegmentIt).sendTime,
                        Math.max(nSegmentsInFlight_ + 1, 1));
            }

            // Remove from pending segments map
            pendingSegments_.remove(pendingSegmentIt);

            // Copy data in segment to temporary buffer
            receivedSegments_.put(segmentNum, data.getContent());

            if (receivedSegments_.size() == 1) {
                versionedDataName_ = data.getName();
                if (segmentNum == 0) {
                    // We received the first segment in response, so we can increment the next segment number
                    nextSegmentNum_++;
                }
            }

            if (data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
                try {
                    nSegments_ = data.getMetaInfo().getFinalBlockId().toSegment() + 1;
                } catch (EncodingException ex) {
                    try {
                        onError_.onError
                                (ErrorCode.DATA_HAS_NO_SEGMENT,
                                        "Error decoding the FinalBlockId segment number " +
                                                data.getMetaInfo().getFinalBlockId().toEscapedString() + ": " + ex);
                    } catch (Throwable exception) {
                        logger_.log(Level.SEVERE, "Error in onError", exception);
                    }
                    return;
                }
            }

            if (highData_ < segmentNum) {
                highData_ = segmentNum;
            }

            if (data.getCongestionMark() > 0 && !options_.ignoreCongMarks) {
                windowDecrease();
            } else {
                windowIncrease();
            }
            fetchSegmentsInWindow();
        }

    }

    private void windowIncrease() {
        if (options_.useConstantCwnd || cwnd_ == options_.maxWindowSize) {
            return;
        }

        if (cwnd_ < ssThresh_) {
            cwnd_ += options_.aiStep; // additive increase
        } else {
            cwnd_ += options_.aiStep / cwnd_; // congestion avoidance
        }
    }

    private void windowDecrease() {
        if (options_.disableCwa || highData_ > recPoint_) {
            recPoint_ = highInterest_;

            if (options_.useConstantCwnd) {
                return;
            }

            // Refer to RFC 5681, Section 3.1 for the rationale behind the code below
            ssThresh_ = Math.max(MIN_SSTHRESH, cwnd_ * options_.mdCoef); // multiplicative decrease
            cwnd_ = options_.resetCwndToInit ? options_.initCwnd : ssThresh_;
        }
    }

    public void onDataValidationFailed(Data data, String reason) {
        if (shouldStop()) return;

        try {
            onError_.onError
                    (SegmentFetcher.ErrorCode.SEGMENT_VERIFICATION_FAILED,
                            "Segment verification failed for " + data.getName().toUri() +
                                    " . Reason: " + reason);
        } catch (Throwable ex) {
            logger_.log(Level.SEVERE, "Error in onError", ex);
        }
    }

        public void onNetworkNack(Interest interest, NetworkNack networkNack) {
        if (shouldStop()) return;

        switch (networkNack.getReason()) {
            case DUPLICATE:
            case CONGESTION:
                long segmentNum = getSegmentNumber(interest);
                if (segmentNum == -1) return;

                afterNackOrTimeout(segmentNum);
                break;
            default:
                try {
                    onError_.onError
                            (ErrorCode.NACK_ERROR, "Nack Error");
                } catch (Throwable ex) {
                    logger_.log(Level.SEVERE, "Error in onError", ex);
                }
                stop();
                break;
        }
    }

    public void onTimeout(Interest interest) {
        if (shouldStop()) return;

        long segmentNum = getSegmentNumber(interest);
        if (segmentNum == -1) return;

        if(pendingSegments_.containsKey(segmentNum)){
            try {
                onError_.onError
                        (ErrorCode.INTEREST_TIMEOUT,
                                "Lifetime expired for interest " + interest.getName().toUri());
            } catch (Throwable ex) {
                logger_.log(Level.SEVERE, "Error in onError", ex);
            }
        }

        afterNackOrTimeout(segmentNum);
    }

    private Runnable rtoTimeoutRunnable_ = new Runnable() {
        public void run() {
            if (shouldStop()) return;

            boolean hasTimeout = false;

            for (Map.Entry<Long, PendingSegment> entry : pendingSegments_.entrySet()) {
                PendingSegment ps = entry.getValue();
                if (ps.state != SegmentState.InRetxQueue) { // skip segments already in the retx queue
                    long timeElapsed = System.currentTimeMillis() - ps.sendTime;
                    if (timeElapsed > ps.rto) { // timer expired?
                        hasTimeout = true;
                        enqueueForRetransmission(entry.getKey());
                    }
                }
            }

            if (hasTimeout) {
                if (!checkMaxTimeout()) return;

                rttEstimator_.backoffRto();
                if (receivedSegments_.size() == 0) {
                    // Resend first Interest (until maximum receive timeout exceeded)
                    fetchFirstSegment(true);
                } else {
                    windowDecrease();
                    fetchSegmentsInWindow();
                }
            }

            // schedule the next check after predefined interval
            face_.callLater(options_.rtoCheckInterval, rtoTimeoutRunnable_);
        }
    };

    private boolean enqueueForRetransmission(Long segmentNumber) {
        if (pendingSegments_.containsKey(segmentNumber)) {
            // Cancel timeout event and set status to InRetxQueue
            PendingSegment pendingSegmentIt = pendingSegments_.get(segmentNumber);
            pendingSegmentIt.state = SegmentState.InRetxQueue;
            nSegmentsInFlight_--;
        } else return false;

        if (receivedSegments_.size() != 0) {
            retxQueue_.offer(segmentNumber);
        }

        return true;
    }

    private void afterNackOrTimeout(long segmentNum) {
        if (!checkMaxTimeout()) return;

        if(!enqueueForRetransmission(segmentNum))
            return;

        rttEstimator_.backoffRto();
        if (receivedSegments_.size() == 0) {
            // Resend first Interest (until maximum receive timeout exceeded)
            fetchFirstSegment(true);
        } else {
            windowDecrease();
            fetchSegmentsInWindow();
        }
    }

    private boolean checkMaxTimeout(){
        if (System.currentTimeMillis() >= timeLastSegmentReceived_ + options_.maxTimeout) {
            // Fail transfer due to exceeding the maximum timeout between the successful receipt of segments
            try {
                onError_.onError
                        (ErrorCode.INTEREST_TIMEOUT,
                                "Timeout exceeded");
            } catch (Throwable ex) {
                logger_.log(Level.SEVERE, "Error in onError", ex);
            }
            stop();
            return false;
        }
        return true;
    }

    private long getSegmentNumber(Interest interest){
        Name.Component lastNameComponent = interest.getName().get(-1);
        if (lastNameComponent.isSegment()) {
            try {
                return lastNameComponent.toSegment();
            } catch (EncodingException e) {
                e.printStackTrace();
                return -1;
            }

        } else {
            // First Interest
            return 0;
        }

    }

    public boolean isStopped() {
        return stop_;
    }

    /**
     * Stop fetching packets and clear the received data.
     */
    public void stop() {
        stop_ = true;
    }

    /**
     * Check if we should stop fetching interests.
     * @return The current state of stop_.
     */
    private boolean shouldStop() {
        if(stop_)
            clean();
        return stop_;
    }

    /**
     * Clean the data received
     */
    private void clean() {
        pendingSegments_.clear(); // cancels pending Interests and timeout events
        receivedSegments_.clear(); // remove the received segments
    }

    /**
     * Check if the last component in the name is a segment number.
     *
     * @param name The name to check.
     * @return True if the name ends with a segment number, otherwise false.
     */
    private static boolean
    endsWithSegmentNumber(Name name) {
        return name.size() >= 1 && name.get(-1).isSegment();
    }

    private double cwnd_ = 1;
    private final Options options_;
    private double ssThresh_;
    private final Face face_;
    private RttEstimator rttEstimator_;

    private long highData_ = 0;
    private long recPoint_ = 0;
    private long highInterest_ = 0;
    private Interest baseInterest_;
    private int nSegmentsInFlight_ = 0;
    private long nSegments_ = -1;
    private Map<Long, PendingSegment> pendingSegments_ = new HashMap();
    private Map<Long, Blob> receivedSegments_ = new HashMap();
    private Queue<Long> retxQueue_ = new LinkedList<>();
    private long nextSegmentNum_ = 0;
    private long timeLastSegmentReceived_ = 0;
    private Name versionedDataName_;
    private boolean stop_ = false;
    private static final double MIN_SSTHRESH = 2.0;
    private final Validator validator_;
    private final KeyChain validatorKeyChain_;
    private final SegmentFetcher.VerifySegment verifySegment_;
    private final SegmentFetcher.OnComplete onComplete_;
    private final SegmentFetcher.OnError onError_;
    private static final Logger logger_ = Logger.getLogger(SegmentFetcher.class.getName());
}