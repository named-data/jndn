/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnDataValidationFailed;

/**
 * SegmentFetcher is a utility class to fetch the latest version of segmented data.
 *
 * SegmentFetcher assumes that the data is named /{prefix}/{version}/{segment},
 * where:
 * - {prefix} is the specified name prefix,
 * - {version} is an unknown version that needs to be discovered, and
 * - {segment} is a segment number. (The number of segments is unknown and is
 *   controlled by the `FinalBlockId` field in at least the last Data packet.
 *
 * The following logic is implemented in SegmentFetcher:
 *
 * 1. Express the first Interest to discover the version:
 *
 *    Interest: /{prefix}?ChildSelector=1&amp;MustBeFresh=true
 *
 * 2. Infer the latest version of the Data: {version} = Data.getName().get(-2)
 *
 * 3. If the segment number in the retrieved packet == 0, go to step 5.
 *
 * 4. Send an Interest for segment 0:
 *
 *     Interest: /{prefix}/{version}/{segment=0}
 *
 * 5. Keep sending Interests for the next segment while the retrieved Data does
 *    not have a FinalBlockId or the FinalBlockId != Data.getName().get(-1).
 *
 *    Interest: /{prefix}/{version}/{segment=(N+1))}
 *
 * 6. Call the OnComplete callback with a blob that concatenates the content
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
public class SegmentFetcher implements OnData, OnDataValidationFailed, OnTimeout {
  public enum ErrorCode {
    INTEREST_TIMEOUT,
    DATA_HAS_NO_SEGMENT,
    SEGMENT_VERIFICATION_FAILED,
    IO_ERROR
  }

  public interface OnComplete {
    void onComplete(Blob content);
  }

  public interface ToFileOnComplete {
    void onComplete(boolean isCompleted);
  }

  public interface VerifySegment {
    boolean verifySegment(Data data);
  }

  public interface OnError {
    void onError(ErrorCode errorCode, String message);
  }

  /**
   * DontVerifySegment may be used in fetch to skip validation of Data packets.
   */
  public static final VerifySegment DontVerifySegment = new VerifySegment() {
   public boolean verifySegment(Data data) {
     return true;
   }};

  /**
   * Initiate segment fetching. For more details, see the documentation for
   * the class.
   * @param face This calls face.expressInterest to fetch more segments.
   * @param baseInterest An Interest for the initial segment of the requested
   * data, where baseInterest.getName() has the name prefix.
   * This interest may include a custom InterestLifetime and selectors that will
   * propagate to all subsequent Interests. The only exception is that the
   * initial Interest will be forced to include selectors "ChildSelector=1" and
   * "MustBeFresh=true" which will be turned off in subsequent Interests.
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
  public static void
  fetch
    (Face face, Interest baseInterest, VerifySegment verifySegment,
     OnComplete onComplete, OnError onError)
  {
    new SegmentFetcher(face, null, verifySegment, onComplete, onError)
            .fetchFirstSegment(baseInterest);
  }

  /**
   * Initiate segment fetching. For more details, see the documentation for
   * the class.
   * @param face This calls face.expressInterest to fetch more segments.
   * @param baseInterest An Interest for the initial segment of the requested
   * data, where baseInterest.getName() has the name prefix.
   * This interest may include a custom InterestLifetime and selectors that will
   * propagate to all subsequent Interests. The only exception is that the
   * initial Interest will be forced to include selectors "ChildSelector=1" and
   * "MustBeFresh=true" which will be turned off in subsequent Interests.
   * @param verifyTransferSegment When a Data packet is received this calls
   * verifySegment.verifySegment(data). If it returns false then abort fetching
   * and call onError.onError with ErrorCode.SEGMENT_VERIFICATION_FAILED. If
   * data validation is not required, use DontVerifySegment.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param ToFileOnComplete When all segments are received, call
   * onComplete.onComplete(isCompleted) where isCompleted is the boolean value
   * specifying whether all all data was written to the file.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError Call onError.onError(errorCode, message) for timeout or an
   * error processing segments.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param fileName The full path of the file with which to write.
   */
  public static void
  fetchFile
  (Face face, Interest baseInterest, VerifySegment verifyTransferSegment,
   ToFileOnComplete onComplete, OnError onError, String fileName)
  {
    new SegmentFetcher(face, null, verifyTransferSegment, onComplete,
            onError, fileName)
      .fetchFirstSegment(baseInterest);
  }

  /**
   * Initiate segment fetching. For more details, see the documentation for
   * the class.
   * @param face This calls face.expressInterest to fetch more segments.
   * @param baseInterest An Interest for the initial segment of the requested
   * data, where baseInterest.getName() has the name prefix.
   * This interest may include a custom InterestLifetime and selectors that will
   * propagate to all subsequent Interests. The only exception is that the
   * initial Interest will be forced to include selectors "ChildSelector=1" and
   * "MustBeFresh=true" which will be turned off in subsequent Interests.
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
  public static void
  fetch
    (Face face, Interest baseInterest, KeyChain validatorKeyChain,
     OnComplete onComplete, OnError onError)
  {
    new SegmentFetcher
      (face, validatorKeyChain, DontVerifySegment, onComplete, onError)
      .fetchFirstSegment(baseInterest);
  }

  /**
   * Initiate segment fetching for file. For more details, see
   * the documentation for the class.
   * @param face This calls face.expressInterest to fetch more segments.
   * @param baseInterest An Interest for the initial segment of the requested
   * data, where baseInterest.getName() has the name prefix.
   * This interest may include a custom InterestLifetime and selectors that will
   * propagate to all subsequent Interests. The only exception is that the
   * initial Interest will be forced to include selectors "ChildSelector=1" and
   * "MustBeFresh=true" which will be turned off in subsequent Interests.
   * @param validatorKeyChain When a Data packet is received this calls
   * validatorKeyChain.verifyData(data). If validation fails then abort
   * fetching and call onError with SEGMENT_VERIFICATION_FAILED. This does not
   * make a copy of the KeyChain; the object must remain valid while fetching.
   * If validatorKeyChain is null, this does not validate the data packet.
   * @param ToFileOnComplete When all segments are received, call
   * onComplete.onComplete(isCompleted) where isCompleted is the boolean value
   * specifying whether all all data was written to the file.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError Call onError.onError(errorCode, message) for timeout
   * or an error processing segments.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param fileName The full path of the file with which to write.
   */
  public static void
  fetchFile
  (Face face, Interest baseInterest, KeyChain validatorKeyChain,
   ToFileOnComplete onComplete, OnError onError, String fileName)
  {
     new SegmentFetcher
      (face, validatorKeyChain, DontVerifySegment, onComplete, onError, fileName)
		 .fetchFirstSegment(baseInterest);
  }

  /**
   * Create a new SegmentFetcher to use the Face. See the static fetch method
   * for details. If validatorKeyChain is not null, use it and ignore
   * verifySegment. After creating the SegmentFetcher, call fetchFirstSegment.
   * @param face This calls face.expressInterest to fetch more segments.
   * @param validatorKeyChain If this is not null, use its verifyData instead of
   * the verifySegment callback.
   * @param verifySegment When a Data packet is received this calls
   * verifySegment.verifySegment(data). If it returns false then abort fetching
   * and call onError.onError with ErrorCode.SEGMENT_VERIFICATION_FAILED.
   * @param onComplete When all segments are received, call
   * onComplete.onComplete(content) where content is the concatenation of the
   * content of all the segments.
   * @param onError Call onError.onError(errorCode, message) for timeout or an
   * error processing segments.
   */
  private SegmentFetcher
    (Face face, KeyChain validatorKeyChain, VerifySegment verifySegment,
     OnComplete onComplete, OnError onError)
  {
    face_ = face;
    validatorKeyChain_ = validatorKeyChain;
    verifySegment_ = verifySegment;
    onComplete_ = onComplete;
    onError_ = onError;
    toFileOnComplete_ = null;
  }


  /**
   * Create a new SegmentFetcher to use the Face. See the static fetch method
   * for details. If validatorKeyChain is not null, use it and ignore
   * verifySegment. After creating the SegmentFetcher, call fetchFirstSegment.
   * @param face This calls face.expressInterest to fetch more segments.
   * @param validatorKeyChain If this is not null, use its verifyData instead of
   * the verifySegment callback.
   * @param verifySegment When a Data packet is received this calls
   * verifySegment.verifySegment(data). If it returns false then abort fetching
   * and call onError.onError with ErrorCode.SEGMENT_VERIFICATION_FAILED.
   * @param onComplete When all segments are received, call
   * onComplete.onComplete(content) where content is the concatenation of the
   * content of all the segments.
   * @param onError Call onError.onError(errorCode, message) for timeout or an
   * error processing segments.
   * @param fileName The full path of the file to write to.
   */
  private SegmentFetcher
  (Face face, KeyChain validatorKeyChain, VerifySegment verifySegment,
   ToFileOnComplete onComplete, OnError onError, String fileName)
  {
    face_ = face;
    validatorKeyChain_ = validatorKeyChain;
    verifySegment_ = verifySegment;
    toFileOnComplete_ = onComplete;
    onComplete_ = null;
    onError_ = onError;
    fileName_ = fileName;
    newFile_ = Paths.get(fileName);
    if (!Files.exists(newFile_)) {
      try {
          Files.createFile(newFile_);
      }
      catch (IOException exception) {
        logger_.log(Level.SEVERE, "Error in creating new file", exception);
        throw new RuntimeException("Failed to create file");
      }
    }
  }

  private void
  fetchFirstSegment(Interest baseInterest)
  {
    Interest interest = new Interest(baseInterest);
    interest.setChildSelector(1);
    interest.setMustBeFresh(true);

    try {
      face_.expressInterest(interest, this, this);
    } catch (IOException ex) {
      try {
        onError_.onError
          (ErrorCode.IO_ERROR, "I/O error fetching the first segment " + ex);
      } catch (Throwable exception) {
        logger_.log(Level.SEVERE, "Error in onError", exception);
      }
    }
  }

  private void
  fetchNextSegment(Interest originalInterest, Name dataName, long segment)
  {
    // Start with the original Interest to preserve any special selectors.
    Interest interest = new Interest(originalInterest);
    // Changing a field clears the nonce so that the library will generate a new one.
    interest.setChildSelector(0);
    interest.setMustBeFresh(false);
    interest.setName(dataName.getPrefix(-1).appendSegment(segment));
    try {
      face_.expressInterest(interest, this, this);
    } catch (IOException ex) {
      try {
        onError_.onError
          (ErrorCode.IO_ERROR, "I/O error fetching the next segment " + ex);
      } catch (Throwable exception) {
        logger_.log(Level.SEVERE, "Error in onError", exception);
      }
    }
  }

  public void
  onData(final Interest originalInterest, Data data)
  {
    if (validatorKeyChain_ != null) {
      try {
        final SegmentFetcher thisSegmentFetcher = this;
        validatorKeyChain_.verifyData
          (data,
           new OnVerified() {
             public void onVerified(Data localData) {
               thisSegmentFetcher.onVerified(localData, originalInterest);
             }
           },
           this);
      } catch (Throwable ex) {
        try {
          onError_.onError
            (ErrorCode.SEGMENT_VERIFICATION_FAILED,
             "Error in KeyChain.verifyData " + ex.getMessage());
        } catch (Throwable ex2) {
          logger_.log(Level.SEVERE, "Error in onError", ex2);
        }
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
        try {
          onError_.onError
            (ErrorCode.SEGMENT_VERIFICATION_FAILED, "Segment verification failed");
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onError", ex);
        }
        return;
      }

      onVerified(data, originalInterest);
    }
  }

  public void
  onVerified(Data data, Interest originalInterest)
  {
    if (!endsWithSegmentNumber(data.getName())) {
      // We don't expect a name without a segment number.  Treat it as a bad packet.
      try {
        onError_.onError
          (ErrorCode.DATA_HAS_NO_SEGMENT,
           "Got an unexpected packet without a segment number: " + data.getName().toUri());
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onError", ex);
      }
    }
    else {
      long currentSegment;
      try {
        currentSegment = data.getName().get(-1).toSegment();
      }
      catch (EncodingException ex) {
        try {
          onError_.onError
            (ErrorCode.DATA_HAS_NO_SEGMENT,
             "Error decoding the name segment number " +
             data.getName().get(-1).toEscapedString() + ": " + ex);
        } catch (Throwable exception) {
          logger_.log(Level.SEVERE, "Error in onError", exception);
        }
        return;
      }

      long expectedSegmentNumber = currentSegment_;
      if (currentSegment != expectedSegmentNumber) {
        // Try again to get the expected segment.  This also includes the case
        //   where the first segment is not segment 0.
        fetchNextSegment(originalInterest, data.getName(), expectedSegmentNumber);
      }
      else {
        // Save the content and check if we are finished.
        ++currentSegment_;
        if (fileName_ == "") {
          contentParts_.add(data.getContent());
        }
        else {

          OutputStream outStream = null;
          try ( OutputStream newOutStream = Files.newOutputStream(newFile_,
                  StandardOpenOption.APPEND)){
            outStream = newOutStream;
            outStream.write(data.getContent().getImmutableArray());

          } catch (IOException exception) {
            logger_.log(Level.SEVERE, "Error in writing bytes to file",
                    exception);
            try {
              outStream.flush();
            } finally {
              try {
                outStream.close();
              } catch (IOException e) {
                logger_.log(Level.SEVERE, "Error in closing file", e);
              }
              toFileOnComplete_.onComplete(false);
              return;
            }
          }
        }

        if (data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
          long finalSegmentNumber;
          try {
            finalSegmentNumber = data.getMetaInfo().getFinalBlockId().toSegment();
          }
          catch (EncodingException ex) {
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

          if (currentSegment == finalSegmentNumber) {
            // We are finished.

            if (fileName_.equals("")) {
              // Get the total size and concatenate to get content.
              int totalSize = 0;
              for (int i = 0; i < contentParts_.size(); ++i)
                totalSize += ((Blob) contentParts_.get(i)).size();
              ByteBuffer content = ByteBuffer.allocate(totalSize);
              for (int i = 0; i < contentParts_.size(); ++i)
                content.put(((Blob) contentParts_.get(i)).buf());
              content.flip();
              try {
                onComplete_.onComplete(new Blob(content, false));
              } catch (Throwable ex) {
                logger_.log(Level.SEVERE, "Error in onComplete", ex);
              }
            }
            else {
              toFileOnComplete_.onComplete(true);
            }
            return;
          }
        }

        // Fetch the next segment.
        fetchNextSegment(originalInterest, data.getName(), expectedSegmentNumber + 1);
      }
    }
  }

  public void
  onDataValidationFailed(Data data, String reason)
  {
    try {
      onError_.onError
        (ErrorCode.SEGMENT_VERIFICATION_FAILED,
         "Segment verification failed for " + data.getName().toUri() +
         " . Reason: " + reason);
    } catch (Throwable ex) {
      logger_.log(Level.SEVERE, "Error in onError", ex);
    }
  }

  public void
  onTimeout(Interest interest)
  {
    try {
      onError_.onError
        (ErrorCode.INTEREST_TIMEOUT,
         "Time out for interest " + interest.getName().toUri());
    } catch (Throwable ex) {
      logger_.log(Level.SEVERE, "Error in onError", ex);
    }
  }

  /**
   * Check if the last component in the name is a segment number.
   * @param name The name to check.
   * @return True if the name ends with a segment number, otherwise false.
   */
  private static boolean
  endsWithSegmentNumber(Name name)
  {
    return name.size() >= 1 && name.get(-1).isSegment();
  }

  // Use a non-template ArrayList so it works with older Java compilers.
  private final ArrayList contentParts_ = new ArrayList(); // of Blob
  private final Face face_;
  private final KeyChain validatorKeyChain_;
  private final VerifySegment verifySegment_;
  private final OnComplete onComplete_;
  private final ToFileOnComplete toFileOnComplete_;
  private final OnError onError_;
  private String fileName_ = "";
  private Path newFile_;
  private long currentSegment_ = 0l;
  private static final Logger logger_ = Logger.getLogger(SegmentFetcher.class.getName());
}
