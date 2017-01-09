/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn.tests;

import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.ProtobufTlv;
import net.named_data.jndn.tests.FaceStatusProto.FaceStatusMessage;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.SegmentFetcher;
import net.named_data.jndn.security.KeyChain;

/**
 * This sends a faces list request to the local NFD and prints the response.
 * This is equivalent to the NFD command line command "nfd-status -f".
 * See http://redmine.named-data.net/projects/nfd/wiki/Management .
 */
public class TestListFaces {
  public static void
  main(String[] args)
  {
    try {
      // The default Face connects to the local NFD.
      Face face = new Face();

      Interest interest = new Interest(new Name("/localhost/nfd/faces/list"));
      interest.setInterestLifetimeMilliseconds(4000);
      System.out.println("Express interest " + interest.getName().toUri());

      final boolean[] enabled = new boolean[] { true };
      SegmentFetcher.fetch
        (face, interest, (KeyChain)null,
         new SegmentFetcher.OnComplete() {
           public void onComplete(Blob content) {
             enabled[0] = false;
             printFaceStatuses(content);
           }},
         new SegmentFetcher.OnError() {
           public void onError(SegmentFetcher.ErrorCode errorCode, String message) {
             enabled[0] = false;
             System.out.println(message);
           }});

      // Loop calling processEvents until a callback sets enabled[0] = false.
      while (enabled[0]) {
        face.processEvents();

        // We need to sleep for a few milliseconds so we don't use 100% of
        //   the CPU.
        Thread.sleep(5);
      }
    }
    catch (Exception e) {
       System.out.println("exception: " + e.getMessage());
    }
  }

  /**
   * This is called when all the segments are received to decode the
   * encodedMessage repeated TLV FaceStatus messages and display the values.
   * @param encodedMessage The repeated TLV-encoded FaceStatus.
   */
  public static void
  printFaceStatuses(Blob encodedMessage)
  {
    FaceStatusMessage.Builder faceStatusMessage = FaceStatusMessage.newBuilder();
    try {
      ProtobufTlv.decode(faceStatusMessage, encodedMessage);
    } catch (EncodingException ex) {
      System.out.println("Error decoding the FaceStatus message: " + ex.getMessage());
    }

    System.out.println("Faces:");
    for (int iEntry = 0; iEntry < faceStatusMessage.getFaceStatusCount(); ++iEntry) {
      FaceStatusMessage.FaceStatus faceStatus = faceStatusMessage.getFaceStatus(iEntry);

      // Format to look the same as "nfd-status -f".
      System.out.print("  faceid=" + faceStatus.getFaceId() +
        " remote=" + faceStatus.getUri() +
        " local=" + faceStatus.getLocalUri());
      if (faceStatus.hasExpirationPeriod())
        // Convert milliseconds to seconds.
        System.out.print(" expires=" +
          Math.round((double)faceStatus.getExpirationPeriod() / 1000) + "s");
      System.out.println(" counters={" + "in={" + faceStatus.getNInInterests() +
        "i " + faceStatus.getNInDatas() + "d " + faceStatus.getNInBytes() + "B}" +
        " out={" + faceStatus.getNOutInterests() + "i "+ faceStatus.getNOutDatas() +
        "d " + faceStatus.getNOutBytes() + "B}" + "}" +
        " " + (faceStatus.getFaceScope() == 1 ? "local" : "non-local") +
        " " + (faceStatus.getFacePersistency() == 2 ? "permanent" :
               faceStatus.getFacePersistency() == 1 ? "on-demand" : "persistent") +
        " " + (faceStatus.getLinkType() == 1 ? "multi-access" : "point-to-point"));
    }
  }
}
