/**
 * Copyright (C) 2015 Regents of the University of California.
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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.ProtobufTlv;
import net.named_data.jndn.tests.RibEntryProto.RibEntryMessage;
import net.named_data.jndn.util.Blob;

/**
 * DataCallbacks handles the onData event to fetch multiple segments. When the
 * final segment is fetched, pass the result to printRibEntry.
 * @author jefft0
 */
class DataCallbacks implements OnData, OnTimeout {
  /**
   * Create a new DataCallbacks to use the Face.
   * @param face This calls face.expressInterest to fetch more segments.
   */
  DataCallbacks(Face face)
  {
    face_ = face;
  }

  public void
  onData(Interest interest, Data data)
  {
    if (!endsWithSegmentNumber(data.getName())) {
      // We don't expect a name without a segment number.  Treat it as a bad packet.
      System.out.println("Got an unexpected packet without a segment number");
      enabled_ = false;
    }
    else {
      long segmentNumber;
      try {
        segmentNumber = data.getName().get(-1).toSegment();
      }
      catch (EncodingException ex) {
        System.out.println("Error decoding the name segment number " + ex);
        enabled_ = false;
        return;
      }

      long expectedSegmentNumber = contentParts_.size();
      if (segmentNumber != expectedSegmentNumber) {
        try {
          // Try again to get the expected segment.  This also includes the case
          //   where the first segment is not segment 0.
          face_.expressInterest
            (data.getName().getPrefix(-1).appendSegment(expectedSegmentNumber),
             this, this);
        }
        catch (IOException ex) {
          System.out.println("I/O error in expressInterest " + ex);
          enabled_ = false;
        }
      }
      else {
        // Save the content and check if we are finished.
        contentParts_.add(data.getContent());

        if (data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
          long finalSegmentNumber;
          try {
            finalSegmentNumber = data.getMetaInfo().getFinalBlockId().toSegment();
          }
          catch (EncodingException ex) {
            System.out.println("Error decoding the FinalBlockId segment number " + ex);
            enabled_ = false;
            return;
          }

          if (segmentNumber == finalSegmentNumber) {
            // We are finished.
            enabled_ = false;

            // Get the total size and concatenate to get encodedContent.
            int totalSize = 0;
            for (int i = 0; i < contentParts_.size(); ++i)
              totalSize += ((Blob)contentParts_.get(i)).size();
            ByteBuffer encodedMessage = ByteBuffer.allocate(totalSize);
            for (int i = 0; i < contentParts_.size(); ++i)
              encodedMessage.put(((Blob)contentParts_.get(i)).buf());
            encodedMessage.flip();

            printRibEntry(new Blob(encodedMessage, false));
            return;
          }
        }

        try {
          // Fetch the next segment.
          face_.expressInterest
            (data.getName().getPrefix(-1).appendSegment(expectedSegmentNumber + 1),
             this, this);
        }
        catch (IOException ex) {
          System.out.println("I/O error in expressInterest " + ex);
          enabled_ = false;
        }
      }
    }
  }

  public void
  onTimeout(Interest interest)
  {
    enabled_ = false;
    System.out.println("Time out for interest " + interest.getName().toUri());
  }

  /**
   * Decode the encodedMessage as a TLV RibEntry message and display the values.
   * @param encodedMessage The TLV-encoded RibEntry.
   */
  private static void
  printRibEntry(Blob encodedMessage)
  {
    RibEntryMessage.Builder ribEntryMessage = RibEntryMessage.newBuilder();
    try {
      ProtobufTlv.decode(ribEntryMessage, encodedMessage);
    } catch (EncodingException ex) {
      System.out.println("Error decoding the RibEntry message: " + ex.getMessage());
    }

    System.out.println("RIB:");
    for (int iEntry = 0; iEntry < ribEntryMessage.getRibEntryCount(); ++iEntry) {
      RibEntryMessage.RibEntry ribEntry = ribEntryMessage.getRibEntry(iEntry);

      // Show the name.
      System.out.print("  ");
      for (int i = 0; i < ribEntry.getName().getComponentCount(); ++i)
        System.out.print("/" + ribEntry.getName().getComponent(i).toStringUtf8());

      // Show the routes.
      for (int iRoute = 0; iRoute < ribEntry.getRoutesCount(); ++iRoute) {
        RibEntryMessage.Route route = ribEntry.getRoutes(iRoute);

        System.out.print(" route={faceId=" + route.getFaceId() + " (origin=" +
          route.getOrigin() + " cost=" + route.getCost());
        if ((route.getFlags() & 1) != 0)
          System.out.print(" ChildInherit");
        if ((route.getFlags() & 2) != 0)
          System.out.print(" Capture");
        if (route.hasExpirationPeriod())
          System.out.print(" expirationPeriod=" + route.getExpirationPeriod());
        System.out.println(")}");
      }
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
    return name.size() >= 1 &&
           name.get(-1).getValue().size() >= 1 &&
           name.get(-1).getValue().buf().get(0) == 0;
  }

  public boolean enabled_ = true;
  // Use a non-template ArrayList so it works with older Java compilers.
  private final ArrayList contentParts_ = new ArrayList(); // of Blob
  private final Face face_;
}

/**
 * This sense a rib list request to the local NFD and prints the response.
 * This is equivalent to the NFD command line command "nfd-status -r".
 */
public class TestListRib {
  public static void
  main(String[] args)
  {
    try {
      // The default Face connects to the local NFD.
      Face face = new Face();

      DataCallbacks callbacks = new DataCallbacks(face);

      Interest interest = new Interest(new Name("/localhost/nfd/rib/list"));
      interest.setChildSelector(1);
      interest.setInterestLifetimeMilliseconds(4000);
      System.out.println("Express interest " + interest.getName().toUri());
      face.expressInterest(interest, callbacks, callbacks);

      // Loop calling processEvents until callbacks is finished and sets enabled_ false.
      while (callbacks.enabled_) {
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
}
