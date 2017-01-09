/**
 * Copyright (C) 2014-2017 Regents of the University of California.
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

import com.google.protobuf.ByteString;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.ProtobufTlv;
import net.named_data.jndn.tests.FibEntryProto.FibEntryMessage;
import net.named_data.jndn.util.Blob;

public class TestEncodeDecodeFibEntry {
  public static void
  main(String[] args)
  {
    try {
      // Construct a sample FibEntry message using the structure in FibEntryProto.java
      // which was produced by protoc.
      FibEntryMessage.Builder builder = FibEntryMessage.newBuilder();
      builder.getFibEntryBuilder().setPhone(FibEntryMessage.PhoneType.WORK);
      builder.getFibEntryBuilder().getNameBuilder()
              .addComponent(ByteString.copyFromUtf8("ndn"))
              .addComponent(ByteString.copyFromUtf8("abc"));
      builder.getFibEntryBuilder().addNextHopRecordsBuilder()
              .setFaceId(16)
              .setCost(1);
      FibEntryMessage message = builder.build();

      // Encode the Protobuf message object as TLV.
      Blob encoding = ProtobufTlv.encode(message);

      FibEntryMessage.Builder decodedMessage = FibEntryMessage.newBuilder();
      ProtobufTlv.decode(decodedMessage, encoding);

      System.out.println("Re-decoded FibEntry:");
      FibEntryMessage.FibEntry fibEntry =  decodedMessage.getFibEntry();
      // This should print the same values that we put in message above.
      System.out.print(ProtobufTlv.toName(fibEntry.getName()).toUri());
      System.out.print(" nexthops = {");
      for (int i = 0; i < fibEntry.getNextHopRecordsCount(); ++i)
        System.out.print("faceid=" + fibEntry.getNextHopRecords(i).getFaceId() +
          " (cost=" + fibEntry.getNextHopRecords(i).getCost() + ")");
      System.out.println(" }");
    } catch (EncodingException e) {
      System.out.println(e.getMessage());
    }
  }
}
