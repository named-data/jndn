/**
 * Copyright (C) 2013-2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

package net.named_data.jndn.tests;

import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.TlvWireFormat;

public class TestEncodeDecodeInterest {
  // Convert the int array to a ByteBuffer.
  private static ByteBuffer
  toBuffer(int[] array)
  {
    ByteBuffer result = ByteBuffer.allocate(array.length);
    for (int i = 0; i < array.length; ++i)
      result.put((byte)(array[i] & 0xff));

    result.flip();
    return result;
  }

  private static final ByteBuffer BinaryXmlInterest = toBuffer(new int[] {
0x01, 0xd2,
  0xf2, 0xfa, 0x9d, 0x6e, 0x64, 0x6e, 0x00, 0xfa, 0x9d, 0x61, 0x62, 0x63, 0x00, 0x00,
  0x05, 0x9a, 0x9e, 0x31, 0x32, 0x33, 0x00,
  0x05, 0xa2, 0x8e, 0x34, 0x00,
  0x03, 0xe2,
    0x02, 0x85, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x00,
  0x02, 0xda, 0xfa, 0x9d, 0x61, 0x62, 0x63, 0x00, 0xea, 0x00, 0x00,
  0x05, 0xaa, 0x8e, 0x31, 0x00,
  0x02, 0xfa, 0x8e, 0x34, 0x00,
  0x02, 0xd2, 0x8e, 0x32, 0x00,
  0x03, 0x82, 0x9d, 0x01, 0xe0, 0x00, 0x00,
  0x02, 0xca, 0xb5, 0x61, 0x62, 0x61, 0x62, 0x61, 0x62, 0x00,
0x00,
1
  });

  private static final ByteBuffer TlvInterest = toBuffer(new int[] {
0x05, 0x53, // Interest
  0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x61, 0x62, 0x63, // Name
  0x09, 0x38, // Selectors
    0x0D, 0x01, 0x04, // MinSuffixComponents
    0x0E, 0x01, 0x06, // MaxSuffixComponents
    0x0F, 0x22, // KeyLocator
      0x1D, 0x20, // KeyLocatorDigest
                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x10, 0x07, // Exclude
      0x08, 0x03, 0x61, 0x62, 0x63, // NameComponent
      0x13, 0x00, // Any
    0x11, 0x01, 0x01, // ChildSelector
    0x12, 0x00, // MustBeFesh
  0x0A, 0x04, 0x61, 0x62, 0x61, 0x62,	// Nonce
  0x0B, 0x01, 0x02, // Scope
  0x0C, 0x02, 0x75, 0x30, // InterestLifetime
1
  });

  private static void
  dumpInterest(Interest interest)
  {
    System.out.println("name: " + interest.getName().toUri());
    System.out.println("minSuffixComponents: " +
      (interest.getMinSuffixComponents() >= 0 ?
       "" + interest.getMinSuffixComponents() : "<none>"));
    System.out.println("maxSuffixComponents: " +
      (interest.getMaxSuffixComponents() >= 0 ?
       "" + interest.getMaxSuffixComponents() : "<none>"));
    System.out.print("keyLocator: ");
    if (interest.getKeyLocator().getType() == KeyLocatorType.NONE)
      System.out.println("<none>");
    else if (interest.getKeyLocator().getType() == KeyLocatorType.KEY)
      System.out.println("Key: " + interest.getKeyLocator().getKeyData().toHex());
    else if (interest.getKeyLocator().getType() == KeyLocatorType.CERTIFICATE)
      System.out.println("Certificate: " + interest.getKeyLocator().getKeyData().toHex());
    else if (interest.getKeyLocator().getType() ==KeyLocatorType.KEY_LOCATOR_DIGEST)
      System.out.println("KeyLocatorDigest: " + interest.getKeyLocator().getKeyData().toHex());
    else if (interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME)
      System.out.println("KeyName: " + interest.getKeyLocator().getKeyName().toUri());
    else
      System.out.println("<unrecognized ndn_KeyLocatorType>");
    System.out.println
      ("exclude: " + (interest.getExclude().size() > 0 ?
                      interest.getExclude().toUri() : "<none>"));
    System.out.println("lifetimeMilliseconds: " +
      (interest.getInterestLifetimeMilliseconds() >= 0 ?
       "" + interest.getInterestLifetimeMilliseconds() : "<none>"));
    System.out.println("childSelector: " +
      (interest.getChildSelector() >= 0 ?
       "" + interest.getChildSelector() : "<none>"));
    System.out.println("mustBeFresh: " + interest.getMustBeFresh());
    System.out.println("scope: " +
      (interest.getScope() >= 0 ? "" + interest.getScope() : "<none>"));
    System.out.println("nonce: " +
      (interest.getNonce().size() > 0 ?
       "" + interest.getNonce().toHex() : "<none>"));
  }

  public static void
  main(String[] args)
  {
    try {
      Interest interest = new Interest();
      // Note: While we transition to the TLV wire format, check if it has been made the default.
      if (WireFormat.getDefaultWireFormat() == TlvWireFormat.get())
        interest.wireDecode(new Blob(TlvInterest, false));
      else
        interest.wireDecode(new Blob(BinaryXmlInterest, false));
      System.out.println("Interest:");
      dumpInterest(interest);

      Blob encoding = interest.wireEncode();
      System.out.println("");
      System.out.println("Re-encoded interest " + encoding.toHex());

      Interest reDecodedInterest = new Interest();
      reDecodedInterest.wireDecode(encoding);
      System.out.println("Re-decoded Interest:");
      dumpInterest(reDecodedInterest);

      Interest freshInterest = new Interest(new Name("/ndn/abc"));
      freshInterest.setMinSuffixComponents(4);
      freshInterest.setMaxSuffixComponents(6);
      freshInterest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
      freshInterest.getKeyLocator().setKeyData
        (new Blob(new byte[] {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F }));
      freshInterest.getExclude().appendComponent(new Name("abc").get(0)).appendAny();
      freshInterest.setInterestLifetimeMilliseconds(30000);
      freshInterest.setChildSelector(1);
      freshInterest.setMustBeFresh(true);
      freshInterest.setScope(2);

      Interest reDecodedFreshInterest = new Interest();
      reDecodedFreshInterest.wireDecode(freshInterest.wireEncode());

      System.out.println("");
      System.out.println("Re-decoded fresh Interest:");
      dumpInterest(reDecodedFreshInterest);
    }
    catch (EncodingException e) {
      System.out.println(e.getMessage());
    }
  }
}
