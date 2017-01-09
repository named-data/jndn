/**
 * Copyright (C) 2016-2017 Regents of the University of California.
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

import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.HmacWithSha256Signature;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.util.Blob;

public class TestSignVerifyDataHmac {
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

  private static final ByteBuffer TlvData = toBuffer(new int[] {
0x06, 0x49, // NDN Data
  0x07, 0x0a, // Name
    0x08, 0x03, 0x6e, 0x64, 0x6e, // "ndn"
    0x08, 0x03, 0x61, 0x62, 0x63, // "abc"
  0x14, 0x00, // MetaInfo
  0x15, 0x08, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x21, // Content = "SUCCESS!"
  0x16, 0x0d, // SignatureInfo
    0x1b, 0x01, 0x04, // SignatureType = SignatureHmacWithSha256
    0x1c, 0x08, // KeyLocator
      0x07, 0x06, // Name
        0x08, 0x04, 0x6b, 0x65, 0x79, 0x31, // "key1"
  0x17, 0x20, // SignatureValue
    0x19, 0x86, 0x8e, 0x71, 0x83, 0x99, 0x8d, 0xf3, 0x73, 0x33,
    0x2f, 0x3d, 0xd1, 0xc9, 0xc9, 0x50, 0xfc, 0x29, 0xd7, 0x34,
    0xc0, 0x79, 0x77, 0x79, 0x1d, 0x83, 0x96, 0xfa, 0x3b, 0x91,
    0xfd, 0x36
  });

  public static void
  main(String[] args)
  {
    try {
      // Don't show INFO log messages.
      Logger.getLogger("").setLevel(Level.WARNING);

      Data data = new Data();
      data.wireDecode(new Blob(TlvData, false));

      // Use a hard-wired secret for testing. In a real application the signer
      // ensures that the verifier knows the shared key and its keyName.
      Blob key = new Blob(toBuffer(new int[] {
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
      }), false);

      if (KeyChain.verifyDataWithHmacWithSha256(data, key))
       System.out.println("Hard-coded data signature verification: VERIFIED");
      else
        System.out.println("Hard-coded data signature verification: FAILED");

      Data freshData = new Data(new Name("/ndn/abc"));
      HmacWithSha256Signature signature = new HmacWithSha256Signature();
      signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
      signature.getKeyLocator().setKeyName(new Name("key1"));
      freshData.setSignature(signature);
      freshData.setContent(new Blob("SUCCESS!"));
      System.out.println("Signing fresh data packet " + freshData.getName().toUri());
      KeyChain.signWithHmacWithSha256(freshData, key);

      if (KeyChain.verifyDataWithHmacWithSha256(freshData, key))
        System.out.println("Freshly-signed data signature verification: VERIFIED");
      else
        System.out.println("Freshly-signed data signature verification: FAILED");
    }
    catch (Exception e) {
      System.out.println(e.getMessage());
    }
  }
}
