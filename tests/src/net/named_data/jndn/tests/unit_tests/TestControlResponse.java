/*
 * jndn
 * Copyright (c) 2015-2016, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 3, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 */

package net.named_data.jndn.tests.unit_tests;

import java.nio.ByteBuffer;
import net.named_data.jndn.ControlParameters;

import net.named_data.jndn.ControlResponse;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.*;
import org.junit.Test;

/**
 * Test encoding/decoding of ControlResponses
 *
 * @author Andrew Brown <andrew.brown@intel.com>
 */
public class TestControlResponse {
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

  static final ByteBuffer TestControlResponse1 = toBuffer(new int[] {
    0x65, 0x1c, // ControlResponse
      0x66, 0x02, 0x01, 0x94, // StatusCode
      0x67, 0x11, // StatusText
        0x4e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x6e, 0x6f, 0x74, 0x20,
        0x66, 0x6f, 0x75, 0x6e, 0x64,
      0x68, 0x03, // ControlParameters
        0x69, 0x01, 0x0a // FaceId
  });

  @Test
  public void Encode() throws Exception {
    ControlResponse response = new ControlResponse();
    response.setStatusCode(404);
    response.setStatusText("Nothing not found");
    response.setBodyAsControlParameters(new ControlParameters());
    response.getBodyAsControlParameters().setFaceId(10);
    Blob wire = response.wireEncode();

    assertEquals(wire.buf(), TestControlResponse1);
  }

  @Test
  public void Decode() throws Exception {
    ControlResponse response = new ControlResponse();
    response.wireDecode(TestControlResponse1);

    assertEquals(response.getStatusCode(), 404);
    assertEquals(response.getStatusText(), "Nothing not found");
    assertEquals(response.getBodyAsControlParameters().getFaceId(), 10);
  }
}
