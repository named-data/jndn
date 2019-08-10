/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
 * From PSync unit tests:
 * https://github.com/named-data/PSync/blob/master/tests/test-state.cpp
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

package net.named_data.jndn.tests.unit_tests;

import java.nio.ByteBuffer;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.sync.detail.PSyncState;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

public class TestPSyncState {
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

  @Test
  public void
  testEncodeDecode() throws EncodingException
  {
    PSyncState state = new PSyncState();
    state.addContent(new Name("test1"));
    state.addContent(new Name("test2"));

    // Simulate getting a buffer of content from a segment fetcher.
    Data data = new Data();
    Blob encoding = state.wireEncode();
    ByteBuffer expectedEncoding = toBuffer(new int[] {
      0x80, 0x12, // PSyncContent
        0x07, 0x07, 0x08, 0x05, 0x74, 0x65, 0x73, 0x74, 0x31, // Name = "/test1"
        0x07, 0x07, 0x08, 0x05, 0x74, 0x65, 0x73, 0x74, 0x32  // Name = "/test2"
    });
    assertTrue(encoding.equals(new Blob(expectedEncoding, false)));
    data.setContent(encoding);

    PSyncState receivedState = new PSyncState();
    receivedState.wireDecode(data.getContent());

    assertArrayEquals(state.getContent().toArray(), receivedState.getContent().toArray());
  }

  @Test
  public void
  testEmptyContent() throws EncodingException
  {
    PSyncState state = new PSyncState();

    // Simulate getting a buffer of content from a segment fetcher.
    Data data = new Data();
    data.setContent(state.wireEncode());

    PSyncState state2 = new PSyncState(data.getContent());
    assertEquals(0, state2.getContent().size());
  }
}
