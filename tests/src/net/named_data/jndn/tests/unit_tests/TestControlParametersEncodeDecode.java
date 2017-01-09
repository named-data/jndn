/**
 * Copyright (C) 2014-2017 Regents of the University of California.
 * @author: Andrew Brown
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

import net.named_data.jndn.ControlParameters;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class TestControlParametersEncodeDecode {

  /**
   * Test encoding/decoding
   *
   * @throws EncodingException
   */
  @Test
  public void
  testEncodeDecode() throws EncodingException
  {
    ControlParameters controlParameters = new ControlParameters();
    controlParameters.setName(new Name("/test/control/parameters"));
    controlParameters.setFaceId(1);
    // encode
    Blob encoded = controlParameters.wireEncode();
    // decode
    ControlParameters decodedControlParameters = new ControlParameters();
    decodedControlParameters.wireDecode(encoded);
    // compare
    assertEquals(controlParameters.getName().toUri(), decodedControlParameters
      .getName().toUri());
    assertEquals(controlParameters.getFaceId(), decodedControlParameters
      .getFaceId());
    assertEquals("decoded forwarding flags childInherit is different",
                 controlParameters.getForwardingFlags().getChildInherit(),
          decodedControlParameters.getForwardingFlags().getChildInherit());
    assertEquals("decoded forwarding flags capture is different",
                 controlParameters.getForwardingFlags().getCapture(),
          decodedControlParameters.getForwardingFlags().getCapture());
  }

  /**
   * Test encoding/decoding with no name defined
   *
   * @throws EncodingException
   */
  @Test
  public void
  testEncodeDecodeWithNoName() throws EncodingException
  {
    ControlParameters controlParameters = new ControlParameters();
    controlParameters.setStrategy(
      new Name("/localhost/nfd/strategy/broadcast"));
    controlParameters.setUri("null://");
    // encode
    Blob encoded = controlParameters.wireEncode();
    // decode
    ControlParameters decodedControlParameters = new ControlParameters();
    decodedControlParameters.wireDecode(encoded);
    // compare
    assertEquals(controlParameters.getStrategy().toUri(),
      decodedControlParameters.getStrategy().toUri());
    assertEquals(controlParameters.getUri(), decodedControlParameters.getUri());
  }

  /**
   * Test that not setting the any properties returns in an (almost) empty Blob
   */
  @Test
  public void
  testExceptionsThrown()
  {
    ControlParameters controlParameters = new ControlParameters();
    Blob encoded = controlParameters.wireEncode();
    assertEquals(2, encoded.buf().limit());
    // only TLV type 104 and length 0 should be set
  }
}
