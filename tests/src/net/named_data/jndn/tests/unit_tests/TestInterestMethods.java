/**
 * Copyright (C) 2014-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/interest.t.cpp
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
import java.util.ArrayList;
import java.util.Arrays;
import net.named_data.jndn.Data;
import net.named_data.jndn.DigestSha256Signature;
import net.named_data.jndn.Exclude;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.OnVerifiedInterest;
import net.named_data.jndn.security.OnInterestValidationFailed;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.identity.MemoryIdentityStorage;
import net.named_data.jndn.security.identity.MemoryPrivateKeyStorage;
import net.named_data.jndn.security.policy.SelfVerifyPolicyManager;
import net.named_data.jndn.util.Blob;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

class VerifyInterestCounter implements OnVerifiedInterest, OnInterestValidationFailed
{
  public void
  onVerifiedInterest(Interest interest)
  {
    ++onVerifiedCallCount_;
  }

  public void
  onInterestValidationFailed(Interest interest, String reason)
  {
    ++onValidationFailedCallCount_;
  }

  public int onVerifiedCallCount_ = 0;
  public int onValidationFailedCallCount_ = 0;
};

public class TestInterestMethods {
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

  private static final ByteBuffer codedInterest = toBuffer(new int[] {
0x05, 0x50, // Interest
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
  0x0A, 0x04, 0x61, 0x62, 0x61, 0x62,   // Nonce
  0x0C, 0x02, 0x75, 0x30, // InterestLifetime
1
  });

  static String dump(Object s1) { return "" + s1; }
  static String dump(Object s1, Object s2) { return s1 + " " + s2; }

  private static ArrayList initialDump = new ArrayList(Arrays.asList(new Object[] {
    "name: /ndn/abc",
    "minSuffixComponents: 4",
    "maxSuffixComponents: 6",
    "keyLocator: KeyLocatorDigest: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "exclude: abc,*",
    "childSelector: 1",
    "mustBeFresh: true",
    "nonce: 61626162",
    "lifetimeMilliseconds: 30000"}));

  private static ArrayList
  dumpInterest(Interest interest)
  {
    ArrayList result = new ArrayList();
    result.add(dump("name:", interest.getName().toUri()));
    result.add(dump("minSuffixComponents:",
      interest.getMinSuffixComponents() >= 0 ?
        interest.getMinSuffixComponents() : "<none>"));
    result.add(dump("maxSuffixComponents:",
      interest.getMaxSuffixComponents() >= 0 ?
        interest.getMaxSuffixComponents() : "<none>"));
    if (interest.getKeyLocator().getType() != KeyLocatorType.NONE) {
      if (interest.getKeyLocator().getType() == KeyLocatorType.KEY_LOCATOR_DIGEST)
        result.add(dump("keyLocator: KeyLocatorDigest:",
          interest.getKeyLocator().getKeyData().toHex()));
      else if (interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME)
        result.add(dump("keyLocator: KeyName:",
          interest.getKeyLocator().getKeyName().toUri()));
      else
        result.add(dump("keyLocator: <unrecognized KeyLocatorType"));
    }
    else
      result.add(dump("keyLocator: <none>"));
    result.add(dump("exclude:",
      interest.getExclude().size() > 0 ? interest.getExclude().toUri() :"<none>"));
    result.add(dump("childSelector:",
      interest.getChildSelector() >= 0 ? interest.getChildSelector() : "<none>"));
    result.add(dump("mustBeFresh:", interest.getMustBeFresh() ? "true" : "false"));
    result.add(dump("nonce:", interest.getNonce().size() == 0 ?
      "<none>" : interest.getNonce().toHex()));
    result.add(dump("lifetimeMilliseconds:",
      interest.getInterestLifetimeMilliseconds() < 0 ?
        "<none>" : "" + (long)interest.getInterestLifetimeMilliseconds()));
    return result;
  }

  /**
   * Return a copy of the strings array, removing any string that start with prefix.
   */
  private static ArrayList
  removeStartingWith(ArrayList strings, String prefix)
  {
    ArrayList result = new ArrayList();
    for (int i = 0; i < strings.size(); ++i) {
      if (!((String)strings.get(i)).startsWith(prefix))
        result.add(strings.get(i));
    }

    return result;
  }

  // ignoring nonce, check that the dumped interests are equal
  private static boolean
  interestDumpsEqual(ArrayList dump1, ArrayList dump2)
  {
    String prefix = "nonce:";
    return Arrays.equals
      (removeStartingWith(dump1, prefix).toArray(),
       removeStartingWith(dump2, prefix).toArray());
  }

  private static Interest
  createFreshInterest()
  {
    Interest freshInterest = new Interest(new Name("/ndn/abc"))
      .setMustBeFresh(false)
      .setMinSuffixComponents(4)
      .setMaxSuffixComponents(6)
      .setInterestLifetimeMilliseconds(30000)
      .setChildSelector(1)
      .setMustBeFresh(true);
    freshInterest.getKeyLocator().setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    freshInterest.getKeyLocator().setKeyData
      (new Blob(new int[] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F }));
    freshInterest.getExclude().appendComponent(new Name("abc").get(0)).appendAny();

    return freshInterest;
  }

  private Interest referenceInterest;

  @Before
  public void
  setUp()
  {
    referenceInterest = new Interest();
    try {
      referenceInterest.wireDecode(new Blob(codedInterest, false));
    } catch (EncodingException ex) {
      // We don't expect this to happen.
      referenceInterest = null;
    }
  }

  @Test
  public void
  testDump()
  {
    // see if the dump format is the same as we expect
    ArrayList decodedDump = dumpInterest(referenceInterest);
    assertArrayEquals("Initial dump does not have expected format",
                      initialDump.toArray(), decodedDump.toArray());
  }

  @Test
  public void
  testRedecode()
  {
    // check that we encode and decode correctly
    Blob encoding = referenceInterest.wireEncode();
    Interest reDecodedInterest = new Interest();
    try {
      reDecodedInterest.wireDecode(encoding);
    } catch (EncodingException ex) {
      fail("Can't decode reDecodedInterest");
    }
    ArrayList redecodedDump = dumpInterest(reDecodedInterest);
    assertArrayEquals("Re-decoded interest does not match original",
                      initialDump.toArray(), redecodedDump.toArray());
  }

  @Test
  public void
  testRedecodeImplicitDigestExclude()
  {
    // Check that we encode and decode correctly with an implicit digest exclude.
    Interest interest = new Interest(new Name("/A"));
    interest.getExclude().appendComponent(new Name("/sha256digest=" +
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").get(0));
    ArrayList dump = dumpInterest(interest);

    Blob encoding = interest.wireEncode();
    Interest reDecodedInterest = new Interest();
    try {
      reDecodedInterest.wireDecode(encoding);
    } catch (EncodingException ex) {
      fail("Can't decode reDecodedInterest");
    }
    ArrayList redecodedDump = dumpInterest(reDecodedInterest);
    assertTrue("Re-decoded interest does not match original",
               interestDumpsEqual(dump, redecodedDump));
  }

  @Test
  public void
  testCreateFresh()
  {
    Interest freshInterest = createFreshInterest();
    ArrayList freshDump = dumpInterest(freshInterest);
    assertTrue("Fresh interest does not match original",
               interestDumpsEqual(initialDump, freshDump));

    Interest reDecodedFreshInterest = new Interest();
    try {
      reDecodedFreshInterest.wireDecode(freshInterest.wireEncode());
    } catch (EncodingException ex) {
      fail("Can't decode reDecodedFreshInterest");
    }
    ArrayList reDecodedFreshDump = dumpInterest(reDecodedFreshInterest);

    assertTrue("Redecoded fresh interest does not match original",
               interestDumpsEqual(freshDump, reDecodedFreshDump));
  }

  @Test
  public void
  testCopyConstructor()
  {
    Interest interest = new Interest(referenceInterest);
    assertTrue("Interest constructed as deep copy does not match original",
               interestDumpsEqual(dumpInterest(interest), dumpInterest(referenceInterest)));
  }

  @Test
  public void
  testEmptyNonce()
  {
    // make sure a freshly created interest has no nonce
    Interest freshInterest = createFreshInterest();
    assertTrue("Freshly created interest should not have a nonce",
               freshInterest.getNonce().isNull());
  }

  @Test
  public void
  testSetRemovesNonce()
  {
    // Ensure that changing a value on an interest clears the nonce.
    assertFalse(referenceInterest.getNonce().isNull());
    Interest interest = new Interest(referenceInterest);
    // Change a child object.
    interest.getExclude().clear();
    assertTrue("Interest should not have a nonce after changing fields",
               interest.getNonce().isNull());
  }

  @Test
  public void
  testRefreshNonce()
  {
    Interest interest = new Interest(referenceInterest);
    Blob oldNonce = interest.getNonce();
    assertEquals(4, oldNonce.size());

    interest.refreshNonce();
    assertEquals("The refreshed nonce should be the same size",
                 oldNonce.size(), interest.getNonce().size());
    assertFalse("The refreshed nonce should be different",
               interest.getNonce().equals(oldNonce));
  }

  @Test
  public void
  testExcludeMatches()
  {
    Exclude exclude = new Exclude();
    exclude.appendComponent(new Name("%00%02").get(0));
    exclude.appendAny();
    exclude.appendComponent(new Name("%00%20").get(0));

    Name.Component component;
    component = new Name("%00%01").get(0);
    assertFalse(component.toEscapedString() + " should not match " + exclude.toUri(),
                exclude.matches(component));
    component = new Name("%00%0F").get(0);
    assertTrue(component.toEscapedString() + " should match " + exclude.toUri(),
               exclude.matches(component));
    component = new Name("%00%21").get(0);
    assertFalse(component.toEscapedString() + " should not match " + exclude.toUri(),
                exclude.matches(component));
}

  @Test
  public void
  testVerifyDigestSha256() throws SecurityException
  {
    // Create a KeyChain but we don't need to add keys.
    MemoryIdentityStorage identityStorage = new MemoryIdentityStorage();
    MemoryPrivateKeyStorage privateKeyStorage = new MemoryPrivateKeyStorage();
    KeyChain keyChain = new KeyChain
      (new IdentityManager(identityStorage, privateKeyStorage),
       new SelfVerifyPolicyManager(identityStorage));

    Interest interest = new Interest(new Name("/test/signed-interest"));
    keyChain.signWithSha256(interest);

    VerifyInterestCounter counter = new VerifyInterestCounter();
    keyChain.verifyInterest(interest, counter, counter);
    assertEquals
      ("Signature verification failed", 0, counter.onValidationFailedCallCount_);
    assertEquals
      ("Verification callback was not used", 1, counter.onVerifiedCallCount_);
  }

  @Test
  public void
  testMatchesData() throws EncodingException
  {
    Interest interest = new Interest(new Name("/A"));
    interest.setMinSuffixComponents(2);
    interest.setMaxSuffixComponents(2);
    interest.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    interest.getKeyLocator().setKeyName(new Name("/B"));
    interest.getExclude().appendComponent(new Name.Component("J"));
    interest.getExclude().appendAny();

    Data data = new Data(new Name("/A/D"));
    Sha256WithRsaSignature signature = new Sha256WithRsaSignature();
    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature.getKeyLocator().setKeyName(new Name("/B"));
    data.setSignature(signature);
    assertEquals(true, interest.matchesData(data));

    // Check violating MinSuffixComponents.
    Data data1 = new Data(data);
    data1.setName(new Name("/A"));
    assertEquals(false, interest.matchesData(data1));

    Interest interest1 = new Interest(interest);
    interest1.setMinSuffixComponents(1);
    assertEquals(true, interest1.matchesData(data1));

    // Check violating MaxSuffixComponents.
    Data data2 = new Data(data);
    data2.setName(new Name("/A/E/F"));
    assertEquals(false, interest.matchesData(data2));

    Interest interest2 = new Interest(interest);
    interest2.setMaxSuffixComponents(3);
    assertEquals(true, interest2.matchesData(data2));

    // Check violating PublisherPublicKeyLocator.
    Data data3 = new Data(data);
    Sha256WithRsaSignature signature3 = new Sha256WithRsaSignature();
    signature3.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature3.getKeyLocator().setKeyName(new Name("/G"));
    data3.setSignature(signature3);
    assertEquals(false, interest.matchesData(data3));

    Interest interest3 = new Interest(interest);
    interest3.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    interest3.getKeyLocator().setKeyName(new Name("/G"));
    assertEquals(true, interest3.matchesData(data3));

    Data data4 = new Data(data);
    data4.setSignature(new DigestSha256Signature());
    assertEquals(false, interest.matchesData(data4));

    Interest interest4 = new Interest(interest);
    interest4.setKeyLocator(new KeyLocator());
    assertEquals(true, interest4.matchesData(data4));

    // Check violating Exclude.
    Data data5 = new Data(data);
    data5.setName(new Name("/A/J"));
    assertEquals(false, interest.matchesData(data5));

    Interest interest5 = new Interest(interest);
    interest5.getExclude().clear();
    interest5.getExclude().appendComponent(new Name.Component("K"));
    interest5.getExclude().appendAny();
    assertEquals(true, interest5.matchesData(data5));

    // Check violating Name.
    Data data6 = new Data(data);
    data6.setName(new Name("/H/I"));
    assertEquals(false, interest.matchesData(data6));

    Data data7 = new Data(data);
    data7.setName(new Name("/A/B"));

    Interest interest7 = new Interest
      (new Name("/A/B/sha256digest=" + 
                "54008e240a7eea2714a161dfddf0dd6ced223b3856e9da96792151e180f3b128"));
    assertEquals(true, interest7.matchesData(data7));

    // Check violating the implicit digest.
    Interest interest7b = new Interest
      (new Name("/A/B/%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00" +
                     "%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00"));
    assertEquals(false, interest7b.matchesData(data7));

    // Check excluding the implicit digest.
    Interest interest8 = new Interest(new Name("/A/B"));
    interest8.getExclude().appendComponent(interest7.getName().get(2));
    assertEquals(false, interest8.matchesData(data7));
}

  @Test
  public void
  testInterestFilterMatching()
  {
    // From ndn-cxx interest.t.cpp.
    assertEquals(true,  new InterestFilter("/a").doesMatch(new Name("/a/b")));
    assertEquals(true,  new InterestFilter("/a/b").doesMatch(new Name("/a/b")));
    assertEquals(false, new InterestFilter("/a/b/c").doesMatch(new Name("/a/b")));

    assertEquals(true,  new InterestFilter("/a", "<b>").doesMatch(new Name("/a/b")));
    assertEquals(false, new InterestFilter("/a/b", "<b>").doesMatch(new Name("/a/b")));

    assertEquals(false, new InterestFilter("/a/b", "<c>").doesMatch(new Name("/a/b/c/d")));
    assertEquals(false, new InterestFilter("/a/b", "<b>").doesMatch(new Name("/a/b/c/b")));
    assertEquals(true,  new InterestFilter("/a/b", "<>*<b>").doesMatch(new Name("/a/b/c/b")));

    assertEquals(false, new InterestFilter("/a", "<b>").doesMatch(new Name("/a/b/c/d")));
    assertEquals(true,  new InterestFilter("/a", "<b><>*").doesMatch(new Name("/a/b/c/d")));
    assertEquals(true,  new InterestFilter("/a", "<b><>*").doesMatch(new Name("/a/b")));
    assertEquals(false, new InterestFilter("/a", "<b><>+").doesMatch(new Name("/a/b")));
    assertEquals(true,  new InterestFilter("/a", "<b><>+").doesMatch(new Name("/a/b/c")));
  }
}
