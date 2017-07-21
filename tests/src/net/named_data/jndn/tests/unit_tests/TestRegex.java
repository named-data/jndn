/**
 * Copyright (C) 2014-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx Regex unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/util/regex.t.cpp
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

import net.named_data.jndn.Name;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.regex.NdnRegexBackrefManager;
import net.named_data.jndn.util.regex.NdnRegexBackrefMatcher;
import net.named_data.jndn.util.regex.NdnRegexComponentMatcher;
import net.named_data.jndn.util.regex.NdnRegexComponentSetMatcher;
import net.named_data.jndn.util.regex.NdnRegexMatcherBase;
import net.named_data.jndn.util.regex.NdnRegexPatternListMatcher;
import net.named_data.jndn.util.regex.NdnRegexRepeatMatcher;
import net.named_data.jndn.util.regex.NdnRegexTopMatcher;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class TestRegex {
  @Test
  public void
  testComponentMatcher() throws NdnRegexMatcherBase.Error
  {
    NdnRegexBackrefManager backRef = new NdnRegexBackrefManager();
    NdnRegexComponentMatcher cm = new NdnRegexComponentMatcher("a", backRef);
    boolean res = cm.match(new Name("/a/b/"), 0, 1);
    assertEquals(true, res);
    assertEquals(1, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexComponentMatcher("a", backRef);
    res = cm.match(new Name("/a/b/"), 1, 1);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexComponentMatcher("(c+)\\.(cd)", backRef);
    res = cm.match(new Name("/ccc.cd/b/"), 0, 1);
    assertEquals(true, res);
    assertEquals(1, cm.getMatchResult().size());
    assertEquals("ccc.cd", cm.getMatchResult().get(0).toEscapedString());

    assertEquals(2, backRef.size());
    assertEquals("ccc", backRef.getBackref(0).getMatchResult().get(0).toEscapedString());
    assertEquals("cd", backRef.getBackref(1).getMatchResult().get(0).toEscapedString());
  }

  @Test
  public void
  testComponentSetMatcher() throws NdnRegexMatcherBase.Error
  {
    NdnRegexBackrefManager backRef = new NdnRegexBackrefManager();
    NdnRegexComponentSetMatcher cm = new NdnRegexComponentSetMatcher
      ("<a>", backRef);
    boolean res = cm.match(new Name("/a/b/"), 0, 1);
    assertEquals(true, res);
    assertEquals(1, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());

    res = cm.match(new Name("/a/b/"), 1, 1);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    res = cm.match(new Name("/a/b/"), 0, 2);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexComponentSetMatcher("[<a><b><c>]", backRef);
    res = cm.match(new Name("/a/b/d"), 1, 1);
    assertEquals(true, res);
    assertEquals(1, cm.getMatchResult().size());
    assertEquals("b", cm.getMatchResult().get(0).toEscapedString());

    res = cm.match(new Name("/a/b/d"), 2, 1);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexComponentSetMatcher("[^<a><b><c>]", backRef);
    res = cm.match(new Name("/b/d"), 1, 1);
    assertEquals(true, res);
    assertEquals(1, cm.getMatchResult().size());
    assertEquals("d", cm.getMatchResult().get(0).toEscapedString());
  }

  @Test
  public void
  testRepeatMatcher() throws NdnRegexMatcherBase.Error
  {
    NdnRegexBackrefManager backRef = new NdnRegexBackrefManager();
    NdnRegexRepeatMatcher cm = new NdnRegexRepeatMatcher
      ("[<a><b>]*", backRef, 8);
    boolean res = cm.match(new Name("/a/b/c"), 0, 0);
    assertEquals(true, res);
    assertEquals(0, cm.getMatchResult().size());

    cm.match(new Name("/a/b/c"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]+", backRef, 8);
    res = cm.match(new Name("/a/b/c"), 0, 0);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    res = cm.match(new Name("/a/b/c"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("<.*>*", backRef, 4);
    res = cm.match(new Name("/a/b/c/d/e/f/"), 0, 6);
    assertEquals(true, res);
    assertEquals(6, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
    assertEquals("d", cm.getMatchResult().get(3).toEscapedString());
    assertEquals("e", cm.getMatchResult().get(4).toEscapedString());
    assertEquals("f", cm.getMatchResult().get(5).toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("<>*", backRef, 2);
    res = cm.match(new Name("/a/b/c/d/e/f/"), 0, 6);
    assertEquals(true, res);
    assertEquals(6, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
    assertEquals("d", cm.getMatchResult().get(3).toEscapedString());
    assertEquals("e", cm.getMatchResult().get(4).toEscapedString());
    assertEquals("f", cm.getMatchResult().get(5).toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("<a>?", backRef, 3);
    res = cm.match(new Name("/a/b/c"), 0, 0);
    assertEquals(true, res);
    assertEquals(0, cm.getMatchResult().size());

    cm = new NdnRegexRepeatMatcher("<a>?", backRef, 3);
    res = cm.match(new Name("/a/b/c"), 0, 1);
    assertEquals(true, res);
    assertEquals(1, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());

    cm = new NdnRegexRepeatMatcher("<a>?", backRef, 3);
    res = cm.match(new Name("/a/b/c"), 0, 2);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]{3}", backRef, 8);
    res = cm.match(new Name("/a/b/a/d/"), 0, 2);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    res = cm.match(new Name("/a/b/a/d/"), 0, 3);
    assertEquals(true, res);
    assertEquals(3, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("a", cm.getMatchResult().get(2).toEscapedString());

    res = cm.match(new Name("/a/b/a/d/"), 0, 4);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]{2,3}", backRef, 8);
    res = cm.match(new Name("/a/b/a/d/e/"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 3);
    assertEquals(true, res);
    assertEquals(3, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("a", cm.getMatchResult().get(2).toEscapedString());

    res = cm.match(new Name("/a/b/a/b/e/"), 0, 4);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 1);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]{2,}", backRef, 8);
    res = cm.match(new Name("/a/b/a/d/e/"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());

    res = cm.match(new Name("/a/b/a/b/e/"), 0, 4);
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("a", cm.getMatchResult().get(2).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(3).toEscapedString());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 1);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexRepeatMatcher("[<a><b>]{,2}", backRef, 8);
    res = cm.match(new Name("/a/b/a/b/e/"), 0, 3);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    res = cm.match(new Name("/a/b/a/b/e/"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 1);
    assertEquals(true, res);
    assertEquals(1, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());

    res = cm.match(new Name("/a/b/a/d/e/"), 0, 0);
    assertEquals(true, res);
    assertEquals(0, cm.getMatchResult().size());
  }

  @Test
  public void
  testBackRefMatcher() throws NdnRegexMatcherBase.Error
  {
    NdnRegexBackrefManager backRef = new NdnRegexBackrefManager();
    NdnRegexBackrefMatcher cm = new NdnRegexBackrefMatcher
      ("(<a><b>)", backRef);
    backRef.pushRef(cm);
    cm.lateCompile();
    boolean res = cm.match(new Name("/a/b/c"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals(1, backRef.size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexBackrefMatcher("(<a>(<b>))", backRef);
    backRef.pushRef(cm);
    cm.lateCompile();
    res = cm.match(new Name("/a/b/c"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals(2, backRef.size());
    assertEquals("a", backRef.getBackref(0).getMatchResult().get(0).toEscapedString());
    assertEquals("b", backRef.getBackref(0).getMatchResult().get(1).toEscapedString());
    assertEquals("b", backRef.getBackref(1).getMatchResult().get(0).toEscapedString());
  }

  @Test
  public void
  testBackRefMatcherAdvanced() throws NdnRegexMatcherBase.Error
  {
    NdnRegexBackrefManager backRef = new NdnRegexBackrefManager();
    NdnRegexRepeatMatcher cm = new NdnRegexRepeatMatcher
      ("([<a><b>])+", backRef, 10);
    boolean res = cm.match(new Name("/a/b/c"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals(1, backRef.size());
    assertEquals("b", backRef.getBackref(0).getMatchResult().get(0).toEscapedString());
  }

  @Test
  public void
  testBackRefMatcherAdvanced2() throws NdnRegexMatcherBase.Error
  {
    NdnRegexBackrefManager backRef =
      new NdnRegexBackrefManager();
    NdnRegexPatternListMatcher cm = new NdnRegexPatternListMatcher
      ("(<a>(<b>))<c>", backRef);
    boolean res = cm.match(new Name("/a/b/c"), 0, 3);
    assertEquals(true, res);
    assertEquals(3, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
    assertEquals(2, backRef.size());
    assertEquals("a", backRef.getBackref(0).getMatchResult().get(0).toEscapedString());
    assertEquals("b", backRef.getBackref(0).getMatchResult().get(1).toEscapedString());
    assertEquals("b", backRef.getBackref(1).getMatchResult().get(0).toEscapedString());
  }

  @Test
  public void
  testPatternListMatcher() throws NdnRegexMatcherBase.Error
  {
    NdnRegexBackrefManager backRef = new NdnRegexBackrefManager();
    NdnRegexPatternListMatcher cm = new NdnRegexPatternListMatcher
      ("<a>[<a><b>]", backRef);
    boolean res = cm.match(new Name("/a/b/c"), 0, 2);
    assertEquals(true, res);
    assertEquals(2, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexPatternListMatcher("<>*<a>", backRef);
    res = cm.match(new Name("/a/b/c"), 0, 1);
    assertEquals(true, res);
    assertEquals(1, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexPatternListMatcher("<>*<a>", backRef);
    res = cm.match(new Name("/a/b/c"), 0, 2);
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    backRef = new NdnRegexBackrefManager();
    cm = new NdnRegexPatternListMatcher("<>*<a><>*", backRef);
    res = cm.match(new Name("/a/b/c"), 0, 3);
    assertEquals(true, res);
    assertEquals(3, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
  }

  @Test
  public void
  testTopMatcher() throws NdnRegexMatcherBase.Error
  {
    NdnRegexTopMatcher cm = new NdnRegexTopMatcher("^<a><b><c>");
    boolean res = cm.match(new Name("/a/b/c/d"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
    assertEquals("d", cm.getMatchResult().get(3).toEscapedString());

    cm = new NdnRegexTopMatcher("<b><c><d>$");
    res = cm.match(new Name("/a/b/c/d"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
    assertEquals("d", cm.getMatchResult().get(3).toEscapedString());

    cm = new NdnRegexTopMatcher("^<a><b><c><d>$");
    res = cm.match(new Name("/a/b/c/d"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
    assertEquals("d", cm.getMatchResult().get(3).toEscapedString());

    res = cm.match(new Name("/a/b/c/d/e"));
    assertEquals(false, res);
    assertEquals(0, cm.getMatchResult().size());

    cm = new NdnRegexTopMatcher("<a><b><c><d>");
    res = cm.match(new Name("/a/b/c/d"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
    assertEquals("d", cm.getMatchResult().get(3).toEscapedString());

    cm = new NdnRegexTopMatcher("<b><c>");
    res = cm.match(new Name("/a/b/c/d"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals("a", cm.getMatchResult().get(0).toEscapedString());
    assertEquals("b", cm.getMatchResult().get(1).toEscapedString());
    assertEquals("c", cm.getMatchResult().get(2).toEscapedString());
    assertEquals("d", cm.getMatchResult().get(3).toEscapedString());
  }

  @Test
  public void
  testTopMatcherAdvanced() throws NdnRegexMatcherBase.Error
  {
    NdnRegexTopMatcher cm = new NdnRegexTopMatcher("^(<.*>*)<.*>");
    boolean res = cm.match(new Name("/n/a/b/c"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals(new Name("/n/a/b/"), cm.expand("\\1"));

    cm = new NdnRegexTopMatcher("^(<.*>*)<.*><c>(<.*>)<.*>");
    res = cm.match(new Name("/n/a/b/c/d/e/"));
    assertEquals(true, res);
    assertEquals(6, cm.getMatchResult().size());
    assertEquals(new Name("/n/a/d/"), cm.expand("\\1\\2"));

    cm = new NdnRegexTopMatcher("(<.*>*)<.*>$");
    res = cm.match(new Name("/n/a/b/c/"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals(new Name("/n/a/b/"), cm.expand("\\1"));

    cm = new NdnRegexTopMatcher("<.*>(<.*>*)<.*>$");
    res = cm.match(new Name("/n/a/b/c/"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals(new Name("/a/b/"), cm.expand("\\1"));

    cm = new NdnRegexTopMatcher("<a>(<>*)<>$");
    res = cm.match(new Name("/n/a/b/c/"));
    assertEquals(true, res);
    assertEquals(4, cm.getMatchResult().size());
    assertEquals(new Name("/b/"), cm.expand("\\1"));

    cm = new NdnRegexTopMatcher("^<ndn><(.*)\\.(.*)><DNS>(<>*)<>");
    res = cm.match(new Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"));
    assertEquals(true, res);
    assertEquals(6, cm.getMatchResult().size());
    assertEquals(new Name("/ndn/edu/ucla/yingdi/mac/"), cm.expand("<ndn>\\2\\1\\3"));

    cm = new NdnRegexTopMatcher
      ("^<ndn><(.*)\\.(.*)><DNS>(<>*)<>", "<ndn>\\2\\1\\3");
    res = cm.match(new Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"));
    assertEquals(true, res);
    assertEquals(6, cm.getMatchResult().size());
    assertEquals(new Name("/ndn/edu/ucla/yingdi/mac/"), cm.expand());
  }

  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}