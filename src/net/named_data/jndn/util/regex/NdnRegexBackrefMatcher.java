/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
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

package net.named_data.jndn.util.regex;

public class NdnRegexBackrefMatcher extends NdnRegexMatcherBase {
  public NdnRegexBackrefMatcher
    (String expr, NdnRegexBackrefManager backrefManager)
  {
    super(expr, NdnRegexExprType.BACKREF, backrefManager);
  }

  public final void
  lateCompile() throws Error
  {
    compile();
  }

  protected void
  compile() throws NdnRegexMatcherBase.Error
  {
    if (expr_.length() < 2)
      throw new NdnRegexMatcherBase.Error("Unrecognized format: " + expr_);

    int lastIndex = expr_.length() - 1;
    if ('(' == expr_.charAt(0) && ')' == expr_.charAt(lastIndex)) {
      NdnRegexMatcherBase matcher = new NdnRegexPatternListMatcher
        (expr_.substring(1, lastIndex), backrefManager_);
      matchers_.add(matcher);
    }
    else
      throw new NdnRegexMatcherBase.Error("Unrecognized format: " + expr_);
  }
}
