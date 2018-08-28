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

public class NdnRegexPatternListMatcher extends NdnRegexMatcherBase {
  public NdnRegexPatternListMatcher
    (String expr, NdnRegexBackrefManager backrefManager)
    throws NdnRegexMatcherBase.Error
  {
    super(expr, NdnRegexExprType.PATTERN_LIST, backrefManager);

    compile();
  }

  protected void
  compile() throws NdnRegexMatcherBase.Error
  {
    int len = expr_.length();
    int[] index = new int[] { 0 };
    int subHead = index[0];

    while (index[0] < len) {
      subHead = index[0];

      if (!extractPattern(subHead, index))
        throw new NdnRegexMatcherBase.Error("Compile error");
    }
  }

  private boolean
  extractPattern(int index, int[] next) throws NdnRegexMatcherBase.Error
  {
    int start = index;
    int end = index;
    int indicator = index;

    if (expr_.charAt(index) == '(') {
      ++index;
      index = extractSubPattern('(', ')', index);
      indicator = index;
      end = extractRepetition(index);
      if (indicator == end) {
        NdnRegexMatcherBase matcher = new NdnRegexBackrefMatcher
            (expr_.substring(start, end), backrefManager_);
        backrefManager_.pushRef(matcher);
        ((NdnRegexBackrefMatcher)matcher).lateCompile();

        matchers_.add(matcher);
      }
      else
        matchers_.add(new NdnRegexRepeatMatcher
          (expr_.substring(start, end), backrefManager_, indicator - start));
    }
    else if (expr_.charAt(index) == '<') {
      ++index;
      index = extractSubPattern('<', '>', index);
      indicator = index;
      end = extractRepetition(index);
      matchers_.add(new NdnRegexRepeatMatcher
        (expr_.substring(start, end), backrefManager_, indicator - start));
    }
    else if (expr_.charAt(index) == '[') {
      ++index;
      index = extractSubPattern('[', ']', index);
      indicator = index;
      end = extractRepetition(index);
      matchers_.add(new NdnRegexRepeatMatcher
        (expr_.substring(start, end), backrefManager_, indicator - start));
    }
    else
      throw new NdnRegexMatcherBase.Error("Unexpected syntax");

    next[0] = end;

    return true;
  }

  private int
  extractSubPattern(char left, char right, int index)
    throws NdnRegexMatcherBase.Error
  {
    int lcount = 1;
    int rcount = 0;

    while (lcount > rcount) {
      if (index >= expr_.length())
        throw new NdnRegexMatcherBase.Error("Parenthesis mismatch");

      if (left == expr_.charAt(index))
        lcount++;

      if (right == expr_.charAt(index))
        rcount++;

      ++index;
    }

    return index;
  }

  private int
  extractRepetition(int index) throws Error
  {
    int exprSize = expr_.length();

    if (index == exprSize)
      return index;

    if ('+' == expr_.charAt(index) || '?' == expr_.charAt(index) ||
        '*' == expr_.charAt(index))
      return ++index;

    if ('{' == expr_.charAt(index)) {
      while ('}' != expr_.charAt(index)) {
        index++;
        if (index == exprSize)
          break;
      }
      if (index == exprSize)
        throw new NdnRegexMatcherBase.Error("Missing right brace bracket");
      else
        return ++index;
    }
    else
      return index;
  }
}
