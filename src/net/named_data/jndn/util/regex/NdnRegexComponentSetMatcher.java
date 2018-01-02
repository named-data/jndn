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

import java.util.ArrayList;
import net.named_data.jndn.Name;

public class NdnRegexComponentSetMatcher extends NdnRegexMatcherBase {
  /**
   * Create an NdnRegexComponentSetMatcher matcher from expr.
   * @param expr The standard regular expression to match a component.
   * @param backrefManager A back-reference manager.
   */
  public NdnRegexComponentSetMatcher
    (String expr, NdnRegexBackrefManager backrefManager)
    throws NdnRegexMatcherBase.Error
  {
    super(expr, NdnRegexExprType.COMPONENT_SET, backrefManager);

    compile();
  }

  public boolean
  match(Name name, int offset, int len) throws NdnRegexMatcherBase.Error
  {
    boolean isMatched = false;

    // ComponentSet only matches one component.
    if (len != 1)
      return false;

    for (NdnRegexComponentMatcher matcher : components_) {
      if (matcher.match(name, offset, len)) {
        isMatched = true;
        break;
      }
    }

    matchResult_.clear();

    if (isInclusion_ ? isMatched : !isMatched) {
      matchResult_.add(name.get(offset));
      return true;
    }
    else
      return false;
  }

  /**
   * Compile the regular expression to generate more matchers when necessary.
   */
  protected void
  compile() throws NdnRegexMatcherBase.Error
  {
    if (expr_.length() < 2)
      throw new NdnRegexMatcherBase.Error
        ("Regexp compile error (cannot parse " + expr_ + ")");

    if (expr_.charAt(0) == '<')
      compileSingleComponent();
    else if (expr_.charAt(0) == '[') {
      int lastIndex = expr_.length() - 1;
      if (']' != expr_.charAt(lastIndex))
        throw new NdnRegexMatcherBase.Error
          ("Regexp compile error (no matching ']' in " + expr_ + ")");

      if ('^' == expr_.charAt(1)) {
        isInclusion_ = false;
        compileMultipleComponents(2, lastIndex);
      }
      else
        compileMultipleComponents(1, lastIndex);
    }
    else
      throw new NdnRegexMatcherBase.Error
        ("Regexp compile error (cannot parse " + expr_ + ")");
  }

  private int
  extractComponent(int index) throws NdnRegexMatcherBase.Error
  {
    int lcount = 1;
    int rcount = 0;

    while (lcount > rcount) {
      if (index >= expr_.length())
        throw new NdnRegexMatcherBase.Error("Error: angle brackets mismatch");

      if (expr_.charAt(index) == '<')
        ++lcount;
      else if (expr_.charAt(index) == '>')
        ++rcount;

      ++index;
    }

    return index;
  }

  private void
  compileSingleComponent() throws NdnRegexMatcherBase.Error
  {
    int end = extractComponent(1);

    if (expr_.length() != end)
      throw new NdnRegexMatcherBase.Error("Component expr error " + expr_);
    else {
      NdnRegexComponentMatcher component = new NdnRegexComponentMatcher
        (expr_.substring(1, end - 1), backrefManager_);

      components_.add(component);
    }
  }

  private void
  compileMultipleComponents(int start, int lastIndex)
    throws NdnRegexMatcherBase.Error
  {
    int index = start;
    int tempIndex = start;

    while (index < lastIndex) {
      if ('<' != expr_.charAt(index))
        throw new NdnRegexMatcherBase.Error("Component expr error " + expr_);

      tempIndex = index + 1;
      index = extractComponent(tempIndex);

      NdnRegexComponentMatcher component = new NdnRegexComponentMatcher
        (expr_.substring(tempIndex, index - 1), backrefManager_);

      components_.add(component);
    }

    if (index != lastIndex)
      throw new NdnRegexMatcherBase.Error
        ("Not sufficient expr to parse " + expr_);
  }

  private final ArrayList<NdnRegexComponentMatcher> components_ =
    new ArrayList<NdnRegexComponentMatcher>();
  boolean isInclusion_ = true;
}
