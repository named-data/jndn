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

public abstract class NdnRegexMatcherBase {
  /**
   * NdnRegexMatcherBase.Error extends Exception for errors using
   * NdnRegexMatcherBase methods. Note that even though this is called "Error"
   * to be consistent with the other libraries, it extends the Java Exception
   * class, not Error.
   */
  public static class Error extends Exception {
    public Error(String message)
    {
      super(message);
    }
  }

  public enum NdnRegexExprType {
    TOP,
    PATTERN_LIST,
    REPEAT_PATTERN,
    BACKREF,
    COMPONENT_SET,
    COMPONENT,
    PSEUDO
  }

  public NdnRegexMatcherBase
    (String expr, NdnRegexExprType type, NdnRegexBackrefManager backrefManager)
  {
    expr_ = expr;
    type_ = type;
    backrefManager_ = backrefManager;
  }

  public NdnRegexMatcherBase(String expr, NdnRegexExprType type)
  {
    expr_ = expr;
    type_ = type;
    backrefManager_ = new NdnRegexBackrefManager();
  }

  public boolean
  match(Name name, int offset, int len) throws NdnRegexMatcherBase.Error
  {
    boolean result = false;

    matchResult_.clear();

    if (recursiveMatch(0, name, offset, len)) {
      for (int i = offset; i < offset + len; i++)
        matchResult_.add(name.get(i));
      result = true;
    }
    else
      result = false;

    return result;
  }

  /**
   * Get the list of matched name components.
   * @return The matched name components. You must not modify this list.
   */
  public final ArrayList<Name.Component>
  getMatchResult() { return matchResult_; }

  public final String
  getExpr() { return expr_; }

  /**
   * Compile the regular expression to generate more matchers when necessary.
   */
  protected abstract void
  compile() throws NdnRegexMatcherBase.Error;

  private boolean
  recursiveMatch(int matcherNo, Name name, int offset, int len)
    throws NdnRegexMatcherBase.Error
  {
    int tried = len;

    if (matcherNo >= matchers_.size())
      return (len == 0);

    NdnRegexMatcherBase matcher = matchers_.get(matcherNo);

    while (tried >= 0) {
      if (matcher.match(name, offset, tried) &&
          recursiveMatch(matcherNo + 1, name, offset + tried, len - tried))
        return true;
      --tried;
    }

    return false;
  }

  protected final String expr_;
  protected final NdnRegexExprType type_;
  protected final NdnRegexBackrefManager backrefManager_;
  protected final ArrayList<NdnRegexMatcherBase> matchers_ =
    new ArrayList<NdnRegexMatcherBase>();
  protected final ArrayList<Name.Component> matchResult_ =
     new ArrayList<Name.Component>();
}
