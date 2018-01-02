/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From PyNDN der.py by Adeola Bannis <thecodemaiden@gmail.com>.
 * @author: Originally from code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.encoding.der;

/**
 * The DerNodeType class defines static values for the known DER node types.
 */
public class DerNodeType {
    public static final int Eoc = 0;
    public static final int Boolean = 1;
    public static final int Integer = 2;
    public static final int BitString = 3;
    public static final int OctetString = 4;
    public static final int Null = 5;
    public static final int ObjectIdentifier = 6;
    public static final int ObjectDescriptor = 7;
    public static final int Real = 9;
    public static final int Enumerated = 10;
    public static final int Utf8String = 12;
    public static final int RelativeOid = 13;
    public static final int NumericString = 18;
    public static final int PrintableString = 19;
    public static final int T61String = 20;
    public static final int VideoTexString = 21;
    public static final int Ia5String = 22;
    public static final int UtcTime = 23;
    public static final int GeneralizedTime = 24;
    public static final int GraphicString = 25;
    public static final int VisibleString = 26;
    public static final int GeneralString = 27;
    public static final int UniversalString = 28;
    public static final int CharacterString = 29;
    public static final int BmpString = 30;
    public static final int External = 40;
    public static final int EmbeddedPdv = 43;
    public static final int Sequence = 48;
    public static final int Set = 49;
    public static final int ExplicitlyTagged = 0xa0;
}
