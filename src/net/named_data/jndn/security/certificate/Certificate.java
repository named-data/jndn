/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From PyNDN certificate.py by Adeola Bannis <thecodemaiden@gmail.com>.
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

package net.named_data.jndn.security.certificate;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import net.named_data.jndn.ContentType;
import net.named_data.jndn.Data;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.der.DerEncodingException;
import net.named_data.jndn.encoding.der.DerNode;
import net.named_data.jndn.encoding.der.DerNode.DerBoolean;
import net.named_data.jndn.encoding.der.DerNode.DerGeneralizedTime;
import net.named_data.jndn.encoding.der.DerNode.DerSequence;
import net.named_data.jndn.security.UnrecognizedKeyFormatException;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

public class Certificate extends Data {
  /**
   * The default constructor.
   */
  public Certificate()
  {
  }

  /**
   * Create a Certificate from the content in the data packet.
   * @param data The data packet with the content to decode.
   */
  public Certificate(Data data) throws DerDecodingException
  {
    super(data);
    decode();
  }

  /**
   * Encode the contents of the certificate in DER format and set the Content
   * and MetaInfo fields.
   */
  public final void
  encode() throws DerEncodingException, DerDecodingException
  {
    DerNode root = toDer();
    setContent(root.encode());
    getMetaInfo().setType(ContentType.KEY);
  }

  /**
   * Override to call the base class wireDecode then populate the certificate
   * fields.
   * @param input The input byte array to be decoded as an immutable Blob.
   * @param wireFormat A WireFormat object used to decode the input.
   */
  public void
  wireDecode(Blob input, WireFormat wireFormat)
    throws EncodingException
  {
    super.wireDecode(input, wireFormat);
    try {
      decode();
    } catch (DerDecodingException ex) {
      throw new EncodingException(ex.getMessage());
    }
  }

  /**
   * Add a subject description.
   * @param description The description to be added.
   */
  public final void
  addSubjectDescription(CertificateSubjectDescription description)
  {
    subjectDescriptionList_.add(description);
  }

  // List of CertificateSubjectDescription.
  public final List
  getSubjectDescriptionList()
  {
    return subjectDescriptionList_;
  }

  /**
   * Add a certificate extension.
   * @param extension the extension to be added
   */
  public final void
  addExtension(CertificateExtension extension)
  {
    extensionList_.add(extension);
  }

  // List of CertificateExtension.
  public final List
  getExtensionList()
  {
    return extensionList_;
  }

  public final void
  setNotBefore(double notBefore)
  {
    notBefore_ = notBefore;
  }

  public final double
  getNotBefore()
  {
    return notBefore_;
  }

  public final void
  setNotAfter(double notAfter)
  {
    notAfter_ = notAfter;
  }

  public final double
  getNotAfter()
  {
    return notAfter_;
  }

  public final void
  setPublicKeyInfo(PublicKey key)
  {
    key_ = key;
  }

  public final PublicKey
  getPublicKeyInfo()
  {
    return key_;
  }

  /**
   * Check if the certificate is valid.
   * @return True if the current time is earlier than notBefore.
   */
  public final boolean
  isTooEarly()
  {
    double now = Common.getNowMilliseconds();
    return now < notBefore_;
  }

  /**
   * Check if the certificate is valid.
   * @return True if the current time is later than notAfter.
   */
  public final boolean
  isTooLate()
  {
    double now = Common.getNowMilliseconds();
    return now > notAfter_;
  }

  /**
   * Encode the certificate fields in DER format.
   * @return The DER encoded contents of the certificate.
   */
  private DerSequence
  toDer() throws DerEncodingException, DerDecodingException
  {
    DerSequence root = new DerSequence();
    DerSequence validity = new DerSequence();
    DerGeneralizedTime notBefore = new DerGeneralizedTime(notBefore_);
    DerGeneralizedTime notAfter = new DerGeneralizedTime(notAfter_);

    validity.addChild(notBefore);
    validity.addChild(notAfter);

    root.addChild(validity);

    DerSequence subjectList = new DerSequence();
    for (int i = 0; i < subjectDescriptionList_.size(); ++i)
      subjectList.addChild(((CertificateSubjectDescription)subjectDescriptionList_.get(i)).toDer());

    root.addChild(subjectList);
    root.addChild(key_.toDer());

    if (extensionList_.size() > 0) {
      DerSequence extensionList = new DerSequence();
      for (int i = 0; i < extensionList_.size(); ++i)
        extensionList.addChild(((CertificateExtension)extensionList_.get(i)).toDer());
      root.addChild(extensionList);
    }

    return root;
  }

  /**
   * Populate the fields by the decoding DER data from the Content.
   */
  private void
  decode() throws DerDecodingException
  {
    DerNode parsedNode = DerNode.parse(getContent().buf());

    // We need to ensure that there are:
    //   validity (notBefore, notAfter)
    //   subject list
    //   public key
    //   (optional) extension list

    List rootChildren = parsedNode.getChildren();
    // 1st: validity info
    List validityChildren = DerNode.getSequence(rootChildren, 0).getChildren();
    notBefore_ = (Double)((DerGeneralizedTime)validityChildren.get(0)).toVal();
    notAfter_ = (Double)((DerGeneralizedTime)validityChildren.get(1)).toVal();

    // 2nd: subjectList
    List subjectChildren = DerNode.getSequence(rootChildren, 1).getChildren();
    for (int i = 0; i < subjectChildren.size(); ++i) {
      DerSequence sd = DerNode.getSequence(subjectChildren, i);
      List descriptionChildren = sd.getChildren();
      String oidStr = (String)((DerNode)descriptionChildren.get(0)).toVal();
      String value = "" + ((Blob)((DerNode)descriptionChildren.get(1)).toVal());

      addSubjectDescription(new CertificateSubjectDescription(oidStr, value));
    }

    // 3rd: public key
    Blob publicKeyInfo = ((DerNode)rootChildren.get(2)).encode();
    try {
      key_ = new PublicKey(publicKeyInfo);
    }
    catch (UnrecognizedKeyFormatException ex) {
      throw new DerDecodingException(ex.getMessage());
    }

    if (rootChildren.size() > 3) {
      List extensionChildren = DerNode.getSequence(rootChildren, 3).getChildren();
      for (int i = 0; i < extensionChildren.size(); ++i) {
        DerSequence extInfo = DerNode.getSequence(extensionChildren, i);

        List children = extInfo.getChildren();
        String oidStr = (String)((DerNode)children.get(0)).toVal();
        boolean isCritical = (Boolean)((DerBoolean)children.get(1)).toVal();
        Blob value = (Blob)((DerNode)children.get(2)).toVal();
        addExtension(new CertificateExtension(oidStr, isCritical, value));
      }
    }
  }

  public String
  toString()
  {
    String s = "Certificate name:\n";
    s += "  " + getName().toUri() + "\n";
    s += "Validity:\n";

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    String notBeforeStr = dateFormat.format(new Date((long)Math.round(notBefore_)));
    String notAfterStr = dateFormat.format(new Date((long)Math.round(notAfter_)));

    s += "  NotBefore: " + notBeforeStr + "\n";
    s += "  NotAfter: " + notAfterStr + "\n";
    for (int i = 0; i < subjectDescriptionList_.size(); ++i) {
      CertificateSubjectDescription sd =
        (CertificateSubjectDescription)subjectDescriptionList_.get(i);
      s += "Subject Description:\n";
      s += "  " + sd.getOidString() + ": " + sd.getValue() + "\n";
    }

    s += "Public key bits:\n";
    Blob keyDer = key_.getKeyDer();
    String encodedKey = Common.base64Encode(keyDer.getImmutableArray());
    for (int i = 0; i < encodedKey.length(); i += 64)
      s += encodedKey.substring(i, Math.min(i + 64, encodedKey.length())) + "\n";

    if (extensionList_.size() > 0) {
      s += "Extensions:\n";
      for (int i = 0; i < extensionList_.size(); ++i) {
        CertificateExtension ext = (CertificateExtension)extensionList_.get(i);
        s += "  OID: " + ext.getOid() + "\n";
        s += "  Is critical: " + (ext.getIsCritical() ? 'Y' : 'N') + "\n";

        s += "  Value: " + ext.getValue().toHex() + "\n" ;
      }
    }

    return s;
  }

  // Use ArrayList without generics so it works with older Java compilers.
  private final ArrayList subjectDescriptionList_ = new ArrayList(); // of CertificateSubjectDescription
  private final ArrayList extensionList_ = new ArrayList();          // of CertificateExtension
  private double notBefore_ = Double.MAX_VALUE; // MillisecondsSince1970
  private double notAfter_ = -Double.MAX_VALUE; // MillisecondsSince1970
  private PublicKey key_ = new PublicKey();
}
