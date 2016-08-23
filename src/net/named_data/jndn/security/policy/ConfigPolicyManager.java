/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN config_policy_manager.py by Adeola Bannis.
 * Originally from Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>.
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

package net.named_data.jndn.security.policy;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.Signature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnVerifiedInterest;
import net.named_data.jndn.security.OnVerifyFailed;
import net.named_data.jndn.security.OnVerifyInterestFailed;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.ValidationRequest;
import net.named_data.jndn.security.certificate.Certificate;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.BoostInfoParser;
import net.named_data.jndn.util.BoostInfoTree;
import net.named_data.jndn.util.NdnRegexMatcher;
import net.named_data.jndn.util.Common;
import net.named_data.jndn.util.SignedBlob;

/**
 * A ConfigPolicyManager manages trust according to a configuration file in the
 * Validator Configuration File Format
 * (http://redmine.named-data.net/projects/ndn-cxx/wiki/CommandValidatorConf)
 *
 * Once a rule is matched, the ConfigPolicyManager looks in the
 * CertificateCache for the IdentityCertificate matching the name in the KeyLocator
 * and uses its public key to verify the data packet or signed interest. If the
 * certificate can't be found, it is downloaded, verified and installed. A chain
 * of certificates will be followed to a maximum depth.
 * If the new certificate is accepted, it is used to complete the verification.
 *
 * The KeyLocators of data packets and signed interests MUST contain a name for
 * verification to succeed.
 */
public class ConfigPolicyManager extends PolicyManager {
  /**
   * Create a new ConfigPolicyManager which will act on the rules specified in
   * the configuration and download unknown certificates when necessary.
   * @param configFileName (optional) If not null or empty, the path to the
   * configuration file containing verification rules. Otherwise, you should
   * separately call load().
   * @param certificateCache (optional) A CertificateCache to hold known
   * certificates. If this is null or omitted, then create an internal
   * CertificateCache.
   * @param searchDepth (optional) The maximum number of links to follow when
   * verifying a certificate chain.
   * @param graceInterval (optional) The window of time difference (in milliseconds)
   * allowed between the timestamp of the first interest signed with a new
   * public key and the validation time. If omitted, use a default value.
   * @param keyTimestampTtl (optional) How long a public key's last-used
   * timestamp is kept in the store (milliseconds). If omitted, use a default
   * value.
   * @param maxTrackedKeys The maximum number of public key use timestamps to
   * track.
   */
  public ConfigPolicyManager
    (String configFileName, CertificateCache certificateCache, int searchDepth,
     double graceInterval, double keyTimestampTtl, int maxTrackedKeys)
       throws IOException, SecurityException
  {
    certificateCache_ = certificateCache;
    maxDepth_ = searchDepth;
    keyGraceInterval_ = graceInterval;
    keyTimestampTtl_ = keyTimestampTtl;
    maxTrackedKeys_ = maxTrackedKeys;

    if (configFileName != null && !configFileName.equals(""))
      load(configFileName);
  }

  public ConfigPolicyManager
    (String configFileName, CertificateCache certificateCache, int searchDepth,
     double graceInterval, double keyTimestampTtl) throws IOException, SecurityException
  {
    certificateCache_ = certificateCache;
    maxDepth_ = searchDepth;
    keyGraceInterval_ = graceInterval;
    keyTimestampTtl_ = keyTimestampTtl;

    if (configFileName != null && !configFileName.equals(""))
      load(configFileName);
  }

  public ConfigPolicyManager
    (String configFileName, CertificateCache certificateCache, int searchDepth,
     double graceInterval) throws IOException, SecurityException
  {
    certificateCache_ = certificateCache;
    maxDepth_ = searchDepth;
    keyGraceInterval_ = graceInterval;

    if (configFileName != null && !configFileName.equals(""))
      load(configFileName);
  }

  public ConfigPolicyManager
    (String configFileName, CertificateCache certificateCache, int searchDepth)
      throws IOException, SecurityException
  {
    certificateCache_ = certificateCache;
    maxDepth_ = searchDepth;

    if (configFileName != null && !configFileName.equals(""))
      load(configFileName);
  }

  public ConfigPolicyManager
    (String configFileName, CertificateCache certificateCache)
      throws IOException, SecurityException
  {
    certificateCache_ = certificateCache;

    if (configFileName != null && !configFileName.equals(""))
      load(configFileName);
  }

  public ConfigPolicyManager(String configFileName)
    throws IOException, SecurityException
  {
    if (configFileName != null && !configFileName.equals(""))
      load(configFileName);
  }

  /**
   * Create a new ConfigPolicyManager which will act on the rules specified in
   * the configuration and download unknown certificates when necessary. Use
   * default parameter values. You must call load().
   */
  public ConfigPolicyManager()
  {
  }

  /**
   * Reset the certificate cache and other fields to the constructor state.
   */
  public final void
  reset()
  {
    certificateCache_.reset();
    fixedCertificateCache_.clear();
    keyTimestamps_.clear();
    requiresVerification_ = true;
    config_ = new BoostInfoParser();
    refreshManager_ = new TrustAnchorRefreshManager();
  }

  /**
   * Call reset() and load the configuration rules from the file.
   * @param configFileName The path to the configuration file containing the
   * verification rules.
   */
  public final void
  load(String configFileName) throws IOException, SecurityException
  {
    reset();
    config_.read(configFileName);
    loadTrustAnchorCertificates();
  }

  /**
   * Call reset() and load the configuration rules from the input.
   * @param input The contents of the configuration rules, with lines separated
   * by "\n" or "\r\n".
   * @param inputName Used for log messages, etc.
   */
  public void
  load(String input, String inputName) throws IOException, SecurityException
  {
    reset();
    config_.read(input, inputName);
    loadTrustAnchorCertificates();
  }

  /**
   * Check if the received data packet can escape from verification and be
   * trusted as valid. If the configuration file contains the trust anchor
   * 'any', nothing is verified.
   * @param data The received data packet.
   * @return true if the data does not need to be verified to be trusted as
   * valid, otherwise false.
   */
  public final boolean
  skipVerifyAndTrust(Data data)
  {
    return !requiresVerification_;
  }

  /**
   * Check if the received signed interest can escape from verification and be
   * trusted as valid. If the configuration file contains the trust anchor
   * 'any', nothing is verified.
   * @param interest The received interest.
   * @return true if the interest does not need to be verified to be trusted as
   * valid, otherwise false.
   */
  public final boolean
  skipVerifyAndTrust(Interest interest)
  {
    return !requiresVerification_;
  }

  /**
   * Check if this PolicyManager has a verification rule for the received data.
   * If the configuration file contains the trust anchor 'any', nothing is
   * verified.
   * @param data The received data packet.
   * @return true if the data must be verified, otherwise false.
   */
  public final boolean
  requireVerify(Data data)
  {
    return requiresVerification_;
  }

  /**
   * Check if this PolicyManager has a verification rule for the received signed
   * interest.
   * If the configuration file contains the trust anchor 'any', nothing is
   * verified.
   * @param interest The received interest.
   * @return true if the interest must be verified, otherwise false.
   */
  public final boolean
  requireVerify(Interest interest)
  {
    return requiresVerification_;
  }

  /**
   * Check whether the received data packet complies with the verification policy,
   * and get the indication of the next verification step.
   * @param data The Data object with the signature to check.
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress.
   * @param onVerified If the signature is verified, this calls
   * onVerified.onVerified(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onVerifyFailed If the signature check fails, this calls
   * onVerifyFailed.onVerifyFailed(data).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return the indication of next verification step, null if there is no
   * further step.
   */
  public final ValidationRequest
  checkVerificationPolicy
    (Data data, int stepCount, OnVerified onVerified,
     OnVerifyFailed onVerifyFailed) throws SecurityException
  {
    Interest certificateInterest = getCertificateInterest
      (stepCount, "data", data.getName(), data.getSignature());
    if (certificateInterest == null) {
      try {
        onVerifyFailed.onVerifyFailed(data);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onVerifyFailed", ex);
      }
      return null;
    }

    if (certificateInterest.getName().size() > 0)
      return new ValidationRequest
        (certificateInterest,
         new OnCertificateDownloadComplete
           (data, stepCount, onVerified, onVerifyFailed),
         onVerifyFailed, 2, stepCount + 1);
    else {
      // Certificate is known. Verify the signature.
      // wireEncode returns the cached encoding if available.
      if (verify(data.getSignature(), data.wireEncode())) {
        try {
          onVerified.onVerified(data);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onVerified", ex);
        }
      }
      else {
        try {
          onVerifyFailed.onVerifyFailed(data);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onVerifyFailed", ex);
        }
      }

      return null;
    }
  }

  /**
   * Check whether the received signed interest complies with the verification
   * policy, and get the indication of the next verification step.
   * @param interest The interest with the signature to check.
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress.
   * @param onVerified If the signature is verified, this calls onVerified(interest).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onVerifyFailed If the signature check fails, this calls
   * onVerifyFailed(interest).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return the indication of next verification step, null if there is no
   * further step.
   */
  public final ValidationRequest
  checkVerificationPolicy
    (Interest interest, int stepCount, OnVerifiedInterest onVerified,
     OnVerifyInterestFailed onVerifyFailed, WireFormat wireFormat) throws SecurityException
  {
    Signature signature = extractSignature(interest, wireFormat);
    if (signature == null) {
      // Can't get the signature from the interest name.
      try {
        onVerifyFailed.onVerifyInterestFailed(interest);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onVerifyInterestFailed", ex);
      }
      return null;
    }

    // For command interests, we need to ignore the last 4 components when
    //   matching the name.
    Interest certificateInterest = getCertificateInterest
      (stepCount, "interest", interest.getName().getPrefix(-4), signature);
    if (certificateInterest == null) {
      try {
        onVerifyFailed.onVerifyInterestFailed(interest);
      } catch (Throwable ex) {
        logger_.log(Level.SEVERE, "Error in onVerifyInterestFailed", ex);
      }
      return null;
    }

    if (certificateInterest.getName().size() > 0)
      return new ValidationRequest
        (certificateInterest,
         new OnCertificateDownloadCompleteForInterest
            (interest, stepCount, onVerified, onVerifyFailed, wireFormat),
         new OnVerifyInterestFailedWrapper(onVerifyFailed, interest),
         2, stepCount + 1);
    else {
      // For interests, we must check that the timestamp is fresh enough.
      // This is done after (possibly) downloading the certificate to avoid filling
      // the cache with bad keys.
      Name signatureName = KeyLocator.getFromSignature(signature).getKeyName();
      Name keyName = IdentityCertificate.certificateNameToPublicKeyName(signatureName);
      double timestamp = interest.getName().get(-4).toNumber();

      if (!interestTimestampIsFresh(keyName, timestamp)) {
        try {
          onVerifyFailed.onVerifyInterestFailed(interest);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onVerifyInterestFailed", ex);
        }
        return null;
      }

      // Certificate is known. Verify the signature.
      // wireEncode returns the cached encoding if available.
      if (verify(signature, interest.wireEncode())) {
        try {
          onVerified.onVerifiedInterest(interest);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onVerifiedInterest", ex);
        }
        updateTimestampForKey(keyName, timestamp);
      }
      else {
        try {
          onVerifyFailed.onVerifyInterestFailed(interest);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onVerifyInterestFailed", ex);
        }
      }

      return null;
    }
  }

  /**
   * Override to always indicate that the signing certificate name and data name
   * satisfy the signing policy.
   * @param dataName The name of data to be signed.
   * @param certificateName The name of signing certificate.
   * @return true to indicate that the signing certificate can be used to sign
   * the data.
   */
  public final boolean
  checkSigningPolicy(Name dataName, Name certificateName)
  {
    return true;
  }

  /**
   * Infer the signing identity name according to the policy. If the signing
   * identity cannot be inferred, return an empty name.
   * @param dataName The name of data to be signed.
   * @return The signing identity or an empty name if cannot infer.
   */
  public final Name
  inferSigningIdentity(Name dataName)
  {
    throw new UnsupportedOperationException
      ("ConfigPolicyManager::inferSigningIdentity is not implemented");
  }

  /**
   * TrustAnchorRefreshManager manages the trust-anchor certificates, including
   *   refresh.
   */
  private static class TrustAnchorRefreshManager {
    public static IdentityCertificate
    loadIdentityCertificateFromFile(String filename) throws SecurityException
    {
      StringBuilder encodedData = new StringBuilder();

      try {
        BufferedReader certFile = new BufferedReader(new FileReader(filename));
        // Use "try/finally instead of "try-with-resources" or "using"
        // which are not supported before Java 7.
        try {
          String line;
          while ((line = certFile.readLine()) != null)
            encodedData.append(line);
        } finally {
          certFile.close();
        }
      } catch (FileNotFoundException ex) {
        throw new SecurityException("Can't find IdentityCertificate file "
          + filename + ": " + ex.getMessage());
      } catch (IOException ex) {
        throw new SecurityException("Error reading IdentityCertificate file "
          + filename + ": " + ex.getMessage());
      }

      byte[] decodedData = Common.base64Decode(encodedData.toString());
      IdentityCertificate cert = new IdentityCertificate();
      try {
        cert.wireDecode(new Blob(decodedData, false));
      } catch (EncodingException ex) {
        throw new SecurityException("Can't decode the IdentityCertificate from file "
          + filename + ": " + ex.getMessage());
      }
      return cert;
    }

    public IdentityCertificate
    getCertificate(Name certificateName)
    {
      // Assume the timestamp is already removed.
      return certificateCache_.getCertificate(certificateName);
    }

    public void
    addDirectory(String directoryName, double refreshPeriod) throws SecurityException
    {
      File[] allFiles = new File(directoryName).listFiles();
      if (allFiles == null)
        throw new SecurityException
          ("Cannot find files in directory " + directoryName);

      // Use ArrayList without generics so it works with older Java compilers.
      ArrayList certificateNames = new ArrayList();
      for (int i = 0; i < allFiles.length; ++i) {
        File file = allFiles[i];

        IdentityCertificate cert;
        try {
          cert = loadIdentityCertificateFromFile(file.getAbsolutePath());
        }
        catch (SecurityException ex) {
          // Allow files that are not certificates.
          continue;
        }

        // Cut off the timestamp so it matches KeyLocator Name format.
        String certUri = cert.getName().getPrefix(-1).toUri();
        certificateCache_.insertCertificate(cert);
        certificateNames.add(certUri);
      }

      refreshDirectories_.put
        (directoryName, new DirectoryInfo
          (certificateNames, Common.getNowMilliseconds() + refreshPeriod,
           refreshPeriod));
    }

    public void
    refreshAnchors() throws SecurityException
    {
      double refreshTime = Common.getNowMilliseconds();

      // We will modify refreshDirectories_ in the loop, so copy its keys.
      Object[] directories = refreshDirectories_.keySet().toArray();
      for (int iDirectory = 0; iDirectory < directories.length; ++iDirectory) {
        String directory = (String)directories[iDirectory];
        DirectoryInfo info = (DirectoryInfo)refreshDirectories_.get(directory);

        double nextRefreshTime = info.nextRefresh_;
        if (nextRefreshTime <= refreshTime) {
          ArrayList certificateList = (ArrayList)info.certificateNames_.clone();

          // Delete the certificates associated with this directory if possible
          //   then re-import.
          // IdentityStorage subclasses may not support deletion.
          for (int i = 0; i < certificateList.size(); ++i)
            certificateCache_.deleteCertificate
              (new Name((String)certificateList.get(i)));

          addDirectory(directory, info.refreshPeriod_);
        }
      }
    }

    private static class DirectoryInfo {
      public DirectoryInfo
        (ArrayList certificateNames, double nextRefresh, double refreshPeriod)
      {
        certificateNames_ = certificateNames;
        nextRefresh_ = nextRefresh;
        refreshPeriod_ = refreshPeriod;
      }

      ArrayList certificateNames_; // of String.
      double nextRefresh_;
      double refreshPeriod_;
    };

    private final CertificateCache certificateCache_ = new CertificateCache();
    // refreshDirectories_ maps the directory name to a DirectoryInfo of
    // the certificate names so they can be deleted when necessary, and the
    // next refresh time.
    // Use HashMap without generics so it works with older Java compilers.
    private final HashMap refreshDirectories_ = new HashMap();
  };

  /**
   * The configuration file allows 'trust anchor' certificates to be preloaded.
   * The certificates may also be loaded from a directory, and if the 'refresh'
   * option is set to an interval, the certificates are reloaded at the
   * specified interval
   */
  private void
  loadTrustAnchorCertificates() throws SecurityException
  {
    ArrayList anchors = config_.getRoot().get("validator/trust-anchor");

    for (int i = 0; i < anchors.size(); ++i) {
      BoostInfoTree anchor = (BoostInfoTree)anchors.get(i);

      String typeName = anchor.getFirstValue("type");
      boolean isPath = false;
      String certID = null;
      if (typeName.equals("file")) {
        certID = anchor.getFirstValue("file-name");
        isPath = true;
      }
      else if (typeName.equals("base64")) {
        certID = anchor.getFirstValue("base64-string");
        isPath = false;
      }
      else if (typeName.equals("dir")) {
        String dirName = anchor.getFirstValue("dir");

        double refreshPeriod = 0;
        ArrayList refreshTrees = anchor.get("refresh");
        if (refreshTrees.size() >= 1) {
          String refreshPeriodStr = ((BoostInfoTree)refreshTrees.get(0)).getValue();

          Pattern regex1 = Pattern.compile("(\\d+)([hms])");
          Matcher refreshMatch = regex1.matcher(refreshPeriodStr);
          if (!refreshMatch.find())
            refreshPeriod = 0;
          else {
            refreshPeriod = Integer.parseInt(refreshMatch.group(1));
            if (!refreshMatch.group(2).equals("s")) {
              refreshPeriod *= 60;
              if (!refreshMatch.group(2).equals("m"))
                refreshPeriod *= 60;
            }
          }
        }

        // Convert refreshPeriod from seconds to milliseconds.
        refreshManager_.addDirectory(dirName, refreshPeriod * 1000);
        continue;
      }
      else if (typeName.equals("any")) {
        // This disables all security!
        requiresVerification_ = false;
        break;
      }

      lookupCertificate(certID, isPath);
    }
  }

  /**
   * Once a rule is found to match data or a signed interest, the name in the
   * KeyLocator must satisfy the condition in the 'checker' section of the rule,
   * else the data or interest is rejected.
   * @param signatureName The certificate name from the KeyLocator.
   * @param objectName The name of the data packet or interest. In the case of
   * signed interests, this excludes the timestamp, nonce and signature
   * components.
   * @param rule The rule from the configuration file that matches the data or
   * interest.
   * @return True if matches.
   */
  private boolean
  checkSignatureMatch(Name signatureName, Name objectName, BoostInfoTree rule)
    throws SecurityException
  {
    BoostInfoTree checker = (BoostInfoTree)rule.get("checker").get(0);
    String checkerType = checker.getFirstValue("type");
    if (checkerType.equals("fixed-signer")) {
      BoostInfoTree signerInfo = (BoostInfoTree)checker.get("signer").get(0);
      String signerType = signerInfo.getFirstValue("type");

      Certificate cert = null;
      if (signerType.equals("file"))
        cert = lookupCertificate(signerInfo.getFirstValue("file-name"), true);
      else if (signerType.equals("base64"))
        cert = lookupCertificate(signerInfo.getFirstValue("base64-string"), false);
      else
        return false;

      if (cert == null)
        return false;
      else
        return cert.getName().equals(signatureName);
    }
    else if (checkerType.equals("hierarchical")) {
      // This just means the data/interest name has the signing identity as a prefix.
      // That means everything before "ksk-?" in the key name.
      String identityRegex = "^([^<KEY>]*)<KEY>(<>*)<ksk-.+><ID-CERT>";
      Matcher identityMatch = NdnRegexMatcher.match(identityRegex, signatureName);
      if (identityMatch != null) {
        Name identityPrefix = new Name(identityMatch.group(1)).append
          (new Name(identityMatch.group(2)));
        return matchesRelation(objectName, identityPrefix, "is-prefix-of");
      }
      else
        return false;
    }
    else if (checkerType.equals("customized")) {
      BoostInfoTree keyLocatorInfo = (BoostInfoTree)checker.get("key-locator").get(0);
      // Not checking type - only name is supported.

      // Is this a simple relation?
      String simpleRelationType = keyLocatorInfo.getFirstValue("relation");
      if (simpleRelationType != null) {
        Name matchName = new Name(keyLocatorInfo.getFirstValue("name"));
        return matchesRelation(signatureName, matchName, simpleRelationType);
      }

      // Is this a simple regex?
      String simpleKeyRegex = keyLocatorInfo.getFirstValue("regex");
      if (simpleKeyRegex != null)
        return NdnRegexMatcher.match(simpleKeyRegex, signatureName) != null;

      // Is this a hyper-relation?
      ArrayList hyperRelationList = keyLocatorInfo.get("hyper-relation");
      if (hyperRelationList.size() >= 1) {
        BoostInfoTree hyperRelation = (BoostInfoTree)hyperRelationList.get(0);

        String keyRegex = hyperRelation.getFirstValue("k-regex");
        String keyExpansion = hyperRelation.getFirstValue("k-expand");
        String nameRegex = hyperRelation.getFirstValue("p-regex");
        String nameExpansion = hyperRelation.getFirstValue("p-expand");
        String relationType = hyperRelation.getFirstValue("h-relation");
        if (keyRegex != null && keyExpansion != null && nameRegex != null &&
            nameExpansion != null && relationType != null) {
          Matcher keyMatch = NdnRegexMatcher.match(keyRegex, signatureName);
          if (keyMatch == null || keyMatch.groupCount() < 1)
            return false;
          String keyMatchPrefix = expand(keyMatch, keyExpansion);

          Matcher nameMatch = NdnRegexMatcher.match(nameRegex, objectName);
          if (nameMatch == null || nameMatch.groupCount() < 1)
            return false;
          String nameMatchStr = expand(nameMatch, nameExpansion);

          return matchesRelation
            (new Name(nameMatchStr), new Name(keyMatchPrefix), relationType);
        }
      }
    }

    // unknown type
    return false;
  }

  /**
   * Similar to Python expand, return expansion where every \1, \2, etc. is
   * replaced by match.group(1), match.group(2), etc.  Note: Even though this is
   * a general utility function, we define it locally because it is only tested
   * to work in the cases used by this class.
   * @param match The match object from String.match.
   * @param expansion The string with \1, \2, etc. to replace from match.
   * @return The expanded string.
   */
  private static String
  expand(Matcher match, String expansion)
  {
    String result = "";
    int beginIndex = 0;
    Pattern regex = Pattern.compile("\\\\(\\d)");
    Matcher expansionMatcher = regex.matcher(expansion);
    while (expansionMatcher.find()) {
      result += expansion.substring(beginIndex, expansionMatcher.start());
      result += match.group(Integer.parseInt(expansionMatcher.group(1)));
      beginIndex = expansionMatcher.end();
    }

    // Add the substring after the last match.
    result += expansion.substring(beginIndex, expansion.length());
    return result;
  }

  /**
   * This looks up certificates specified as base64-encoded data or file names.
   * These are cached by filename or encoding to avoid repeated reading of files
   * or decoding.
   * @param certID
   * @param isPath
   * @return The certificate object.
   */
  private IdentityCertificate
  lookupCertificate(String certID, boolean isPath) throws SecurityException
  {
    IdentityCertificate cert;

    if (!fixedCertificateCache_.containsKey(certID)) {
      if (isPath)
        // Load the certificate data (base64 encoded IdentityCertificate)
        cert = TrustAnchorRefreshManager.loadIdentityCertificateFromFile(certID);
      else {
        byte[] certData = Common.base64Decode(certID);
        cert = new IdentityCertificate();
        try {
          cert.wireDecode(new Blob(certData, false));
        } catch (EncodingException ex) {
          throw new SecurityException("Cannot base64 decode the cert data: " +
            ex.getMessage());
        }
      }

      String certUri = cert.getName().getPrefix(-1).toUri();
      fixedCertificateCache_.put(certID, certUri);
      certificateCache_.insertCertificate(cert);
    }
    else
      cert = certificateCache_.getCertificate
        (new Name((String)fixedCertificateCache_.get(certID)));

    return cert;
  }

  /**
   * Search the configuration file for the first rule that matches the data or
   * signed interest name. In the case of interests, the name to match should
   * exclude the timestamp, nonce, and signature components.
   * @param objName The name to be matched.
   * @param matchType The rule type to match, "data" or "interest".
   * @return The BoostInfoTree for the matching rule, or null if not found.
   */
  private BoostInfoTree
  findMatchingRule(Name objName, String matchType)
  {
    ArrayList rules = config_.getRoot().get("validator/rule");
    for (int iRule = 0; iRule < rules.size(); ++iRule) {
      BoostInfoTree r = (BoostInfoTree)rules.get(iRule);

      if (r.getFirstValue("for").equals(matchType)) {
        boolean passed = true;
        ArrayList filters = r.get("filter");
        if (filters.isEmpty())
          // no filters means we pass!
          return r;
        else {
          for (int iFilter = 0; iFilter < filters.size(); ++iFilter) {
            BoostInfoTree f = (BoostInfoTree)filters.get(iFilter);

            // Don't check the type - it can only be name for now.
            // We need to see if this is a regex or a relation.
            String regexPattern = f.getFirstValue("regex");
            if (regexPattern == null) {
              String matchRelation = f.getFirstValue("relation");
              String matchUri = f.getFirstValue("name");
              Name matchName = new Name(matchUri);
              passed = matchesRelation(objName, matchName, matchRelation);
            }
            else
              passed = (NdnRegexMatcher.match(regexPattern, objName) != null);

            if (!passed)
              break;
          }

          if (passed)
            return r;
        }
      }
    }

    return null;
  }

  /**
   * Determines if a name satisfies the relation to another name, based on
   * matchRelation.
   * @param name
   * @param matchName
   * @param matchRelation  Can be one of:
      "is-prefix-of" - passes if the name is equal to or has the other
         name as a prefix
      "is-strict-prefix-of" - passes if the name has the other name as a
         prefix, and is not equal
      "equal" - passes if the two names are equal
   * @return True if matches.
   */
  private static boolean
  matchesRelation(Name name, Name matchName, String matchRelation)
  {
    boolean passed = false;
    if (matchRelation.equals("is-strict-prefix-of")) {
      if (matchName.size() == name.size())
        passed = false;
      else if (matchName.match(name))
        passed = true;
    }
    else if (matchRelation.equals("is-prefix-of")) {
      if (matchName.match(name))
        passed = true;
    }
    else if (matchRelation.equals("equal")) {
      if (matchName.equals(name))
        passed = true;
    }

    return passed;
  }

  /**
   * Extract the signature information from the interest name.
   * @param interest The interest whose signature is needed.
   * @param wireFormat The wire format used to decode signature information
   * from the interest name.
   * @return A shared_ptr for the Signature object. This is null if can't decode.
   */
  private static Signature
  extractSignature(Interest interest, WireFormat wireFormat)
  {
    if (interest.getName().size() < 2)
      return null;

    try {
      return wireFormat.decodeSignatureInfoAndValue
              (interest.getName().get(-2).getValue().buf(),
               interest.getName().get(-1).getValue().buf(), false);
    } catch (EncodingException ex) {
      return null;
    }
  }

  /**
   * Determine whether the timestamp from the interest is newer than the last
   * use of this key, or within the grace interval on first use.
   * @param keyName The name of the public key used to sign the interest.
   * @param timestamp The timestamp extracted from the interest name.
   * @return True if timestamp is fresh as described above.
   */
  private boolean
  interestTimestampIsFresh(Name keyName, double timestamp)
  {
    String keyNameUri = keyName.toUri();
    if (!keyTimestamps_.containsKey(keyNameUri)) {
      double now = Common.getNowMilliseconds();
      double notBefore = now - keyGraceInterval_;
      double notAfter = now + keyGraceInterval_;
      return timestamp > notBefore && timestamp < notAfter;
    }
    else {
      double lastTimestamp = (double)(Double)keyTimestamps_.get(keyNameUri);
      return timestamp > lastTimestamp;
    }
  }

  /**
   * Trim the table size down if necessary, and insert/update the latest
   * interest signing timestamp for the key. Any key which has not been used
   * within the TTL period is purged. If the table is still too large, the
   * oldest key is purged.
   * @param keyName The name of the public key used to sign the interest.
   * @param timestamp The timestamp extracted from the interest name.
   */
  private void
  updateTimestampForKey(Name keyName, double timestamp)
  {
    keyTimestamps_.put(keyName.toUri(), timestamp);

    if (keyTimestamps_.size() >= maxTrackedKeys_) {
      double now = Common.getNowMilliseconds();
      double oldestTimestamp = now;
      String oldestKey = "";

      // Get the keys to erase without disturbing the map.
      // Use ArrayList without generics so it works with older Java compilers.
      ArrayList keysToErase = new ArrayList();

      Object[] keys = keyTimestamps_.keySet().toArray();
      for (int i = 0; i < keys.length; ++i) {
        String keyUri = (String)keys[i];
        double ts = (double)(Double)keyTimestamps_.get(keyUri);
        if (now - ts > keyTimestampTtl_)
          keysToErase.add(keyUri);
        else if (ts < oldestTimestamp) {
          oldestTimestamp = ts;
          oldestKey = keyUri;
        }
      }

      // Now erase.
      for (int i = 0; i < keysToErase.size(); ++i)
        keyTimestamps_.remove(keysToErase.get(i));

      if (keyTimestamps_.size() > maxTrackedKeys_ && oldestKey.length() != 0)
        // have not removed enough
        keyTimestamps_.remove(oldestKey);
    }
  }

  /**
   * Check the type of signatureInfo to get the KeyLocator. Look in the
   * IdentityStorage for the public key with the name in the KeyLocator and use
   * it to verify the signedBlob. If the public key can't be found, return
   * false. (This is a generalized method which can verify both a Data packet
   * and an interest.)
   * @param signatureInfo An object of a subclass of Signature, e.g.
   * Sha256WithRsaSignature.
   * @param signedBlob the SignedBlob with the signed portion to verify.
   * @return True if the signature verifies, False if not.
   */
  private boolean
  verify(Signature signatureInfo, SignedBlob signedBlob) throws SecurityException
  {
    // We have already checked once that there is a key locator.
    KeyLocator keyLocator = KeyLocator.getFromSignature(signatureInfo);

    if (keyLocator.getType() == KeyLocatorType.KEYNAME) {
      // Assume the key name is a certificate name.
      Name signatureName = keyLocator.getKeyName();
      IdentityCertificate certificate =
        refreshManager_.getCertificate(signatureName);
      if (certificate == null)
        certificate = certificateCache_.getCertificate(signatureName);
      if (certificate == null)
        return false;

      Blob publicKeyDer = certificate.getPublicKeyInfo().getKeyDer();
      if (publicKeyDer.isNull())
        // Can't find the public key with the name.
        return false;

      return verifySignature(signatureInfo, signedBlob, publicKeyDer);
    }
    else
      // Can't find a key to verify.
      return false;
  }

  /**
   * This is a helper for checkVerificationPolicy to verify the rule and return
   * a certificate interest to fetch the next certificate in the hierarchy if
   * needed.
   * @param stepCount The number of verification steps that have been done, used
   * to track the verification progress.
   * @param matchType Either "data" or "interest".
   * @param objectName The name of the data or interest packet.
   * @param signature The Signature object for the data or interest packet.
   * @return null if validation failed, otherwise the interest for the
   * ValidationRequest to fetch the next certificate. However, if the interest
   * has an empty name, the validation succeeded and no need to fetch a
   * certificate.
   */
  private Interest
  getCertificateInterest
    (int stepCount, String matchType, Name objectName, Signature signature)
      throws SecurityException
  {
    if (stepCount > maxDepth_)
      return null;

    if (!KeyLocator.canGetFromSignature(signature))
      // We only support signature types with key locators.
      return null;

    KeyLocator keyLocator;
    keyLocator = KeyLocator.getFromSignature(signature);

    Name signatureName = keyLocator.getKeyName();
    // No key name in KeyLocator -> fail.
    if (signatureName.size() == 0)
      return null;

    // first see if we can find a rule to match this packet
    BoostInfoTree matchedRule = findMatchingRule(objectName, matchType);

    // No matching rule -> fail.
    if (matchedRule == null)
      return null;

    boolean signatureMatches = checkSignatureMatch
      (signatureName, objectName, matchedRule);
    if (!signatureMatches)
      return null;

    // Before we look up keys, refresh any certificate directories.
    refreshManager_.refreshAnchors();

    // If we don't actually have the certificate yet, return a certificateInterest
    //   for it.
    IdentityCertificate foundCert = refreshManager_.getCertificate(signatureName);
    if (foundCert == null)
      foundCert = certificateCache_.getCertificate(signatureName);
    if (foundCert == null)
      return new Interest(signatureName);
    else
      return new Interest();
  }

  /**
   * The onVerified method of this inner class is called by KeyChain.verifyData
   * because checkVerificationPolicy returned a ValidationRequest to fetch a
   * certificate and verify a certificate, through a separate call to
   * KeyChain.verifyData. When it verifies the data, it calls onVerified which
   * is this method.
   * @param data The fetched data packet containing the certificate which has
   * already been verified.
   * @param originalData The original data from checkVerificationPolicy.
   * @param stepCount The value from checkVerificationPolicy.
   * @param onVerified The value from checkVerificationPolicy.
   * @param onVerifyFailed The value from checkVerificationPolicy.
   */
  private class OnCertificateDownloadComplete implements OnVerified {
    public OnCertificateDownloadComplete
      (Data originalData, int stepCount, OnVerified onVerified,
       OnVerifyFailed onVerifyFailed)
    {
      originalData_ = originalData;
      stepCount_ = stepCount;
      onVerified_ = onVerified;
      onVerifyFailed_ = onVerifyFailed;
    }

    public final void
    onVerified(Data data)
    {
      IdentityCertificate certificate;
      try {
        certificate = new IdentityCertificate(data);
      } catch (DerDecodingException ex) {
        try {
          onVerifyFailed_.onVerifyFailed(originalData_);
        } catch (Throwable exception) {
          logger_.log(Level.SEVERE, "Error in onVerifyFailed", exception);
        }
        return;
      }
      certificateCache_.insertCertificate(certificate);

      try {
        // Now that we stored the needed certificate, increment stepCount and try again
        //   to verify the originalData.
        checkVerificationPolicy
          (originalData_, stepCount_ + 1, onVerified_, onVerifyFailed_);
      } catch (SecurityException ex) {
        try {
          onVerifyFailed_.onVerifyFailed(originalData_);
        } catch (Throwable exception) {
          logger_.log(Level.SEVERE, "Error in onVerifyFailed", exception);
        }
      }
    }

    private final Data originalData_;
    private final int stepCount_;
    private final OnVerified onVerified_;
    private final OnVerifyFailed onVerifyFailed_;
  }

  /**
   * The onVerified method of this inner class is called by KeyChain.verifyData
   * because checkVerificationPolicy returned a ValidationRequest to fetch a
   * certificate and verify a certificate, through a separate call to
   * KeyChain.verifyData. When it verifies the data, it calls onVerified which
   * is this method.
   * @param data The fetched data packet containing the certificate which has
   * already been verified.
   * @param originalInterest The original interest from checkVerificationPolicy.
   * @param stepCount The value from checkVerificationPolicy.
   * @param onVerified The value from checkVerificationPolicy.
   * @param onVerifyFailed The value from checkVerificationPolicy.
   */
  private class OnCertificateDownloadCompleteForInterest implements OnVerified {
    public OnCertificateDownloadCompleteForInterest
      (Interest originalInterest, int stepCount,
       OnVerifiedInterest onVerified, OnVerifyInterestFailed onVerifyFailed,
       WireFormat wireFormat)
    {
      originalInterest_ = originalInterest;
      stepCount_ = stepCount;
      onVerified_ = onVerified;
      onVerifyFailed_ = onVerifyFailed;
      wireFormat_ = wireFormat;
    }

    public final void
    onVerified(Data data)
    {
      IdentityCertificate certificate;
      try {
        certificate = new IdentityCertificate(data);
      } catch (DerDecodingException ex) {
        try {
          onVerifyFailed_.onVerifyInterestFailed(originalInterest_);
        } catch (Throwable exception) {
          logger_.log(Level.SEVERE, "Error in onVerifyInterestFailed", exception);
        }
        return;
      }
      certificateCache_.insertCertificate(certificate);

      try {
        // Now that we stored the needed certificate, increment stepCount and try again
        //   to verify the originalData.
        checkVerificationPolicy
                (originalInterest_, stepCount_ + 1, onVerified_, onVerifyFailed_, wireFormat_);
      } catch (SecurityException ex) {
        try {
          onVerifyFailed_.onVerifyInterestFailed(originalInterest_);
        } catch (Throwable exception) {
          logger_.log(Level.SEVERE, "Error in onVerifyInterestFailed", exception);
        }
      }
    }

    private final Interest originalInterest_;
    private final int stepCount_;
    private final OnVerifiedInterest onVerified_;
    private final OnVerifyInterestFailed onVerifyFailed_;
    private final WireFormat wireFormat_;
  }

  /**
   * Ignore data and call onVerifyFailed(interest). This is so that an
   * OnVerifyInterestFailed can be passed as an OnVerifyFailed.
   */
  private class OnVerifyInterestFailedWrapper implements OnVerifyFailed {
    public OnVerifyInterestFailedWrapper
      (OnVerifyInterestFailed onVerifyFailed, Interest interest)
    {
      onVerifyFailed_ = onVerifyFailed;
      interest_ = interest;
    }

    public final void
    onVerifyFailed(Data data)
    {
      onVerifyFailed_.onVerifyInterestFailed(interest_);
    }

    private final OnVerifyInterestFailed onVerifyFailed_;
    private final Interest interest_;
  }

  /**
   * A class implements Friend if it has a method
   * setConfigPolicyManagerFriendAccess which setFriendAccess calls to set
   * the FriendAccess object.
   */
  public interface Friend {
    void setConfigPolicyManagerFriendAccess(FriendAccess friendAccess);
  }

  /**
   * Call friend.setConfigPolicyManagerFriendAccess to pass an instance of
   * a FriendAccess class to allow a friend class to call private methods.
   * @param friend The friend class for calling setConfigPolicyManagerFriendAccess.
   * This uses friend.getClass() to make sure that it is a friend class.
   * Therefore, only a friend class gets an implementation of FriendAccess.
   */
  public static void setFriendAccess(Friend friend)
  {
    if (friend.getClass().getName().equals
          ("src.net.named_data.jndn.tests.integration_tests.TestPolicyManager") ||
        friend.getClass().getName().equals
          ("src.net.named_data.jndn.tests.integration_tests.TestVerificationRules"))
    {
      friend.setConfigPolicyManagerFriendAccess(new FriendAccessImpl());
    }
  }

  /**
   * A friend class can call the methods of FriendAccess to access private
   * methods.  This abstract class is public, but setFriendAccess passes an
   * instance of a private class which implements the methods.
   */
  public abstract static class FriendAccess {
    public abstract BoostInfoTree
    findMatchingRule(ConfigPolicyManager policyManager, Name objName, String matchType);

    public abstract boolean
    checkSignatureMatch
      (ConfigPolicyManager policyManager, Name signatureName, Name objectName, BoostInfoTree rule)
      throws SecurityException;
  }

  /**
   * setFriendAccess passes an instance of this private class which implements
   * the FriendAccess methods.
   */
  private static class FriendAccessImpl extends FriendAccess {
    public BoostInfoTree
    findMatchingRule(ConfigPolicyManager policyManager, Name objName, String matchType)
    {
      return policyManager.findMatchingRule(objName, matchType);
    }

    public boolean
    checkSignatureMatch
      (ConfigPolicyManager policyManager, Name signatureName, Name objectName, BoostInfoTree rule)
      throws SecurityException
    {
      return policyManager.checkSignatureMatch(signatureName, objectName, rule);
    }
  }

  private CertificateCache certificateCache_ = new CertificateCache();
  private int maxDepth_ = 5;
  private double keyGraceInterval_ = 3000;
  private double keyTimestampTtl_ = 3600000;
  private int maxTrackedKeys_ = 1000;
  // fixedCertificateCache_ stores the fixed-signer certificate name associated with
  //    validation rules so we don't keep loading from files.
  // Use HashMap without generics so it works with older Java compilers.
  private final HashMap fixedCertificateCache_ = new HashMap();
  // keyTimestamps_ stores the timestamps for each public key used in command
  //   interests to avoid replay attacks.
  // key is the public key name, value is the last timestamp.
  private final HashMap keyTimestamps_ = new HashMap();
  private BoostInfoParser config_ = new BoostInfoParser();
  private boolean requiresVerification_ = true;
  private TrustAnchorRefreshManager refreshManager_ =
    new TrustAnchorRefreshManager();
  private static final Logger logger_ = Logger.getLogger
    (ConfigPolicyManager.class.getName());
}
