/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-fetcher.hpp
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

package net.named_data.jndn.security.v2;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.ValidatorConfigError;

/**
 * CertificateFetcher is an abstract base class which provides an interface used
 * by the validator to fetch missing certificates.
 */
public abstract class CertificateFetcher {
  public interface ValidationContinuation {
    void
    continueValidation(CertificateV2 certificate, ValidationState state)
      throws CertificateV2.Error, ValidatorConfigError;
  }

  /**
   * Assign the certificate storage used to check for known certificates and to
   * cache unverified ones.
   * @param certificateStorage The certificate storage object which must be
   * valid for the lifetime of this CertificateFetcher.
   */
  public void
  setCertificateStorage(CertificateStorage certificateStorage)
  {
    certificateStorage_ = certificateStorage;
  }

  /**
   * Asynchronously fetch a certificate. setCertificateStorage must have been
   * called first.
   * If the requested certificate exists in the storage, then this method will
   * immediately call continueValidation with the certificate. If certificate is
   * not available, then the implementation-specific doFetch will be called to
   * asynchronously fetch the certificate. The successfully-retrieved
   * certificate will be automatically added to the unverified cache of the
   * certificate storage.
   * When the requested certificate is retrieved, continueValidation is called.
   * Otherwise, the fetcher implementation calls state.failed() with the
   * appropriate error code and diagnostic message.
   * @param certificateRequest The the request with the Interest for fetching
   * the certificate.
   * @param state The validation state.
   * @param continueValidation After fetching, this calls
   * continueValidation.continueValidation(certificate, state) where certificate
   * is the fetched certificate and state is the ValidationState.
   */
  public final void
  fetch
    (CertificateRequest certificateRequest, ValidationState state,
     ValidationContinuation continueValidation)
     throws CertificateV2.Error, ValidatorConfigError
  {
    if (certificateStorage_ == null)
      throw new Error
        ("CertificateFetcher.fetch: You must first call setCertificateStorage");

    CertificateV2 certificate =
      certificateStorage_.getUnverifiedCertificateCache().find
        (certificateRequest.interest_);
    if (certificate != null) {
        logger_.log(Level.FINE, "Found certificate in **un**verified key cache {0}",
          certificate.getName().toUri());
      continueValidation.continueValidation(certificate, state);
      return;
    }

    // Rename continueValidation to avoid a loop.
    final ValidationContinuation outerContinueValidation = continueValidation;
    // Fetch asynchronously.
    doFetch
      (certificateRequest, state, new ValidationContinuation() {
        public void
        continueValidation(CertificateV2 certificate, ValidationState state)
          throws CertificateV2.Error, ValidatorConfigError {
          certificateStorage_.cacheUnverifiedCertificate(certificate);
          outerContinueValidation.continueValidation(certificate, state);
        }
      });
  }

  /**
   * An implementation to fetch a certificate asynchronously. The subclass must
   * implement this method.
   * @param certificateRequest The the request with the Interest for fetching
   * the certificate.
   * @param state The validation state.
   * @param continueValidation After fetching, this calls
   * continueValidation.continueValidation(certificate, state) where certificate
   * is the fetched certificate and state is the ValidationState.
   */
  protected abstract void
  doFetch
    (CertificateRequest certificateRequest, ValidationState state,
     ValidationContinuation continueValidation)
     throws CertificateV2.Error;

  protected CertificateStorage certificateStorage_ = null;
  private static final Logger logger_ =
    Logger.getLogger(CertificateFetcher.class.getName());
}
