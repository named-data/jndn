/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-fetcher-from-network.cpp
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

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.security.ValidatorConfigError;

/**
 * CertificateFetcherFromNetwork extends CertificateFetcher to fetch missing
 * certificates from the network.
 */
public class CertificateFetcherFromNetwork extends CertificateFetcher {
  /**
   * Create a CertificateFetcherFromNetwork to fetch certificates using the Face.
   * @param face The face for calling expressInterest.
   */
  public CertificateFetcherFromNetwork(Face face)
  {
    face_ = face;
  }

  /**
   * Implement doFetch to use face_.expressInterest to fetch a certificate.
   * @param certificateRequest The the request with the Interest for fetching
   * the certificate.
   * @param state The validation state.
   * @param continueValidation After fetching, this calls
   * continueValidation.continueValidation(certificate, state) where certificate
   * is the fetched certificate and state is the ValidationState.
   */
  protected void
  doFetch
    (final CertificateRequest certificateRequest, final ValidationState state,
     final ValidationContinuation continueValidation)
     throws CertificateV2.Error
  {
    try {
      face_.expressInterest
        (certificateRequest.interest_,
        new OnData() {
          public void onData(Interest interest, Data data) {
            logger_.log(Level.FINE, "Fetched certificate from network {0}",
              data.getName().toUri());

            CertificateV2 certificate;
            try {
              certificate = new CertificateV2(data);
            } catch (Throwable ex) {
              state.fail(new ValidationError
                (ValidationError.MALFORMED_CERTIFICATE,
                 "Fetched a malformed certificate `" + data.getName().toUri() +
                 "` (" + ex + ")"));
              return;
            }

            try {
              continueValidation.continueValidation(certificate, state);
            } catch (Throwable ex) {
              state.fail(new ValidationError
                (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                 "Error in continueValidation: " + ex));
            }
          }
        },
        new OnTimeout() {
          public void onTimeout(Interest interest) {
            logger_.log(Level.FINE,
              "Timeout while fetching certificate {0}, retrying",
              certificateRequest.interest_.getName().toUri());

            --certificateRequest.nRetriesLeft_;
            if (certificateRequest.nRetriesLeft_ >= 0) {
              try {
                fetch(certificateRequest, state, continueValidation);
              } catch (Exception ex) {
                 state.fail(new ValidationError
                   (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                    "Error in fetch: " + ex));
              }
            }
            else
              state.fail(new ValidationError
                (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                 "Cannot fetch certificate after all retries `" +
                 certificateRequest.interest_.getName().toUri() + "`"));
          }
        },
        new OnNetworkNack() {
          public void onNetworkNack(Interest interest, NetworkNack networkNack) {
            logger_.log(Level.FINE, "NACK ({0}) while fetching certificate {1}",
              new Object[] {networkNack.getReason(),
                            certificateRequest.interest_.getName().toUri()});

            --certificateRequest.nRetriesLeft_;
            if (certificateRequest.nRetriesLeft_ >= 0) {
              try {
                fetch(certificateRequest, state, continueValidation);
              } catch (Exception ex) {
                 state.fail(new ValidationError
                   (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                    "Error in fetch: " + ex));
              }
            }
            else
              state.fail(new ValidationError
                (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                 "Cannot fetch certificate after all retries `" +
                 certificateRequest.interest_.getName().toUri() + "`"));
          }
        });
    } catch (IOException ex) {
      state.fail(new ValidationError(ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
        "Error in expressInterest: " + ex));
    }
  }

  private final Face face_;
  private static final Logger logger_ =
    Logger.getLogger(CertificateFetcherFromNetwork.class.getName());
}
