import { Context, HttpRequestHeaders } from '@azure/functions';

import { pki, md, asn1 } from 'node-forge';
import { BadRequestException, NotAuthorizedException } from 'sidelab-http-exceptions';

import { readPkcs12 } from 'pem';

const decodeClientCertificate = (header: string) => {
  const pem = `-----BEGIN CERTIFICATE-----${header}-----END CERTIFICATE-----`;
  const incomingCert: pki.Certificate = pki.certificateFromPem(pem);
  return incomingCert
}

const decodeServerCertificate = async (certBase64: string) => {
  const cer = Buffer.from(certBase64, 'base64')
  const value = { cert: '' }

  const getPrivateKey = async (value: { cert: string }) => {

    return new Promise(async (resolve) => {
      readPkcs12(cer, { p12Password: '' }, (_: any, cert: any) => {
        value.cert = cert.cert
        resolve(1);
      });
    });
  }
  await getPrivateKey(value)
  const incomingCert: pki.Certificate = pki.certificateFromPem(value.cert);
  return incomingCert
}

const getFingerprint = (cert: pki.Certificate) => {
  const fingerPrint = md.sha1.create().update(asn1.toDer(pki.certificateToAsn1(cert)).getBytes()).digest().toHex();
  return fingerPrint
}

export const authorizeClientCertificate = async (headers: HttpRequestHeaders, context: Context): Promise<void> => {
  // Get header
  const serverCert = process.env.CERTIFICATE_KV;
  const clientCert = headers.certificate

  if (!clientCert) throw new NotAuthorizedException('Send a certificate');
  if (!serverCert) throw new NotAuthorizedException('No certificate provided for server');

  // Decode certificates
  const clientCertDecoded = decodeClientCertificate(clientCert)
  const serverCertDecoded = await decodeServerCertificate(serverCert)

  // Validate certificate thumbprint
  const clientFingerPrint = getFingerprint(clientCertDecoded)
  const serverFingerPrint = getFingerprint(serverCertDecoded)

  if (clientFingerPrint !== serverFingerPrint)
    throw new NotAuthorizedException('Invalid thumbprint');

  // Validate time validity
  const currentDate = new Date();
  if (currentDate < clientCertDecoded.validity.notBefore || currentDate > clientCertDecoded.validity.notAfter) throw new NotAuthorizedException('Send a certificate with valid date');
};
