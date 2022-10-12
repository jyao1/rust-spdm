/** @file
 * X.509 Certificate Verification Wrapper Implementation.
 **/

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/asn1.h>

/**
 * Verify X509 certificate chains
 *
 * @param[in]      cert_chain           One or more ASN.1 DER-encoded X.509 certificates
 *                                      where the first certificate CA certificate.
 *                                      Certificate or is the Root Cerificate itself. and
 *                                      subsequent cerificate is signed by the preceding
 *                                      cerificate.
 * @param[in]      cert_chain_length    Total length of the certificate chain, in bytes.
 * 
 * @retval  0       All cerificates was issued by the first certificate in X509Certchain.
 * @retval  1       Invalid certificate or the certificate was not issued by the given
 *                  first CA cert.
 **/
int spdm_verify_cert_chain(char *certchain, size_t certchain_size)
{
    int ret;
    mbedtls_x509_crt crt, ca;
    unsigned char *p, *end, *pcert;
    size_t len;
    uint32_t flags;

    ret = 0;
    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_init(&ca);

    // Use the certchain_size until we figure out the actual length.
    pcert = p = (unsigned char *)certchain;
    end = (unsigned char *)certchain + certchain_size;

    // Parse CA cert in certchain.
    if (ret == 0)
    {
        ret = mbedtls_x509_crt_parse_der_nocopy(&ca, pcert, end - pcert);
    }
    if (ret == 0)
    {
        p = pcert;
        ret = mbedtls_asn1_get_tag((unsigned char **)&p, end, &len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    }

    /* 
     * Parse certchain include CA cert.
     */
    p = pcert;
    len = 0;

    /* parse certs in certchain.
     * pcert point to next certificate.
     */
    while (ret == 0 && (pcert = p + len) < end)
    {
        /*
         * Certificate  ::=  SEQUENCE  {
         *      tbsCertificate       TBSCertificate,
         *      signatureAlgorithm   AlgorithmIdentifier,
         *      signatureValue       BIT STRING  }
         */
        if (ret == 0)
        {
            ret = mbedtls_x509_crt_parse_der_nocopy(&crt, pcert, end - pcert);
        }

        if (ret == 0)
        {
            p = pcert;
            ret = mbedtls_asn1_get_tag((unsigned char **)&p, end, &len,
                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        }
    };

    /* Verify certificate chains.
     */
    ret = mbedtls_x509_crt_verify(&crt, &ca, NULL, NULL, &flags, NULL, NULL);

    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&ca);

    return ret;
}

/**
 * Certificate Check for SPDM leaf cert.
 *
 * @param[in]  cert                  Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size             The size of certificate data in bytes.
 *
 * @retval  0   Success.
 * @retval  1   Certificate is not valid
 **/
int spdm_x509_certificate_check(unsigned char *cert, size_t cert_size)
{
    // TODO
    (void)cert;
    (void)cert_size;
    return 0;
}

#ifdef SELF_DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define MAX_CERTCHAIN_SIZE 40960

int main(int argc, char **argv)
{
    char *certchain_buffer;
    size_t certchain_buffer_size;
    FILE *f;
    int ret;

    certchain_buffer = (char *)malloc(MAX_CERTCHAIN_SIZE);
    assert(certchain_buffer);

    f = fopen("public_cert.der", "rb");
    assert(f);

    certchain_buffer_size = fread(certchain_buffer, 1, MAX_CERTCHAIN_SIZE, f);
    fclose(f);

    if (certchain_buffer_size > 0)
    {
        ret = spdm_verify_cert_chain(certchain_buffer, certchain_buffer_size);
        assert(ret == 0);
    }
}

#endif
