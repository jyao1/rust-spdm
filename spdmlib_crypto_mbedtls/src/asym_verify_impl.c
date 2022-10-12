/** @file
 * EcDSA Wrapper Implementation.
 *
 **/

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

/**
 * Verifies the Ed-DSA signature.
 *
 * @param[in]  md_type      Hash algorithm used.
 * @param[in]  cert         Certificate which contains public key.
 * @param[in]  cert_size    Certificate size in bytes.
 * @param[in]  data         Pointer to octet data to be checked (hash).
 * @param[in]  data_size    Size of the data in bytes.
 * @param[in]  signature    Pointer to Ed-DSA signature to be verified.
 * @param[in]  sig_size     Size of signature in bytes.
 *
 * @retval  0       Valid signature encoded in Ed-DSA.
 * @retval  not 0   Invalid signature.
 *
 **/
int spdm_ecdsa_verify(
    const int md_type,
    const uint8_t *cert, size_t cert_size,
    const uint8_t *data, size_t data_size,
    const uint8_t *signature, size_t signature_size)
{
    mbedtls_x509_crt crt;
    int ret;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0)
    {
        ret = mbedtls_pk_verify(&crt.pk, md_type, data, data_size, signature, signature_size);
    }

    mbedtls_x509_crt_free(&crt);

    return ret;
}
