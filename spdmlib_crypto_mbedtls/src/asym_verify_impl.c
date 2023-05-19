/** @file
 * EcDSA and RSA Wrapper Implementation.
 *
 **/

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

/**
 * Verifies RSASSA and Ecdsa signature.
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
 * Note: This function wrapper mbedtls_pk_verify function.
 * This function doesn't support RSA-PSS verification.
 *
 **/
int spdm_pk_verify(
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

/**
 * Verifies the RSA-PSS signature.
 *
 * @param[in]  md_type      Hash algorithm used.
 * @param[in]  cert         Certificate which contains public key.
 * @param[in]  cert_size    Certificate size in bytes.
 * @param[in]  data         Pointer to octet data to be checked (hash).
 * @param[in]  data_size    Size of the data in bytes.
 * @param[in]  signature    Pointer to RSA-PSS signature to be verified.
 * @param[in]  sig_size     Size of signature in bytes.
 *
 * @retval  0       Valid signature encoded in Ed-DSA.
 * @retval  not 0   Invalid signature.
 *
 * Note: This function wrapper mbedtls_pk_verify function.
 * This function doesn't support RSA-PSS verification.
 *
 **/
int spdm_rsa_pss_verify(
    const int md_type,
    const uint8_t *cert, size_t cert_size,
    const uint8_t *data, size_t data_size,
    const uint8_t *signature, size_t signature_size)
{
    mbedtls_x509_crt crt;
    mbedtls_rsa_context *rsa_context;
    int ret;
    // suppress "unused"
    (void)signature_size;

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, cert, cert_size);

    if (ret == 0)
    {
        rsa_context = mbedtls_pk_rsa(crt.pk);
        if (rsa_context == NULL)
        {
            ret = MBEDTLS_ERR_PK_INVALID_PUBKEY;
        }
    }

    if (ret == 0)
    {
        ret = mbedtls_rsa_rsassa_pss_verify(
            rsa_context, NULL, NULL,
            MBEDTLS_RSA_PUBLIC,
            md_type, data_size, data, signature);
    }

    mbedtls_x509_crt_free(&crt);

    return ret;
}
