/** @file
 * ECDH Wrapper Implementation.
 **/

#include <mbedtls/ecdh.h>

/**
 * Generates EC private key and EC public key (X, Y).
 *
 * This function generates random secret, and computes the public key (X, Y)
 * 
 * @param[in, out]  group_id       EC group ID mbedtls_ecp_group_id
 * @param[out]      pubkey         Pointer to the buffer to receive generated public X,Y. In
 *                                 MBEDTLS_ECP_PF_UNCOMPRESSED format. For more format information,
 *                                 Please refer mbedtls_ecp_point_write_binary implementation.
 * @param[in,out]   publen         Max pubkey buffer len for input.
 *                                 Actual pubkey len for output.
 * @param[out]      prikey         Pointer to prikey buffer to receive generated private key.
 * @param[in,out]   prilen         Max prilen buffer len for input.
 *                                 Actual pubkey len for output. 
 * @param[in]       random_fn          The RNG function.
 * @param[in]       random_fn_param    RNG function context pass to random_fn.
 * 
 * @retval 0          EC public X,Y generation succeeded.
 * @retval not 0      EC public X,Y generation failed.
 *
 **/
int spdm_ecdh_gen_public(
    mbedtls_ecp_group_id group_id,
    unsigned char *pubkey, size_t *publen,
    unsigned char *prikey, size_t *prilen,
    void *random_fn, void *random_fn_param)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi pri;
    mbedtls_ecp_point pub;

    mbedtls_mpi_init(&pri);
    mbedtls_ecp_point_init(&pub);
    mbedtls_ecp_group_init(&grp);

    int ret = 0;
    ret = mbedtls_ecp_group_load(&grp, group_id);

    if (ret == 0)
    {
        ret = mbedtls_ecdh_gen_public(&grp, &pri, &pub, random_fn, random_fn_param);
    }

    if (ret == 0)
    {
        size_t outlen = *publen;
        ret = mbedtls_ecp_point_write_binary(
            &grp, &pub, MBEDTLS_ECP_PF_UNCOMPRESSED, publen, pubkey, outlen);
    }

    if (ret == 0)
    {
        size_t outlen = mbedtls_mpi_size(&pri);
        ret = mbedtls_mpi_write_binary(&pri, prikey, outlen);
        if (ret == 0)
        {
            *prilen = outlen;
        }
    }

    mbedtls_mpi_free(&pri);
    mbedtls_ecp_point_free(&pub);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

/**
 * Computes exchanged common key.
 *
 * Given peer's public key (X, Y), this function computes the exchanged common key,
 * based on private key and ecp group info.
 *
 * @param[in]       group_id           EC group ID mbedtls_ecp_group_id
 * @param[in]       prikey             Private EC key.
 * @param[in]       prilen             Private EC key len.
 * @param[in]       peer_pubkey        Pointer to the peer's public X,Y.
 * @param[in]       peer_pubkey_len    Size of peer's public X,Y in bytes.
 * @param[out]      out_buffer         Pointer to the buffer to receive generated key.
 * @param[in, out]  out_len            On input, the size of key buffer in bytes.
 *                                     On output, the size of data returned in key buffer in bytes.
 * @param[in]       random_fn          The RNG function.
 * @param[in]       random_fn_param    RNG function context pass to random_fn.
 *
 * @retval true   EC exchanged key generation succeeded.
 * @retval false  EC exchanged key generation failed.
 * @retval false  key_size is not large enough.
 *
 **/
int spdm_ecdh_compute_shared(
    mbedtls_ecp_group_id group_id,
    unsigned char *prikey, size_t prilen,
    unsigned char *peer_pubkey, size_t peer_pubkey_len,
    unsigned char *out_buffer, size_t *out_len,
    void *random_fn, void *random_fn_param)
{

    mbedtls_ecp_group grp;
    mbedtls_mpi pri;
    mbedtls_ecp_point pub;

    mbedtls_mpi shared_key;

    mbedtls_mpi_init(&pri);
    mbedtls_ecp_point_init(&pub);
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&shared_key);

    int ret = 0;
    ret = mbedtls_ecp_group_load(&grp, group_id);

    if (ret == 0)
    {
        ret = mbedtls_ecp_point_read_binary(
            &grp, &pub,
            peer_pubkey, peer_pubkey_len);
    }

    if (ret == 0)
    {
        ret = mbedtls_mpi_read_binary(&pri, prikey, prilen);
    }

    if (ret == 0)
    {
        ret = mbedtls_ecdh_compute_shared(
            &grp, &shared_key, &pub, &pri,
            random_fn, random_fn_param);
    }

    if (ret == 0)
    {

        size_t bufferlen = mbedtls_mpi_size(&shared_key);
        if (*out_len < bufferlen)
        {
            return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
        }

        ret = mbedtls_mpi_write_binary(&shared_key, out_buffer, bufferlen);
        if (ret == 0)
        {
            *out_len = bufferlen;
        }
    }

    mbedtls_mpi_free(&pri);
    mbedtls_ecp_point_free(&pub);
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&shared_key);

    return ret;
}

int spdm_ecdh_gen_public_p256(
    unsigned char *pubkey, size_t *publen,
    unsigned char *prikey, size_t *prilen,
    void *random_fn, void *random_fn_param)
{
    return spdm_ecdh_gen_public(
        MBEDTLS_ECP_DP_SECP256R1,
        pubkey, publen,
        prikey, prilen,
        random_fn, random_fn_param);
}

int spdm_ecdh_gen_public_p384(
    unsigned char *pubkey, size_t *publen,
    unsigned char *prikey, size_t *prilen,
    void *random_fn, void *random_fn_param)
{
    return spdm_ecdh_gen_public(
        MBEDTLS_ECP_DP_SECP384R1,
        pubkey, publen, prikey, prilen,
        random_fn, random_fn_param);
}

int spdm_ecdh_compute_shared_p256(
    unsigned char *prikey,
    size_t prilen,
    unsigned char *peer_pubkey,
    size_t peer_pubkey_len,
    unsigned char *out_buffer,
    size_t *out_len,
    void *random_fn, void *random_fn_param)
{
    return spdm_ecdh_compute_shared(
        MBEDTLS_ECP_DP_SECP256R1,
        prikey, prilen,
        peer_pubkey, peer_pubkey_len,
        out_buffer, out_len,
        random_fn, random_fn_param);
}

int spdm_ecdh_compute_shared_p384(
    unsigned char *prikey,
    size_t prilen,
    unsigned char *peer_pubkey,
    size_t peer_pubkey_len,
    unsigned char *out_buffer,
    size_t *out_len,
    void *random_fn, void *random_fn_param)
{
    return spdm_ecdh_compute_shared(
        MBEDTLS_ECP_DP_SECP384R1,
        prikey, prilen,
        peer_pubkey, peer_pubkey_len,
        out_buffer, out_len,
        random_fn, random_fn_param);
}

#if SELF_DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rand_buffer(void *s, char *buffer, size_t len)
{
    int r;
    int left = len;
    for (; left > 0;)
    {
        left--;
        r = rand();
        buffer[left] = r && 0xff;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char private_key1[512];
    char public_key1[512];
    size_t private_key1_len = 512;
    size_t public_key1_len = 512;
    private_key1_len = 512;
    public_key1_len = 512;
    int res;
    res = spdm_ecdh_gen_public_p256(public_key1, &public_key1_len, private_key1, &private_key1_len, rand_buffer, NULL);

    char private_key2[512];
    char public_key2[512];
    size_t private_key2_len;
    size_t public_key2_len;
    private_key2_len = 512;
    public_key2_len = 512;

    res = spdm_ecdh_gen_public_p256(public_key2, &public_key2_len, private_key2, &private_key2_len, rand_buffer, NULL);

    char shared_key1[512];
    char shared_key2[512];
    size_t shared_key1_len = 512;
    size_t shared_key2_len = 512;

    spdm_ecdh_compute_shared_p256(
        private_key1, private_key1_len,
        public_key2, public_key2_len,
        shared_key1, &shared_key1_len,
        rand_buffer,
        NULL);

    spdm_ecdh_compute_shared_p256(
        private_key2, private_key2_len,
        public_key1, public_key1_len,
        shared_key2, &shared_key2_len,
        rand_buffer,
        NULL);
    if (memcmp(shared_key1, shared_key2, shared_key1_len) == 0 && memcmp(shared_key1, shared_key2, shared_key2_len) == 0)
    {
        printf("Passing");
    }
    else
    {
        printf("Failed");
    }

    return 0;
}
#endif