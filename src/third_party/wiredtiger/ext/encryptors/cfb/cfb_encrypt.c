#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <wiredtiger.h>
#include <wiredtiger_ext.h>

#include <openssl/evp.h>

#define CFB_NAME "cfb"

typedef struct
{
   WT_ENCRYPTOR encryptor;		/* Must come first */
   WT_EXTENSION_API *wt_api;
   unsigned char *secret;
}CFB_ENCRYPTOR;

static int hexchar2int(unsigned char c)
{
   switch (c) {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
          return 4;
    case '5':
          return 5;
    case '6':
          return 6;
    case '7':
          return 7;
    case '8':
          return 8;
    case '9':
          return 9;
    case 'a': case 'A':
          return 0x0A;
    case 'b': case 'B':
          return 0x0B;
    case 'c': case 'C':
          return 0x0C;
    case 'd': case 'D':
          return 0x0D;
    case 'e': case 'E':
          return 0x0E;
    case 'f': case 'F':
          return 0x0F;
    }
    return -1;
}

static unsigned char *hexstr2buf(const char *str, int len)
{
   unsigned char *hexbuf = NULL;
   unsigned char *q;
   unsigned char ch, cl;
   int chi, cli, i;
   const unsigned char *p;

   int loop = 0; 

   if (0 != len % 2)
   {
      goto error;
   }

   loop = len >> 1;

   if ((hexbuf = malloc(loop)) == NULL) {
       goto error;
   }
   for (i = 0, p = (const unsigned char *)str, q = hexbuf; i < loop; ++i) {
       ch = *p++;
       if (ch == ':')
           continue;
       cl = *p++;
       if (!cl) {
          goto error;
       }
       cli = hexchar2int(cl);
       chi = hexchar2int(ch);
       if (cli < 0 || chi < 0) {
          goto error;
       }
       *q++ = (unsigned char)((chi << 4) | cli);
   }

done:
   return hexbuf;
error:
   free(hexbuf);
   hexbuf = NULL;
   goto done;
}

static int cfb_encrypt(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
                       uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_len,
                       size_t *result_lenp)
{
   int rc = 0;
   unsigned char vec[16] = {0};
   int out = 0;
   int final_out = 0;
   CFB_ENCRYPTOR *cbc = (CFB_ENCRYPTOR *)encryptor;
   EVP_CIPHER_CTX ctx;

   EVP_CIPHER_CTX_init(&ctx);

   if (NULL == cbc->secret)
   {
      rc = -1;
      goto error;
   }

   if (dst_len < src_len)
   {
      rc = ENOMEM;
      goto error;
   }


   /// can we put ctx and cipher into encryptor as members?
   rc = EVP_EncryptInit_ex(&ctx, EVP_aes_128_cfb128(), NULL, cbc->secret, vec);
   if (1 != rc)
   {
      rc = -1;
      goto error;
   }

   rc = EVP_EncryptUpdate(&ctx, dst, &out, src, src_len);
   if (1 != rc)
   {
      rc = -1;
      goto error;
   } 

   rc = EVP_EncryptFinal_ex(&ctx, dst + out, &final_out);
   if (1 != rc)
   {
      rc = -1;
      goto error;
   }

   if ((int)src_len != out + final_out)
   {
      rc = -1;
      goto error;
   }
   *result_lenp = src_len;
   rc = 0;
done:
   EVP_CIPHER_CTX_cleanup(&ctx);
   return rc;
error:
   goto done;
}

static int cfb_decrypt(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
                       uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_len,
                       size_t *result_lenp)
{
   int rc = 0;
   unsigned char vec[16] = {0};
   CFB_ENCRYPTOR *cbc = (CFB_ENCRYPTOR *)encryptor;
   EVP_CIPHER_CTX ctx;
   int out = 0;
   int final_out = 0;

   EVP_CIPHER_CTX_init(&ctx);

   if (NULL == cbc->secret)
   {
      rc = -1;
      goto error;
   }

   if (dst_len < src_len)
   {
      rc = ENOMEM;
      goto error;
   }

   /// can we put ctx and cipher into encryptor as members?
   rc = EVP_DecryptInit_ex(&ctx, EVP_aes_128_cfb128(), NULL, cbc->secret, vec);
   if (1 != rc)
   {
      rc = -1;
      goto error;
   }

   rc = EVP_DecryptUpdate(&ctx, dst, &out, src, src_len);
   if (1 != rc)
   {
      rc = -1;
      goto error;
   }

   rc = EVP_DecryptFinal_ex(&ctx, dst + out, &final_out);
   if (1 != rc)
   {
      rc = -1;
      goto error;
   }

   if ((int)src_len != final_out + out)
   {
      rc = -1;
      goto error;
   }

   *result_lenp = src_len;
   rc = 0;
done:
   EVP_CIPHER_CTX_cleanup(&ctx);
   return rc;
error:
   goto done;
}

static int cfb_sizing(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
                      size_t *expansion_constantp)
{
   *expansion_constantp = 0;
   return 0;
}

static int cfb_customize(WT_ENCRYPTOR *encryptor,
                         WT_SESSION *session,
                         WT_CONFIG_ARG *encrypt_config,
                         WT_ENCRYPTOR **customp)
{
   int rc = 0;
   CFB_ENCRYPTOR *new_encryptor = NULL;
   const CFB_ENCRYPTOR *orig_encryptor = (const CFB_ENCRYPTOR *)encryptor;
   WT_CONFIG_ITEM secret;
   WT_EXTENSION_API *extapi =
              session->connection->get_extension_api(session->connection);

   new_encryptor = calloc(1, sizeof(CFB_ENCRYPTOR));
   if (NULL == new_encryptor)
   {
      rc = errno;
      goto error;
   }

   new_encryptor->encryptor = orig_encryptor->encryptor;
   new_encryptor->wt_api = orig_encryptor->wt_api;
   new_encryptor->secret = NULL;

   rc = extapi->config_get(extapi, session, encrypt_config,
                           "secretkey", &secret);
   if (0 != rc)
   {
      goto error;
   }
   else if (32 == secret.len)
   {
      new_encryptor->secret = hexstr2buf(secret.str, secret.len);
      if (NULL == new_encryptor->secret)
      {
         rc = errno;
         goto error;
      }
   }
   else
   {
      /// invalid key length
      rc = -1;
      goto error;
   }

   *customp = (WT_ENCRYPTOR *)new_encryptor;

done:
   return rc;
error:
   if (NULL != new_encryptor)
   {
      free(new_encryptor->secret);
      free(new_encryptor);
   }
   goto done;
}

static int cfb_terminate(WT_ENCRYPTOR *encryptor, WT_SESSION *session)
{
   CFB_ENCRYPTOR *cfb_encryptor = (CFB_ENCRYPTOR *)encryptor;
   (void)session;

   if (NULL != cfb_encryptor)
   {
      free(cfb_encryptor->secret);
      free(cfb_encryptor);
   }
   return 0;
}

int cfb_extension_init(WT_CONNECTION *connection,
                       WT_CONFIG_ARG *config)
{
   int rc = 0;
   CFB_ENCRYPTOR *encryptor = NULL;

   encryptor = calloc(1, sizeof(CFB_ENCRYPTOR));
   if (NULL == encryptor)
   {
      rc = errno;
      goto error;
   }

   encryptor->encryptor.encrypt = cfb_encrypt;
   encryptor->encryptor.decrypt = cfb_decrypt;
   encryptor->encryptor.sizing = cfb_sizing;
   encryptor->encryptor.customize = cfb_customize;
   encryptor->encryptor.terminate = cfb_terminate;
   encryptor->wt_api = connection->get_extension_api(connection);
   encryptor->secret = NULL;

   rc = connection->add_encryptor(
	    connection, CFB_NAME, (WT_ENCRYPTOR *)encryptor, NULL);
   if (0 != rc)
   {
      goto error;
   }
   
done:
   return rc;
error:
   if (NULL != encryptor)
   {
      free(encryptor);
   }
   goto done;
}
