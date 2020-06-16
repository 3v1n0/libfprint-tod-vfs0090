/*
 * Validity VFS0090 driver for libfprint
 * Copyright (C) 2017 Nikita Mikhailov <nikita.s.mikhailov@gmail.com>
 * Copyright (C) 2018-2020 Marco Trevisan <marco@ubuntu.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "vfs009x"

#include "drivers_api.h"

#include <errno.h>
#include <ctype.h>
#include <nss.h>
#include <pk11pub.h>
#include <sechash.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "vfs0090.h"

#define STRINGIZE(s) #s
#define EP_IN (1 | FPI_USB_ENDPOINT_IN)
#define EP_OUT (1 | FPI_USB_ENDPOINT_OUT)
#define VFS0090_TRANSFER_TYPE_INTERRUPT 3 /* Matches LIBUSB_TRANSFER_TYPE_INTERRUPT */
#define EP_INTERRUPT (VFS0090_TRANSFER_TYPE_INTERRUPT | FPI_USB_ENDPOINT_IN)

/* The main driver structure */
struct _FpiDeviceVfs0090
{
  FpDevice parent;

  gboolean activated;
  gboolean deactivating;
  gboolean db_checked;
  gboolean db_has_prints;

  /* Buffer for saving usb data through states */
  unsigned char *buffer;
  int            buffer_length;

  unsigned int   enroll_stage;
  FpiMatchResult match_result;
  GError        *action_error;
  FpPrint       *enrolled_print;
  FpImage       *captured_image;

  /* TLS keyblock for current session */
  unsigned char key_block[0x120];

  /* Current action cancellable */
  GCancellable *cancellable;
};

G_DEFINE_TYPE (FpiDeviceVfs0090, fpi_device_vfs0090, FP_TYPE_DEVICE)

GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_vfs0090_get_type ();
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ECDSA_SIG, ECDSA_SIG_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EC_KEY, EC_KEY_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_PKEY, EVP_PKEY_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_PKEY_CTX, EVP_PKEY_CTX_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (BIGNUM, BN_free);

typedef struct _VfsInit
{
  unsigned char *main_seed;
  unsigned int   main_seed_length;
  unsigned char  pubkey[VFS_PUBLIC_KEY_SIZE];
  unsigned char  ecdsa_private_key[VFS_ECDSA_PRIVATE_KEY_SIZE];
  unsigned char  masterkey_aes[VFS_MASTER_KEY_SIZE];
  unsigned char  tls_certificate[G_N_ELEMENTS (TLS_CERTIFICATE_BASE)];
} VfsInit;

static void
vfs_init_free (VfsInit *vinit)
{
  g_clear_pointer (&vinit->main_seed, g_free);
  g_free (vinit);
}

static void
print_hex_gn (unsigned char *data, int len, int sz)
{
  if (!len || !data)
    return;

  for (int i = 0; i < len; i++)
    {
      if ((i % 16) == 0)
        {
          if (i != 0)
            {
              g_print (" | ");
              for (int j = i - 16; j < i; ++j)
                g_print ("%c", isprint (data[j * sz]) ? data[j * sz] : '.');
              g_print ("\n");
            }
          g_print ("%04x ", i);
        }
      else if ((i % 8) == 0)
        {
          g_print (" ");
        }
      g_print ("%02x ", data[i * sz]);
    }

  if (((len - 1) % 16) != 0)
    {
      int j;
      int missing_bytes = (15 - (len - 1) % 16);
      int missing_spaces = missing_bytes * 3 + (missing_bytes >= 8 ? 1 : 0);

      for (int i = 0; i < missing_spaces; ++i)
        g_print (" ");

      g_print (" | ");

      for (j = len - 1; j > 0 && (j % 16) != 0; --j)
        ;
      for (; j < len; ++j)
        g_print ("%c", isprint (data[j * sz]) ? data[j * sz] : '.');
    }
  puts ("");
}

#if 0
static void
print_hex_string (char *data, int len)
{
  for (int i = 0; i < len; i++)
    g_print ("%02x", data[i]);
  puts ("");
}
#endif

static void
print_hex (unsigned char *data, int len)
{
  print_hex_gn (data, len, 1);
}

static void dev_deactivate (FpDevice *dev);
static void start_reactivate_ssm (FpDevice *dev);
static gboolean vfs0090_deinit (FpiDeviceVfs0090 *vdev,
                                GError          **error);
static void finger_scan_interrupt_callback (FpiUsbTransfer *transfer,
                                            FpDevice       *dev,
                                            gpointer        data,
                                            GError         *error);


/* remove emmmeeme */
static unsigned char *tls_encrypt (FpDevice            *dev,
                                   const unsigned char *data,
                                   int                  data_size,
                                   int                 *encrypted_len_out);
static gboolean tls_decrypt (FpDevice            *dev,
                             const unsigned char *buffer,
                             int                  buffer_size,
                             unsigned char       *output_buffer,
                             int                 *output_len);

typedef struct _VfsAsyncUsbOperationData
{
  FpiUsbTransferCallback callback;
  void                  *callback_data;
} VfsAsyncUsbOperationData;

static void
async_write_callback (FpiUsbTransfer *transfer, FpDevice *device,
                      gpointer user_data, GError *error)
{
  g_autofree VfsAsyncUsbOperationData *op_data = user_data;
  FpiDeviceVfs0090 *vdev;

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    {
      fp_dbg ("USB write transfer cancelled");
      goto out;
    }

  vdev = FPI_DEVICE_VFS0090 (device);
  g_clear_object (&vdev->cancellable);

  if (error)
    {
      fp_err ("USB write transfer error: %s", error->message);
      goto out;
    }

  if (transfer->actual_length != transfer->length)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                        "Written only %lu of %lu bytes",
                                        transfer->length,
                                        transfer->actual_length);
      fp_err ("%s", error->message);
    }

out:
  if (op_data && op_data->callback)
    op_data->callback (transfer, device, op_data->callback_data, error);
  else if (error)
    fpi_device_action_error (device, error);
}

static void
async_write_to_usb (FpDevice *dev,
                    const unsigned char *data, int data_size,
                    FpiUsbTransferCallback callback, gpointer callback_data)
{
  VfsAsyncUsbOperationData *op_data;
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpiUsbTransfer *transfer;

  g_assert_true (!vdev->cancellable ||
                 g_cancellable_is_cancelled (vdev->cancellable));

  op_data = g_new0 (VfsAsyncUsbOperationData, 1);
  op_data->callback = callback;
  op_data->callback_data = callback_data;

  transfer = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk_full (transfer, EP_OUT,
                                   (guint8 *) data, data_size, NULL);

  g_set_object (&vdev->cancellable, g_cancellable_new ());
  fpi_usb_transfer_submit (transfer, VFS_USB_TIMEOUT,
                           vdev->cancellable,
                           async_write_callback, op_data);
}

static void
async_read_callback (FpiUsbTransfer *transfer, FpDevice *device,
                     gpointer user_data, GError *error)
{
  g_autofree VfsAsyncUsbOperationData *op_data = user_data;
  FpiDeviceVfs0090 *vdev;

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    {
      fp_dbg ("USB read transfer cancelled");
      goto out;
    }

  vdev = FPI_DEVICE_VFS0090 (device);
  vdev->buffer_length = 0;
  g_clear_object (&vdev->cancellable);

  if (error)
    {
      fp_err ("USB read transfer error: %s",
              error->message);
      goto out;
    }

  vdev->buffer_length = transfer->actual_length;

out:
  if (op_data && op_data->callback)
    op_data->callback (transfer, device, op_data->callback_data, error);
  else if (error)
    fpi_device_action_error (device, error);
}

static void
async_read_from_usb (FpDevice *dev, FpiTransferType transfer_type,
                     unsigned char *buffer, int buffer_size,
                     FpiUsbTransferCallback callback, gpointer callback_data)
{
  VfsAsyncUsbOperationData *op_data;
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpiUsbTransfer *transfer;
  guint timeout = VFS_USB_TIMEOUT;

  g_assert_true (!vdev->cancellable ||
                 g_cancellable_is_cancelled (vdev->cancellable));

  transfer = fpi_usb_transfer_new (dev);
  g_set_object (&vdev->cancellable, g_cancellable_new ());

  op_data = g_new0 (VfsAsyncUsbOperationData, 1);
  op_data->callback = callback;
  op_data->callback_data = callback_data;

  switch (transfer_type)
    {
    case FP_TRANSFER_INTERRUPT:
      timeout = 0;
      fpi_usb_transfer_fill_interrupt_full (transfer,
                                            EP_INTERRUPT, buffer,
                                            buffer_size, NULL);
      break;

    case FP_TRANSFER_BULK:
      fpi_usb_transfer_fill_bulk_full (transfer, EP_IN,
                                       (guint8 *) buffer, buffer_size, NULL);
      break;

    default:
      g_assert_not_reached ();
    }

  fpi_usb_transfer_submit (transfer, timeout,
                           vdev->cancellable,
                           async_read_callback, op_data);
}

typedef struct _VfsAsyncUsbEncryptedOperationData
{
  FpiUsbTransferCallback callback;
  void                  *callback_data;

  unsigned char         *encrypted_data;
  int                    encrypted_data_size;
} VfsAsyncUsbEncryptedOperationData;

static void
async_write_encrypted_callback (FpiUsbTransfer *transfer, FpDevice *dev,
                                gpointer data, GError *error)
{
  g_autofree VfsAsyncUsbEncryptedOperationData *enc_op = data;

  if (enc_op->callback)
    enc_op->callback (transfer, dev, enc_op->callback_data, error);
  else if (error)
    fpi_device_action_error (dev, error);

  g_clear_pointer (&enc_op->encrypted_data, g_free);
}

static void
async_write_encrypted_to_usb (FpDevice              *dev,
                              const unsigned char   *data,
                              int                    data_size,
                              FpiUsbTransferCallback callback,
                              gpointer               callback_data)
{
  VfsAsyncUsbEncryptedOperationData *enc_op;
  unsigned char *encrypted_data;
  int encrypted_data_size;

  encrypted_data = tls_encrypt (dev, data, data_size,
                                &encrypted_data_size);

  enc_op = g_new0 (VfsAsyncUsbEncryptedOperationData, 1);
  enc_op->callback = callback;
  enc_op->callback_data = callback_data;
  enc_op->encrypted_data = encrypted_data;
  enc_op->encrypted_data_size = encrypted_data_size;

  async_write_to_usb (dev, encrypted_data, encrypted_data_size,
                      async_write_encrypted_callback, enc_op);
}

static gboolean
check_validity_reply (FpiDeviceVfs0090 *vdev, GError **error)
{
  VfsReply *reply = (VfsReply *) vdev->buffer;

  if (reply->status != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "Validity replied with an error status: 0x%02x",
                   reply->status);
      fp_err ("Unexpected reply status 0x%02x", reply->status);

      return FALSE;
    }

  return TRUE;
}

static void
async_read_encrypted_callback (FpiUsbTransfer *transfer, FpDevice *dev,
                               gpointer data, GError *error)
{
  g_autofree VfsAsyncUsbEncryptedOperationData *enc_op = data;
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);

  enc_op->encrypted_data = g_memdup (vdev->buffer, vdev->buffer_length);
  enc_op->encrypted_data_size = vdev->buffer_length;

  if (!error &&
      enc_op->encrypted_data && enc_op->encrypted_data_size &&
      !tls_decrypt (dev, enc_op->encrypted_data,
                    enc_op->encrypted_data_size,
                    vdev->buffer, &vdev->buffer_length))
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                        "Impossible to decrypt "
                                        "received data");
    }

  if (!error)
    check_validity_reply (vdev, &error);

  if (enc_op->callback)
    enc_op->callback (transfer, dev, enc_op->callback_data, error);
  else if (error)
    fpi_device_action_error (dev, error);

  g_clear_pointer (&enc_op->encrypted_data, g_free);
}

static void
async_read_decrypt_from_usb (FpDevice *dev, FpiTransferType transfer_type,
                             unsigned char *buffer, int buffer_size,
                             FpiUsbTransferCallback callback, gpointer callback_data)
{
  VfsAsyncUsbEncryptedOperationData *enc_op;

  enc_op = g_new0 (VfsAsyncUsbEncryptedOperationData, 1);
  enc_op->callback = callback;
  enc_op->callback_data = callback_data;

  async_read_from_usb (dev, transfer_type, buffer, buffer_size,
                       async_read_encrypted_callback, enc_op);
}

typedef struct _VfsAsyncDataExchange
{
  FpiUsbTransferCallback callback;
  gpointer               callback_data;

  int                    exchange_mode;
  unsigned char         *buffer;
  int                    buffer_size;
} VfsAsyncDataExchange;

static void
on_async_data_exchange_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                           gpointer data, GError *error)
{
  g_autofree VfsAsyncDataExchange *dex = data;

  g_assert_nonnull (dex);

  if (!error)
    {
      if (dex->exchange_mode == DATA_EXCHANGE_PLAIN)
        {
          async_read_from_usb (dev, FP_TRANSFER_BULK,
                               dex->buffer,
                               dex->buffer_size,
                               dex->callback, dex->callback_data);
        }
      else if (dex->exchange_mode == DATA_EXCHANGE_ENCRYPTED)
        {
          async_read_decrypt_from_usb (dev, FP_TRANSFER_BULK,
                                       dex->buffer,
                                       dex->buffer_size,
                                       dex->callback,
                                       dex->callback_data);
        }
    }
  else if (dex->callback)
    {
      dex->callback (transfer, dev, dex->callback_data, error);
    }
}

static void
async_data_exchange (FpDevice *dev, int exchange_mode,
                     const unsigned char *data, int data_size,
                     unsigned char *buffer, int buffer_size,
                     FpiUsbTransferCallback callback, gpointer callback_data)
{
  VfsAsyncDataExchange *dex;

  dex = g_new0 (VfsAsyncDataExchange, 1);
  dex->buffer = buffer;
  dex->buffer_size = buffer_size;
  dex->callback = callback;
  dex->callback_data = callback_data;
  dex->exchange_mode = exchange_mode;

  if (dex->exchange_mode == DATA_EXCHANGE_PLAIN)
    {
      async_write_to_usb (dev, data, data_size,
                          on_async_data_exchange_cb, dex);
    }
  else if (dex->exchange_mode == DATA_EXCHANGE_ENCRYPTED)
    {
      async_write_encrypted_to_usb (dev, data, data_size,
                                    on_async_data_exchange_cb, dex);
    }
  else
    {
      GError *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                "Unknown exchange mode selected");
      fp_err ("%s", error->message);

      if (callback)
        callback (NULL, dev, callback_data, error);
      else
        fpi_device_action_error (dev, error);
    }
}

static void
async_transfer_callback_with_ssm (FpiUsbTransfer *transfer, FpDevice *dev,
                                  gpointer data, GError *error)
{
  transfer->ssm = data;
  fpi_ssm_usb_transfer_cb (transfer, dev, data, error);
}

static void
generate_main_seed (FpDevice *dev, VfsInit *vinit)
{
  char name[NAME_MAX], serial[NAME_MAX];
  FILE *name_file, *serial_file;
  int name_len, serial_len;
  GError *error = NULL;

  if (!(name_file = fopen (DMI_PRODUCT_NAME_NODE, "r")))
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                        "Can't open "
                                        DMI_PRODUCT_NAME_NODE);
      fp_err ("%s", error->message);
      fpi_device_action_error (dev, error);
      return;
    }
  if (!(serial_file = fopen (DMI_PRODUCT_SERIAL_NODE, "r")))
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                        "Can't open "
                                        DMI_PRODUCT_SERIAL_NODE);
      fp_err ("%s", error->message);
      fpi_device_action_error (dev, error);
      goto out_serial;
    }

  if (fscanf (name_file, "%s", name) != 1)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                        "Can't parse product name from "
                                        DMI_PRODUCT_NAME_NODE);
      fp_err ("%s", error->message);
      fpi_device_action_error (dev, error);
      goto out_closeall;
    }

  if (fscanf (serial_file, "%s", serial) != 1)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                        "Can't parse product name from "
                                        DMI_PRODUCT_SERIAL_NODE);
      fp_err ("%s", error->message);
      fpi_device_action_error (dev, error);
      goto out_closeall;
    }

  name_len = strlen (name);
  serial_len = strlen (serial);
  vinit->main_seed_length = name_len + serial_len + 2;
  vinit->main_seed = g_malloc0 (vinit->main_seed_length);

  memcpy (vinit->main_seed, name, name_len + 1);
  memcpy (vinit->main_seed + name_len + 1, serial, serial_len + 1);

out_closeall:
  fclose (serial_file);
out_serial:
  fclose (name_file);
}

#define usb_operation(func, dev, error_ptr) usb_operation_perform (STRINGIZE (func), func, dev, error_ptr)
static gboolean
usb_operation_perform (const char *op, gboolean ret, FpDevice *dev, GError **error)
{
  if (!ret)
    {
      fp_err ("USB operation '%s' failed: %s", op,
              (error && *error) ? (*error)->message : NULL);
      if (dev && error)
        fpi_device_action_error (dev, *error);
    }

  return ret;
}

/*
   static gboolean openssl_operation(int ret, FpDevice *dev)
   {
        if (ret != TRUE) {
                fp_err("OpenSSL operation failed: %d", ret);
                error = fpi_device_error_new_msg FP_DEVICE_ERROR_GENERAL,
                                                 (dev) {
                        fpi_device_action_error(dev, error);
                }
                return FALSE;
        }

        return TRUE;
   }
 */

static PK11Context *
hmac_make_context (const unsigned char *key_bytes, int key_len)
{
  PK11SymKey *pkKey;
  CK_MECHANISM_TYPE hmacMech = CKM_SHA256_HMAC;
  PK11SlotInfo *slot = PK11_GetBestSlot (hmacMech, NULL);

  SECItem key;

  key.type = siBuffer;
  key.data = (unsigned char *) key_bytes;
  key.len = key_len;

  pkKey = PK11_ImportSymKey (slot, hmacMech, PK11_OriginUnwrap, CKA_SIGN, &key, NULL);

  SECItem param = { .type = siBuffer, .data = NULL, .len = 0 };

  PK11Context * context = PK11_CreateContextBySymKey (hmacMech, CKA_SIGN, pkKey, &param);
  PK11_DigestBegin (context);
  PK11_FreeSlot (slot);
  PK11_FreeSymKey (pkKey);

  return context;
}

static unsigned char *
hmac_compute (const unsigned char *key, int key_len, unsigned char * data, int data_len)
{
  // XXX: REUSE CONTEXT HERE, don't create it all the times
  PK11Context * context = hmac_make_context (key, key_len);

  PK11_DigestOp (context, data, data_len);

  unsigned int len = 0x20;
  unsigned char *res = g_malloc (len);
  PK11_DigestFinal (context, res, &len, len);
  PK11_DestroyContext (context, PR_TRUE);

  return res;
}

static void
mac_then_encrypt (unsigned char type, unsigned char *key_block, const unsigned char *data, int data_len, unsigned char **res, int *res_len)
{
  g_autofree unsigned char *all_data = NULL;
  g_autofree unsigned char *hmac = NULL;
  g_autofree unsigned char *pad = NULL;

  g_autoptr(EVP_CIPHER_CTX) context = NULL;
  const unsigned char iv[] = {
    0x4b, 0x77, 0x62, 0xff, 0xa9, 0x03, 0xc1, 0x1e,
    0x6f, 0xd8, 0x35, 0x93, 0x17, 0x2d, 0x54, 0xef
  };

  int prefix_len = (type != 0xFF) ? 5 : 0;

  // header for hmac + data + hmac
  all_data = g_malloc (prefix_len + data_len + 0x20);
  all_data[0] = type;
  all_data[1] = all_data[2] = 0x03;
  all_data[3] = (data_len >> 8) & 0xFF;
  all_data[4] = data_len & 0xFF;
  memcpy (all_data + prefix_len, data, data_len);

  hmac = hmac_compute (key_block, 0x20, all_data, prefix_len + data_len);
  memcpy (all_data + prefix_len + data_len, hmac, 0x20);

  context = EVP_CIPHER_CTX_new ();
  EVP_EncryptInit (context, EVP_aes_256_cbc (), key_block + 0x40, iv);
  EVP_CIPHER_CTX_set_padding (context, 0);

  *res_len = ((data_len + 16) / 16) * 16 + 0x30;
  *res = g_malloc (*res_len);
  memcpy (*res, iv, 0x10);
  int written = 0, wr2, wr3 = 0;

  EVP_EncryptUpdate (context, *res + 0x10, &written, all_data + prefix_len, data_len + 0x20);

  int pad_len = *res_len - (0x30 + data_len);
  if (pad_len == 0)
    pad_len = 16;
  pad = g_malloc (pad_len);
  memset (pad, pad_len - 1, pad_len);

  EVP_EncryptUpdate (context, *res + 0x10 + written, &wr3, pad, pad_len);

  EVP_EncryptFinal (context, *res + 0x10 + written + wr3, &wr2);
  *res_len = written + wr2 + wr3 + 0x10;
}

static unsigned char *
tls_encrypt (FpDevice *dev,
             const unsigned char *data, int data_size,
             int *encrypted_len_out)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  g_autofree unsigned char *res = NULL;
  unsigned char *wr;
  int res_len;

  g_assert (vdev->key_block);

  mac_then_encrypt (0x17, vdev->key_block, data, data_size, &res, &res_len);

  wr = g_malloc (res_len + 5);
  memcpy (wr + 5, res, res_len);
  wr[0] = 0x17;
  wr[1] = wr[2] = 0x03;
  wr[3] = res_len >> 8;
  wr[4] = res_len & 0xFF;

  *encrypted_len_out = res_len + 5;

  return wr;
}

static gboolean
tls_decrypt (FpDevice *dev,
             const unsigned char *buffer, int buffer_size,
             unsigned char *output_buffer, int *output_len)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);

  g_autoptr(EVP_CIPHER_CTX) context = NULL;

  int buff_len = buffer_size - 5;
  int out_len = buff_len - 0x10;
  int tlen1 = 0, tlen2;

  g_return_val_if_fail (buffer != NULL, FALSE);
  g_return_val_if_fail (buffer_size > 0, FALSE);
  g_assert (vdev->key_block);

  buffer += 5;
  *output_len = 0;

  context = EVP_CIPHER_CTX_new ();
  if (!EVP_DecryptInit (context, EVP_aes_256_cbc (), vdev->key_block + 0x60, buffer))
    {
      fp_err ("Decryption failed, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return FALSE;
    }

  EVP_CIPHER_CTX_set_padding (context, 0);

  if (!EVP_DecryptUpdate (context, output_buffer, &tlen1, buffer + 0x10, out_len))
    {
      fp_err ("Decryption failed, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return FALSE;
    }

  if (!EVP_DecryptFinal (context, output_buffer + tlen1, &tlen2))
    {
      fp_err ("Decryption failed, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return FALSE;
    }

  *output_len = tlen1 + tlen2 - 0x20 - (output_buffer[out_len - 1] + 1);

  return TRUE;
}

static gboolean
check_data_exchange (FpiDeviceVfs0090 *vdev, const VfsDataExchange *dex)
{
  if (dex->rsp_length >= 0 && vdev->buffer_length != dex->rsp_length)
    {
      return FALSE;
    }
  else if (dex->rsp_length > 0 && dex->rsp != NULL)
    {
      int i;
      const unsigned char *expected = dex->rsp;

      for (i = 0; i < vdev->buffer_length; ++i)
        {
          if (vdev->buffer[i] != expected[i])
            {
              fp_warn ("Reply mismatch, expected at char %d "
                       "(actual 0x%x, expected  0x%x)",
                       i, vdev->buffer[i], expected[i]);

              if (!dex->weak_match)
                return FALSE;
            }
        }
    }

  return TRUE;
}

static gboolean
check_data_exchange_dbg (FpiDeviceVfs0090 *vdev, const VfsDataExchange *dex)
{
  gboolean ret = check_data_exchange (vdev, dex);

  if (!ret)
    {
      if (dex->rsp_length >= 0 && vdev->buffer_length != dex->rsp_length)
        fp_err ("Expected len: %d, but got %d",
                dex->rsp_length, vdev->buffer_length);

      print_hex (vdev->buffer, vdev->buffer_length);
    }

  return ret;
}

typedef struct _VfsDataExchangeAsyncData
{
  FpiSsm                *ssm;
  const VfsDataExchange *dex;
} VfsDataExchangeAsyncData;

static void
on_data_exchange_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                     gpointer data, GError *error)
{
  g_autofree VfsDataExchangeAsyncData *dex_data = data;
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);

  if (!error)
    {
      if (check_data_exchange_dbg (vdev, dex_data->dex))
        fpi_ssm_next_state (dex_data->ssm);
      else
        error = fpi_device_error_new (FP_DEVICE_ERROR_PROTO);
    }

  if (error)
    {
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        fp_err ("Data exchange failed at state %d, usb error: %s",
                fpi_ssm_get_cur_state (dex_data->ssm), error->message);

      fpi_ssm_mark_failed (dex_data->ssm, error);
    }
}

static void
do_data_exchange (FpiDeviceVfs0090 *vdev, FpiSsm *ssm,
                  const VfsDataExchange *dex, int mode)
{
  VfsDataExchangeAsyncData *dex_data;

  dex_data = g_new0 (VfsDataExchangeAsyncData, 1);
  dex_data->ssm = ssm;
  dex_data->dex = dex;

  async_data_exchange (FP_DEVICE (vdev), mode, dex->msg, dex->msg_length,
                       vdev->buffer, VFS_USB_BUFFER_SIZE,
                       on_data_exchange_cb, dex_data);
}

static void
TLS_PRF2 (const unsigned char *secret, int secret_len, const char *str,
          const unsigned char *seed40, int seed40_len,
          unsigned char *out_buffer, int buffer_len)
{
  int total_len = 0;
  int str_len = strlen (str);
  unsigned char seed[str_len + seed40_len];
  int seed_len = str_len + seed40_len;
  g_autofree unsigned char *a = NULL;

  memcpy (seed, str, str_len);
  memcpy (seed + str_len, seed40, seed40_len);

  a = hmac_compute (secret, secret_len, seed, seed_len);

  while (total_len < buffer_len)
    {
      unsigned char buffer[0x20 + seed_len];
      g_autofree unsigned char *p = NULL;
      g_autofree unsigned char *t = NULL;

      memcpy (buffer, a, 0x20);
      memcpy (buffer + 0x20, seed, seed_len);

      p = hmac_compute (secret, secret_len, buffer, 0x20 + seed_len);
      memcpy (out_buffer + total_len, p, MIN (0x20, buffer_len - total_len));

      total_len += 0x20;

      t = g_steal_pointer (&a);
      a = hmac_compute (secret, secret_len, t, 0x20);
    }
}

static gboolean
check_pad (unsigned char *data, int len)
{
  int pad_size = data[len - 1];

  for(int i = 0; i < pad_size; ++i)
    if (data[len - 1 - i] != pad_size)
      return FALSE;

  return TRUE;
}

static void
reverse_mem (unsigned char * data, int size)
{
  unsigned char tmp;

  for (int i = 0; i < size / 2; ++i)
    {
      tmp = data[i];
      data[i] = data[size - 1 - i];
      data[size - 1 - i] = tmp;
    }
}

static gboolean
initialize_ecdsa_key (VfsInit *vinit, unsigned char *enc_data, int res_len)
{
  int tlen1 = 0, tlen2;
  g_autofree unsigned char *res = NULL;

  g_autoptr(EVP_CIPHER_CTX) context = NULL;

  context = EVP_CIPHER_CTX_new ();

  if (!EVP_DecryptInit (context, EVP_aes_256_cbc (), vinit->masterkey_aes, enc_data))
    {
      fp_err ("Failed to initialize EVP decrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return FALSE;
    }

  res = g_malloc (res_len);
  EVP_CIPHER_CTX_set_padding (context, 0);

  if (!EVP_DecryptUpdate (context, res, &tlen1, enc_data + 0x10, res_len))
    {
      fp_err ("Failed to EVP decrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return FALSE;
    }

  if (!EVP_DecryptFinal (context, res + tlen1, &tlen2))
    {
      fp_err ("EVP Final decrypt failed, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return FALSE;
    }

  reverse_mem (res, 0x20);
  reverse_mem (res + 0x20, 0x20);
  reverse_mem (res + 0x40, 0x20);

  memcpy (vinit->ecdsa_private_key, res, VFS_ECDSA_PRIVATE_KEY_SIZE);

  return check_pad (res, res_len);
}

static gboolean
make_ecdsa_key (VfsInit *vinit, unsigned char *data)
{
  if (!initialize_ecdsa_key (vinit, data + 0x52, 0x70))
    return FALSE;

  memset (vinit->ecdsa_private_key, 0, 0x40);
  // 97 doesn't have XY in private key
  memcpy (vinit->ecdsa_private_key, data + 0x11e, 0x20);
  reverse_mem (vinit->ecdsa_private_key, 0x20);

  memcpy (vinit->ecdsa_private_key + 0x20, data + 0x162, 0x20);
  reverse_mem (vinit->ecdsa_private_key + 0x20, 0x20);

  return TRUE;
}

static EC_KEY *
load_key (const unsigned char *data, gboolean is_private)
{
  g_autoptr(BIGNUM) x = NULL;
  g_autoptr(BIGNUM) y = NULL;
  g_autoptr(BIGNUM) d = NULL;
  g_autoptr(EC_KEY) key = NULL;

  x = BN_bin2bn (data, 0x20, NULL);
  y = BN_bin2bn (data + 0x20, 0x20, NULL);
  key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);

  if (!EC_KEY_set_public_key_affine_coordinates (key, x, y))
    {
      fp_err ("Failed to set public key coordinates, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return NULL;
    }

  if (is_private)
    {
      d = BN_bin2bn (data + 0x40, 0x20, NULL);
      if (!EC_KEY_set_private_key (key, d))
        {
          fp_err ("Failed to set private key, error: %lu, %s",
                  ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
          return NULL;
        }
    }

  if (!EC_KEY_check_key (key))
    {
      fp_err ("Failed to check key, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return NULL;
    }

  return g_steal_pointer (&key);
}

static void
fill_buffer_with_random (unsigned char *buffer, int size)
{
  int i;

  srand (time (NULL));

  for (i = 0; i < size; ++i)
    buffer[i] = rand () % 0x100;
}

static unsigned char *
sign2 (EC_KEY * key, unsigned char *data, int data_len)
{
  int len = 0;
  unsigned char *res = NULL;

  do
    {
      g_autoptr(ECDSA_SIG) sig = NULL;

      sig = ECDSA_do_sign (data, data_len, key);
      len = i2d_ECDSA_SIG (sig, NULL);

      free (res);
      res = g_malloc (len);
      unsigned char *f = res;
      i2d_ECDSA_SIG (sig, &f);
    }
  while (len != VFS_ECDSA_SIGNATURE_SIZE);

  return res;
}

typedef struct _VfsTlsHandshake
{
  VfsInit       *vinit;
  HASHContext   *tls_hash_context;
  HASHContext   *tls_hash_context2;
  unsigned char  read_buffer[VFS_USB_BUFFER_SIZE];
  unsigned char  client_random[0x20];
  unsigned char  master_secret[0x30];
  unsigned char *client_hello;
} VfsTlsHandshake;

static void
tls_handshake_free (VfsTlsHandshake *tlshd)
{
  HASH_Destroy (tlshd->tls_hash_context);
  HASH_Destroy (tlshd->tls_hash_context2);
  g_clear_pointer (&tlshd->client_hello, g_free);
  g_free (tlshd);
}

static void
handshake_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  VfsTlsHandshake *tlshd = fpi_ssm_get_data (ssm);
  VfsInit *vinit = tlshd->vinit;
  GError *error = NULL;

  switch(fpi_ssm_get_cur_state (ssm))
    {
    case TLS_HANDSHAKE_STATE_CLIENT_HELLO:
      {
        time_t current_time;
        unsigned char *client_hello;

        tlshd->tls_hash_context = HASH_Create (HASH_AlgSHA256);
        tlshd->tls_hash_context2 = HASH_Create (HASH_AlgSHA256);

        HASH_Begin (tlshd->tls_hash_context);
        HASH_Begin (tlshd->tls_hash_context2);

        client_hello = g_malloc (G_N_ELEMENTS (TLS_CLIENT_HELLO));
        tlshd->client_hello = client_hello;

        current_time = time (NULL);
        memcpy (tlshd->client_random, &current_time, sizeof (time_t));
        fill_buffer_with_random (tlshd->client_random + 4, G_N_ELEMENTS (tlshd->client_random) - 4);

        memcpy (client_hello, TLS_CLIENT_HELLO, G_N_ELEMENTS (TLS_CLIENT_HELLO));
        memcpy (client_hello + 0xf, tlshd->client_random, G_N_ELEMENTS (tlshd->client_random));
        HASH_Update (tlshd->tls_hash_context, client_hello + 0x09, 0x43);
        HASH_Update (tlshd->tls_hash_context2, client_hello + 0x09, 0x43);

        async_data_exchange (dev, DATA_EXCHANGE_PLAIN,
                             client_hello, G_N_ELEMENTS (TLS_CLIENT_HELLO),
                             tlshd->read_buffer, sizeof (tlshd->read_buffer),
                             async_transfer_callback_with_ssm, ssm);

        break;
      }

    case TLS_HANDSHAKE_STATE_SERVER_HELLO_RCV:
      {
        unsigned char server_random[0x40];
        unsigned char seed[0x40], expansion_seed[0x40];
        size_t pre_master_secret_len;
        g_autofree unsigned char *pre_master_secret = NULL;
        g_autoptr(EC_KEY) priv_key = NULL;
        g_autoptr(EC_KEY) pub_key = NULL;
        g_autoptr(EVP_PKEY_CTX) ctx = NULL;
        g_autoptr(EVP_PKEY) priv = NULL;
        g_autoptr(EVP_PKEY) pub = NULL;

        memcpy (server_random, tlshd->read_buffer + 0xb, G_N_ELEMENTS (server_random));
        HASH_Update (tlshd->tls_hash_context, tlshd->read_buffer + 0x05, 0x3d);
        HASH_Update (tlshd->tls_hash_context2, tlshd->read_buffer + 0x05, 0x3d);

        if (!(priv_key = load_key (PRIVKEY, TRUE)))
          {
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                              "Impossible to load private key");
            fpi_ssm_mark_failed (ssm, error);
            break;
          }

        if (!(pub_key = load_key (vinit->pubkey, FALSE)))
          {
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                              "Impossible to load private key");
            fpi_ssm_mark_failed (ssm, error);
            break;
          }

        priv = EVP_PKEY_new ();
        EVP_PKEY_set1_EC_KEY (priv, priv_key);
        pub = EVP_PKEY_new ();
        EVP_PKEY_set1_EC_KEY (pub, pub_key);

        ctx = EVP_PKEY_CTX_new (priv, NULL);

        EVP_PKEY_derive_init (ctx);
        EVP_PKEY_derive_set_peer (ctx, pub);

        EVP_PKEY_derive (ctx, NULL, &pre_master_secret_len);

        pre_master_secret = g_malloc (pre_master_secret_len);
        if (!ECDH_compute_key (pre_master_secret, pre_master_secret_len, EC_KEY_get0_public_key (pub_key), priv_key, NULL))
          {
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                              "Failed to compute key, "
                                              "error: %lu, %s",
                                              ERR_peek_last_error (),
                                              ERR_error_string (ERR_peek_last_error (), NULL));
            fpi_ssm_mark_failed (ssm, error);
            break;
          }

        memcpy (seed, tlshd->client_random, G_N_ELEMENTS (tlshd->client_random));
        memcpy (seed + G_N_ELEMENTS (tlshd->client_random), server_random, G_N_ELEMENTS (seed) - G_N_ELEMENTS (tlshd->client_random));

        memcpy (expansion_seed + (G_N_ELEMENTS (expansion_seed) - G_N_ELEMENTS (tlshd->client_random)), tlshd->client_random, G_N_ELEMENTS (tlshd->client_random));
        memcpy (expansion_seed, server_random, G_N_ELEMENTS (expansion_seed) - G_N_ELEMENTS (tlshd->client_random));

        TLS_PRF2 (pre_master_secret, pre_master_secret_len, "master secret", seed, G_N_ELEMENTS (seed),
                  tlshd->master_secret, G_N_ELEMENTS (tlshd->master_secret));
        TLS_PRF2 (tlshd->master_secret, G_N_ELEMENTS (tlshd->master_secret), "key expansion",
                  seed, G_N_ELEMENTS (seed), vdev->key_block, G_N_ELEMENTS (vdev->key_block));

        fpi_ssm_next_state (ssm);

        break;
      }

    case TLS_HANDSHAKE_GENERATE_CERT:
      {
        g_autoptr(EC_KEY) ecdsa_key = NULL;
        unsigned char test[0x20];
        g_autofree unsigned char *cert_verify_signature = NULL;
        g_autofree unsigned char *final = NULL;
        unsigned int test_len;
        int len;

        memcpy (vinit->tls_certificate + 0xce + 4, PRIVKEY, 0x40);

        HASH_Update (tlshd->tls_hash_context, vinit->tls_certificate + 0x09, 0x109);
        HASH_Update (tlshd->tls_hash_context2, vinit->tls_certificate + 0x09, 0x109);

        HASH_End (tlshd->tls_hash_context, test, &test_len, G_N_ELEMENTS (test));

        ecdsa_key = load_key (vinit->ecdsa_private_key, TRUE);
        cert_verify_signature = sign2 (ecdsa_key, test, 0x20);
        memcpy (vinit->tls_certificate + 0x09 + 0x109 + 0x04, cert_verify_signature, VFS_ECDSA_SIGNATURE_SIZE);

        // encrypted finished
        unsigned char handshake_messages[0x20];
        unsigned int len3 = 0x20;
        HASH_Update (tlshd->tls_hash_context2, vinit->tls_certificate + 0x09 + 0x109, 0x4c);
        HASH_End (tlshd->tls_hash_context2, handshake_messages, &len3, 0x20);

        unsigned char finished_message[0x10] = { 0x14, 0x00, 0x00, 0x0c, 0 };
        unsigned char client_finished[0x0c];
        TLS_PRF2 (tlshd->master_secret, 0x30, "client finished", handshake_messages, 0x20,
                  client_finished, G_N_ELEMENTS (client_finished));
        memcpy (finished_message + 0x04, client_finished, G_N_ELEMENTS (client_finished));
        // copy handshake protocol

        mac_then_encrypt (0x16, vdev->key_block, finished_message, 0x10, &final, &len);
        memcpy (vinit->tls_certificate + 0x169, final, len);

        fpi_ssm_next_state (ssm);

        break;
      }

    case TLS_HANDSHAKE_STATE_SEND_CERT:
      {
        async_data_exchange (dev, DATA_EXCHANGE_PLAIN,
                             vinit->tls_certificate,
                             sizeof (vinit->tls_certificate),
                             tlshd->read_buffer, VFS_USB_BUFFER_SIZE,
                             async_transfer_callback_with_ssm, ssm);

        break;
      }

    case TLS_HANDSHAKE_STATE_CERT_REPLY:
      {
        const unsigned char WRONG_TLS_CERT_RSP[] = { 0x15, 0x03, 0x03, 0x00, 0x02 };

        if (vdev->buffer_length < 50 ||
            memcmp (tlshd->read_buffer, WRONG_TLS_CERT_RSP,
                    MIN (vdev->buffer_length, G_N_ELEMENTS (WRONG_TLS_CERT_RSP))) == 0)
          {
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                              "TLS Certificate submitted isn't accepted by reader");
            fpi_ssm_mark_failed (ssm, error);
            break;
          }

        fpi_ssm_next_state (ssm);

        break;
      }

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown state");
      fpi_ssm_mark_failed (ssm, error);
    }
}

static void
start_handshake_ssm (FpDevice *dev,
                     FpiSsm   *parent_ssm,
                     VfsInit  *vinit)
{
  FpiSsm *ssm;
  VfsTlsHandshake *tlshd;

  tlshd = g_new0 (VfsTlsHandshake, 1);
  tlshd->vinit = vinit;

  ssm = fpi_ssm_new (dev, handshake_ssm,
                     TLS_HANDSHAKE_STATE_LAST);
  fpi_ssm_set_data (ssm, tlshd, (GDestroyNotify) tls_handshake_free);
  fpi_ssm_start_subsm (parent_ssm, ssm);
}

static int
translate_interrupt (unsigned char *interrupt, int interrupt_size, GError **error)
{
  const int expected_size = 5;
  const unsigned char waiting_finger[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
  const unsigned char finger_down_prefix[] = { 0x02, 0x00, 0x40 };
  const unsigned char scanning_prints[] = { 0x03, 0x40, 0x01, 0x00, 0x00 };
  const unsigned char scan_completed[] = { 0x03, 0x41, 0x03, 0x00, 0x40 };

  const unsigned char scan_success[] = { 0x03, 0x43, 0x04, 0x00, 0x41 };
  const unsigned char db_identified_prefix[] = { 0x03, 0x00 };
  const unsigned char db_unidentified_prefix[] = { 0x04, 0x00 };
  const unsigned char db_checked_sufix[] = { 0x00, 0xdb };
  const unsigned char db_check_error[] = { 0x05, 0x00, 0xb3, 0x04, 0xdb };
  const unsigned char low_quality_scan[] = { 0x03, 0x42, 0x04, 0x00, 0x40 };
  const unsigned char scan_failed_too_short[] = { 0x03, 0x60, 0x07, 0x00, 0x40 };
  const unsigned char scan_failed_too_short2[] = { 0x03, 0x61, 0x07, 0x00, 0x41 };
  const unsigned char scan_failed_too_fast[] = { 0x03, 0x20, 0x07, 0x00, 0x00 };

  if (sizeof (waiting_finger) == interrupt_size &&
      memcmp (waiting_finger, interrupt, interrupt_size) == 0)
    {
      fp_info ("Waiting for finger...");
      return VFS_SCAN_WAITING_FOR_FINGER;
    }

  if (expected_size == interrupt_size &&
      memcmp (finger_down_prefix, interrupt, sizeof (finger_down_prefix)) == 0)
    {
      fp_info ("Finger is on the sensor...");
      return VFS_SCAN_FINGER_ON_SENSOR;
    }

  if (sizeof (scanning_prints) == interrupt_size &&
      memcmp (scanning_prints, interrupt, interrupt_size) == 0)
    {
      fp_info ("Scan in progress...");
      return VFS_SCAN_IN_PROGRESS;
    }

  if (sizeof (scan_completed) == interrupt_size &&
      memcmp (scan_completed, interrupt, interrupt_size) == 0)
    {
      fp_info ("Fingerprint scan completed...");
      return VFS_SCAN_COMPLETED;
    }

  if (sizeof (scan_success) == interrupt_size &&
      memcmp (scan_success, interrupt, interrupt_size) == 0)
    {
      fp_info ("Fingerprint scan success...");
      return VFS_SCAN_SUCCESS;
    }

  if (sizeof (low_quality_scan) == interrupt_size &&
      memcmp (low_quality_scan, interrupt, interrupt_size) == 0)
    {
      fp_info ("Fingerprint scan success, but low quality...");
      return VFS_SCAN_SUCCESS_LOW_QUALITY;
    }

  if (expected_size == interrupt_size &&
      memcmp (db_identified_prefix, interrupt,
              sizeof (db_identified_prefix)) == 0 &&
      memcmp (db_checked_sufix,
              interrupt + interrupt_size - sizeof (db_checked_sufix),
              sizeof (db_checked_sufix)) == 0)
    {
      fp_info ("Identified DB finger id %d", interrupt[2]);
      return VFS_SCAN_DB_MATCH_SUCCESS;
    }

  if (expected_size == interrupt_size &&
      memcmp (db_unidentified_prefix,
              interrupt, sizeof (db_unidentified_prefix)) == 0 &&
      memcmp (db_checked_sufix,
              interrupt + interrupt_size - sizeof (db_checked_sufix),
              sizeof (db_checked_sufix)) == 0)
    {
      fp_info ("Finger DB identification failed");
      return VFS_SCAN_DB_MATCH_FAILED;
    }

  if (sizeof (db_check_error) == interrupt_size &&
      memcmp (db_check_error, interrupt, interrupt_size) == 0)
    {
      fp_info ("Finger DB check error");
      return VFS_SCAN_DB_MATCH_FAILED;
    }

  if (sizeof (scan_failed_too_short) == interrupt_size &&
      memcmp (scan_failed_too_short, interrupt, interrupt_size) == 0)
    {
      fp_warn ("Impossible to read fingerprint, don't move your finger");
      return VFS_SCAN_FAILED_TOO_SHORT;
    }

  if (sizeof (scan_failed_too_short2) == interrupt_size &&
      memcmp (scan_failed_too_short2, interrupt, interrupt_size) == 0)
    {
      fp_warn ("Impossible to read fingerprint, don't move your finger (2)");
      return VFS_SCAN_FAILED_TOO_SHORT;
    }

  if (sizeof (scan_failed_too_fast) == interrupt_size &&
      memcmp (scan_failed_too_fast, interrupt, interrupt_size) == 0)
    {
      fp_warn ("Impossible to read fingerprint, movement was too fast");
      return VFS_SCAN_FAILED_TOO_FAST;
    }

  fp_err ("Interrupt not tracked, please report!");
  print_hex (interrupt, interrupt_size);

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "Unknown device interrupt");

  return VFS_SCAN_UNKNOWN;
}

static void
send_init_sequence (FpiDeviceVfs0090 *vdev, FpiSsm *ssm,
                    int sequence)
{
  do_data_exchange (vdev, ssm, &INIT_SEQUENCES[sequence], DATA_EXCHANGE_PLAIN);
}

static void
init_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  VfsInit *vinit = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case INIT_STATE_GENERATE_MAIN_SEED:
      generate_main_seed (dev, vinit);
      fpi_ssm_next_state (ssm);
      break;

    case INIT_STATE_SEQ_2:
      if (vdev->buffer_length == 38)
        {
          if (vdev->buffer[vdev->buffer_length - 1] != 0x07)
            {
              error = fpi_device_error_new_msg (
                FP_DEVICE_ERROR_NOT_SUPPORTED,
                "Sensor not initialized, init byte is 0x%x " \
                "(should be 0x07 on initialized devices, 0x02 otherwise)\n" \
                "This is a driver in beta state and the device needs to be" \
                "paired using external tools to load a non-free firmware.\n " \
                "This can be done natively on Linux using the " \
                "validity-sensors-tools, available at " \
                "https://snapcraft.io/validity-sensors-tools\n" \
                "Otherwise it's possible to use a VirtualBox VM running "
                "Windows, or a native Windows installation.",
                vdev->buffer[vdev->buffer_length - 1]);
              fp_warn ("%s", error->message);
              fpi_ssm_mark_failed (ssm, error);
              break;
            }
        }
      else
        {
          fp_warn ("Unknown reply at init stage %d, retrying...",
                   fpi_ssm_get_cur_state (ssm));
          fpi_ssm_jump_to_state (ssm, INIT_STATE_SEQ_1);
          break;
        }

    case INIT_STATE_SEQ_1:
    case INIT_STATE_SEQ_3:
    case INIT_STATE_SEQ_4:
    case INIT_STATE_SEQ_5:
    case INIT_STATE_SEQ_6:
      send_init_sequence (vdev, ssm, fpi_ssm_get_cur_state (ssm) - INIT_STATE_SEQ_1);
      break;

    case INIT_STATE_MASTER_KEY:
      TLS_PRF2 (PRE_KEY, sizeof (PRE_KEY), "GWK", vinit->main_seed,
                vinit->main_seed_length,
                vinit->masterkey_aes, VFS_MASTER_KEY_SIZE);

      fpi_ssm_next_state (ssm);
      break;

    case INIT_STATE_ECDSA_KEY:
      if (make_ecdsa_key (vinit, vdev->buffer))
        {
          fpi_ssm_next_state (ssm);
        }
      else if (memcmp (TEST_SEED, vinit->main_seed, vinit->main_seed_length) != 0)
        {
          fp_info ("Failed using system seed for ECDSA key generation, "
                   "trying with a VirtualBox one");

          g_clear_pointer (&vinit->main_seed, g_free);
          vinit->main_seed = g_malloc (sizeof (TEST_SEED));
          memcpy (vinit->main_seed, TEST_SEED, sizeof (TEST_SEED));
          vinit->main_seed_length = sizeof (TEST_SEED);

          fpi_ssm_jump_to_state (ssm, INIT_STATE_MASTER_KEY);
        }
      else
        {
          error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                            "Initialization failed at state %d, "
                                            "ECDSA key generation",
                                            fpi_ssm_get_cur_state (ssm));
          fpi_ssm_mark_failed (ssm, error);
        }
      break;

    case INIT_STATE_TLS_CERT:
      memcpy (vinit->tls_certificate, TLS_CERTIFICATE_BASE,
              G_N_ELEMENTS (TLS_CERTIFICATE_BASE));
      memcpy (vinit->tls_certificate + 21, vdev->buffer + 0x116, 0xb8);

      fpi_ssm_next_state (ssm);
      break;

    case INIT_STATE_PUBLIC_KEY:
      {
        const int half_key = VFS_PUBLIC_KEY_SIZE / 2;
        memcpy (vinit->pubkey, vdev->buffer + 0x600 + 10, half_key);
        memcpy (vinit->pubkey + half_key, vdev->buffer + 0x640 + 0xe, half_key);

        reverse_mem (vinit->pubkey, half_key);
        reverse_mem (vinit->pubkey + half_key, half_key);

        fpi_ssm_next_state (ssm);
        break;
      }

    case INIT_STATE_HANDSHAKE:
      start_handshake_ssm (dev, ssm, vinit);
      break;

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown init state");
      fpi_ssm_mark_failed (ssm, error);
    }
}

/* Callback for dev_open ssm */
static void
dev_open_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  /* Notify open complete */
  if (error)
    fpi_device_action_error (dev, error);

  if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    fpi_device_open_complete (dev, error);
  else
    vfs0090_deinit (FPI_DEVICE_VFS0090 (dev), NULL);
}

static gboolean
vfs0090_init (FpiDeviceVfs0090 *vdev)
{
  FpDevice *dev = FP_DEVICE (vdev);
  GUsbDevice *udev;
  GError *error = NULL;
  SECStatus secs_status;
  int usb_config;

  fp_dbg ("Initializing device");

  udev = fpi_device_get_usb_device (dev);

  if (!usb_operation (g_usb_device_reset (udev, &error), dev, &error))
    return FALSE;

  usb_config = g_usb_device_get_configuration (udev, &error);
  if (!usb_operation (error == NULL, dev, &error))
    return FALSE;

  if (usb_config != 1)
    if (!usb_operation (g_usb_device_set_configuration (udev, 1, &error), dev, &error))
      return FALSE;

  if (!usb_operation (g_usb_device_claim_interface (udev, 0, 0, &error), dev, &error))
    return FALSE;

  secs_status = NSS_NoDB_Init (NULL);
  if (secs_status != SECSuccess)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "could not initialise NSS");
      fp_err ("%s", error->message);
      fpi_device_action_error (dev, error);
      return FALSE;
    }

  OpenSSL_add_all_algorithms ();
  ERR_load_crypto_strings ();

  /* Initialize private structure */
  vdev->buffer = g_malloc (VFS_USB_BUFFER_SIZE);
  vdev->buffer_length = 0;

  return TRUE;
}

/* Open device */
static void
dev_open (FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpiSsm *ssm;

  if (!vfs0090_init (vdev))
    return;

  /* Clearing previous device state */
  ssm = fpi_ssm_new (dev, init_ssm, INIT_STATE_LAST);
  fpi_ssm_set_data (ssm, g_new0 (VfsInit, 1), (GDestroyNotify) vfs_init_free);
  fpi_ssm_start (ssm, dev_open_callback);
}

static void
led_blink_callback_with_ssm (FpiUsbTransfer *transfer, FpDevice *dev,
                             gpointer data, GError *error)
{
  FpiSsm *ssm = data;

  if (!error)
    {
      fpi_ssm_next_state_delayed (ssm, 200, NULL);
    }
  else
    {
      /* NO need to fail here, it's not a big issue... */
      fp_err ("LED blinking failed with error %s", error->message);
      fpi_ssm_next_state (ssm);
    }
}

static void
restart_scan_or_deactivate (FpiDeviceVfs0090 *vdev)
{
  FpDevice *dev = FP_DEVICE (vdev);

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL &&
      vdev->enroll_stage < fp_device_get_nr_enroll_stages (dev))
    start_reactivate_ssm (dev);
  else
    dev_deactivate (dev);
}

static gboolean
vfs_device_supports_capture (FpDevice *dev)
{
  if (!fp_device_supports_capture (dev))
    return FALSE;

  return fpi_device_get_driver_data (dev) == FPI_DEVICE_ACTION_CAPTURE;
}

static gboolean
scan_action_succeeded (FpiDeviceVfs0090 *vdev)
{
  return !vdev->action_error && vdev->match_result == FPI_MATCH_SUCCESS;
}

static gboolean
finger_db_check_fallbacks_to_image (FpiDeviceVfs0090 *vdev)
{
  FpDevice *dev = FP_DEVICE (vdev);
  FpiDeviceAction action;

  if (!vfs_device_supports_capture (dev))
    return FALSE;

  if (scan_action_succeeded (vdev))
    return FALSE;

  action = fpi_device_get_current_action (dev);

  return action == FPI_DEVICE_ACTION_ENROLL ||
         action == FPI_DEVICE_ACTION_IDENTIFY;
}

static void
finger_db_check_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpiSsm *parent_ssm = fpi_ssm_get_data (ssm);

  if (!error)
    {
      if (finger_db_check_fallbacks_to_image (vdev))
        {
          /* In these cases we may still have failed the DB identification, but
          * we may still re-use the image-verification and so let's try agin */
          vdev->db_has_prints = FALSE;
          fpi_ssm_jump_to_state (parent_ssm, IMAGE_DOWNLOAD_STATE_SUBMIT_IMAGE);
          vdev->db_has_prints = TRUE;
        }
      else
        {
          fpi_ssm_mark_completed (parent_ssm);
        }
    }
  else
    {
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        fp_err ("Scan failed failed at state %d, unexpected"
                "device reply during db check", fpi_ssm_get_cur_state (ssm));
      fpi_ssm_mark_failed (parent_ssm, error);
    }
}

/* Remove once included in TOD */
static gchar *
_fpi_print_generate_user_id (FpPrint *print)
{
  const gchar *username = NULL;
  gchar *user_id = NULL;
  const GDate *date;
  gint y = 0, m = 0, d = 0;
  gint32 rand_id = 0;

  g_assert (print);
  date = fp_print_get_enroll_date (print);
  if (date && g_date_valid (date))
    {
      y = g_date_get_year (date);
      m = g_date_get_month (date);
      d = g_date_get_day (date);
    }

  username = fp_print_get_username (print);
  if (!username)
    username = "nobody";

  if (g_strcmp0 (g_getenv ("FP_DEVICE_EMULATION"), "1") == 0)
    rand_id = 0;
  else
    rand_id = g_random_int ();

  user_id = g_strdup_printf ("FP1-%04d%02d%02d-%X-%08X-%s",
                             y, m, d,
                             fp_print_get_finger (print),
                             rand_id,
                             username);

  return user_id;

}

static void
handle_db_match_reply (FpiDeviceVfs0090 *vdev, FpiMatchResult result)
{
  FpDevice *dev = FP_DEVICE (vdev);
  FpiDeviceAction action;

  vdev->match_result = result;
  action = fpi_device_get_current_action (dev);

  switch (action)
    {
    case FPI_DEVICE_ACTION_ENROLL:
      {
        g_autofree gchar *user_id = NULL;
        VfsDbIdentifyInterrupt *identification;
        FpPrint *print;
        GVariant *data;

        if (vdev->match_result != FPI_MATCH_SUCCESS)
          {
            fp_dbg ("Finger doesn't match any enrolled finger in DB");

            if (vfs_device_supports_capture (dev))
              /* Returning here will cause fallig back to image enrolling  */
              return;

            /* We don't want to retry enrollment in this case, there's no point */
            vdev->enroll_stage = fp_device_get_nr_enroll_stages (dev);
            vdev->action_error =
              fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                        "This device currently only supports enrolling fingers " \
                                        "that have been previously enrolled using external " \
                                        "tools, use validity-sensors-tools, available at " \
                                        "https://snapcraft.io/validity-sensors-tools\n" \
                                        "Otherwise it's possible to use a VirtualBox VM running "
                                        "Windows, or a native Windows installation.");
            return;
          }

        while (vdev->enroll_stage < fp_device_get_nr_enroll_stages (dev))
          {
            /* Not nice, but we can't change the enroll stages at this point */
            vdev->enroll_stage++;
            fpi_device_enroll_progress (dev, vdev->enroll_stage,
                                        NULL, NULL);
          }

        g_assert_true (vdev->buffer_length == sizeof (VfsDbIdentifyInterrupt));
        identification = ((VfsDbIdentifyInterrupt *) (vdev->buffer));

        fpi_device_get_enroll_data (dev, &print);
        user_id = _fpi_print_generate_user_id (print);
        data = g_variant_new ("(us)", identification->finger_id, user_id);

        fpi_print_set_type (print, FPI_PRINT_RAW);
        fpi_print_set_device_stored (print, TRUE);

        fp_dbg ("Enrolling finger id %d (%s)", identification->finger_id, user_id);

        g_object_set (print, "fpi-data", data, NULL);
        g_object_set (print, "description", user_id, NULL);

        g_set_object (&vdev->enrolled_print, print);
        break;
      }

    case FPI_DEVICE_ACTION_VERIFY:
      {
        g_autoptr(GVariant) data = NULL;
        FpPrint *print;
        const char *user_id;
        guint matched_finger_id;
        guint finger_id;

        if (vdev->match_result != FPI_MATCH_SUCCESS)
          {
            fpi_device_verify_report (dev, vdev->match_result, NULL, NULL);
            return;
          }

        fpi_device_get_verify_data (dev, &print);
        g_object_get (print, "fpi-data", &data, NULL);
        g_variant_get (data, "(u&s)", &finger_id, &user_id);

        g_assert_true (vdev->buffer_length > 3);
        matched_finger_id = vdev->buffer[2];

        if (matched_finger_id != finger_id)
          vdev->match_result = FPI_MATCH_FAIL;

        fp_dbg ("Verifing template for finger id %d (%s): %s", finger_id, user_id,
                vdev->match_result == FPI_MATCH_SUCCESS ? "match" : "no-match");

        fpi_device_verify_report (dev, vdev->match_result, NULL, NULL);
        break;
      }

    case FPI_DEVICE_ACTION_IDENTIFY:
      {
        gint i;
        GPtrArray *templates;
        FpPrint *identified = NULL;
        guint matched_finger_id;
        gboolean have_image_prints;

        fpi_device_get_identify_data (dev, &templates);

        have_image_prints = FALSE;
        if (vfs_device_supports_capture (dev))
          {
            for (i = 0; i < templates->len; i++)
              {
                FpPrint *template = g_ptr_array_index (templates, i);

                if (!fp_print_get_device_stored (template))
                  {
                    have_image_prints = TRUE;
                    break;
                  }
              }
          }

        if (vdev->match_result != FPI_MATCH_SUCCESS)
          {
            if (have_image_prints)
              {
                /* The gallery contains other prints that are not stored in
                 * device, so we need to fallback to image analisys for them */
                fp_dbg ("Chip verification failed, falling back to host matching");
                return;
              }

            /* The identification gallery has no other valid prints, so we can
             * just stop early without bothering the image check, if any,
             * thus we set the local match result as success, so that we can
             * stop further checks */
            fp_dbg ("Chip verification failed");
            fpi_device_identify_report (dev, NULL, NULL, NULL);
            vdev->match_result = FPI_MATCH_SUCCESS;
            return;
          }

        g_assert_true (vdev->buffer_length > 3);
        matched_finger_id = vdev->buffer[2];

        for (i = 0; i < templates->len; i++)
          {
            FpPrint *template = g_ptr_array_index (templates, i);
            GVariant *data;
            const char *user_id;
            guint finger_id;

            if (!fp_print_get_device_stored (template))
              continue;

            g_object_get (template, "fpi-data", &data, NULL);
            g_variant_get (data, "(u&s)", &finger_id, &user_id);

            if (matched_finger_id == finger_id)
              {
                identified = template;
                break;
              }
          }

        vdev->match_result = identified ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL;
        if (vdev->match_result == FPI_MATCH_FAIL && have_image_prints)
          {
            /* The gallery contains other prints that are not stored in
             * device, so we need to fallback to image analisys for them */
            fp_dbg ("Chip verification failed, falling back to host matching");
            return;
          }

        fpi_device_identify_report (dev, identified, NULL, NULL);
        fp_dbg ("Identifying finger id %d: %s", matched_finger_id,
                vdev->match_result == FPI_MATCH_SUCCESS ? "match" : "no-match");

        /* The identification gallery has no other valid prints, so we can
         * just stop early without bothering the image check, if any,
         * thus we set the local match result as success, so that we can
         * stop further checks */
        vdev->match_result = FPI_MATCH_SUCCESS;
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
send_db_check_sequence (FpiDeviceVfs0090 *vdev, FpiSsm *ssm, int sequence)
{
  do_data_exchange (vdev, ssm, &DB_IDENTIFY_SEQUENCES[sequence], DATA_EXCHANGE_ENCRYPTED);
}

static void
finger_db_check_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DB_CHECK_STATE_REQUEST:
      send_db_check_sequence (vdev, ssm, 0);
      break;

    case DB_CHECK_STATE_MATCH_RESULT_WAIT:
      async_read_from_usb (dev, FP_TRANSFER_INTERRUPT,
                           vdev->buffer, VFS_USB_INTERRUPT_BUFFER_SIZE,
                           finger_scan_interrupt_callback, ssm);
      break;

    case DB_CHECK_STATE_MATCH_SUCCESS:
      handle_db_match_reply (vdev, FPI_MATCH_SUCCESS);
      send_db_check_sequence (vdev, ssm, 1);
      break;

    case DB_CHECK_STATE_MATCH_SUCCESS_DETAILS:
      fpi_ssm_jump_to_state (ssm, DB_CHECK_STATE_MATCH_CHECK_RESULT);
      break;

    case DB_CHECK_STATE_MATCH_FAILED:
      handle_db_match_reply (vdev, FPI_MATCH_FAIL);
      fpi_ssm_jump_to_state (ssm, DB_CHECK_STATE_MATCH_CHECK_RESULT);
      break;

    case DB_CHECK_STATE_MATCH_CHECK_RESULT:
      if (scan_action_succeeded (vdev))
        {
          fpi_ssm_jump_to_state (ssm, DB_CHECK_STATE_GREEN_LED_BLINK);
        }
      else
        {
          if (finger_db_check_fallbacks_to_image (vdev))
            fpi_ssm_mark_completed (ssm);
          else
            fpi_ssm_jump_to_state (ssm, DB_CHECK_STATE_RED_LED_BLINK);
        }

      break;

    case DB_CHECK_STATE_GREEN_LED_BLINK:
      async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                           LED_GREEN_BLINK, G_N_ELEMENTS (LED_GREEN_BLINK),
                           vdev->buffer, VFS_USB_BUFFER_SIZE,
                           led_blink_callback_with_ssm, ssm);

      break;


    case DB_CHECK_STATE_RED_LED_BLINK:
      async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                           LED_RED_BLINK, G_N_ELEMENTS (LED_RED_BLINK),
                           vdev->buffer, VFS_USB_BUFFER_SIZE,
                           led_blink_callback_with_ssm, ssm);
      break;

    case DB_CHECK_STATE_AFTER_GREEN_LED_BLINK:
    case DB_CHECK_STATE_AFTER_RED_LED_BLINK:
      fpi_ssm_jump_to_state (ssm, DB_CHECK_STATE_SUBMIT_RESULT);
      break;

    case DB_CHECK_STATE_SUBMIT_RESULT:
      restart_scan_or_deactivate (vdev);
      fpi_ssm_next_state (ssm);
      break;

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown db check state %d",
                                        fpi_ssm_get_cur_state (ssm));
      fpi_ssm_mark_failed (ssm, error);
    }
}

static void
start_finger_db_check_subsm (FpDevice *dev, FpiSsm *parent_ssm)
{
  FpiSsm *ssm;

  ssm = fpi_ssm_new (dev, finger_db_check_ssm, DB_CHECK_STATE_LAST);
  fpi_ssm_set_data (ssm, parent_ssm, NULL);

  fpi_ssm_start (ssm, finger_db_check_callback);
}

typedef struct _VfsImageDownload
{
  FpiSsm       *parent_ssm;

  unsigned char image[VFS_IMAGE_SIZE * VFS_IMAGE_SIZE];
  int           image_size;
} VfsImageDownload;

static void
finger_image_download_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  VfsImageDownload *imgdown = fpi_ssm_get_data (ssm);

  if (!error)
    {
      fpi_ssm_mark_completed (imgdown->parent_ssm);
    }
  else
    {
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fp_err ("Scan failed failed at state %d, unexpected"
                  "device reply during image download",
                  fpi_ssm_get_cur_state (ssm));
        }

      fpi_ssm_mark_failed (imgdown->parent_ssm, error);
    }
}

typedef struct _VfsMinutiaeDetection
{
  FpDevice *dev;
  FpiSsm   *download_ssm;
} VfsMinutiaeDetection;

static void
minutiae_detected (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  g_autoptr(FpImage) image = FP_IMAGE (source_object);
  g_autoptr(FpPrint) print = NULL;
  g_autofree VfsMinutiaeDetection *minutiae_data = user_data;
  FpDevice *dev = minutiae_data->dev;
  FpiSsm *download_ssm = minutiae_data->download_ssm;
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GError *error = NULL;
  FpiDeviceAction action;

  if (!fp_image_detect_minutiae_finish (image, res, &error))
    {
      /* Cancel operation */
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fpi_ssm_mark_failed (download_ssm, error);
          return;
        }

      /* Replace error with a retry condition. */
      g_warning ("Failed to detect minutiae: %s", error->message);
      g_clear_pointer (&error, g_error_free);

      error = fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL,
                                        "Minutiae detection failed, please retry");
    }

  vdev->match_result = FPI_MATCH_SUCCESS;
  action = fpi_device_get_current_action (dev);

  if (action == FPI_DEVICE_ACTION_CAPTURE)
    {
      vdev->action_error = g_steal_pointer (&error);
      vdev->captured_image = g_steal_pointer (&image);

      fpi_ssm_jump_to_state (download_ssm, IMAGE_DOWNLOAD_STATE_CHECK_RESULT);
      return;
    }

  if (!error)
    {
      print = fp_print_new (dev);
      fpi_print_set_type (print, FPI_PRINT_NBIS);

      if (!fpi_print_add_from_image (print, image, &error))
        {
          g_clear_object (&print);

          if (error->domain != FP_DEVICE_RETRY)
            {
              vdev->action_error = g_steal_pointer (&error);
              fpi_ssm_jump_to_state (download_ssm, IMAGE_DOWNLOAD_STATE_CHECK_RESULT);
              return;
            }
        }
    }

  switch (action)
    {
    case FPI_DEVICE_ACTION_ENROLL:
      {
        FpPrint *enroll_print;
        fpi_device_get_enroll_data (dev, &enroll_print);

        if (print)
          {
            if (vdev->enroll_stage == 0)
              fpi_print_set_type (enroll_print, FPI_PRINT_NBIS);

            fpi_print_add_print (enroll_print, print);
            vdev->enroll_stage += 1;
          }

        g_set_object (&vdev->enrolled_print, enroll_print);
        fpi_device_enroll_progress (dev, vdev->enroll_stage,
                                    g_steal_pointer (&print), error);

        fpi_ssm_jump_to_state (download_ssm, IMAGE_DOWNLOAD_STATE_CHECK_RESULT);
        break;
      }

    case FPI_DEVICE_ACTION_VERIFY:
      {
        FpPrint *template;

        fpi_device_get_verify_data (dev, &template);
        if (print)
          vdev->match_result = fpi_print_bz3_match (template, print,
                                                    VFS_BZ3_THRESHOLD,
                                                    &error);
        else
          vdev->match_result = FPI_MATCH_ERROR;

        fp_dbg ("Verified finger %d minutiae: %s",
                fp_print_get_finger (print),
                vdev->match_result == FPI_MATCH_SUCCESS ? "match" : "no-match");

        if (!error || error->domain == FP_DEVICE_RETRY)
          fpi_device_verify_report (dev, vdev->match_result,
                                    g_steal_pointer (&print),
                                    g_steal_pointer (&error));

        vdev->action_error = g_steal_pointer (&error);
        fpi_ssm_jump_to_state (download_ssm, IMAGE_DOWNLOAD_STATE_CHECK_RESULT);
        break;
      }

    case FPI_DEVICE_ACTION_IDENTIFY:
      {
        gint i;
        GPtrArray *templates;
        FpPrint *result = NULL;

        fpi_device_get_identify_data (dev, &templates);
        for (i = 0; !error && i < templates->len; i++)
          {
            FpPrint *template = g_ptr_array_index (templates, i);

            if (fp_print_get_device_stored (template))
              continue;

            if (fpi_print_bz3_match (template, print, VFS_BZ3_THRESHOLD, &error) == FPI_MATCH_SUCCESS)
              {
                result = template;
                break;
              }
          }

        fp_dbg ("Identified finger minutiae: %s", result ? "match" : "no-match");

        if (!error || error->domain == FP_DEVICE_RETRY)
          fpi_device_identify_report (dev, result, g_steal_pointer (&print),
                                      g_steal_pointer (&error));

        vdev->action_error = g_steal_pointer (&error);
        vdev->match_result = result ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL;
        fpi_ssm_jump_to_state (download_ssm, IMAGE_DOWNLOAD_STATE_CHECK_RESULT);
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
finger_image_submit (FpDevice         *dev,
                     VfsImageDownload *imgdown,
                     FpiSsm           *download_ssm)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  VfsMinutiaeDetection *minutiae_data;
  FpImage *img;

  img = fp_image_new (VFS_IMAGE_SIZE, VFS_IMAGE_SIZE);
  img->flags = FPI_IMAGE_H_FLIPPED;
  memcpy (img->data, imgdown->image, VFS_IMAGE_SIZE * VFS_IMAGE_SIZE);

#if HAVE_PIXMAN
  if (VFS_IMAGE_RESCALE > 1)
    {
      g_autoptr(FpImage) resized = NULL;

      resized = fpi_image_resize (img, VFS_IMAGE_RESCALE, VFS_IMAGE_RESCALE);
      g_set_object (&img, resized);
    }
#endif

  minutiae_data = g_new0 (VfsMinutiaeDetection, 1);
  minutiae_data->dev = dev;
  minutiae_data->download_ssm = download_ssm;

  fp_dbg ("Detecting minutiae");
  fp_image_detect_minutiae (img,
                            vdev->cancellable,
                            minutiae_detected,
                            minutiae_data);
}

static void
finger_image_download_read_callback (FpiUsbTransfer *transfer, FpDevice *dev,
                                     gpointer data, GError *error)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpiSsm *ssm = data;
  VfsImageDownload *imgdown = fpi_ssm_get_data (ssm);
  unsigned char *image_data;
  guint16 data_size;

  if (error)
    {
      fp_err ("Image download failed at state %d", fpi_ssm_get_cur_state (ssm));
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  else if (!check_validity_reply (vdev, &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (fpi_ssm_get_cur_state (ssm) == IMAGE_DOWNLOAD_STATE_1)
    {
      Vfs0090ImageReply *img_reply = (Vfs0090ImageReply *) vdev->buffer;

      image_data = img_reply->image.image_data;
      data_size = img_reply->data_size - G_STRUCT_OFFSET (Vfs0090ImageReply, image);

      if (img_reply->width != VFS_IMAGE_SIZE || img_reply->height != VFS_IMAGE_SIZE)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                         "Unexpected image size"));
          return;
        }

      if (img_reply->image.error)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                         "Image capture failed"));
          return;
        }

      fp_dbg ("Got image of %dx%d, %d bit per pixel", img_reply->width,
              img_reply->height, img_reply->image.bit_per_pixels);
    }
  else
    {
      Vfs0090ImageChunk *img_chunk = (Vfs0090ImageChunk *) vdev->buffer;

      image_data = img_chunk->image_data;
      data_size = img_chunk->data_size;
    }

  if (image_data + data_size != vdev->buffer + vdev->buffer_length)
    {
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                     "Expected image data size mismatch"));
      return;
    }

  fp_dbg ("Getting %d bytes of image data", data_size);
  memcpy (imgdown->image + imgdown->image_size, image_data, data_size);
  imgdown->image_size += data_size;

  fpi_ssm_next_state (ssm);
}

static gboolean
use_database_matching (FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpPrint *print;

  if (!vdev->db_has_prints)
    return FALSE;

  switch (fpi_device_get_current_action (dev))
    {
    case FPI_DEVICE_ACTION_ENROLL:
      return TRUE;

    case FPI_DEVICE_ACTION_VERIFY:
      fpi_device_get_verify_data (dev, &print);
      return fp_print_get_device_stored (print);

    case FPI_DEVICE_ACTION_IDENTIFY:
      {
        unsigned int i;
        GPtrArray *templates;

        fpi_device_get_identify_data (dev, &templates);
        for (i = 0; i < templates->len; i++)
          {
            print = g_ptr_array_index (templates, i);

            if (fp_print_get_device_stored (print))
              return TRUE;
          }

        return FALSE;
      }

    default:
      return FALSE;
    }
}

static void
finger_image_download_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  VfsImageDownload *imgdown = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  const unsigned char read_buffer_request[] = {
    0x51, 0x00, 0x20, 0x00, 0x00
  };

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case IMAGE_DOWNLOAD_STATE_1:
    case IMAGE_DOWNLOAD_STATE_2:
    case IMAGE_DOWNLOAD_STATE_3:
      async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                           read_buffer_request,
                           sizeof (read_buffer_request),
                           vdev->buffer,
                           VFS_IMAGE_SIZE * VFS_IMAGE_SIZE,
                           finger_image_download_read_callback,
                           ssm);

      break;


    case IMAGE_DOWNLOAD_STATE_SUBMIT_IMAGE:
      if (use_database_matching (dev))
        start_finger_db_check_subsm (dev, ssm);
      else
        finger_image_submit (dev, imgdown, ssm);
      break;

    case IMAGE_DOWNLOAD_STATE_CHECK_RESULT:
      if (scan_action_succeeded (vdev))
        fpi_ssm_jump_to_state (ssm, IMAGE_DOWNLOAD_STATE_GREEN_LED_BLINK);
      else
        fpi_ssm_jump_to_state (ssm, IMAGE_DOWNLOAD_STATE_RED_LED_BLINK);

      break;

    case IMAGE_DOWNLOAD_STATE_GREEN_LED_BLINK:
      async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                           LED_GREEN_BLINK, G_N_ELEMENTS (LED_GREEN_BLINK),
                           vdev->buffer, VFS_USB_BUFFER_SIZE,
                           led_blink_callback_with_ssm, ssm);

      break;


    case IMAGE_DOWNLOAD_STATE_RED_LED_BLINK:
      async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                           LED_RED_BLINK, G_N_ELEMENTS (LED_RED_BLINK),
                           vdev->buffer, VFS_USB_BUFFER_SIZE,
                           led_blink_callback_with_ssm, ssm);

      break;

    case IMAGE_DOWNLOAD_STATE_AFTER_GREEN_LED_BLINK:
    case IMAGE_DOWNLOAD_STATE_AFTER_RED_LED_BLINK:
      fpi_ssm_jump_to_state (ssm, IMAGE_DOWNLOAD_STATE_SUBMIT_RESULT);
      break;

    case IMAGE_DOWNLOAD_STATE_SUBMIT_RESULT:
      restart_scan_or_deactivate (vdev);
      fpi_ssm_next_state (ssm);
      break;

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown image download state");
      fpi_ssm_mark_failed (ssm, error);
    }
}

static void
start_finger_image_download_subsm (FpDevice *dev,
                                   FpiSsm   *parent_ssm)
{
  FpiSsm *ssm;
  VfsImageDownload *imgdown;

  imgdown = g_new0 (VfsImageDownload, 1);
  imgdown->parent_ssm = parent_ssm;

  ssm = fpi_ssm_new (dev,
                     finger_image_download_ssm,
                     IMAGE_DOWNLOAD_STATE_LAST);

  fpi_ssm_set_data (ssm, imgdown, g_free);
  fpi_ssm_start (ssm, finger_image_download_callback);
}

static void
scan_error_handler_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiSsm *parent_ssm = fpi_ssm_get_data (ssm);

  if (error)
    {
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fp_err ("Scan failed failed at state %d, unexpected "
                  "device reply during scan error handling",
                  fpi_ssm_get_cur_state (ssm));
        }

      fpi_ssm_mark_failed (parent_ssm, error);
    }
  else
    {
      fpi_ssm_mark_completed (parent_ssm);
    }
}

static void
report_retry_error (FpDevice *dev, FpDeviceRetry retry)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GError *error = fpi_device_retry_new (retry);

  switch (fpi_device_get_current_action (dev))
    {
    case FPI_DEVICE_ACTION_ENROLL:
      fpi_device_enroll_progress (dev, vdev->enroll_stage, NULL, error);
      break;

    case FPI_DEVICE_ACTION_VERIFY:
      fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, error);
      break;

    case FPI_DEVICE_ACTION_IDENTIFY:
      fpi_device_identify_report (dev, NULL, NULL, error);
      break;

    default:
      fpi_device_action_error (dev, error);
    }
}

static void
scan_error_handler_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_ERROR_STATE_LED_BLINK:
      async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                           LED_RED_BLINK, G_N_ELEMENTS (LED_RED_BLINK),
                           vdev->buffer, VFS_USB_BUFFER_SIZE,
                           led_blink_callback_with_ssm, ssm);
      break;

    case SCAN_ERROR_STATE_REACTIVATE_REQUEST:
      restart_scan_or_deactivate (vdev);
      fpi_ssm_next_state (ssm);
      break;

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown scan state");
      fpi_ssm_mark_failed (ssm, error);
    }
}

static void
start_scan_error_handler_ssm (FpDevice     *dev,
                              FpiSsm       *parent_ssm,
                              FpDeviceRetry retry)
{
  FpiSsm *ssm;

  report_retry_error (dev, retry);

  ssm = fpi_ssm_new (dev, scan_error_handler_ssm,
                     SCAN_ERROR_STATE_LAST);
  fpi_ssm_set_data (ssm, parent_ssm, NULL);
  fpi_ssm_start (ssm, scan_error_handler_callback);
}

static void
finger_scan_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error && !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    {
      fp_err ("Scan failed failed at state %d, unexpected "
              "device reply during finger scanning", fpi_ssm_get_cur_state (ssm));

      fpi_device_action_error (dev, error);
    }
  else
    {
      g_clear_error (&error);
    }
}

static void
finger_scan_interrupt_callback (FpiUsbTransfer *transfer, FpDevice *dev,
                                gpointer data, GError *error)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpiSsm *ssm = data;
  int interrupt_type;

  if (!error)
    {
      interrupt_type = translate_interrupt (vdev->buffer,
                                            vdev->buffer_length,
                                            &error);
    }

  if (error)
    fpi_ssm_mark_failed (ssm, error);
  else
    fpi_ssm_jump_to_state (ssm, interrupt_type);
}

static void
finger_scan_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_STATE_FINGER_ON_SENSOR:
      fp_dbg ("Finger on sensor...");

    case SCAN_STATE_WAITING_FOR_FINGER:
    case SCAN_STATE_IN_PROGRESS:
    case SCAN_STATE_COMPLETED:
      async_read_from_usb (dev, FP_TRANSFER_INTERRUPT,
                           vdev->buffer, VFS_USB_INTERRUPT_BUFFER_SIZE,
                           finger_scan_interrupt_callback, ssm);

      break;

    case SCAN_STATE_FAILED_TOO_SHORT:
    case SCAN_STATE_FAILED_TOO_FAST:
      start_scan_error_handler_ssm (dev, ssm, FP_DEVICE_RETRY_TOO_SHORT);
      break;

    case SCAN_STATE_SUCCESS_LOW_QUALITY:
      {
        FpiDeviceAction action = fpi_device_get_current_action (dev);

        if (action == FPI_DEVICE_ACTION_ENROLL)
          {
            start_scan_error_handler_ssm (dev, ssm, FP_DEVICE_RETRY_CENTER_FINGER);
          }
        else if (action == FPI_DEVICE_ACTION_VERIFY ||
                 action == FPI_DEVICE_ACTION_IDENTIFY)
          {
            fp_warn ("Low quality image in verification, might fail");
            fpi_ssm_jump_to_state (ssm, SCAN_STATE_SUCCESS);
          }
      }
      break;

    case SCAN_STATE_SUCCESS:
      if (vfs_device_supports_capture (dev))
        start_finger_image_download_subsm (dev, ssm);
      else
        start_finger_db_check_subsm (dev, ssm);
      break;

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown scan state");
      fpi_ssm_mark_failed (ssm, error);
    }
}

static void
start_finger_scan (FpDevice *dev)
{
  FpiSsm *ssm;

  ssm = fpi_ssm_new (dev, finger_scan_ssm, SCAN_STATE_LAST);
  fpi_ssm_start (ssm, finger_scan_callback);
}

static void
send_activate_sequence (FpiDeviceVfs0090 *vdev, FpiSsm *ssm,
                        int sequence)
{
  do_data_exchange (vdev, ssm, &ACTIVATE_SEQUENCES[sequence], DATA_EXCHANGE_ENCRYPTED);
}

static void
activate_device_interrupt_callback (FpiUsbTransfer *transfer, FpDevice *dev,
                                    gpointer data, GError *error)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpiSsm *ssm = data;
  int interrupt_type;

  if (!error)
    {
      interrupt_type = translate_interrupt (vdev->buffer,
                                            vdev->buffer_length,
                                            &error);
      if (error)
        {
          fpi_ssm_mark_failed (ssm, error);
        }
      else if (interrupt_type == VFS_SCAN_WAITING_FOR_FINGER)
        {
          fpi_ssm_mark_completed (ssm);
        }
      else
        {
          error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                            "Unexpected device interrupt "
                                            "(%d) at this state",
                                            interrupt_type);
          print_hex (vdev->buffer, vdev->buffer_length);
          fpi_ssm_mark_failed (ssm, error);
        }
    }
  else
    {
      fpi_ssm_mark_failed (ssm, error);
    }
}

static void
activate_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_STATE_CHECK_DB:

      if (!vdev->db_checked)
        {
          fp_dbg ("Checking internal database for previously saved fingers");

          async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                               DB_DUMP_STGWINDSOR,
                               G_N_ELEMENTS (DB_DUMP_STGWINDSOR),
                               vdev->buffer, VFS_USB_BUFFER_SIZE,
                               async_transfer_callback_with_ssm, ssm);
        }
      else
        {
          fpi_ssm_jump_to_state (ssm, ACTIVATE_STATE_GREEN_LED_ON);
        }
      break;

    case ACTIVATE_STATE_CHECK_DB_DONE:
      vdev->db_checked = TRUE;

      if (vdev->buffer_length > 4 &&
          vdev->buffer[0] == 0x00 && vdev->buffer[1] == 0x00)
        {
          fp_dbg ("Enrolled fingers found in the internal memory");
          vdev->db_has_prints = TRUE;
        }
      else
        {
          fp_dbg ("No enrolled fingers found in the internal memory");
          vdev->db_has_prints = FALSE;
        }

      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_STATE_GREEN_LED_ON:
      async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                           LED_GREEN_ON, G_N_ELEMENTS (LED_GREEN_ON),
                           vdev->buffer, VFS_USB_BUFFER_SIZE,
                           async_transfer_callback_with_ssm, ssm);
      break;

    case ACTIVATE_STATE_SEQ_1:
    case ACTIVATE_STATE_SEQ_2:
    case ACTIVATE_STATE_SEQ_3:
    case ACTIVATE_STATE_SEQ_4:
    case ACTIVATE_STATE_SEQ_5:
    case ACTIVATE_STATE_SEQ_6:
    case ACTIVATE_STATE_SEQ_7:
    case ACTIVATE_STATE_SCAN_MATRIX:
      send_activate_sequence (vdev, ssm, fpi_ssm_get_cur_state (ssm) - ACTIVATE_STATE_SEQ_1);
      break;

    case ACTIVATE_STATE_WAIT_DEVICE:
      if (check_data_exchange (vdev, &MATRIX_ALREADY_ACTIVATED_DEX))
        {
          fp_info ("Waiting for device not needed, already active");
          fpi_ssm_next_state (ssm);
          break;
        }

      async_read_from_usb (dev, FP_TRANSFER_INTERRUPT,
                           vdev->buffer, VFS_USB_INTERRUPT_BUFFER_SIZE,
                           activate_device_interrupt_callback, ssm);
      break;

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown activation state");
      fpi_ssm_mark_failed (ssm, error);
    }
}

/* Callback for dev_activate ssm */
static void
dev_activate_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);

  if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) && error)
    fp_err ("Activation failed failed at state %d, unexpected "
            "device reply during activation", fpi_ssm_get_cur_state (ssm));

  vdev->activated = TRUE;

  start_finger_scan (dev);
}

static void
dev_activate (FpDevice *dev)
{
  FpiSsm *ssm;
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  if (action == FPI_DEVICE_ACTION_CAPTURE)
    {
      gboolean wait_for_finger;

      if (!vfs_device_supports_capture (dev))
        {
          fpi_device_action_error (dev,
                                   fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
          return;
        }

      fpi_device_get_capture_data (dev, &wait_for_finger);

      if (!wait_for_finger)
        {
          fpi_device_action_error (dev,
                                   fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
          return;
        }
    }

  ssm = fpi_ssm_new (dev, activate_ssm, ACTIVATE_STATE_LAST);
  fpi_ssm_start (ssm, dev_activate_callback);
}

static void
send_deactivate_sequence (FpiDeviceVfs0090 *vdev, FpiSsm *ssm,
                          int sequence)
{
  do_data_exchange (vdev, ssm, &DEACTIVATE_SEQUENCES[sequence], DATA_EXCHANGE_ENCRYPTED);
}

static void
deactivate_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DEACTIVATE_STOP_TRANSFER:
      g_cancellable_cancel (vdev->cancellable);
      g_clear_object (&vdev->cancellable);

      fpi_ssm_next_state (ssm);
      break;

    case DEACTIVATE_STATE_SEQ_1:
      send_deactivate_sequence (vdev, ssm, fpi_ssm_get_cur_state (ssm) - DEACTIVATE_STATE_SEQ_1);
      break;

    case DEACTIVATE_STATE_LED_OFF:
      async_data_exchange (dev, DATA_EXCHANGE_ENCRYPTED,
                           LED_OFF, G_N_ELEMENTS (LED_OFF),
                           vdev->buffer, VFS_USB_BUFFER_SIZE,
                           async_transfer_callback_with_ssm, ssm);
      break;

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown deactivate state");
      fpi_ssm_mark_failed (ssm, error);
    }
}

static void
dev_deactivate_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);

  if (error)
    {
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fp_err ("Deactivation failed at state %d, unexpected "
                  "device reply during deactivation",
                  fpi_ssm_get_cur_state (ssm));
        }

      fpi_device_action_error (dev, g_steal_pointer (&error));
    }
  else if (vdev->action_error)
    {
      fpi_device_action_error (dev, g_steal_pointer (&vdev->action_error));
    }
  else
    {
      switch (fpi_device_get_current_action (dev))
        {
        case FPI_DEVICE_ACTION_NONE:
          break;

        case FPI_DEVICE_ACTION_ENROLL:
          fpi_device_enroll_complete (dev,
                                      g_steal_pointer (&vdev->enrolled_print),
                                      NULL);
          break;

        case FPI_DEVICE_ACTION_CAPTURE:
          fpi_device_capture_complete (dev,
                                       g_steal_pointer (&vdev->captured_image),
                                       NULL);
          break;

        case FPI_DEVICE_ACTION_VERIFY:
          fpi_device_verify_complete (dev, NULL);
          break;

        case FPI_DEVICE_ACTION_IDENTIFY:
          fpi_device_identify_complete (dev, NULL);
          break;

        default:
          g_assert_not_reached ();
        }
    }

  g_clear_object (&vdev->cancellable);
  g_clear_object (&vdev->enrolled_print);
  g_clear_object (&vdev->captured_image);
  g_clear_error (&vdev->action_error);

  vdev->deactivating = FALSE;
  vdev->activated = FALSE;
}

static void
dev_deactivate (FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  FpiSsm *ssm;

  if (vdev->deactivating)
    return;

  vdev->deactivating = TRUE;
  ssm = fpi_ssm_new (dev, deactivate_ssm,
                     DEACTIVATE_STATE_LAST);
  fpi_ssm_start (ssm, dev_deactivate_callback);
}

static void
reactivate_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiSsm *child_ssm = NULL;
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case REACTIVATE_STATE_WAIT:
      fpi_ssm_next_state_delayed (ssm, 100, NULL);
      break;

    case REACTIVATE_STATE_DEACTIVATE:
      child_ssm = fpi_ssm_new (dev, deactivate_ssm,
                               DEACTIVATE_STATE_LAST);
      break;

    case REACTIVATE_STATE_ACTIVATE:
      child_ssm = fpi_ssm_new (dev, activate_ssm,
                               ACTIVATE_STATE_LAST);
      break;

    case REACTIVATE_STATE_SCAN:
      start_finger_scan (dev);
      fpi_ssm_next_state (ssm);
      break;

    default:
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Unknown reactivate state");
      fpi_ssm_mark_failed (ssm, error);
    }

  if (child_ssm)
    fpi_ssm_start_subsm (ssm, child_ssm);
}

static void
reactivate_ssm_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    fpi_device_action_error (dev, error);
}

static void
start_reactivate_ssm (FpDevice *dev)
{
  FpiSsm *ssm;

  ssm = fpi_ssm_new (dev, reactivate_ssm,
                     REACTIVATE_STATE_LAST);
  fpi_ssm_start (ssm, reactivate_ssm_callback);
}

static gboolean
vfs0090_deinit (FpiDeviceVfs0090 *vdev, GError **error)
{
  GUsbDevice *udev = fpi_device_get_usb_device (FP_DEVICE (vdev));

  NSS_Shutdown ();
  ERR_free_strings ();
  EVP_cleanup ();

  g_clear_pointer (&vdev->buffer, g_free);
  vdev->buffer_length = 0;

  return g_usb_device_release_interface (udev, 0, 0, error);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GError *error = NULL;

  vfs0090_deinit (vdev, &error);
  fpi_device_close_complete (dev, error);
}

static void
dev_probe_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  GUsbDevice *usb_dev;

  usb_dev = fpi_device_get_usb_device (dev);

  if (error)
    {
      fpi_device_probe_complete (dev, NULL, NULL, error);
      g_usb_device_close (usb_dev, NULL);
      vfs0090_deinit (vdev, NULL);
      return;
    }

  if (!vfs0090_deinit (vdev, &error))
    {
      usb_operation (g_usb_device_close (usb_dev, &error), dev, &error);
      return;
    }

  if (!usb_operation (g_usb_device_close (usb_dev, &error), dev, &error))
    return;

  fpi_device_probe_complete (dev, NULL, NULL, error);
}

static void
dev_probe (FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);
  g_autofree gchar *serial = NULL;
  GError *error = NULL;
  GUsbDevice *usb_dev;
  FpiSsm *ssm;

  usb_dev = fpi_device_get_usb_device (dev);
  if (!usb_operation (g_usb_device_open (usb_dev, &error), dev, &error))
    return;

  if (!vfs0090_init (vdev))
    {
      usb_operation (g_usb_device_close (usb_dev, &error), dev, &error);
      return;
    }

  ssm = fpi_ssm_new (dev, init_ssm, PROBE_STATE_LAST);
  fpi_ssm_set_data (ssm, g_new0 (VfsInit, 1), (GDestroyNotify) vfs_init_free);
  fpi_ssm_start (ssm, dev_probe_callback);
}

static void
dev_cancel (FpDevice *dev)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (dev);

  if (!fp_device_is_open (dev))
    {
      g_cancellable_cancel (vdev->cancellable);
      return;
    }

  if (!vdev->activated)
    {
      GError *error = NULL;

      g_cancellable_cancel (vdev->cancellable);

      if (!vfs0090_deinit (vdev, &error))
        fpi_device_action_error (dev, error);
      return;
    }

  if (vdev->deactivating && vdev->action_error)
    return;

  g_set_error (&vdev->action_error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
               "Device action cancelled");

  dev_deactivate (dev);
}

/* Usb id table of device */
static const FpIdEntry id_table[] = {
  { .vid = 0x138a, .pid = 0x0090, .driver_data = FPI_DEVICE_ACTION_CAPTURE },
  { .vid = 0x138a, .pid = 0x0097, .driver_data = FPI_DEVICE_ACTION_NONE },
  { .vid = 0,  .pid = 0, .driver_data = 0 },
};

static void
fpi_device_vfs0090_init (FpiDeviceVfs0090 *vdev)
{
  FpDevice *dev = FP_DEVICE (vdev);

  if (!vfs_device_supports_capture (dev))
    fpi_device_set_nr_enroll_stages (dev, 1);
}

static void
fpi_device_vfs0090_dispose (GObject *object)
{
  FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090 (object);

  g_clear_pointer (&vdev->buffer, g_free);

  G_OBJECT_CLASS (fpi_device_vfs0090_parent_class)->dispose (object);
}

static void
fpi_device_vfs0090_class_init (FpiDeviceVfs0090Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = fpi_device_vfs0090_dispose;

  dev_class->id = "vfs0090";
  dev_class->full_name = "Validity VFS0090";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = 5;
  dev_class->probe = dev_probe;

  dev_class->open = dev_open;
  dev_class->close = dev_close;

  dev_class->enroll = dev_activate;
  dev_class->verify = dev_activate;
  dev_class->identify = dev_activate;
  dev_class->capture = dev_activate;
  dev_class->cancel = dev_cancel;
}
