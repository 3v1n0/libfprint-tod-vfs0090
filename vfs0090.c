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

#include "fp-device.h"
#include "fpi-device.h"
#include "fpi-image-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"
#define FP_COMPONENT "vfs0090"

// #include "fpi-device.h"
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
#include <stdio.h>
#include <string.h>

#include "vfs0090.h"

#define STRINGIZE(s) #s
#define EP_IN (1 | FPI_USB_ENDPOINT_IN)
#define EP_OUT (1 | FPI_USB_ENDPOINT_OUT)
#define VFS0090_TRANSFER_TYPE_INTERRUPT 3 /* Matches LIBUSB_TRANSFER_TYPE_INTERRUPT */
#define EP_INTERRUPT (VFS0090_TRANSFER_TYPE_INTERRUPT | FPI_USB_ENDPOINT_IN)

/* The main driver structure */
struct _FpiDeviceVfs0090 {
	FpImageDevice parent;
	gboolean activated;
	gboolean deactivating;

	/* Buffer for saving usb data through states */
	unsigned char *buffer;
	int buffer_length;

	/* TLS keyblock for current session */
	unsigned char key_block[0x120];

	/* Current action cancellable */
	GCancellable *cancellable;
};

G_DEFINE_TYPE (FpiDeviceVfs0090, fpi_device_vfs0090, FP_TYPE_IMAGE_DEVICE)

struct vfs_init_t {
	unsigned char *main_seed;
	unsigned int main_seed_length;
	unsigned char pubkey[VFS_PUBLIC_KEY_SIZE];
	unsigned char ecdsa_private_key[VFS_ECDSA_PRIVATE_KEY_SIZE];
	unsigned char masterkey_aes[VFS_MASTER_KEY_SIZE];
	unsigned char tls_certificate[G_N_ELEMENTS(TLS_CERTIFICATE_BASE)];
};

static void vfs_init_free(struct vfs_init_t *vinit)
{
	g_clear_pointer(&vinit->main_seed, g_free);
	g_free(vinit);
}

/* DEBUGGG */
#include <stdio.h>

static void print_hex_gn(unsigned char *data, int len, int sz) {
	if (!len || !data)
		return;

	for (int i = 0; i < len; i++) {
		if ((i % 16) == 0) {
			if (i != 0) {
				printf(" | ");
				for (int j = i-16; j < i; ++j)
					printf("%c", isprint(data[j * sz]) ? data[j * sz] : '.');
				printf("\n");
			}
			printf("%04x ", i);
		} else if ((i % 8) == 0) {
			printf(" ");
		}
		printf("%02x ", data[i * sz]);
	}

	if (((len-1) % 16) != 0) {
		int j;
		int missing_bytes = (15 - (len-1) % 16);
		int missing_spaces = missing_bytes * 3 + (missing_bytes >= 8 ? 1 : 0);

		for (int i = 0; i < missing_spaces; ++i)
			printf(" ");

		printf(" | ");

		for (j = len-1; j > 0 && (j % 16) != 0; --j);
		for (; j < len; ++j)
			printf("%c", isprint(data[j * sz]) ? data[j * sz] : '.');
	}
	puts("");
}

static void print_hex_string(char *data, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x", data[i]);
	}
	puts("");
}

static void print_hex(unsigned char *data, int len) {
	print_hex_gn(data, len, 1);
}

static void start_reactivate_ssm(FpDevice *dev);

/* remove emmmeeme */
static unsigned char *tls_encrypt(FpImageDevice *idev,
				  const unsigned char *data, int data_size,
				  int *encrypted_len_out);
static gboolean tls_decrypt(FpImageDevice *idev,
			    const unsigned char *buffer, int buffer_size,
			    unsigned char *output_buffer, int *output_len);

typedef void (*async_operation_cb)(FpImageDevice *idev, gpointer data, GError *error);

struct async_usb_operation_data_t {
	async_operation_cb callback;
	void *callback_data;
};

static void async_write_callback(FpiUsbTransfer *transfer, FpDevice *device,
				 gpointer user_data, GError *error)
{
	g_autofree struct async_usb_operation_data_t *op_data = user_data;
	FpiDeviceVfs0090 *vdev;

	if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		fp_dbg("USB write transfer cancelled");
		goto out;
	}

	vdev = FPI_DEVICE_VFS0090(device);
	g_clear_object(&vdev->cancellable);

	if (error) {
		fp_err("USB write transfer error: %s", error->message);
		goto out;
	}

	if (transfer->actual_length != transfer->length) {
		error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
						  "Written only %lu of %lu bytes",
						  transfer->length,
						  transfer->actual_length);
		fp_err("%s", error->message);
	}

out:
	if (op_data && op_data->callback)
		op_data->callback(FP_IMAGE_DEVICE(device), op_data->callback_data, error);
	else if (error)
		fpi_image_device_session_error(FP_IMAGE_DEVICE(device), error);
}

static void async_write_to_usb(FpImageDevice *idev,
			       const unsigned char *data, int data_size,
			       async_operation_cb callback, void* callback_data)
{
	struct async_usb_operation_data_t *op_data;
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	FpiUsbTransfer *transfer;

	g_assert_true(!vdev->cancellable ||
	              g_cancellable_is_cancelled(vdev->cancellable));

	op_data = g_new0(struct async_usb_operation_data_t, 1);
	op_data->callback = callback;
	op_data->callback_data = callback_data;

	transfer = fpi_usb_transfer_new(FP_DEVICE(idev));
	fpi_usb_transfer_fill_bulk_full(transfer, EP_OUT,
					(guint8 *) data, data_size, NULL);

	g_set_object(&vdev->cancellable, g_cancellable_new ());
	fpi_usb_transfer_submit(transfer, VFS_USB_TIMEOUT,
				vdev->cancellable,
				async_write_callback, op_data);
}

static void async_read_callback(FpiUsbTransfer *transfer, FpDevice *device,
				gpointer user_data, GError *error)
{
	g_autofree struct async_usb_operation_data_t *op_data = user_data;
	FpiDeviceVfs0090 *vdev;

	if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		fp_dbg("USB read transfer cancelled");
		goto out;
	}

	vdev = FPI_DEVICE_VFS0090(device);
	vdev->buffer_length = 0;
	g_clear_object(&vdev->cancellable);

	if (error) {
		fp_err("USB read transfer error: %s",
		       error->message);
		goto out;
	}

	vdev->buffer_length = transfer->actual_length;

out:
	if (op_data && op_data->callback)
		op_data->callback(FP_IMAGE_DEVICE(device), op_data->callback_data, error);
	else if (error)
		fpi_image_device_session_error(FP_IMAGE_DEVICE(device), error);
}

static void async_read_from_usb(FpImageDevice *idev, FpiTransferType transfer_type,
				unsigned char *buffer, int buffer_size,
				async_operation_cb callback, void* callback_data)
{
	struct async_usb_operation_data_t *op_data;
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	FpiUsbTransfer *transfer;
	guint timeout = VFS_USB_TIMEOUT;

	g_assert_true(!vdev->cancellable ||
	              g_cancellable_is_cancelled(vdev->cancellable));

	transfer = fpi_usb_transfer_new(FP_DEVICE(idev));
	g_set_object(&vdev->cancellable, g_cancellable_new());

	op_data = g_new0(struct async_usb_operation_data_t, 1);
	op_data->callback = callback;
	op_data->callback_data = callback_data;

	switch (transfer_type) {
	case FP_TRANSFER_INTERRUPT:
		timeout = 0;
		fpi_usb_transfer_fill_interrupt_full (transfer,
						      EP_INTERRUPT, buffer,
						      buffer_size, NULL);
		break;
	case FP_TRANSFER_BULK:
		fpi_usb_transfer_fill_bulk_full(transfer, EP_IN,
						(guint8 *) buffer, buffer_size, NULL);
		break;
	default:
		g_assert_not_reached();
	}

	fpi_usb_transfer_submit(transfer, timeout,
				vdev->cancellable,
				async_read_callback, op_data);
}

struct async_usb_encrypted_operation_data_t {
	async_operation_cb callback;
	void *callback_data;

	unsigned char *encrypted_data;
	int encrypted_data_size;
};

static void async_write_encrypted_callback(FpImageDevice *idev, gpointer data, GError *error)
{
	g_autofree struct async_usb_encrypted_operation_data_t *enc_op = data;

	if (enc_op->callback)
		enc_op->callback(idev, enc_op->callback_data, error);

	g_clear_pointer(&enc_op->encrypted_data, g_free);
}

static void async_write_encrypted_to_usb(FpImageDevice *idev,
					 const unsigned char *data,
					 int data_size,
					 async_operation_cb callback,
					 void* callback_data)
{
	struct async_usb_encrypted_operation_data_t *enc_op;
	unsigned char *encrypted_data;
	int encrypted_data_size;

	encrypted_data = tls_encrypt(idev, data, data_size,
				     &encrypted_data_size);

	enc_op = g_new0(struct async_usb_encrypted_operation_data_t, 1);
	enc_op->callback = callback;
	enc_op->callback_data = callback_data;
	enc_op->encrypted_data = encrypted_data;
	enc_op->encrypted_data_size = encrypted_data_size;

	async_write_to_usb(idev, encrypted_data, encrypted_data_size,
			   async_write_encrypted_callback, enc_op);
}

static void async_read_encrypted_callback(FpImageDevice *idev, gpointer data, GError *error)
{
	g_autofree struct async_usb_encrypted_operation_data_t *enc_op = data;
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);

	enc_op->encrypted_data = g_memdup(vdev->buffer, vdev->buffer_length);
	enc_op->encrypted_data_size = vdev->buffer_length;

	if (!error &&
	    enc_op->encrypted_data && enc_op->encrypted_data_size &&
	    !tls_decrypt(idev, enc_op->encrypted_data,
			 enc_op->encrypted_data_size,
			 vdev->buffer, &vdev->buffer_length)) {
		error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
						  "Impossible to decrypt "
						  "received data");
	}

	if (enc_op->callback)
		enc_op->callback(idev, enc_op->callback_data, error);

	g_clear_pointer(&enc_op->encrypted_data, g_free);
}

static void async_read_decrypt_from_usb(FpImageDevice *idev, FpiTransferType transfer_type,
					unsigned char *buffer, int buffer_size,
					async_operation_cb callback, void* callback_data)
{
	struct async_usb_encrypted_operation_data_t *enc_op;

	enc_op = g_new0(struct async_usb_encrypted_operation_data_t, 1);
	enc_op->callback = callback;
	enc_op->callback_data = callback_data;

	async_read_from_usb(idev, transfer_type, buffer, buffer_size,
			    async_read_encrypted_callback, enc_op);
}

struct async_data_exchange_t {
	async_operation_cb callback;
	void* callback_data;

	int exchange_mode;
	unsigned char *buffer;
	int buffer_size;
};

static void on_async_data_exchange_cb(FpImageDevice *idev, gpointer data, GError *error)
{
	g_autofree struct async_data_exchange_t *dex = data;

	g_assert_nonnull(dex);

	if (!error) {
		if (dex->exchange_mode == DATA_EXCHANGE_PLAIN) {
			async_read_from_usb(idev, FP_TRANSFER_BULK,
					    dex->buffer,
					    dex->buffer_size,
					    dex->callback, dex->callback_data);
		} else if (dex->exchange_mode == DATA_EXCHANGE_ENCRYPTED) {
			async_read_decrypt_from_usb(idev, FP_TRANSFER_BULK,
						    dex->buffer,
						    dex->buffer_size,
						    dex->callback,
						    dex->callback_data);
		}
	} else if (dex->callback) {
		dex->callback(idev, dex->callback_data, error);
	}
}

static void async_data_exchange(FpImageDevice *idev, int exchange_mode,
				const unsigned char *data, int data_size,
				unsigned char *buffer, int buffer_size,
				async_operation_cb callback, void* callback_data)
{
	struct async_data_exchange_t *dex;

	dex = g_new0(struct async_data_exchange_t, 1);
	dex->buffer = buffer;
	dex->buffer_size = buffer_size;
	dex->callback = callback;
	dex->callback_data = callback_data;
	dex->exchange_mode = exchange_mode;

	if (dex->exchange_mode == DATA_EXCHANGE_PLAIN) {
		async_write_to_usb(idev, data, data_size,
				   on_async_data_exchange_cb, dex);
	} else if (dex->exchange_mode == DATA_EXCHANGE_ENCRYPTED) {
		async_write_encrypted_to_usb(idev, data, data_size,
					     on_async_data_exchange_cb, dex);
	} else {
		GError *error = fpi_device_error_new_msg(FP_DEVICE_ERROR_DATA_INVALID,
							 "Unknown exchange mode selected");
		fp_err("%s", error->message);

		if (callback)
			callback(idev, callback_data, error);
		else
			fpi_image_device_session_error(idev, error);
	}
}

static void async_transfer_callback_with_ssm(FpImageDevice *idev, gpointer data, GError *error)
{
	FpiSsm *ssm = data;

	if (!error) {
		fpi_ssm_next_state(ssm);
	} else {
		fpi_ssm_mark_failed(ssm, error);
	}
}

static void generate_main_seed(FpImageDevice *idev, struct vfs_init_t *vinit) {
	char name[NAME_MAX], serial[NAME_MAX];
	FILE *name_file, *serial_file;
	int name_len, serial_len;
	GError *error = NULL;

	if (!(name_file = fopen(DMI_PRODUCT_NAME_NODE, "r"))) {
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_DATA_NOT_FOUND,
						 "Can't open "
						 DMI_PRODUCT_NAME_NODE);
		fp_err("%s", error->message);
		fpi_device_action_error(FP_DEVICE(idev), error);
		return;
	}
	if (!(serial_file = fopen(DMI_PRODUCT_SERIAL_NODE, "r"))) {
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_DATA_NOT_FOUND,
						 "Can't open "
						 DMI_PRODUCT_SERIAL_NODE);
		fp_err("%s", error->message);
		fpi_device_action_error(FP_DEVICE(idev), error);
		goto out_serial;
	}

	if (fscanf(name_file, "%s", name) != 1) {
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_DATA_INVALID,
						 "Can't parse product name from "
						 DMI_PRODUCT_NAME_NODE);
		fp_err("%s", error->message);
		fpi_device_action_error(FP_DEVICE(idev), error);
		goto out_closeall;
	}

	if (fscanf(serial_file, "%s", serial) != 1) {
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_DATA_INVALID,
						 "Can't parse product name from "
						 DMI_PRODUCT_SERIAL_NODE);
		fp_err("%s", error->message);
		fpi_device_action_error(FP_DEVICE(idev), error);
		goto out_closeall;
	}

	name_len = strlen(name);
	serial_len = strlen(serial);
	vinit->main_seed_length = name_len + serial_len + 2;
	vinit->main_seed = g_malloc0(vinit->main_seed_length);

	memcpy(vinit->main_seed, name, name_len + 1);
	memcpy(vinit->main_seed + name_len + 1, serial, serial_len + 1);

out_closeall:
	fclose(serial_file);
out_serial:
	fclose(name_file);
}

#define usb_operation(func, dev, error) usb_operation_perform(STRINGIZE(func), func, dev, error)
static gboolean usb_operation_perform(const char *op, gboolean ret, FpDevice *dev, GError *error)
{
	if (!ret && error) {
		fp_err("USB operation '%s' failed: %s", op, error->message);
		if (dev) {
			fpi_device_action_error(dev, error);
		}
	}

	return ret;
}

/*
static gboolean openssl_operation(int ret, struct fp_img_dev *idev)
{
	if (ret != TRUE) {
		fp_err("OpenSSL operation failed: %d", ret);
		error = fpi_device_error_new_msg FP_DEVICE_ERROR_GENERAL,
						 (idev) {
			fpi_image_device_session_error(idev, error);
		}
		return FALSE;
	}

	return TRUE;
}
*/

static PK11Context* hmac_make_context(const unsigned char *key_bytes, int key_len)
{
	PK11SymKey *pkKey;
	CK_MECHANISM_TYPE hmacMech = CKM_SHA256_HMAC;
	PK11SlotInfo *slot = PK11_GetBestSlot(hmacMech, NULL);

	SECItem key;

	key.data = (unsigned char*) key_bytes;
	key.len = key_len;

	pkKey = PK11_ImportSymKey(slot, hmacMech, PK11_OriginUnwrap, CKA_SIGN, &key, NULL);

	SECItem param = { .type = siBuffer, .data = NULL, .len = 0 };

	PK11Context* context = PK11_CreateContextBySymKey(hmacMech, CKA_SIGN, pkKey, &param);
	PK11_DigestBegin(context);
	PK11_FreeSlot(slot);
	PK11_FreeSymKey(pkKey);

	return context;
}

static unsigned char* hmac_compute(const unsigned char *key, int key_len, unsigned char* data, int data_len)
{
	// XXX: REUSE CONTEXT HERE, don't create it all the times
	PK11Context* context = hmac_make_context(key, key_len);
	PK11_DigestOp(context, data, data_len);

	unsigned int len = 0x20;
	unsigned char *res = g_malloc(len);
	PK11_DigestFinal(context, res, &len, len);
	PK11_DestroyContext(context, PR_TRUE);

	return res;
}

static void mac_then_encrypt(unsigned char type, unsigned char *key_block, const unsigned char *data, int data_len, unsigned char **res, int *res_len) {
	g_autofree unsigned char *all_data = NULL;
	g_autofree unsigned char *hmac = NULL;
	g_autofree unsigned char *pad = NULL;
	const unsigned char iv[] = {
		0x4b, 0x77, 0x62, 0xff, 0xa9, 0x03, 0xc1, 0x1e,
		0x6f, 0xd8, 0x35, 0x93, 0x17, 0x2d, 0x54, 0xef
	};

	int prefix_len = (type != 0xFF) ? 5 : 0;

	// header for hmac + data + hmac
	all_data = g_malloc(prefix_len + data_len + 0x20);
	all_data[0] = type; all_data[1] = all_data[2] = 0x03;
	all_data[3] = (data_len >> 8) & 0xFF;
	all_data[4] = data_len & 0xFF;
	memcpy(all_data + prefix_len, data, data_len);

	hmac = hmac_compute(key_block, 0x20, all_data, prefix_len + data_len);
	memcpy(all_data + prefix_len + data_len, hmac, 0x20);

	EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(context, EVP_aes_256_cbc(), key_block + 0x40, iv);
	EVP_CIPHER_CTX_set_padding(context, 0);

	*res_len = ((data_len + 16) / 16) * 16 + 0x30;
	*res = g_malloc(*res_len);
	memcpy(*res, iv, 0x10);
	int written = 0, wr2, wr3 = 0;

	EVP_EncryptUpdate(context, *res + 0x10, &written, all_data + prefix_len, data_len + 0x20);

	int pad_len = *res_len - (0x30 + data_len);
	if (pad_len == 0) {
		pad_len = 16;
	}
	pad = g_malloc(pad_len);
	memset(pad, pad_len - 1, pad_len);

	EVP_EncryptUpdate(context, *res + 0x10 + written, &wr3, pad, pad_len);

	EVP_EncryptFinal(context, *res + 0x10 + written + wr3, &wr2);
	*res_len = written + wr2 + wr3 + 0x10;

	EVP_CIPHER_CTX_free(context);
}

static unsigned char *tls_encrypt(FpImageDevice *idev,
				  const unsigned char *data, int data_size,
				  int *encrypted_len_out) {
	FpiDeviceVfs0090 *vdev;
	g_autofree unsigned char *res = NULL;
	unsigned char *wr;
	int res_len;

	vdev = FPI_DEVICE_VFS0090(idev);
	g_assert(vdev->key_block);

	mac_then_encrypt(0x17, vdev->key_block, data, data_size, &res, &res_len);

	wr = g_malloc(res_len + 5);
	memcpy(wr + 5, res, res_len);
	wr[0] = 0x17; wr[1] = wr[2] = 0x03; wr[3] = res_len >> 8; wr[4] = res_len & 0xFF;

	*encrypted_len_out = res_len + 5;

	return wr;
}

static gboolean tls_decrypt(FpImageDevice *idev,
			    const unsigned char *buffer, int buffer_size,
			    unsigned char *output_buffer, int *output_len)
{
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);

	int buff_len = buffer_size - 5;
	int out_len = buff_len - 0x10;
	int tlen1 = 0, tlen2;
	gboolean ret = FALSE;

	g_return_val_if_fail(buffer != NULL, FALSE);
	g_return_val_if_fail(buffer_size > 0, FALSE);
	g_assert(vdev->key_block);

	buffer += 5;
	*output_len = 0;

	EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit(context, EVP_aes_256_cbc(), vdev->key_block + 0x60, buffer)) {
		fp_err("Decryption failed, error: %lu, %s",
		       ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	EVP_CIPHER_CTX_set_padding(context, 0);

	if (!EVP_DecryptUpdate(context, output_buffer, &tlen1, buffer + 0x10, out_len)) {
		fp_err("Decryption failed, error: %lu, %s",
		       ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	if (!EVP_DecryptFinal(context, output_buffer + tlen1, &tlen2)) {
		fp_err("Decryption failed, error: %lu, %s",
		       ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	*output_len = tlen1 + tlen2 - 0x20 - (output_buffer[out_len - 1] + 1);
	ret = TRUE;

	out:
	EVP_CIPHER_CTX_free(context);

	return ret;
}

static gboolean check_data_exchange(FpiDeviceVfs0090 *vdev, const struct data_exchange_t *dex)
{
	if (dex->rsp_length >= 0 && vdev->buffer_length != dex->rsp_length) {
		return FALSE;
	} else if (dex->rsp_length > 0 && dex->rsp != NULL) {
		int i;
		const unsigned char *expected = dex->rsp;

		for (i = 0; i < vdev->buffer_length; ++i) {
			if (vdev->buffer[i] != expected[i]) {
				fp_warn("Reply mismatch, expected at char %d "
					"(actual 0x%x, expected  0x%x)",
					i, vdev->buffer[i], expected[i]);

				if (!dex->weak_match)
					return FALSE;
			}
		}
	}

	return TRUE;
}

static gboolean check_data_exchange_dbg(FpiDeviceVfs0090 *vdev, const struct data_exchange_t *dex)
{
	gboolean ret = check_data_exchange(vdev, dex);

	if (!ret) {
		if (dex->rsp_length >= 0 && vdev->buffer_length != dex->rsp_length) {
			fp_err("Expected len: %d, but got %d",
			       dex->rsp_length, vdev->buffer_length);
		}

		print_hex(vdev->buffer, vdev->buffer_length);
	}

	return ret;
}

struct data_exchange_async_data_t {
	FpiSsm *ssm;
	const struct data_exchange_t *dex;
};

static void on_data_exchange_cb(FpImageDevice *idev, gpointer data, GError *error)
{
	g_autofree struct data_exchange_async_data_t *dex_data = data;
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);

	if (!error) {
		if (check_data_exchange_dbg(vdev, dex_data->dex)) {
			fpi_ssm_next_state(dex_data->ssm);
		} else {
			error = fpi_device_error_new (FP_DEVICE_ERROR_PROTO);
		}
	}

  if (error) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			fp_err("Data exchange failed at state %d, usb error: %s",
			       fpi_ssm_get_cur_state(dex_data->ssm), error->message);
		}

		fpi_ssm_mark_failed(dex_data->ssm, error);
	}
}

static void do_data_exchange(FpImageDevice *idev, FpiSsm *ssm,
			     const struct data_exchange_t *dex, int mode)
{
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	struct data_exchange_async_data_t *dex_data;

	dex_data = g_new0(struct data_exchange_async_data_t, 1);
	dex_data->ssm = ssm;
	dex_data->dex = dex;

	async_data_exchange(idev, mode, dex->msg, dex->msg_length,
			    vdev->buffer, VFS_USB_BUFFER_SIZE,
			    on_data_exchange_cb, dex_data);
}

static void TLS_PRF2(const unsigned char *secret, int secret_len, const char *str,
		     const unsigned char *seed40, int seed40_len,
		     unsigned char *out_buffer, int buffer_len)
{
	int total_len = 0;
	int str_len = strlen(str);
	unsigned char seed[str_len + seed40_len];
	int seed_len = str_len + seed40_len;
	g_autofree unsigned char *a = NULL;

	memcpy(seed, str, str_len);
	memcpy(seed + str_len, seed40, seed40_len);

	a = hmac_compute(secret, secret_len, seed, seed_len);

	while (total_len < buffer_len) {
		unsigned char buffer[0x20 + seed_len];
		g_autofree unsigned char *p = NULL;
		g_autofree unsigned char *t = NULL;

		memcpy(buffer, a, 0x20);
		memcpy(buffer + 0x20, seed, seed_len);

		p = hmac_compute(secret, secret_len, buffer, 0x20 + seed_len);
		memcpy(out_buffer + total_len, p, MIN(0x20, buffer_len - total_len));

		total_len += 0x20;

		t = g_steal_pointer(&a);
		a = hmac_compute(secret, secret_len, t, 0x20);
	}
}

static gboolean check_pad(unsigned char *data, int len)
{
    int pad_size = data[len - 1];

    for(int i = 0; i < pad_size; ++i) {
	if (data[len - 1 - i] != pad_size) {
	    return FALSE;
	}
    }

    return TRUE;
}

static void reverse_mem(unsigned char* data, int size)
{
    unsigned char tmp;
    for (int i = 0; i < size / 2; ++i) {
	tmp = data[i];
	data[i] = data[size - 1 - i];
	data[size - 1 - i] = tmp;
    }
}

static gboolean initialize_ecdsa_key(struct vfs_init_t *vinit, unsigned char *enc_data, int res_len)
{
	int tlen1 = 0, tlen2;
	g_autofree unsigned char *res = NULL;
	gboolean ret;
	EVP_CIPHER_CTX *context;

	ret = FALSE;
	context = EVP_CIPHER_CTX_new();

	if (!EVP_DecryptInit(context, EVP_aes_256_cbc(), vinit->masterkey_aes, enc_data)) {
		fp_err("Failed to initialize EVP decrypt, error: %lu, %s",
		       ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	res = g_malloc(res_len);
	EVP_CIPHER_CTX_set_padding(context, 0);

	if (!EVP_DecryptUpdate(context, res, &tlen1, enc_data + 0x10, res_len)) {
		fp_err("Failed to EVP decrypt, error: %lu, %s",
		       ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	if (!EVP_DecryptFinal(context, res + tlen1, &tlen2)) {
		fp_err("EVP Final decrypt failed, error: %lu, %s",
		       ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	reverse_mem(res, 0x20);
	reverse_mem(res + 0x20, 0x20);
	reverse_mem(res + 0x40, 0x20);

	memcpy(vinit->ecdsa_private_key, res, VFS_ECDSA_PRIVATE_KEY_SIZE);

	ret = check_pad(res, res_len);
out:
	EVP_CIPHER_CTX_free(context);

	return ret;
}

static gboolean make_ecdsa_key(struct vfs_init_t *vinit, unsigned char *data)
{
	if (!initialize_ecdsa_key(vinit, data + 0x52, 0x70))
		return FALSE;

	memset(vinit->ecdsa_private_key, 0, 0x40);
	// 97 doesn't have XY in private key
	memcpy(vinit->ecdsa_private_key, data + 0x11e, 0x20);
	reverse_mem(vinit->ecdsa_private_key, 0x20);

	memcpy(vinit->ecdsa_private_key + 0x20, data + 0x162, 0x20);
	reverse_mem(vinit->ecdsa_private_key + 0x20, 0x20);

	return TRUE;
}

static EC_KEY *load_key(const unsigned char *data, gboolean is_private)
{
	BIGNUM *x = BN_bin2bn(data, 0x20, NULL);
	BIGNUM *y = BN_bin2bn(data + 0x20, 0x20, NULL);
	BIGNUM *d = NULL;
	EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!EC_KEY_set_public_key_affine_coordinates(key, x,y)) {
		fp_err("Failed to set public key coordinates, error: %lu, %s",
		       ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
		goto err;
	}

	if (is_private) {
		d = BN_bin2bn(data + 0x40, 0x20, NULL);
		if (!EC_KEY_set_private_key(key, d)) {
			fp_err("Failed to set private key, error: %lu, %s",
				ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
			goto err;
		}
	}

	if (!EC_KEY_check_key(key)) {
		fp_err("Failed to check key, error: %lu, %s",
			ERR_peek_last_error(), ERR_error_string(ERR_peek_last_error(), NULL));
		goto err;
	}

	goto out;

err:
	g_clear_pointer(&key, EC_KEY_free);

out:
	g_clear_pointer(&x, BN_free);
	g_clear_pointer(&y, BN_free);
	g_clear_pointer(&d, BN_free);

	return key;
}

static void fill_buffer_with_random(unsigned char *buffer, int size)
{
	int i;
	srand(time(NULL));

	for (i = 0; i < size; ++i)
		buffer[i] = rand() % 0x100;
}

static unsigned char *sign2(EC_KEY* key, unsigned char *data, int data_len) {
	int len = 0;
	unsigned char *res = NULL;

	do {
		ECDSA_SIG *sig = ECDSA_do_sign(data, data_len, key);
		len = i2d_ECDSA_SIG(sig, NULL);

		free(res);
		res = malloc(len);
		unsigned char *f = res;
		i2d_ECDSA_SIG(sig, &f);
		ECDSA_SIG_free(sig);
	} while (len != VFS_ECDSA_SIGNATURE_SIZE);

	return res;
}

struct tls_handshake_t {
	FpiSsm *parent_ssm;
	struct vfs_init_t *vinit;
	HASHContext *tls_hash_context;
	HASHContext *tls_hash_context2;
	unsigned char read_buffer[VFS_USB_BUFFER_SIZE];
	unsigned char client_random[0x20];
	unsigned char master_secret[0x30];
	unsigned char *client_hello;
};

static void tls_handshake_free(struct tls_handshake_t *tlshd)
{
	HASH_Destroy(tlshd->tls_hash_context);
	HASH_Destroy(tlshd->tls_hash_context2);
	g_clear_pointer(&tlshd->client_hello, g_free);
	g_free(tlshd);
}

static void handshake_ssm(FpiSsm *ssm, FpDevice *dev)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	struct tls_handshake_t *tlshd = fpi_ssm_get_data(ssm);
	struct vfs_init_t *vinit = tlshd->vinit;
	GError *error = NULL;

	switch(fpi_ssm_get_cur_state(ssm)) {
	case TLS_HANDSHAKE_STATE_CLIENT_HELLO:
	{
		time_t current_time;
		unsigned char *client_hello;

		tlshd->tls_hash_context = HASH_Create(HASH_AlgSHA256);
		tlshd->tls_hash_context2 = HASH_Create(HASH_AlgSHA256);

		HASH_Begin(tlshd->tls_hash_context);
		HASH_Begin(tlshd->tls_hash_context2);

		client_hello = g_malloc(G_N_ELEMENTS(TLS_CLIENT_HELLO));
		tlshd->client_hello = client_hello;

		current_time = time(NULL);
		memcpy(tlshd->client_random, &current_time, sizeof(time_t));
		fill_buffer_with_random(tlshd->client_random + 4, G_N_ELEMENTS(tlshd->client_random) - 4);

		memcpy(client_hello, TLS_CLIENT_HELLO, G_N_ELEMENTS(TLS_CLIENT_HELLO));
		memcpy(client_hello + 0xf, tlshd->client_random, G_N_ELEMENTS(tlshd->client_random));
		HASH_Update(tlshd->tls_hash_context, client_hello + 0x09, 0x43);
		HASH_Update(tlshd->tls_hash_context2, client_hello + 0x09, 0x43);

		async_data_exchange(idev, DATA_EXCHANGE_PLAIN,
				    client_hello, G_N_ELEMENTS(TLS_CLIENT_HELLO),
				    tlshd->read_buffer, sizeof(tlshd->read_buffer),
				    async_transfer_callback_with_ssm, ssm);

		break;
	}
	case TLS_HANDSHAKE_STATE_SERVER_HELLO_RCV:
	{
		unsigned char server_random[0x40];
		unsigned char seed[0x40], expansion_seed[0x40];
		g_autofree unsigned char *pre_master_secret = NULL;
		size_t pre_master_secret_len;

		EC_KEY *priv_key, *pub_key;
		EVP_PKEY_CTX *ctx;
		EVP_PKEY *priv, *pub;

		memcpy(server_random, tlshd->read_buffer + 0xb, G_N_ELEMENTS(server_random));
		HASH_Update(tlshd->tls_hash_context, tlshd->read_buffer + 0x05, 0x3d);
		HASH_Update(tlshd->tls_hash_context2, tlshd->read_buffer + 0x05, 0x3d);

		if (!(priv_key = load_key(PRIVKEY, TRUE))) {
			error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
							 "Impossible to load private key");
			fpi_ssm_mark_failed(ssm, error);
			break;
		}

		if (!(pub_key = load_key(vinit->pubkey, FALSE))) {
			error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
							 "Impossible to load private key");
			fpi_ssm_mark_failed(ssm, error);
			break;
		}

		priv = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(priv, priv_key);
		pub = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(pub, pub_key);

		ctx = EVP_PKEY_CTX_new(priv, NULL);

		EVP_PKEY_derive_init(ctx);
		EVP_PKEY_derive_set_peer(ctx, pub);

		EVP_PKEY_derive(ctx, NULL, &pre_master_secret_len);

		pre_master_secret = g_malloc(pre_master_secret_len);
		if (!ECDH_compute_key(pre_master_secret, pre_master_secret_len, EC_KEY_get0_public_key(pub_key), priv_key, NULL)) {
			error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
							 "Failed to compute key, "
							 "error: %lu, %s",
							 ERR_peek_last_error(),
							 ERR_error_string(ERR_peek_last_error(), NULL));
			fpi_ssm_mark_failed(ssm, error);
			break;
		}

		memcpy(seed, tlshd->client_random, G_N_ELEMENTS(tlshd->client_random));
		memcpy(seed + G_N_ELEMENTS(tlshd->client_random), server_random, G_N_ELEMENTS(seed) - G_N_ELEMENTS(tlshd->client_random));

		memcpy(expansion_seed + (G_N_ELEMENTS(expansion_seed) - G_N_ELEMENTS(tlshd->client_random)), tlshd->client_random, G_N_ELEMENTS(tlshd->client_random));
		memcpy(expansion_seed, server_random, G_N_ELEMENTS(expansion_seed) - G_N_ELEMENTS(tlshd->client_random));

		TLS_PRF2(pre_master_secret, pre_master_secret_len, "master secret", seed, G_N_ELEMENTS(seed),
			 tlshd->master_secret, G_N_ELEMENTS(tlshd->master_secret));
		TLS_PRF2(tlshd->master_secret, G_N_ELEMENTS(tlshd->master_secret), "key expansion",
			seed, G_N_ELEMENTS(seed), vdev->key_block, G_N_ELEMENTS(vdev->key_block));

		EC_KEY_free(priv_key);
		EC_KEY_free(pub_key);
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		EVP_PKEY_CTX_free(ctx);

		fpi_ssm_next_state(ssm);

		break;
	}
	case TLS_HANDSHAKE_GENERATE_CERT:
	{
		EC_KEY *ecdsa_key;
		unsigned char test[0x20];
		g_autofree unsigned char *cert_verify_signature = NULL;
		g_autofree unsigned char *final = NULL;
		unsigned int test_len;
		int len;

		memcpy(vinit->tls_certificate + 0xce + 4, PRIVKEY, 0x40);

		HASH_Update(tlshd->tls_hash_context, vinit->tls_certificate + 0x09, 0x109);
		HASH_Update(tlshd->tls_hash_context2, vinit->tls_certificate + 0x09, 0x109);

		HASH_End(tlshd->tls_hash_context, test, &test_len, G_N_ELEMENTS(test));

		ecdsa_key = load_key(vinit->ecdsa_private_key, TRUE);
		cert_verify_signature = sign2(ecdsa_key, test, 0x20);
		memcpy(vinit->tls_certificate + 0x09 + 0x109 + 0x04, cert_verify_signature, VFS_ECDSA_SIGNATURE_SIZE);

		// encrypted finished
		unsigned char handshake_messages[0x20];
		unsigned int len3 = 0x20;
		HASH_Update(tlshd->tls_hash_context2, vinit->tls_certificate + 0x09 + 0x109, 0x4c);
		HASH_End(tlshd->tls_hash_context2, handshake_messages, &len3, 0x20);

		unsigned char finished_message[0x10] = { 0x14, 0x00, 0x00, 0x0c, 0 };
		unsigned char client_finished[0x0c];
		TLS_PRF2(tlshd->master_secret, 0x30, "client finished", handshake_messages, 0x20,
			 client_finished, G_N_ELEMENTS(client_finished));
		memcpy(finished_message + 0x04, client_finished, G_N_ELEMENTS(client_finished));
		// copy handshake protocol

		mac_then_encrypt(0x16, vdev->key_block, finished_message, 0x10, &final, &len);
		memcpy(vinit->tls_certificate + 0x169, final, len);

		EC_KEY_free(ecdsa_key);

		fpi_ssm_next_state(ssm);

		break;
	}
	case TLS_HANDSHAKE_STATE_SEND_CERT:
	{
		async_data_exchange(idev, DATA_EXCHANGE_PLAIN,
				    vinit->tls_certificate,
				    sizeof(vinit->tls_certificate),
				    tlshd->read_buffer, VFS_USB_BUFFER_SIZE,
				    async_transfer_callback_with_ssm, ssm);

		break;
	}
	case TLS_HANDSHAKE_STATE_CERT_REPLY:
	{
		const unsigned char WRONG_TLS_CERT_RSP[] = { 0x15, 0x03, 0x03, 0x00, 0x02 };

		if (vdev->buffer_length < 50 ||
		    memcmp(tlshd->read_buffer, WRONG_TLS_CERT_RSP,
		           MIN(vdev->buffer_length, G_N_ELEMENTS(WRONG_TLS_CERT_RSP))) == 0) {
			error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
							 "TLS Certificate submitted isn't accepted by reader");
			fpi_ssm_mark_failed(ssm, error);
			break;
		}

		fpi_ssm_next_state(ssm);

		break;
	}
	default:
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "Unknown state");
		fpi_ssm_mark_failed(ssm, error);
	}
}

static void handshake_ssm_cb(FpiSsm *ssm, FpDevice *dev, GError *error)
{
	struct tls_handshake_t *tlshd = fpi_ssm_get_data(ssm);
	FpiSsm *parent_ssm = tlshd->parent_ssm;

	if (error) {
		fpi_ssm_mark_failed(parent_ssm, error);
	} else {
		fpi_ssm_next_state(parent_ssm);
	}
}

static void start_handshake_ssm(FpImageDevice *idev,
				FpiSsm *parent_ssm,
				struct vfs_init_t *vinit)
{
	FpiSsm *ssm;
	struct tls_handshake_t *tlshd;

	tlshd = g_new0(struct tls_handshake_t, 1);
	tlshd->parent_ssm = parent_ssm;
	tlshd->vinit = vinit;

	ssm = fpi_ssm_new(FP_DEVICE(idev), handshake_ssm,
			  TLS_HANDSHAKE_STATE_LAST);
	fpi_ssm_set_data(ssm, tlshd, (GDestroyNotify) tls_handshake_free);
	fpi_ssm_start(ssm, handshake_ssm_cb);
}

static int translate_interrupt(unsigned char *interrupt, int interrupt_size)
{
	const int expected_size = 5;
	const unsigned char waiting_finger[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
	const unsigned char finger_down_prefix[] = { 0x02, 0x00, 0x40 };
	const unsigned char scanning_prints[] = { 0x03, 0x40, 0x01, 0x00, 0x00 };
	const unsigned char scan_completed[] = { 0x03, 0x41, 0x03, 0x00, 0x40 };

	const unsigned char scan_success[] = { 0x03, 0x43, 0x04, 0x00, 0x41 };
	const unsigned char low_quality_scan[] = { 0x03, 0x42, 0x04, 0x00, 0x40 };
	const unsigned char scan_failed_too_short[] = { 0x03, 0x60, 0x07, 0x00, 0x40 };
	const unsigned char scan_failed_too_short2[] = { 0x03, 0x61, 0x07, 0x00, 0x41 };
	const unsigned char scan_failed_too_fast[] = { 0x03, 0x20, 0x07, 0x00, 0x00 };

	if (sizeof(waiting_finger) == interrupt_size &&
		memcmp(waiting_finger, interrupt, interrupt_size) == 0) {
		fp_info("Waiting for finger...");
		return VFS_SCAN_WAITING_FOR_FINGER;
	}

	if (expected_size == interrupt_size &&
	     memcmp(finger_down_prefix, interrupt, sizeof(finger_down_prefix)) == 0) {
		fp_info("Finger is on the sensor...");
		return VFS_SCAN_FINGER_ON_SENSOR;
	}

	if (sizeof(scanning_prints) == interrupt_size &&
	    memcmp(scanning_prints, interrupt, interrupt_size) == 0) {
		fp_info("Scan in progress...");
		return VFS_SCAN_IN_PROGRESS;
	}

	if (sizeof(scan_completed) == interrupt_size &&
	    memcmp(scan_completed, interrupt, interrupt_size) == 0) {
		fp_info("Fingerprint scan completed...");
		return VFS_SCAN_COMPLETED;
	}

	if (sizeof(scan_success) == interrupt_size &&
	    memcmp(scan_success, interrupt, interrupt_size) == 0) {
		fp_info("Fingerprint scan success...");
		return VFS_SCAN_SUCCESS;
	}

	if (sizeof(low_quality_scan) == interrupt_size &&
	    memcmp(low_quality_scan, interrupt, interrupt_size) == 0) {
		fp_info("Fingerprint scan success, but low quality...");
		return VFS_SCAN_SUCCESS_LOW_QUALITY;
	}

	if (sizeof(scan_failed_too_short) == interrupt_size &&
	    memcmp(scan_failed_too_short, interrupt, interrupt_size) == 0) {
		fp_warn("Impossible to read fingerprint, don't move your finger");
		return VFS_SCAN_FAILED_TOO_SHORT;
	}

	if (sizeof(scan_failed_too_short2) == interrupt_size &&
	    memcmp(scan_failed_too_short2, interrupt, interrupt_size) == 0) {
		fp_warn("Impossible to read fingerprint, don't move your finger (2)");
		return VFS_SCAN_FAILED_TOO_SHORT;
	}

	if (sizeof(scan_failed_too_fast) == interrupt_size &&
	    memcmp(scan_failed_too_fast, interrupt, interrupt_size) == 0) {
		fp_warn("Impossible to read fingerprint, movement was too fast");
		return VFS_SCAN_FAILED_TOO_FAST;
	}

	fp_err("Interrupt not tracked, please report!");
	print_hex(interrupt, interrupt_size);

	return VFS_SCAN_UNKNOWN;
}

static void send_init_sequence(FpImageDevice *idev, FpiSsm *ssm,
			       int sequence)
{
	do_data_exchange(idev, ssm, &INIT_SEQUENCES[sequence], DATA_EXCHANGE_PLAIN);
}

/* Main SSM loop */
static void init_ssm(FpiSsm *ssm, FpDevice *dev)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(dev);
	struct vfs_init_t *vinit = fpi_ssm_get_data(ssm);
	GError *error = NULL;

	switch (fpi_ssm_get_cur_state(ssm)) {
	case INIT_STATE_GENERATE_MAIN_SEED:
		generate_main_seed(idev, vinit);
		fpi_ssm_next_state(ssm);
		break;

	case INIT_STATE_SEQ_2:
		if (vdev->buffer_length == 38) {
			if (vdev->buffer[vdev->buffer_length-1] != 0x07) {
				error = fpi_device_error_new_msg(
						FP_DEVICE_ERROR_NOT_SUPPORTED,
						"Sensor not initialized, init byte is 0x%x " \
						"(should be 0x07 on initialized devices, 0x02 " \
						"otherwise)\n" \
						"This is a driver in alpha state and the " \
						"device needs to be setup in a VirtualBox " \
						"instance running Windows, or with a native " \
						"Windows installation first.",
						vdev->buffer[vdev->buffer_length-1]);
				fpi_ssm_mark_failed(ssm, error);
				break;
			}
		} else {
			fp_warn("Unknown reply at init stage %d, retrying...",
				fpi_ssm_get_cur_state(ssm));
			fpi_ssm_jump_to_state(ssm, INIT_STATE_SEQ_1);
			break;
		}
	case INIT_STATE_SEQ_1:
	case INIT_STATE_SEQ_3:
	case INIT_STATE_SEQ_4:
	case INIT_STATE_SEQ_5:
	case INIT_STATE_SEQ_6:
		send_init_sequence(idev, ssm, fpi_ssm_get_cur_state(ssm) - INIT_STATE_SEQ_1);
		break;

	case INIT_STATE_MASTER_KEY:
		TLS_PRF2(PRE_KEY, sizeof(PRE_KEY), "GWK", vinit->main_seed,
			 vinit->main_seed_length,
			 vinit->masterkey_aes, VFS_MASTER_KEY_SIZE);

		fpi_ssm_next_state(ssm);
		break;

	case INIT_STATE_ECDSA_KEY:
		if (make_ecdsa_key(vinit, vdev->buffer)) {
			fpi_ssm_next_state(ssm);
		} else if (memcmp(TEST_SEED, vinit->main_seed, vinit->main_seed_length) != 0) {
			fp_info("Failed using system seed for ECDSA key generation, "
				"trying with a VirtualBox one");

			g_clear_pointer(&vinit->main_seed, g_free);
			vinit->main_seed = g_malloc(sizeof(TEST_SEED));
			memcpy(vinit->main_seed, TEST_SEED, sizeof(TEST_SEED));
			vinit->main_seed_length = sizeof(TEST_SEED);

			fpi_ssm_jump_to_state(ssm, INIT_STATE_MASTER_KEY);
		} else {
			error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
					"Initialization failed at state %d, "
					"ECDSA key generation",
					fpi_ssm_get_cur_state(ssm));
			fpi_ssm_mark_failed(ssm, error);
		}
		break;

	case INIT_STATE_TLS_CERT:
		memcpy(vinit->tls_certificate, TLS_CERTIFICATE_BASE,
		       G_N_ELEMENTS(TLS_CERTIFICATE_BASE));
		memcpy(vinit->tls_certificate + 21, vdev->buffer + 0x116, 0xb8);

		fpi_ssm_next_state(ssm);
		break;

	case INIT_STATE_PUBLIC_KEY:
	{
		const int half_key = VFS_PUBLIC_KEY_SIZE / 2;
		memcpy(vinit->pubkey, vdev->buffer + 0x600 + 10, half_key);
		memcpy(vinit->pubkey + half_key, vdev->buffer + 0x640 + 0xe, half_key);

		reverse_mem(vinit->pubkey, half_key);
		reverse_mem(vinit->pubkey + half_key, half_key);

		fpi_ssm_next_state(ssm);
		break;
	}

	case INIT_STATE_HANDSHAKE:
		start_handshake_ssm(idev, ssm, vinit);
		break;

	default:
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "Unknown init state");
		fpi_ssm_mark_failed(ssm, error);
	}
}

static FpiImageDeviceState get_imgdev_state(FpImageDevice *idev)
{
	FpiImageDeviceState state;

	g_object_get(idev, "fpi-image-device-state", &state, NULL);
	return state;
}

/* Callback for dev_open ssm */
static void dev_open_callback(FpiSsm *ssm, FpDevice *dev, GError *error)
{
	/* Notify open complete */
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);

	if (error)
		fpi_image_device_session_error(idev, error);

	if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		fpi_image_device_open_complete(idev, error);
}

/* Open device */
static void dev_open(FpImageDevice *idev)
{
	FpDevice *dev = FP_DEVICE(idev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(dev);
	FpiSsm *ssm;
	GUsbDevice *udev;
	GError *error = NULL;
	SECStatus secs_status;
	int usb_config;

	fp_dbg("Opening device");

	secs_status = NSS_NoDB_Init(NULL);
	if (secs_status != SECSuccess) {
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "could not initialise NSS");
		fp_err("%s", error->message);
		fpi_image_device_open_complete(idev, error);
		return;
	}

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* Initialize private structure */
	vdev->buffer = g_malloc(VFS_USB_BUFFER_SIZE);
	vdev->buffer_length = 0;

	udev = fpi_device_get_usb_device(dev);

	if (!usb_operation(g_usb_device_reset(udev, &error), dev, error))
		return;

	usb_config = g_usb_device_get_configuration(udev, &error);
	if (!usb_operation(error == NULL, dev, error))
		return;

	if (usb_config != 1) {
		if (!usb_operation(g_usb_device_set_configuration(udev, 1, &error), dev, error))
			return;
	}

	if (!usb_operation(g_usb_device_claim_interface(udev, 0, 0, &error), dev, error))
		return;

	/* Clearing previous device state */
	ssm = fpi_ssm_new(dev, init_ssm, INIT_STATE_LAST);
	fpi_ssm_set_data(ssm, g_new0(struct vfs_init_t, 1), (GDestroyNotify) vfs_init_free);
	fpi_ssm_start(ssm, dev_open_callback);
}

static void led_blink_callback_with_ssm(FpImageDevice *idev, gpointer data, GError *error)
{
	FpiSsm *ssm = data;

	if (!error) {
		fpi_ssm_next_state_delayed(ssm, 200, NULL);
	} else {
		/* NO need to fail here, it's not a big issue... */
		fp_err("LED blinking failed with error %s", error->message);
		fpi_ssm_next_state(ssm);
	}
}

struct image_download_t {
	FpiSsm *parent_ssm;

	unsigned char image[VFS_IMAGE_SIZE * VFS_IMAGE_SIZE];
	int image_size;
};

static void finger_image_download_callback(FpiSsm *ssm, FpDevice *dev, GError *error)
{
	struct image_download_t *imgdown = fpi_ssm_get_data(ssm);

	if (!error) {
		fpi_ssm_mark_completed(imgdown->parent_ssm);
	} else {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			fp_err("Scan failed failed at state %d, unexpected"
			       "device reply during image download",
			       fpi_ssm_get_cur_state(ssm));
		}

		fpi_ssm_mark_failed(imgdown->parent_ssm, error);
	}
}

static void finger_image_submit(FpImageDevice *idev,
				struct image_download_t *imgdown)
{
	FpImage *img;

	img = fp_image_new(VFS_IMAGE_SIZE, VFS_IMAGE_SIZE);
	img->flags = FPI_IMAGE_H_FLIPPED;
	memcpy(img->data, imgdown->image, VFS_IMAGE_SIZE * VFS_IMAGE_SIZE);

	if (VFS_IMAGE_RESCALE > 1) {
		g_autoptr(FpImage) resized = NULL;

		resized = fpi_image_resize(img, VFS_IMAGE_RESCALE, VFS_IMAGE_RESCALE);
		g_set_object(&img, resized);
	}

	fp_dbg("Submitting captured image");
	fpi_image_device_image_captured(idev, img);
}

static void finger_image_download_read_callback(FpImageDevice *idev, gpointer data, GError *error)
{
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	FpiSsm *ssm = data;
	struct image_download_t *imgdown = fpi_ssm_get_data(ssm);
	int offset = (fpi_ssm_get_cur_state(ssm) == IMAGE_DOWNLOAD_STATE_1) ? 0x12 : 0x06;
	int data_size = vdev->buffer_length - offset;

	if (error) {
		fp_err("Image download failed at state %d", fpi_ssm_get_cur_state(ssm));
		fpi_ssm_mark_failed(ssm, error);
		return;
	}

	memcpy(imgdown->image + imgdown->image_size, vdev->buffer + offset, data_size);
	imgdown->image_size += data_size;

	fpi_ssm_next_state(ssm);
}

static void finger_image_download_ssm(FpiSsm *ssm, FpDevice *dev)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	struct image_download_t *imgdown = fpi_ssm_get_data(ssm);
	GError *error = NULL;

	const unsigned char read_buffer_request[] = {
		0x51, 0x00, 0x20, 0x00, 0x00
	};

	switch (fpi_ssm_get_cur_state(ssm)) {
	case IMAGE_DOWNLOAD_STATE_1:
	case IMAGE_DOWNLOAD_STATE_2:
	case IMAGE_DOWNLOAD_STATE_3:
		async_data_exchange(idev, DATA_EXCHANGE_ENCRYPTED,
				    read_buffer_request,
				    sizeof(read_buffer_request),
				    vdev->buffer,
				    VFS_IMAGE_SIZE * VFS_IMAGE_SIZE,
				    finger_image_download_read_callback,
				    ssm);

		break;


	case IMAGE_DOWNLOAD_STATE_SUBMIT:
		finger_image_submit(idev, imgdown);

		/* FIXME: we can't get the state of the previous operation
		 * with the new API, so let's just skip the red or green
		 * blinking */

		fpi_ssm_jump_to_state(ssm, IMAGE_DOWNLOAD_STATE_SUBMIT_RESULT);
// FIXME
		// if ((fpi_device_get_current_action(FP_DEVICE(idev)) == FPI_DEVICE_ACTION_VERIFY ||
		//      fpi_device_get_current_action(FP_DEVICE(idev)) == FPI_DEVICE_ACTION_IDENTIFY) &&
		//     fpi_device_get_current_action((idev) != FP_VERIFY_MATCH) {
		// 	fpi_ssm_jump_to_state(ssm, IMAGE_DOWNLOAD_STATE_RED_LED_BLINK);
		// } else {
		// 	fpi_ssm_jump_to_state(ssm, IMAGE_DOWNLOAD_STATE_GREEN_LED_BLINK);
		// }

		break;

	case IMAGE_DOWNLOAD_STATE_GREEN_LED_BLINK:
		async_data_exchange(idev, DATA_EXCHANGE_ENCRYPTED,
				    LED_GREEN_BLINK, G_N_ELEMENTS(LED_GREEN_BLINK),
				    vdev->buffer, VFS_USB_BUFFER_SIZE,
				    led_blink_callback_with_ssm, ssm);

		break;


	case IMAGE_DOWNLOAD_STATE_RED_LED_BLINK:
		async_data_exchange(idev, DATA_EXCHANGE_ENCRYPTED,
				    LED_RED_BLINK, G_N_ELEMENTS(LED_RED_BLINK),
				    vdev->buffer, VFS_USB_BUFFER_SIZE,
				    led_blink_callback_with_ssm, ssm);

		break;

	case IMAGE_DOWNLOAD_STATE_AFTER_GREEN_LED_BLINK:
	case IMAGE_DOWNLOAD_STATE_AFTER_RED_LED_BLINK:
		fpi_ssm_jump_to_state(ssm, IMAGE_DOWNLOAD_STATE_SUBMIT_RESULT);
		break;

	case IMAGE_DOWNLOAD_STATE_SUBMIT_RESULT:
		fpi_image_device_report_finger_status(idev, FALSE);
		fpi_ssm_next_state(ssm);
		break;

	default:
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "Unknown image download state");
		fpi_ssm_mark_failed(ssm, error);
	}
}

static void start_finger_image_download_subsm(FpImageDevice *idev,
					      FpiSsm *parent_ssm)
{
	FpiSsm *ssm;
	struct image_download_t *imgdown;

	imgdown = g_new0(struct image_download_t, 1);
	imgdown->parent_ssm = parent_ssm;

	ssm = fpi_ssm_new(FP_DEVICE(idev),
			  finger_image_download_ssm,
			  IMAGE_DOWNLOAD_STATE_LAST);

	fpi_ssm_set_data(ssm, imgdown, g_free);
	fpi_ssm_start(ssm, finger_image_download_callback);
}

struct scan_error_handler_data_t {
	FpDeviceRetry retry;
	FpiSsm *parent_ssm;
};

static void scan_error_handler_callback(FpiSsm *ssm, FpDevice *dev, GError *error)
{
	struct scan_error_handler_data_t *error_data = fpi_ssm_get_data (ssm);

	if (error) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			fp_err("Scan failed failed at state %d, unexpected "
			       "device reply during scan error handling",
			       fpi_ssm_get_cur_state(ssm));
		}

		fpi_ssm_mark_failed(error_data->parent_ssm, error);
	} else {
		fpi_ssm_mark_completed(error_data->parent_ssm);
	}
}

static void scan_error_handler_ssm(FpiSsm *ssm, FpDevice *dev)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	struct scan_error_handler_data_t *error_data = fpi_ssm_get_data(ssm);
	GError *error = NULL;

	switch (fpi_ssm_get_cur_state(ssm)) {
	case SCAN_ERROR_STATE_LED_BLINK:
		async_data_exchange(idev, DATA_EXCHANGE_ENCRYPTED,
				    LED_RED_BLINK, G_N_ELEMENTS(LED_RED_BLINK),
				    vdev->buffer, VFS_USB_BUFFER_SIZE,
				    led_blink_callback_with_ssm, ssm);
		break;

	case SCAN_ERROR_STATE_REACTIVATE_REQUEST:
		fpi_image_device_retry_scan(FP_IMAGE_DEVICE(dev),
					    error_data->retry);
		fpi_image_device_report_finger_status(idev, FALSE);

		fpi_ssm_next_state(ssm);
		break;

	default:
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "Unknown scan state");
		fpi_ssm_mark_failed(ssm, error);
	}
}

static void start_scan_error_handler_ssm(FpImageDevice *idev,
					 FpiSsm *parent_ssm,
					 FpDeviceRetry retry)
{
	struct scan_error_handler_data_t *error_data;
	FpiSsm *ssm;

	error_data = g_new0(struct scan_error_handler_data_t, 1);
	error_data->retry = retry;
	error_data->parent_ssm = parent_ssm;

	ssm = fpi_ssm_new(FP_DEVICE(idev), scan_error_handler_ssm,
			  SCAN_ERROR_STATE_LAST);
	fpi_ssm_set_data(ssm, error_data, g_free);
	fpi_ssm_start(ssm, scan_error_handler_callback);
}

static void finger_scan_callback(FpiSsm *ssm, FpDevice *dev, GError *error)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);

	if (error && !g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		fp_err("Scan failed failed at state %d, unexpected "
		       "device reply during finger scanning", fpi_ssm_get_cur_state(ssm));

		fpi_image_device_session_error(idev, error);
	} else {
		g_clear_error(&error);
	}
}

static void finger_scan_interrupt_callback(FpImageDevice *idev, gpointer data, GError *error)
{
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	FpiSsm *ssm = data;
	int interrupt_type;

	if (!error) {
		interrupt_type = translate_interrupt(vdev->buffer,
						     vdev->buffer_length);
		fpi_ssm_jump_to_state(ssm, interrupt_type);
	} else {
		fpi_ssm_mark_failed(ssm, error);
	}
}

static void finger_scan_ssm(FpiSsm *ssm, FpDevice *dev)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	GError *error = NULL;

	switch (fpi_ssm_get_cur_state(ssm)) {
	case SCAN_STATE_FINGER_ON_SENSOR:
		fpi_image_device_report_finger_status(idev, TRUE);

	case SCAN_STATE_WAITING_FOR_FINGER:
	case SCAN_STATE_IN_PROGRESS:
	case SCAN_STATE_COMPLETED:
		async_read_from_usb(idev, FP_TRANSFER_INTERRUPT,
				    vdev->buffer, VFS_USB_INTERRUPT_BUFFER_SIZE,
				    finger_scan_interrupt_callback, ssm);

		break;

	case SCAN_STATE_FAILED_TOO_SHORT:
	case SCAN_STATE_FAILED_TOO_FAST:
		start_scan_error_handler_ssm(idev, ssm, FP_DEVICE_RETRY_TOO_SHORT);
		break;

	case SCAN_STATE_SUCCESS_LOW_QUALITY:
		if (fpi_device_get_current_action(FP_DEVICE(idev)) == FPI_DEVICE_ACTION_ENROLL) {
			start_scan_error_handler_ssm(idev, ssm, FP_DEVICE_RETRY_CENTER_FINGER);
		} else if (fpi_device_get_current_action(FP_DEVICE(idev)) == FPI_DEVICE_ACTION_VERIFY) {
			fp_warn("Low quality image in verification, might fail");
			fpi_ssm_jump_to_state(ssm, SCAN_STATE_SUCCESS);
		}
		break;

	case SCAN_STATE_SUCCESS:
		start_finger_image_download_subsm(idev, ssm);
		break;

	default:
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "Unknown scan state");
		fpi_ssm_mark_failed(ssm, error);
	}
}

static void start_finger_scan(FpImageDevice *idev)
{
	FpiSsm *ssm;

	ssm = fpi_ssm_new(FP_DEVICE(idev), finger_scan_ssm, SCAN_STATE_LAST);
	fpi_ssm_start(ssm, finger_scan_callback);
}

static void send_activate_sequence(FpImageDevice *idev, FpiSsm *ssm,
				   int sequence)
{
	do_data_exchange(idev, ssm, &ACTIVATE_SEQUENCES[sequence], DATA_EXCHANGE_ENCRYPTED);
}

static void activate_device_interrupt_callback(FpImageDevice *idev, gpointer data, GError *error)
{
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	FpiSsm *ssm = data;
	int interrupt_type;

	if (!error) {
		interrupt_type = translate_interrupt(vdev->buffer,
						     vdev->buffer_length);

		if (interrupt_type == VFS_SCAN_WAITING_FOR_FINGER) {
			fpi_ssm_mark_completed(ssm);
		} else {
			error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
							 "Unexpected device interrupt "
							 "(%d) at this state",
							 interrupt_type);
			print_hex(vdev->buffer, vdev->buffer_length);
			fpi_ssm_mark_failed(ssm, error);
		}
	} else {
		fpi_ssm_mark_failed(ssm, error);
	}
}

static void activate_ssm(FpiSsm *ssm, FpDevice *dev)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	GError *error = NULL;

	switch (fpi_ssm_get_cur_state(ssm)) {
	case ACTIVATE_STATE_GREEN_LED_ON:
		async_data_exchange(idev, DATA_EXCHANGE_ENCRYPTED,
				    LED_GREEN_ON, G_N_ELEMENTS(LED_GREEN_ON),
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
		send_activate_sequence(idev, ssm, fpi_ssm_get_cur_state(ssm) - ACTIVATE_STATE_SEQ_1);
		break;

	case ACTIVATE_STATE_WAIT_DEVICE:
		if (check_data_exchange(vdev, &MATRIX_ALREADY_ACTIVATED_DEX)) {
			fp_info("Waiting for device not needed, already active");
			fpi_ssm_next_state(ssm);
			break;
		}

		async_read_from_usb(idev, FP_TRANSFER_INTERRUPT,
				    vdev->buffer, VFS_USB_INTERRUPT_BUFFER_SIZE,
				    activate_device_interrupt_callback, ssm);
		break;

	default:
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "Unknown activation state");
		fpi_ssm_mark_failed(ssm, error);
	}
}

/* Callback for dev_activate ssm */
static void dev_activate_callback(FpiSsm *ssm, FpDevice *dev, GError *error)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);

	if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED) && error) {
		fp_err("Activation failed failed at state %d, unexpected "
		       "device reply during activation", fpi_ssm_get_cur_state(ssm));
	}

	fpi_image_device_activate_complete(idev, error);
	vdev->activated = TRUE;
}

static void dev_activate(FpImageDevice *idev)
{
	FpiSsm *ssm;

	ssm = fpi_ssm_new(FP_DEVICE(idev), activate_ssm, ACTIVATE_STATE_LAST);
	fpi_ssm_start(ssm, dev_activate_callback);
}

static void send_deactivate_sequence(FpImageDevice *idev, FpiSsm *ssm,
				     int sequence)
{
	do_data_exchange(idev, ssm, &DEACTIVATE_SEQUENCES[sequence], DATA_EXCHANGE_ENCRYPTED);
}

static void deactivate_ssm(FpiSsm *ssm, FpDevice *dev)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	GError *error = NULL;

	switch (fpi_ssm_get_cur_state(ssm)) {
	case DEACTIVATE_STOP_TRANSFER:
		g_cancellable_cancel(vdev->cancellable);
		g_clear_object(&vdev->cancellable);

		fpi_ssm_next_state(ssm);
		break;

	case DEACTIVATE_STATE_SEQ_1:
	case DEACTIVATE_STATE_SEQ_2:
		send_deactivate_sequence(idev, ssm, fpi_ssm_get_cur_state(ssm) - DEACTIVATE_STATE_SEQ_1);
		break;

	case DEACTIVATE_STATE_LED_OFF:
		async_data_exchange(idev, DATA_EXCHANGE_ENCRYPTED,
				    LED_OFF, G_N_ELEMENTS(LED_OFF),
				    vdev->buffer, VFS_USB_BUFFER_SIZE,
				    async_transfer_callback_with_ssm, ssm);
		break;

	default:
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "Unknown deactivate state");
		fpi_ssm_mark_failed(ssm, error);
	}
}

static void dev_deactivate_callback(FpiSsm *ssm, FpDevice *dev, GError *error)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);

	if (error) {
		if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			fp_err("Deactivation failed at state %d, unexpected "
			       "device reply during deactivation",
			       fpi_ssm_get_cur_state(ssm));
		}

		fpi_image_device_session_error(idev, error);
	}

	g_clear_object(&vdev->cancellable);

	fpi_image_device_deactivate_complete(idev, NULL);

	vdev->activated = FALSE;
	vdev->deactivating = FALSE;
}

static void dev_deactivate(FpImageDevice *idev)
{
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	FpiSsm *ssm;

	if (vdev->deactivating)
		return;

	vdev->deactivating = TRUE;
	ssm = fpi_ssm_new(FP_DEVICE(idev), deactivate_ssm,
			  DEACTIVATE_STATE_LAST);
	fpi_ssm_start(ssm, dev_deactivate_callback);
}

static void reactivate_ssm(FpiSsm *ssm, FpDevice *dev)
{
	FpImageDevice *idev = FP_IMAGE_DEVICE(dev);
	FpiSsm *child_ssm = NULL;
	GError *error = NULL;

	switch (fpi_ssm_get_cur_state(ssm)) {
	case REACTIVATE_STATE_WAIT:
		fpi_ssm_next_state_delayed(ssm, 100, NULL);
		break;
	case REACTIVATE_STATE_DEACTIVATE:
		child_ssm = fpi_ssm_new(dev, deactivate_ssm,
				        DEACTIVATE_STATE_LAST);
		break;
	case REACTIVATE_STATE_ACTIVATE:
		child_ssm = fpi_ssm_new(dev, activate_ssm,
				        ACTIVATE_STATE_LAST);
		break;
	case REACTIVATE_STATE_MAYBE_SCAN:
		if (get_imgdev_state(idev) == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
			start_finger_scan(idev);

		fpi_ssm_next_state(ssm);
		break;
	default:
		error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL,
						 "Unknown reactivate state");
		fpi_ssm_mark_failed(ssm, error);
	}

	if (child_ssm)
		fpi_ssm_start_subsm(ssm, child_ssm);
}

static void reactivate_ssm_callback(FpiSsm *ssm, FpDevice *dev, GError *error)
{
	if (error)
		fpi_image_device_session_error(FP_IMAGE_DEVICE(dev), error);
}

static void start_reactivate_ssm(FpDevice *dev)
{
	FpiSsm *ssm;

	ssm = fpi_ssm_new(dev, reactivate_ssm,
			  REACTIVATE_STATE_LAST);
	fpi_ssm_start(ssm, reactivate_ssm_callback);
}

static void dev_close(FpImageDevice *idev)
{
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);
	GUsbDevice *udev = fpi_device_get_usb_device(FP_DEVICE(idev));
	GError *error = NULL;

	usb_operation(g_usb_device_release_interface(udev, 0, 0, &error), NULL, error);

	NSS_Shutdown();
	ERR_free_strings();
	EVP_cleanup();

	g_clear_pointer(&vdev->buffer, g_free);
	vdev->buffer_length = 0;

	fpi_image_device_close_complete(idev, error);
}

static void
dev_change_state (FpImageDevice *idev, FpiImageDeviceState state)
{
	FpiDeviceVfs0090 *vdev = FPI_DEVICE_VFS0090(idev);

	switch (state) {
	case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON:
		if (!vdev->activated)
			start_finger_scan(idev);
		else
			start_reactivate_ssm(FP_DEVICE(idev));
		break;

	case FPI_IMAGE_DEVICE_STATE_CAPTURE:
	case FPI_IMAGE_DEVICE_STATE_INACTIVE:
	case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF:
		break;
	}
}

/* Usb id table of device */
static const FpIdEntry id_table [] = {
	{ .vid = 0x138a, .pid = 0x0090 },
	{ .vid = 0,  .pid = 0, .driver_data = 0 },
};

static void fpi_device_vfs0090_init(FpiDeviceVfs0090 *self)
{
}

static void fpi_device_vfs0090_class_init(FpiDeviceVfs0090Class *klass)
{
	FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);
	FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS(klass);

	dev_class->id = "vfs0090";
	dev_class->full_name = "Validity VFS0090";
	dev_class->type = FP_DEVICE_TYPE_USB;
	dev_class->id_table = id_table;
	dev_class->scan_type = FP_SCAN_TYPE_PRESS;

	img_class->img_open = dev_open;
	img_class->img_close = dev_close;
	img_class->activate = dev_activate;
	img_class->deactivate = dev_deactivate;
	img_class->change_state = dev_change_state;

	img_class->bz3_threshold = 12;

	img_class->img_width = VFS_IMAGE_SIZE * VFS_IMAGE_RESCALE;
	img_class->img_height = VFS_IMAGE_SIZE * VFS_IMAGE_RESCALE;
}
