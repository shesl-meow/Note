---
title: "`apksigner`"
date: 2019-02-19T06:23:32+08:00
tags: [""]
categories: ["工具使用接口", "Android"]
---

> 学习途径：
>
> - 官方命令行工具：https://developer.android.com/studio/command-line/apksigner


## Usage

### sign an `apk`

The syntax for signing an APK using the `apksigner` tool is as follows:

```bash
$ apksigner sign --ks keystore.jks [signer_options] app-name.apk

# or

$ apksigner sign --key key.pk8 --cert cert.x509.pem [signer_options] app-name.apk
```

When you sign an APK using the `apksigner` tool, you must provide the signer's private key and certificate. You can include this information in two different ways:

- Specify a Key Store file using the `--ks` option.
- Specify the private key file and certificate file separately using the `--key` and `--cert` options, respectively. The private key file must use the `PKCS #8` format, and the certificate file must use the `X.509` format.

Usually, you sign an APK using only one signer. In the event that you need to sign an APK using multiple signers, use the `--next-signer` option to separate the set of [general options](https://developer.android.com/studio/command-line/apksigner#options-sign-general) to apply to each signer:

```bash
$ apksigner sign [signer_1_options] --next-signer [signer_2_options] app-name.apk
```

### verify the signature of an `apk`

The syntax for confirming that an APK's signature will be verified successfully on supported platforms is as follows:

```bash
$ apksigner verify [options] app-name.apk
```

### Rotate signing keys

The syntax for rotating a *signing certificate lineage*, or a new sequence of signatures, is as follows:

```bash
$ apksigner rotate --in /path/to/existing/lineage \
  --out /path/to/new/file \
  --old-signer --ks old-signer-jks \
  --new-signer --ks new-signer-jks
```

## Example

### Sign an APK

Sign an APK using `release.jks`, which is the only key in the KeyStore:

```bash
$ apksigner sign --ks release.jks app.apk
```

Sign an APK using a private key and certificate, stored as separate files:

```bash
$ apksigner sign --key release.pk8 --cert release.x509.pem app.apk
```

Sign an APK using two keys:

```bash
$ apksigner sign --ks first-release-key.jks --next-signer --ks second-release-key.jks app.apk
```

### Verify the signature of an APK

Check whether the APK's signatures are expected to be confirmed as valid on all Android platforms that the APK supports:

```bash
$ apksigner verify app.apk
```

Check whether the APK's signatures are expected to be confirmed as valid on Android 4.0.3 (API level 15) and higher:

```bash
$ apksigner verify --min-sdk-version 15 app.apk
```

### Rotate signing keys

Enable a signing certificate lineage that supports key rotation:

```bash
$ apksigner rotate --out /path/to/new/file --old-signer \
    --ks release.jks --new-signer --ks release2.jks
```

Rotate your signing keys again:

```bash
$ apksigner rotate --in /path/to/existing/lineage \
  --out /path/to/new/file --old-signer --ks release2.jks \
  --new-signer --ks release3.jks
```
