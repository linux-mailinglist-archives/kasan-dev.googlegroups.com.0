Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZWV26MAMGQEUD4XWIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 140A85AD268
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:15 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id x20-20020a2e7c14000000b00267570ecceesf2840139ljc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380774; cv=pass;
        d=google.com; s=arc-20160816;
        b=bfNxl7Ko9lFeAPlx1VQrckuTsan1ib8pY7TfJ8xSKUbgzDNXDWrbgxe6HOSTLr+HRp
         Se2aB3EbBV97T6Uui4xHxxsOkXPW6mx/nIichyJqKcjeQFhszXIwhaPhlhZyuL8hYMGk
         nSjHO6atRiuqD8PJILJ2YGXPKw9ncgWqUON+IUptXtQ7oPGZbbz47jYUHsFd5RMUwAc5
         xeyTQxIevvdqhlAMN8xd4j4W9tr/sBBtqNeu3N2VI3LOeJfb8CWBRgPo4VibXT4lrDS3
         X8E7ecW/wJFZiCnMigf4ueE4A1iksRywu12ZLXbXcMNEHUpcRsrMf1Cs74If1t+xdiak
         WSlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=EeZ3o1M/IB1ahGQnF7RyvsExfr/5n3Jb78mSnmHdVJE=;
        b=RDqEZpSryr0rxIRjHHbQs7N9yxMQYLIymtWIde6XsmnZPq09ffH6d6LSlFdcPlac8z
         g2UNCp8858CBphZQx2r8oOoUxl4U0Rvfjd55vbm7ePkSx09CnHWP8i1rMBkG8ljRothc
         UXSD5B8lc7tr+AkHQdh1BnJVhIF+3YhhCZ7ll6nwtYQ5bsXkb+715638DvppOu7jz6iX
         tABGc2AXWvLPHHvkVKnfJMA4P3uDCxf5lt8Q2tPz5lb2hAORRqJhywmRBxlYWB0xtmQI
         PF494FUpsfzz4Y1XqWAE+sN2g978twz05pOqGOGVWljfai/O8SIZkZL7Q4t+IIwDtQfZ
         oJPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EuJefT6p;
       spf=pass (google.com: domain of 35oovywykctetyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35OoVYwYKCTETYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=EeZ3o1M/IB1ahGQnF7RyvsExfr/5n3Jb78mSnmHdVJE=;
        b=UmU0qPR9slnDe+AaYg0OYy2gK+fnQzz9xZ+bhm6kIjMmEEax8DIlrUpbommTvLnIhb
         XpI5bk0GgxwbSU+8uQhja56S6UzvM3kCIB2uZAiXoxyMxeOGA/+O0ZDydS63IpcUlV7+
         pSohgdA740WBzrhjKSJJbGzjwNcNW5wdRV1+Urj+zcW4b8F3lYxjxzcaS+6efz6DgmZq
         67z1x/p3sUIhr2BzRg+8vELlqXMsuW0rCQyV+dsFt4PjkQlzpKlw49O2tMB24MUfqi6U
         XZ0ptvoMmUTgAAMb9z5ZLzMcwLKxeoC57U6Vp660+71uwWK7vpKVENM6TB8SYB+5LgDK
         ceKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=EeZ3o1M/IB1ahGQnF7RyvsExfr/5n3Jb78mSnmHdVJE=;
        b=v8rerZ8ktRvCaKw+aIthI/qW9r2p1keQueNGqbOLR2etHP5KjU5Y5VaeMrL/HXLQbT
         Nkpxf9j2E1vuT1yZFM5DtpPFUWEs77j1O63vr0rzrugYpgiO3pDOdno2y5+0DwGatydi
         bqtOFZ/Lm4Azhxwf4T0MExKPgfQuee5rS4fQH77UsnWwt4BKX40drgbXsWSgSLLa7YWF
         MMbpAztHDfU12rMjxLt2fDcLXZeMuZcpuWni8JrLpdhuTavbT335HC5ohPT/kqMN6fLz
         SB8Y61Jeau1f3vvx7eSyMIFFRR2pNK/53Ek+sPhsfy4aQB6Q9skq0TItjt/Tiq3EfjcW
         98aw==
X-Gm-Message-State: ACgBeo3u+zwuz62ms7FZH3o/LhY/FI8yv++ZNAgsyYVd0avpdTYJbm79
	36UKfVUSArSRqYj/0MHxvm4=
X-Google-Smtp-Source: AA6agR40a1MSDdZ27o3O9BjA5crZRIsHmmHJplfdoWfI6YOKWBUwC8u1UhMbgXX7cUwv0kdodqxURw==
X-Received: by 2002:a05:6512:c1c:b0:494:6c98:a298 with SMTP id z28-20020a0565120c1c00b004946c98a298mr10638405lfu.18.1662380774619;
        Mon, 05 Sep 2022 05:26:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:80ce:0:b0:261:ccd8:c60 with SMTP id r14-20020a2e80ce000000b00261ccd80c60ls1558276ljg.10.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:26:12 -0700 (PDT)
X-Received: by 2002:a2e:bcc7:0:b0:261:8fb3:d4ec with SMTP id z7-20020a2ebcc7000000b002618fb3d4ecmr13704720ljp.96.1662380772770;
        Mon, 05 Sep 2022 05:26:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380772; cv=none;
        d=google.com; s=arc-20160816;
        b=JD0jfMQVr/uN8lCGq69KY9VG1CLjXpHEqkJ1k07e0gZPiSj6vJUnaEGFwhxggBXVbw
         wLbXVcElNi2eEa7tv3baMaSTQy36A8q1VEzKgQK8ISaNcK6ZROpidCAF1Io8vsglJblu
         S+sF5o9k1rk8HKgLsWxEFm6bCKvqbIMdY4IZpudfzNvSzLfPAIOLsZrYIwK31yKe+053
         mkU7lmhJFAl1VUgsMZ2T3Q62E1UknkY2pfE6vbL7NGcyXaNdHniinQnwSZBnLnFMcZN4
         37bV73Ff6+foPbXDH5gR37OV2Vh8VGupsg22U1WdJuDmJFAgyFsk2BUcficCfJwcAWZj
         B2sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YUiFcVJy4Yf/nhkRGOhECdnAl5j2ey18UxYwbxsEwuI=;
        b=mHgLDpwLfLKJt2qZJe15A/MKfyhuBDqGTm8NiDj5SuKUTqrJrnZo+hmyW7bwVhYESu
         UuS2Ei6fBIKSlE/0VeT1WOa3M6YX7UuMqfIlwgVhR4MHgqFkCcx54PHHJveDkzl/mrvU
         d+7xJ169t6m9E7LmUEwO2GNeEIGcNc9PzyeNr4A4Dj1SJ6jhIrNsoEr9q8Hg8OGMGhgL
         RvBc2G6v4ye5j24qpMT7BuuDQr2HzMjP2QADISIRP0MHWB1lK4IyU1ANqjz0Bs7MTU/y
         BrktUDgLeFHrp8I7KQsBTJTNswCfFZW+TVpwxP2cDvwlAIKIvQXw7O+sae1tjIPo1x6H
         FVLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EuJefT6p;
       spf=pass (google.com: domain of 35oovywykctetyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35OoVYwYKCTETYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id c17-20020a056512075100b0048b38f379d7si344261lfs.0.2022.09.05.05.26.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35oovywykctetyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id q10-20020a1ce90a000000b003a60123678aso1668900wmc.6
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:12 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6000:713:b0:226:ea6c:2d7d with SMTP id
 bs19-20020a056000071300b00226ea6c2d7dmr14917835wrb.293.1662380772234; Mon, 05
 Sep 2022 05:26:12 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:35 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-28-glider@google.com>
Subject: [PATCH v6 27/44] crypto: kmsan: disable accelerated configs under KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EuJefT6p;       spf=pass
 (google.com: domain of 35oovywykctetyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35OoVYwYKCTETYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

KMSAN is unable to understand when initialized values come from assembly.
Disable accelerated configs in KMSAN builds to prevent false positive
reports.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/Idb2334bf3a1b68b31b399709baefaa763038cc50
---
 crypto/Kconfig      | 30 ++++++++++++++++++++++++++++++
 drivers/net/Kconfig |  1 +
 2 files changed, 31 insertions(+)

diff --git a/crypto/Kconfig b/crypto/Kconfig
index bb427a835e44a..182fb817ebb52 100644
--- a/crypto/Kconfig
+++ b/crypto/Kconfig
@@ -319,6 +319,7 @@ config CRYPTO_CURVE25519
 config CRYPTO_CURVE25519_X86
 	tristate "x86_64 accelerated Curve25519 scalar multiplication library"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_LIB_CURVE25519_GENERIC
 	select CRYPTO_ARCH_HAVE_LIB_CURVE25519
 
@@ -367,11 +368,13 @@ config CRYPTO_AEGIS128
 config CRYPTO_AEGIS128_SIMD
 	bool "Support SIMD acceleration for AEGIS-128"
 	depends on CRYPTO_AEGIS128 && ((ARM || ARM64) && KERNEL_MODE_NEON)
+	depends on !KMSAN # avoid false positives from assembly
 	default y
 
 config CRYPTO_AEGIS128_AESNI_SSE2
 	tristate "AEGIS-128 AEAD algorithm (x86_64 AESNI+SSE2 implementation)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_AEAD
 	select CRYPTO_SIMD
 	help
@@ -517,6 +520,7 @@ config CRYPTO_NHPOLY1305
 config CRYPTO_NHPOLY1305_SSE2
 	tristate "NHPoly1305 hash function (x86_64 SSE2 implementation)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_NHPOLY1305
 	help
 	  SSE2 optimized implementation of the hash function used by the
@@ -525,6 +529,7 @@ config CRYPTO_NHPOLY1305_SSE2
 config CRYPTO_NHPOLY1305_AVX2
 	tristate "NHPoly1305 hash function (x86_64 AVX2 implementation)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_NHPOLY1305
 	help
 	  AVX2 optimized implementation of the hash function used by the
@@ -649,6 +654,7 @@ config CRYPTO_CRC32C
 config CRYPTO_CRC32C_INTEL
 	tristate "CRC32c INTEL hardware acceleration"
 	depends on X86
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_HASH
 	help
 	  In Intel processor with SSE4.2 supported, the processor will
@@ -689,6 +695,7 @@ config CRYPTO_CRC32
 config CRYPTO_CRC32_PCLMUL
 	tristate "CRC32 PCLMULQDQ hardware acceleration"
 	depends on X86
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_HASH
 	select CRC32
 	help
@@ -748,6 +755,7 @@ config CRYPTO_BLAKE2B
 config CRYPTO_BLAKE2S_X86
 	bool "BLAKE2s digest algorithm (x86 accelerated version)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_LIB_BLAKE2S_GENERIC
 	select CRYPTO_ARCH_HAVE_LIB_BLAKE2S
 
@@ -762,6 +770,7 @@ config CRYPTO_CRCT10DIF
 config CRYPTO_CRCT10DIF_PCLMUL
 	tristate "CRCT10DIF PCLMULQDQ hardware acceleration"
 	depends on X86 && 64BIT && CRC_T10DIF
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_HASH
 	help
 	  For x86_64 processors with SSE4.2 and PCLMULQDQ supported,
@@ -831,6 +840,7 @@ config CRYPTO_POLY1305
 config CRYPTO_POLY1305_X86_64
 	tristate "Poly1305 authenticator algorithm (x86_64/SSE2/AVX2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_LIB_POLY1305_GENERIC
 	select CRYPTO_ARCH_HAVE_LIB_POLY1305
 	help
@@ -920,6 +930,7 @@ config CRYPTO_SHA1
 config CRYPTO_SHA1_SSSE3
 	tristate "SHA1 digest algorithm (SSSE3/AVX/AVX2/SHA-NI)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SHA1
 	select CRYPTO_HASH
 	help
@@ -931,6 +942,7 @@ config CRYPTO_SHA1_SSSE3
 config CRYPTO_SHA256_SSSE3
 	tristate "SHA256 digest algorithm (SSSE3/AVX/AVX2/SHA-NI)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SHA256
 	select CRYPTO_HASH
 	help
@@ -943,6 +955,7 @@ config CRYPTO_SHA256_SSSE3
 config CRYPTO_SHA512_SSSE3
 	tristate "SHA512 digest algorithm (SSSE3/AVX/AVX2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SHA512
 	select CRYPTO_HASH
 	help
@@ -1168,6 +1181,7 @@ config CRYPTO_WP512
 config CRYPTO_GHASH_CLMUL_NI_INTEL
 	tristate "GHASH hash function (CLMUL-NI accelerated)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_CRYPTD
 	help
 	  This is the x86_64 CLMUL-NI accelerated implementation of
@@ -1228,6 +1242,7 @@ config CRYPTO_AES_TI
 config CRYPTO_AES_NI_INTEL
 	tristate "AES cipher algorithms (AES-NI)"
 	depends on X86
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_AEAD
 	select CRYPTO_LIB_AES
 	select CRYPTO_ALGAPI
@@ -1369,6 +1384,7 @@ config CRYPTO_BLOWFISH_COMMON
 config CRYPTO_BLOWFISH_X86_64
 	tristate "Blowfish cipher algorithm (x86_64)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_BLOWFISH_COMMON
 	imply CRYPTO_CTR
@@ -1399,6 +1415,7 @@ config CRYPTO_CAMELLIA
 config CRYPTO_CAMELLIA_X86_64
 	tristate "Camellia cipher algorithm (x86_64)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	imply CRYPTO_CTR
 	help
@@ -1415,6 +1432,7 @@ config CRYPTO_CAMELLIA_X86_64
 config CRYPTO_CAMELLIA_AESNI_AVX_X86_64
 	tristate "Camellia cipher algorithm (x86_64/AES-NI/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_CAMELLIA_X86_64
 	select CRYPTO_SIMD
@@ -1433,6 +1451,7 @@ config CRYPTO_CAMELLIA_AESNI_AVX_X86_64
 config CRYPTO_CAMELLIA_AESNI_AVX2_X86_64
 	tristate "Camellia cipher algorithm (x86_64/AES-NI/AVX2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_CAMELLIA_AESNI_AVX_X86_64
 	help
 	  Camellia cipher algorithm module (x86_64/AES-NI/AVX2).
@@ -1478,6 +1497,7 @@ config CRYPTO_CAST5
 config CRYPTO_CAST5_AVX_X86_64
 	tristate "CAST5 (CAST-128) cipher algorithm (x86_64/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_CAST5
 	select CRYPTO_CAST_COMMON
@@ -1501,6 +1521,7 @@ config CRYPTO_CAST6
 config CRYPTO_CAST6_AVX_X86_64
 	tristate "CAST6 (CAST-256) cipher algorithm (x86_64/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_CAST6
 	select CRYPTO_CAST_COMMON
@@ -1534,6 +1555,7 @@ config CRYPTO_DES_SPARC64
 config CRYPTO_DES3_EDE_X86_64
 	tristate "Triple DES EDE cipher algorithm (x86-64)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_LIB_DES
 	imply CRYPTO_CTR
@@ -1604,6 +1626,7 @@ config CRYPTO_CHACHA20
 config CRYPTO_CHACHA20_X86_64
 	tristate "ChaCha stream cipher algorithms (x86_64/SSSE3/AVX2/AVX-512VL)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_LIB_CHACHA_GENERIC
 	select CRYPTO_ARCH_HAVE_LIB_CHACHA
@@ -1674,6 +1697,7 @@ config CRYPTO_SERPENT
 config CRYPTO_SERPENT_SSE2_X86_64
 	tristate "Serpent cipher algorithm (x86_64/SSE2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_SERPENT
 	select CRYPTO_SIMD
@@ -1693,6 +1717,7 @@ config CRYPTO_SERPENT_SSE2_X86_64
 config CRYPTO_SERPENT_SSE2_586
 	tristate "Serpent cipher algorithm (i586/SSE2)"
 	depends on X86 && !64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_SERPENT
 	select CRYPTO_SIMD
@@ -1712,6 +1737,7 @@ config CRYPTO_SERPENT_SSE2_586
 config CRYPTO_SERPENT_AVX_X86_64
 	tristate "Serpent cipher algorithm (x86_64/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_SERPENT
 	select CRYPTO_SIMD
@@ -1732,6 +1758,7 @@ config CRYPTO_SERPENT_AVX_X86_64
 config CRYPTO_SERPENT_AVX2_X86_64
 	tristate "Serpent cipher algorithm (x86_64/AVX2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SERPENT_AVX_X86_64
 	help
 	  Serpent cipher algorithm, by Anderson, Biham & Knudsen.
@@ -1876,6 +1903,7 @@ config CRYPTO_TWOFISH_586
 config CRYPTO_TWOFISH_X86_64
 	tristate "Twofish cipher algorithm (x86_64)"
 	depends on (X86 || UML_X86) && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_ALGAPI
 	select CRYPTO_TWOFISH_COMMON
 	imply CRYPTO_CTR
@@ -1893,6 +1921,7 @@ config CRYPTO_TWOFISH_X86_64
 config CRYPTO_TWOFISH_X86_64_3WAY
 	tristate "Twofish cipher algorithm (x86_64, 3-way parallel)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_TWOFISH_COMMON
 	select CRYPTO_TWOFISH_X86_64
@@ -1913,6 +1942,7 @@ config CRYPTO_TWOFISH_X86_64_3WAY
 config CRYPTO_TWOFISH_AVX_X86_64
 	tristate "Twofish cipher algorithm (x86_64/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_SIMD
 	select CRYPTO_TWOFISH_COMMON
diff --git a/drivers/net/Kconfig b/drivers/net/Kconfig
index 94c889802566a..2aaf02bfe6f7e 100644
--- a/drivers/net/Kconfig
+++ b/drivers/net/Kconfig
@@ -76,6 +76,7 @@ config WIREGUARD
 	tristate "WireGuard secure network tunnel"
 	depends on NET && INET
 	depends on IPV6 || !IPV6
+	depends on !KMSAN # KMSAN doesn't support the crypto configs below
 	select NET_UDP_TUNNEL
 	select DST_CACHE
 	select CRYPTO
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-28-glider%40google.com.
