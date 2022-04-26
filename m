Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNWDUCJQMGQEZM4FGQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B215510401
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:43 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id l13-20020a2e868d000000b0024f078d7ea0sf2005391lji.4
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991542; cv=pass;
        d=google.com; s=arc-20160816;
        b=JVLmX9JYiFJ9fLs3Rk4B3rjF8A/DFVvBu+0QWNtd6G1ERzvdYDVoPfOwfChkAtSEFp
         H9qj3Nn8C01Fl9zMrX+rfy81nEQeNRJ7UNkLiDPZuuHO25wiLpFjTaH/oOc0Q5NAd/5k
         7o0HhE43fAzVDFUdJXqINJmJGTCmJ7XL2It18gnudf3WJ+QMOBDLRZVJbds2mXd3aYom
         Vy7SBYM7YomGrVy3YTxPx/ltL8R8qobUJ4R7DNTpJE3fJ2gyPN54EPOwBZmulJo3T8v0
         p5xw4lSqthZc0FZgYNMA57R6SpKaFvKlAASjShzaB6ct7n/n4h1OwML9Q42Oahq3sVnK
         8lqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=D3QgskjCZdqlJ5P8pwvQSuKKce5BhKxAHxb75dDy6HU=;
        b=wgDGgXt7hPEaUrXtZ4agRDrgYb9efhFsBp/p5tDDaDT6RgxKKSJqx1FP6ZRlSgwm0R
         QV/uRboo53zxQFOrsZPRH6nXxlDlkjO3q/MrEozGmzf0HRWEYAxNVzPRCTuw8+Co3st3
         d0IOl2Bwydj42LoTcGqcFdQwRt16h0EXQmhEkU//7cnGFScK0lmoegrCbrcBubO0pfTW
         Vmf3nvD1Q/ANUETqdXkudL+GpqCUBdfq/GTeHUNkGdWksaCtm7uWDAhfTpcGD8faHfs1
         KNaEwRTYEdJX/VyG3l3/t9ahhGAu00cz2gPsL1nOobaHwBzOQwwlVD8h5Td6+jgfIzuD
         zBBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CJZchZCi;
       spf=pass (google.com: domain of 3tcfoygykcbexczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3tCFoYgYKCbEXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D3QgskjCZdqlJ5P8pwvQSuKKce5BhKxAHxb75dDy6HU=;
        b=EHwEiX04EVYeDUQsxG3Z+Ydyu4XHl0CFc/xiuE6T1iE5CxQgAMmCKxxsUkmgTRxu2O
         yY5dTdMf5tNNsphb+uklY5Pp7NCj9Wj65ddw0Vd36y/tAmVKead3TvD0Uw9PXXBq1rFn
         Y5V3q2OxhxKGezWneIQTIbQV091aWQV3yuTXvAe3YYbYOsHF/WYrmjbsQqL7gVUBgpJa
         lIVbcfNAgmh6VMZllGp+CMBm592AbD8tf4erk7FggK2aNZS6sooujWl5TdhYi9Ng1Krz
         qZjP5qQ9ajACxv0QJPOqVDbLAsVaQqqrNRPaaRVOs6igCauAXUAJYXd1dPaEoHgSL4CG
         y2IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D3QgskjCZdqlJ5P8pwvQSuKKce5BhKxAHxb75dDy6HU=;
        b=qZrBrkS1IgoS5KI1Khik706oBdrLlWR24prEaUjVWvTanypNamE0k0ehMAvXqjnHd+
         hyq56PpC/LRNykZnCYrearF3ah2j6V5UMW/KpvNhMK4B+X3WpQWPbvpy9yNOQWyzZSjA
         qzb5nqsLqXrajHdQEPXMdc5jkXfwIwOy59hoh++r1HBtBBqBGZziJX3LLV+GCwCzrJOd
         h9C4PS5kIq1yLqAfKjcUOorBoAvHXnG1Hyg9awfYC+HdefqEB719w/f3Fs94fxqCezF4
         nd1OvVyTTYTGiU5NYNswtQOTfUvA/zoYaQH/MjlL/QPlsISx5/Qvq3Mn2sYN9dnKZRhn
         WuIQ==
X-Gm-Message-State: AOAM531bcHmWbK0B98DsdmwvVZqp9UHpwWJ8alM0/aiyRMBV/IyVQA2U
	GvofFV1wFHlUVXgVr7azS+M=
X-Google-Smtp-Source: ABdhPJz8nz189FiSGc9fVmDYYZDrK+JrUdgAlIO+tXH3b4Ta0xq7d/MXdQTSMfRKn9g8rjz0Ac+Opw==
X-Received: by 2002:a05:651c:3c2:b0:24f:b91:fcba with SMTP id f2-20020a05651c03c200b0024f0b91fcbamr9085694ljp.154.1650991542633;
        Tue, 26 Apr 2022 09:45:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e2a:b0:471:af61:f198 with SMTP id
 i42-20020a0565123e2a00b00471af61f198ls2094333lfv.0.gmail; Tue, 26 Apr 2022
 09:45:41 -0700 (PDT)
X-Received: by 2002:a05:6512:6d1:b0:471:903d:4aab with SMTP id u17-20020a05651206d100b00471903d4aabmr17069598lff.20.1650991541634;
        Tue, 26 Apr 2022 09:45:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991541; cv=none;
        d=google.com; s=arc-20160816;
        b=fvI8TLxHyCSF65G2mNGvJzOtTvSrtCW2h31UINILFTq0UcSPPyqGPfXyq7X8qg+lRB
         8jm/RxPh6tZ9KCGOwodSNqqmEeXykzIg9SwmUAHfy9vol4blUastUF971QSbz94h5xk/
         3jMBEwpl4VDqHDmgyfHEc4hN9kUWpdje9KMIHM+eKJAvPSs0fLVB9JJjgvn/znvWlrCh
         l4mlGlVfhlsIHyJqLNMJJGRAHJt/E0avVjU3GSJRyUrcda3GumSrXrSJ3vDP4wD4uS7e
         onH7L3Uu93MxPLaQLklzQ+YY5sP2CBkwf6b/W9VYdXCGjPPbXc4U9GqXlENVxninpRWQ
         AG2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=38v0n0Mu0Z4gUwOcZ/qVPNhGReXdywq1ed1xS1ZMc/s=;
        b=ORblS14/ObldK8prrIYI49izKogk4F2IcCCkppM536g0o6tuxXfKff/p0jHn2Glb4i
         myHvkQlX5x0jCJhxB02r9ZZgZNCudDddg6zuKEzXrMpnhJGBKrOp+nyGC/cXSoyKxTbR
         wPpHsJTAZGKYUDRFzqeNM7j3RTh6hWy+YojuJ1Pp4GPhEf8hAqc+aTONdvWFzDQrS75N
         dAAJws3FFI5ooUVmXZ49REUrw7JDqkUAqG27IN3+RKXH5v39JlRotXL9AN8OHmXjvvFw
         /fSOLJrakf7rf0NFlhXyyNst0ufHIo2NzRh4h50YKnamhZ6VnoFI/vXlq/eE9BMs/+xf
         S/pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CJZchZCi;
       spf=pass (google.com: domain of 3tcfoygykcbexczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3tCFoYgYKCbEXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id u14-20020a056512128e00b0047196449b6bsi852217lfs.0.2022.04.26.09.45.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tcfoygykcbexczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id cz24-20020a0564021cb800b00425dfdd7768so3907801edb.2
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:41 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:4305:b0:423:f73b:4dd8 with SMTP id
 m5-20020a056402430500b00423f73b4dd8mr25672281edc.218.1650991540848; Tue, 26
 Apr 2022 09:45:40 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:00 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-32-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 31/46] crypto: kmsan: disable accelerated configs under KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CJZchZCi;       spf=pass
 (google.com: domain of 3tcfoygykcbexczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3tCFoYgYKCbEXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
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
index 41068811fd0e1..8078dbba8dd2c 100644
--- a/crypto/Kconfig
+++ b/crypto/Kconfig
@@ -297,6 +297,7 @@ config CRYPTO_CURVE25519
 config CRYPTO_CURVE25519_X86
 	tristate "x86_64 accelerated Curve25519 scalar multiplication library"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_LIB_CURVE25519_GENERIC
 	select CRYPTO_ARCH_HAVE_LIB_CURVE25519
 
@@ -345,11 +346,13 @@ config CRYPTO_AEGIS128
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
@@ -486,6 +489,7 @@ config CRYPTO_NHPOLY1305
 config CRYPTO_NHPOLY1305_SSE2
 	tristate "NHPoly1305 hash function (x86_64 SSE2 implementation)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_NHPOLY1305
 	help
 	  SSE2 optimized implementation of the hash function used by the
@@ -494,6 +498,7 @@ config CRYPTO_NHPOLY1305_SSE2
 config CRYPTO_NHPOLY1305_AVX2
 	tristate "NHPoly1305 hash function (x86_64 AVX2 implementation)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_NHPOLY1305
 	help
 	  AVX2 optimized implementation of the hash function used by the
@@ -607,6 +612,7 @@ config CRYPTO_CRC32C
 config CRYPTO_CRC32C_INTEL
 	tristate "CRC32c INTEL hardware acceleration"
 	depends on X86
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_HASH
 	help
 	  In Intel processor with SSE4.2 supported, the processor will
@@ -647,6 +653,7 @@ config CRYPTO_CRC32
 config CRYPTO_CRC32_PCLMUL
 	tristate "CRC32 PCLMULQDQ hardware acceleration"
 	depends on X86
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_HASH
 	select CRC32
 	help
@@ -712,6 +719,7 @@ config CRYPTO_BLAKE2S
 config CRYPTO_BLAKE2S_X86
 	tristate "BLAKE2s digest algorithm (x86 accelerated version)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_LIB_BLAKE2S_GENERIC
 	select CRYPTO_ARCH_HAVE_LIB_BLAKE2S
 
@@ -726,6 +734,7 @@ config CRYPTO_CRCT10DIF
 config CRYPTO_CRCT10DIF_PCLMUL
 	tristate "CRCT10DIF PCLMULQDQ hardware acceleration"
 	depends on X86 && 64BIT && CRC_T10DIF
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_HASH
 	help
 	  For x86_64 processors with SSE4.2 and PCLMULQDQ supported,
@@ -778,6 +787,7 @@ config CRYPTO_POLY1305
 config CRYPTO_POLY1305_X86_64
 	tristate "Poly1305 authenticator algorithm (x86_64/SSE2/AVX2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_LIB_POLY1305_GENERIC
 	select CRYPTO_ARCH_HAVE_LIB_POLY1305
 	help
@@ -866,6 +876,7 @@ config CRYPTO_SHA1
 config CRYPTO_SHA1_SSSE3
 	tristate "SHA1 digest algorithm (SSSE3/AVX/AVX2/SHA-NI)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SHA1
 	select CRYPTO_HASH
 	help
@@ -877,6 +888,7 @@ config CRYPTO_SHA1_SSSE3
 config CRYPTO_SHA256_SSSE3
 	tristate "SHA256 digest algorithm (SSSE3/AVX/AVX2/SHA-NI)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SHA256
 	select CRYPTO_HASH
 	help
@@ -889,6 +901,7 @@ config CRYPTO_SHA256_SSSE3
 config CRYPTO_SHA512_SSSE3
 	tristate "SHA512 digest algorithm (SSSE3/AVX/AVX2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SHA512
 	select CRYPTO_HASH
 	help
@@ -1061,6 +1074,7 @@ config CRYPTO_WP512
 config CRYPTO_GHASH_CLMUL_NI_INTEL
 	tristate "GHASH hash function (CLMUL-NI accelerated)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_CRYPTD
 	help
 	  This is the x86_64 CLMUL-NI accelerated implementation of
@@ -1111,6 +1125,7 @@ config CRYPTO_AES_TI
 config CRYPTO_AES_NI_INTEL
 	tristate "AES cipher algorithms (AES-NI)"
 	depends on X86
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_AEAD
 	select CRYPTO_LIB_AES
 	select CRYPTO_ALGAPI
@@ -1235,6 +1250,7 @@ config CRYPTO_BLOWFISH_COMMON
 config CRYPTO_BLOWFISH_X86_64
 	tristate "Blowfish cipher algorithm (x86_64)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_BLOWFISH_COMMON
 	imply CRYPTO_CTR
@@ -1265,6 +1281,7 @@ config CRYPTO_CAMELLIA
 config CRYPTO_CAMELLIA_X86_64
 	tristate "Camellia cipher algorithm (x86_64)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	imply CRYPTO_CTR
 	help
@@ -1281,6 +1298,7 @@ config CRYPTO_CAMELLIA_X86_64
 config CRYPTO_CAMELLIA_AESNI_AVX_X86_64
 	tristate "Camellia cipher algorithm (x86_64/AES-NI/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_CAMELLIA_X86_64
 	select CRYPTO_SIMD
@@ -1299,6 +1317,7 @@ config CRYPTO_CAMELLIA_AESNI_AVX_X86_64
 config CRYPTO_CAMELLIA_AESNI_AVX2_X86_64
 	tristate "Camellia cipher algorithm (x86_64/AES-NI/AVX2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_CAMELLIA_AESNI_AVX_X86_64
 	help
 	  Camellia cipher algorithm module (x86_64/AES-NI/AVX2).
@@ -1344,6 +1363,7 @@ config CRYPTO_CAST5
 config CRYPTO_CAST5_AVX_X86_64
 	tristate "CAST5 (CAST-128) cipher algorithm (x86_64/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_CAST5
 	select CRYPTO_CAST_COMMON
@@ -1367,6 +1387,7 @@ config CRYPTO_CAST6
 config CRYPTO_CAST6_AVX_X86_64
 	tristate "CAST6 (CAST-256) cipher algorithm (x86_64/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_CAST6
 	select CRYPTO_CAST_COMMON
@@ -1400,6 +1421,7 @@ config CRYPTO_DES_SPARC64
 config CRYPTO_DES3_EDE_X86_64
 	tristate "Triple DES EDE cipher algorithm (x86-64)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_LIB_DES
 	imply CRYPTO_CTR
@@ -1457,6 +1479,7 @@ config CRYPTO_CHACHA20
 config CRYPTO_CHACHA20_X86_64
 	tristate "ChaCha stream cipher algorithms (x86_64/SSSE3/AVX2/AVX-512VL)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_LIB_CHACHA_GENERIC
 	select CRYPTO_ARCH_HAVE_LIB_CHACHA
@@ -1500,6 +1523,7 @@ config CRYPTO_SERPENT
 config CRYPTO_SERPENT_SSE2_X86_64
 	tristate "Serpent cipher algorithm (x86_64/SSE2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_SERPENT
 	select CRYPTO_SIMD
@@ -1519,6 +1543,7 @@ config CRYPTO_SERPENT_SSE2_X86_64
 config CRYPTO_SERPENT_SSE2_586
 	tristate "Serpent cipher algorithm (i586/SSE2)"
 	depends on X86 && !64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_SERPENT
 	select CRYPTO_SIMD
@@ -1538,6 +1563,7 @@ config CRYPTO_SERPENT_SSE2_586
 config CRYPTO_SERPENT_AVX_X86_64
 	tristate "Serpent cipher algorithm (x86_64/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_SERPENT
 	select CRYPTO_SIMD
@@ -1558,6 +1584,7 @@ config CRYPTO_SERPENT_AVX_X86_64
 config CRYPTO_SERPENT_AVX2_X86_64
 	tristate "Serpent cipher algorithm (x86_64/AVX2)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SERPENT_AVX_X86_64
 	help
 	  Serpent cipher algorithm, by Anderson, Biham & Knudsen.
@@ -1699,6 +1726,7 @@ config CRYPTO_TWOFISH_586
 config CRYPTO_TWOFISH_X86_64
 	tristate "Twofish cipher algorithm (x86_64)"
 	depends on (X86 || UML_X86) && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_ALGAPI
 	select CRYPTO_TWOFISH_COMMON
 	imply CRYPTO_CTR
@@ -1716,6 +1744,7 @@ config CRYPTO_TWOFISH_X86_64
 config CRYPTO_TWOFISH_X86_64_3WAY
 	tristate "Twofish cipher algorithm (x86_64, 3-way parallel)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_TWOFISH_COMMON
 	select CRYPTO_TWOFISH_X86_64
@@ -1736,6 +1765,7 @@ config CRYPTO_TWOFISH_X86_64_3WAY
 config CRYPTO_TWOFISH_AVX_X86_64
 	tristate "Twofish cipher algorithm (x86_64/AVX)"
 	depends on X86 && 64BIT
+	depends on !KMSAN # avoid false positives from assembly
 	select CRYPTO_SKCIPHER
 	select CRYPTO_SIMD
 	select CRYPTO_TWOFISH_COMMON
diff --git a/drivers/net/Kconfig b/drivers/net/Kconfig
index b2a4f998c180e..fed89b6981759 100644
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-32-glider%40google.com.
