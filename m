Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKOEUOMAMGQEVJ4GZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F8D05A2A85
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:30 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf295097lfa.10
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526569; cv=pass;
        d=google.com; s=arc-20160816;
        b=rJz160Ps9z7FTVpWjFbWqD+eFyxT1TK36ed5Uqkg1fyRf284qFjgrsnQfbiwzxEUEf
         6vRdaThKI6nDJLkDtGubtBa96syfEFKBTkdjcF2PpeeQuW+RhxKEDmTXLqCAdZliTUQn
         AHtXRw7HR/zmJdehApe7Cj6ElSHp+m+1zI5R4PmRycEWnwBHt5aL2PYlaFPuLaNwbDzK
         YPB2qS0ee3jPkdOeSimRWAOy63ze1lEJHQvLP2k3RmYGTZ/xU/+9aOO9WljReDGmDDcC
         xAFkYm3qCISLFCk1H6hmt8JxKu302z1K7NiX8GRP1PhhWXu1djGqtaJ8TQJUKRK0ivOd
         662g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=DaQuAh6Xld3uEq6AewIn6/tL8Tvem/DsODBvNr9C7f4=;
        b=GwGuvAHOYLud71u4/z4EhzGG226P6Lsq7EnsuuyN3vWr02frEjsc23YToFA4QR+HtG
         tPbLub81bT1fI7zfKocrPi994GbR0Aeg2TRokBwkzA3V8/R7AzvChtK8gYBRI64ca9uB
         ww6+HiPozumYAPa0ZMXjlOxJWKTeYPq6il6uzJ7L2hSjw9QCeU4OshYfqU3mFH/1Ngpx
         wRgYEz4nDIlRK22KXNjGh14z2XQLMgAhlBoSMDQU2Nn5h4rRfheHxoQ+CANKMmA9jNof
         jbDxTcVeSGfjIREEFMJJ8jLsRw+uYS2AnVZzttWAW9Wz3r6BCPK72JVhCu6Tq8Nxg3Ye
         7pxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C36uYdPs;
       spf=pass (google.com: domain of 3j-iiywykcs4qvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3J-IIYwYKCS4QVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=DaQuAh6Xld3uEq6AewIn6/tL8Tvem/DsODBvNr9C7f4=;
        b=JOdRUJcitBAG29pUtGWfuHjA1pSV9PRWWvPzgAdt2qICPOxHqGl5csR5LFnD6HLaCN
         FQ9U4zw1dWy4e6Znw8LEfZ2DAhPnELFwlVfes8o3AxqMUN5sLylspP8X5+uJjNYwXLcS
         qdjK8FzCLIEIyGz6ZwWWbWoyk/l9tDv9NNKBokJ65dq3hSRfN3ZJCQ3iUG6z5bWYe0st
         QRe22Tck60I9VxmGIcTpWCnia3edvcKZwtjH9J74aZgA5ro6tLOT7kQ/wsGMFAEi3fBF
         c4UmSsPhoFqh/x4ZclAW3yhO5TbkRKhpf17qDB8WWeIkOy4BGfr2gXmKr9KSUy+XeisL
         hdgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=DaQuAh6Xld3uEq6AewIn6/tL8Tvem/DsODBvNr9C7f4=;
        b=hRBaghrjd9UPUuXqSYZdgXhxUwpZnQ57AHHbgBW7hrGzWUa2iSmpBl3eSU5k63swPB
         u46J1BGNFUZRYwjBvAhBiNa3PL2xBVZzF3UFB6Kh4IgUhGxFJiT94SkSzqRBayWRjG1S
         YM3iLcTGsA7ViqG15UMJ3usGj+P/YHpqcRrXRMOpFuAYVfJnXcqty12MWTEU7KSxo4/X
         +RSlcTEtDXJ3wuISZgkdMfyqFR5e/LO/g4cFH/o767qQdj526DudzDSV1ajtS7gmHPq8
         PbBYGtPRmShJtGIkL7xAXcb9nu+hQXm20IfNG2Tp3VLApK0XMYPUXJ5euCLIHh5R8bv2
         Yfow==
X-Gm-Message-State: ACgBeo2UceFu3y/E3KItYgFsp7upLQKvFRcqGISnzNBEMN1ptTPELRV9
	ju5Rhc3WtyK8NPWYG9+h9WY=
X-Google-Smtp-Source: AA6agR5KQZTaZmkY6x9uJbb+HG8gXlld4qdLACxz2hVz7Taf6c15CoiRmDI36D+q84bHOym3gASKaw==
X-Received: by 2002:a2e:9c03:0:b0:262:9b6d:bcc0 with SMTP id s3-20020a2e9c03000000b002629b6dbcc0mr1066145lji.312.1661526569590;
        Fri, 26 Aug 2022 08:09:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3588:b0:48b:3a68:3b0 with SMTP id
 m8-20020a056512358800b0048b3a6803b0ls1146678lfr.0.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:28 -0700 (PDT)
X-Received: by 2002:a05:6512:114f:b0:492:3aec:69f9 with SMTP id m15-20020a056512114f00b004923aec69f9mr2428693lfg.289.1661526568536;
        Fri, 26 Aug 2022 08:09:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526568; cv=none;
        d=google.com; s=arc-20160816;
        b=dCsBvF8ihQ92deZEGgl9eHuZepgfkb7Bv9U6DlG7gITavawtZrmKU7ZJYV2U6SvQ6H
         y94d7asC2b6SNuNCZlndsuBeNqmOsIPBZlV9InjmAdAIF6ISryPSYkBdXecw6PhJ+FxD
         l5VXKTyeoVAIrMATxPkNFeJak/EB2H8gHaCVUgTnwJACuOXAlqD+cywFg4OAOgqzw410
         2p7JTodbCpYbUI4QzYvEg+qjZcXO+ALUT1ovxXo8hgAeJD6zq5YyO9Jg0vwiBcOsyaeN
         vuNRUHbN3pX+1Kj06Ruq9ZX77Zp07jBuMJd8bYIlkcZOHM0QTx87/AbwqihJ6keO73hw
         TNwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=1gFHCXdD1YZhZE1n87Od5kpjEzNiLhH4oD7CKEg8NyA=;
        b=RxLJCSwXi+KwdQtekUo6UDW8OLWRx4LGVNsD09Z6C66dDHYPAdW4jMwqGYE9SFmx4M
         neRFJt547pvswb5VOoojI7OGIbdyYUuHU681ROQ3letLIZ9HdcFZgZ4sVU/aOGEg2OXw
         Zh9dGjaBgflmuT/QiPc2Qwp7P6RIrSC4z1jMULl9g3diWj+1GxgTz8dCkV77YQWMwDHW
         jWWdvhuCb6uQQZ3Q83mBP033Jjmsrz6dpJLJdZA+8qICn7lltlrD15Gs1xnSROObw8pB
         ta28eHdY9VrqO5V8Aqv1EmvzaEA1S6BAafc6UsZ9LKTJW2unefEzUnpFaP0gjTgEr5i0
         FIfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C36uYdPs;
       spf=pass (google.com: domain of 3j-iiywykcs4qvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3J-IIYwYKCS4QVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bd26-20020a05651c169a00b0026182ffd1c0si78630ljb.5.2022.08.26.08.09.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j-iiywykcs4qvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id ne1-20020a1709077b8100b0073d957e2869so724368ejc.1
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:28 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:882:b0:447:e6b9:89db with SMTP id
 e2-20020a056402088200b00447e6b989dbmr2901305edy.346.1661526567955; Fri, 26
 Aug 2022 08:09:27 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:50 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-28-glider@google.com>
Subject: [PATCH v5 27/44] crypto: kmsan: disable accelerated configs under KMSAN
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
 header.i=@google.com header.s=20210112 header.b=C36uYdPs;       spf=pass
 (google.com: domain of 3j-iiywykcs4qvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3J-IIYwYKCS4QVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-28-glider%40google.com.
