Return-Path: <kasan-dev+bncBCCMH5WKTMGRBT76RSMQMGQEU4LZUIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CCCA5B9E1F
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:52 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id d20-20020a2eb054000000b0026c08f42b50sf4086420ljl.20
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254352; cv=pass;
        d=google.com; s=arc-20160816;
        b=d2rhITZ4T8yv+FNHiQdAAlJ8GbWXZCUjx9VppfCPwrDiSv+oU2ENYWWOCmORiEkHWO
         zejaUKg7p9muaHWpSpfZI1kMX8PN6HlJCSHJHiYkLauxcV1vUAYfUra0fH6folEz4HaV
         WbMgX8Ax+lTP3v9VAK5RddAYgSv1ow8qXVjduYiosO05HgjlAS3WdUNp1zdc5qzqPmuh
         bsXS4e+eoo/on26Xu9oXoskPqJFTbkDlNjz1OJtX5auBp1o0j1jvWUJqABPq20skps+d
         IWTtk+tY8SssToZ7be9BQCmqVpWt+/67Z4vgaMEhSZh7klNbue7znIbCOi6/X1yuFEzx
         TQ2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Qbe7m/T5DSDSsVY1Thfjtfh18ClAiFT9MfY/D1DW/hA=;
        b=ZrDrOr9LW8Z7wdTiHrO0i0jb4n5+D5hhgl0n3U4N5Fpg2FoHR6Z1rVt6L0yLcoFUXW
         nZ2W9xy8IVV10dJFDZykIB+7zcSFdpCl4av4Fui+bXBJCuFmYxi2oRhXsPUVKSwb4Ksl
         13rbvyLPXDSY8P7F/yt2Earii88MiWcmw2GQ4vEXv05rRXpLPkJnh6ldJLY3YDGUY1Gk
         pNxBnt67SegY9+ZSQZFkI8szTDgvzXv3Fs7xMJT0rPmacP0IGQMztQCdz8zxXxpJ2KcE
         as5TtxYwbERJXgSDD821m2ABonUCx7LD3DR2Y5QIFsnL5iKUBusi8f8oEQogZoVILKnl
         zwKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VliFMYVC;
       spf=pass (google.com: domain of 3tt8jywykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3TT8jYwYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=Qbe7m/T5DSDSsVY1Thfjtfh18ClAiFT9MfY/D1DW/hA=;
        b=Vr6qMeb/LNb1OEo0DjdzqvFMF5W17MCpGkKNlNQwqTUbkWhOsQoT1bzyojahgq5++z
         EaTYs00zsAtXrcD8pZ5RjO244tcRrTFWYItDkKzKyBbSqo9KkYdq4PjkndmKTn4LChPB
         sI76M8dlZYmW0UIeVSRKRMuE0QSrWl39T5lBNk1b86vhOlUg6N2PSsyOaNIe9IPdOCYR
         JP82yhR82hyPJC6Iymbel8J9Swx2WI5S/uo4OXCZSmG6Z5gDpK5tBpNGB8AadeuHrgL8
         aklIRQ9EZFAflq9LuIJV1s740JGYOgXWdSxR95B2zhRdtdddz0ar3Mar5M0DwcDmtB81
         D/qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Qbe7m/T5DSDSsVY1Thfjtfh18ClAiFT9MfY/D1DW/hA=;
        b=RBmJu+hLeqP7CF7g7I8NS5huoupVykoP3Zx7nWLOx84X198QVHk3R4woKd/G57vq/8
         TOG94whxh5EPKj9kHTDmsyCo6/c+4AdDRajQEUS+w7ZzVuU7bkxB1UN7AFPDGG+AQAT/
         HiFwlKZX3JA4wwB0QzkejXmQy83kSpCLt7KLx4XGmfVkN/8kcdQ3VT9SFJkZT+PrH5DY
         m+3n8+M+Q12zKEgSPNhPjPohBzS4e5F+duVA3xcv9PyMORGTWmIECGo/t20N2ln7UW2r
         04juHCsYfD+bWlrFx6CPbrFveWE8klaXJlDhN6+niDQsuqdwJkTlXulHzxLebUgwgglz
         yRdQ==
X-Gm-Message-State: ACrzQf0TITuUNj6B7L4PaNwRm/pHtYHajszu5lmdU2hrAmDlqlju/0pu
	fF2xHlj5KOuR2zpffE6Snd8=
X-Google-Smtp-Source: AMsMyM50dm4I1Ify2SFOyLHrtXCjHikwPpYBmyj8/aWP71P5gO4yPuuQW+O+bin/3uoiOEWLvZD96w==
X-Received: by 2002:a05:6512:3a87:b0:499:2069:17af with SMTP id q7-20020a0565123a8700b00499206917afmr137074lfu.38.1663254351967;
        Thu, 15 Sep 2022 08:05:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a177:0:b0:26c:215b:964d with SMTP id u23-20020a2ea177000000b0026c215b964dls1150387ljl.11.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:49 -0700 (PDT)
X-Received: by 2002:a2e:320a:0:b0:26b:f7cc:bcd2 with SMTP id y10-20020a2e320a000000b0026bf7ccbcd2mr64770ljy.200.1663254349895;
        Thu, 15 Sep 2022 08:05:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254349; cv=none;
        d=google.com; s=arc-20160816;
        b=X8QtNuzKFQA39MRG1lYRY2fIN/m8tkjbdsoP4NzE7yiNM2LQdHCYB0yeaVM3AAYshB
         myYTycrT9n8B2zXUDbyee2WwFcE0bydorwBzbjaIexOdo/38eu1JQ+CdaqqJ4ctcJKtU
         RpR4uKTE08NZYxMvdtKfFH0kVf4+QaGmzYd/4n11fbESquejojQNyhLbVSjReM8QSt7o
         qNumXltXW1faavtmWpBVzQjztqaR9mty35XU1b+0LnPbQw0eW9TECHSHzDJAylnO82pC
         p45iXDDls+WVujdHTOgOUiqlDQmH+xokFKXhIuFxIX23k0WNf5T9Q3MIYADVE/umk5We
         bMtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YUiFcVJy4Yf/nhkRGOhECdnAl5j2ey18UxYwbxsEwuI=;
        b=uMfp6woPURqgvfQ+gJ3+Y8axsuF6JLz+3/6clu4kDziBXXFyxE/EVpor5WSkko8Zof
         jfbXnz7y9qsA7mQHTvaQyOjuTOfO1uoQbnuf0vktY7wmOyQ1OB2QQYUJ+KOtOi+4/8W5
         e8N3BWGwXZVC4SdpsSW7MKGRdsMqM6MYh8hN+wTccQZufyYhczjBpZr0NJEGa7UA0Se/
         zu/2CuXyyi+oWjdol6YQZdIki6B++/WXOJF7MR9GD5Y7qVsxVqX2mQURy+kkJJkz6gCG
         Ve9rm0WlPB584ues43UlFLRdRu/D+nBNMTGcC2kUl+NXwrCRmhgGV9rRgk1jO5EFqFpL
         mXvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VliFMYVC;
       spf=pass (google.com: domain of 3tt8jywykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3TT8jYwYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id u19-20020a05651c131300b0026c1dedf78csi249329lja.0.2022.09.15.08.05.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tt8jywykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gb9-20020a170907960900b0077d89030bb2so5491714ejc.18
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:49 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:2722:b0:77f:c136:62eb with SMTP id
 d2-20020a170907272200b0077fc13662ebmr301739ejl.522.1663254349203; Thu, 15 Sep
 2022 08:05:49 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:00 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-27-glider@google.com>
Subject: [PATCH v7 26/43] crypto: kmsan: disable accelerated configs under KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VliFMYVC;       spf=pass
 (google.com: domain of 3tt8jywykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3TT8jYwYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-27-glider%40google.com.
