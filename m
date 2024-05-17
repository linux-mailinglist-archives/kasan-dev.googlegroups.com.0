Return-Path: <kasan-dev+bncBAABBKFKTWZAMGQEK7VQEFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CC47E8C86E5
	for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 15:01:29 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2e289eec4bfsf17003921fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 06:01:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715950889; cv=pass;
        d=google.com; s=arc-20160816;
        b=YLdxwLyk7Q8AWGEVzGmjWVnbX2gQn15McSTHl7ASBbtJVLhwH0yZyuL5EiSLsFcx5T
         qn1v6kjJLcjAAMPd+m+s4ggRVYu1AAcdlmfzsp47FRMUzQ1oMAuI0Vj352ASFNGwJvlg
         OzBOcLYYzGz9woxcgsQef+6SQgbPPTKshsSi3ou9epVE75fdnRLqyb90dxeDyp30gALK
         poof1yzeoqez/cRH6cHTe+5h4GxUFcOX8sXsxwxbG9W/DrsZAs8u69REePbSJt68OaQe
         qgN+PxDZxZPZqxIivpOj4+jaaCe4raayJXsJP5lFO/KXJFfx1nDq75pEdY5+qMnxj6xC
         nAxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=38MgWpKyt4J3+4T8iRqrNLmAlmGHOyHiBRwsKQJa7Ds=;
        fh=jY6bD0Zmk0Nn8WNZvPWILOy9Z2DiiQeblvMqZzFq4rg=;
        b=scC7/rPJAh/c6XD+armIf+9hRii1EBvjWxMw9gPsiwwyC5uVPn4/VusoA6aB1bYnBo
         Co7pDTCO2/b0++2hjLPzhsRquzpaI1+N7bB25tT5hEBto4Ja+h9hQK4FQi3o4G0rA3zI
         VE2HsokyK97G5RWiA+3kC4/+gKJUV0BwKqh1WDmHhzaR5pSjADwCWfAQIjrHq8Ctke73
         2nlrDvm2tqXstd7RzTyWmJi2SM8c3+REl7xw7dxXGGU5qaHs7ncg6h1/P0pW5cWerniy
         5LjaodpZQ4sVfZ8Q0EudFxvS1C2060Mwx2OmM1uk0vqEBWGeOQI+6opkkoxlNci/svWv
         7U2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=twrr19Ft;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715950889; x=1716555689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=38MgWpKyt4J3+4T8iRqrNLmAlmGHOyHiBRwsKQJa7Ds=;
        b=u8BoUZNw0B3b+jSwRI+hy5V4IdbQVgy5KpjTaedmxvKu01TWI3b6m6KueH/HhOBpoJ
         ywTVElXF0oqNCLtaIN1T11DUZ70ENEICB3EfMI8iRUKZmknPz+QS90zbd4ngDVSKQ6mU
         8/fr8E0Zw+ihiTHieRzgRZ0+375A4IIK1pxW5iP40B+VQZkuE/EbgPYha4J3df0X/Zop
         r/hwi0QJaO1dkpAdBIh8rfFtjMwmFVAb2lYJTVUOm6ROkVAvht92rDmZxSeIM/OrC1Ui
         Sw9GnmIlLHBObpw6mdPU3Yd64iB86JS9rdaPmI+TtHL1iWmnXbE/VU+kiTc08pFC/CEu
         cc5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715950889; x=1716555689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=38MgWpKyt4J3+4T8iRqrNLmAlmGHOyHiBRwsKQJa7Ds=;
        b=kmNNOASzivRgtG+XD46YiltWASdNaRQkmA0+YpavM6BZbgZGqQDxHPSJ2q5Bp5qB6z
         I1D5qxywq8O8fDOL42XSzE2JrcD+CfnnSUvQCF4o3lONFdGzSAelTY/M6B/o115jeDdi
         5dgTuXhtU1vgVKwqazW0ozxc8lmD4pOBTmpbJPVMoYPrO18YBz/6sjlzW5Jcl1V5OiN0
         kilFrXiV7t1w0FVxvlAewUj0CUT9vIL0mZgArmNbxcBlwkAKcCmnwFzeyM6TAnY24XWg
         w1L4OeRMpRaRBrehzz9CglrzlAq8V5NjWzASWaPAIGT0PCQzW7ScqubZySyJrgYTi7n4
         LzNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhWxGjs0CqE3FqA6msMFEv/D5dMOSolZbKepTjKgqmP7s1Y71TCfJcdOZVnPD/BCMM/FBKArQf6stPL6SKz5PbTUrz2LR0UQ==
X-Gm-Message-State: AOJu0YyTvwcdBHLUg6ZXjtCidX5u3uZwlaWtZ3gTIDicPX7xqOzT725j
	Lbh8scUqbP4KOBSbUYjvfw1T2qimTUlRuvYHjdqkUbmKxRp9V3fy
X-Google-Smtp-Source: AGHT+IGEo296Mc6HeyGj+oNRnW241waDJaDg6vtWge7JPvZFtvHQXdhNlNaaeF3d3D2aigQzDQXbOg==
X-Received: by 2002:a05:6512:e81:b0:51b:ada6:f1a2 with SMTP id 2adb3069b0e04-5221006e63bmr15799243e87.3.1715950888569;
        Fri, 17 May 2024 06:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:51b:db14:78ff with SMTP id
 2adb3069b0e04-521e3032ec4ls1832984e87.0.-pod-prod-01-eu; Fri, 17 May 2024
 06:01:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4Ca4SqEb1AVWBrzGE5pOO4sab/YAtZRyDO8J60xvXX+FPNJ0jVlbwlpeldRSPc5x71gIPfgAGUEqSFXBiRjYMdWDiNdkubFhuKQ==
X-Received: by 2002:a19:f001:0:b0:51c:adb8:8921 with SMTP id 2adb3069b0e04-5221006c765mr12965324e87.58.1715950886669;
        Fri, 17 May 2024 06:01:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715950886; cv=none;
        d=google.com; s=arc-20160816;
        b=d2c6CttVWfgKzA9Ssq/Xlxvn4ODzJp6pxuKDpYJFXvk3KmXF7MTxeSjLi1mTpnzqJq
         0aQuoQESOjQee1rIdzlPNsLGjM9seya9u88a71t8HXgvy5qSBod5ka/qRtT/mSHZ7681
         J8/YnaPhOyFtzU3tDfdln1ULgKRVq9Cbp8Ur9cCstbvu+UIWBS0zTKNSPak9c94+o17m
         Tn8zF/db/zKVI9FomH6yRg7A4Iq3fuuSdyhcJUgmge2558d/kO7hZr70xwNVKvURUm0C
         fcxNfytq1i4WaMAegaCI5aLFQpFK//L7q3mkutCKThq0+AafVXkuVGVwZqd9njJ1CkrH
         kLBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=tyN60hwyyyZujQaT4M6CmN3OZiKg7vscoBXPblyi5YU=;
        fh=RcBQLGK3NgZYGRmG8ty4nAEOWBH9kZnq/a9VViofapo=;
        b=Txyb2+39qhIlsG2ZNhKved1ggDIsF77topDsvMdHFftDHkPCLget2dlHu+v7T7Qcg9
         84p20LW2uGQHyr6hAjDq3LVcLDAthcgfrynsnQqVc2CCbpvx19evk613pmIQIG6dwTvk
         puVyYBxd3NYM6LCbqt+TaF3QwnZ4Ah9+pnb8mBnMxpEB2XsMS1ozzJvrA3ItApkb3myH
         DRCoSNqdSrApVrf1xAX4cv+duRw9FF+stkbu8CJZvKYv6Gyd81l1Bo9O1udPmA361SKt
         tBlIKTo69KPeaUyAppBXMcOVyW4j9f7YRqv+UiWwpdVtKs5utvw4aTN++yPoBMXiFD1v
         tFZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=twrr19Ft;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [95.215.58.181])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52231471aeesi386807e87.3.2024.05.17.06.01.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 May 2024 06:01:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) client-ip=95.215.58.181;
X-Envelope-To: elver@google.com
X-Envelope-To: andreyknvl@gmail.com
X-Envelope-To: glider@google.com
X-Envelope-To: dvyukov@google.com
X-Envelope-To: ryabinin.a.a@gmail.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: akpm@linux-foundation.org
X-Envelope-To: linux-mm@kvack.org
X-Envelope-To: erhard_f@mailbox.org
X-Envelope-To: npache@redhat.com
X-Envelope-To: dja@axtens.net
X-Envelope-To: linux-kernel@vger.kernel.org
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Erhard Furtner <erhard_f@mailbox.org>,
	Nico Pache <npache@redhat.com>,
	Daniel Axtens <dja@axtens.net>,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan, fortify: properly rename memintrinsics
Date: Fri, 17 May 2024 15:01:18 +0200
Message-Id: <20240517130118.759301-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=twrr19Ft;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@gmail.com>

After commit 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*()
functions") and the follow-up fixes, with CONFIG_FORTIFY_SOURCE enabled,
even though the compiler instruments meminstrinsics by generating calls
to __asan/__hwasan_ prefixed functions, FORTIFY_SOURCE still uses
uninstrumented memset/memmove/memcpy as the underlying functions.

As a result, KASAN cannot detect bad accesses in memset/memmove/memcpy.
This also makes KASAN tests corrupt kernel memory and cause crashes.

To fix this, use __asan_/__hwasan_memset/memmove/memcpy as the underlying
functions whenever appropriate. Do this only for the instrumented code
(as indicated by __SANITIZE_ADDRESS__).

Reported-by: Erhard Furtner <erhard_f@mailbox.org>
Reported-by: Nico Pache <npache@redhat.com>
Closes: https://lore.kernel.org/all/20240501144156.17e65021@outsider.home/
Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memintrinsics")
Fixes: 36be5cba99f6 ("kasan: treat meminstrinsic as builtins in uninstrumented files")
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 include/linux/fortify-string.h | 22 ++++++++++++++++++----
 1 file changed, 18 insertions(+), 4 deletions(-)

diff --git a/include/linux/fortify-string.h b/include/linux/fortify-string.h
index 85fc0e6f0f7f..bac010cfc42f 100644
--- a/include/linux/fortify-string.h
+++ b/include/linux/fortify-string.h
@@ -75,17 +75,30 @@ void __write_overflow_field(size_t avail, size_t wanted) __compiletime_warning("
 	__ret;							\
 })
 
-#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+#if defined(__SANITIZE_ADDRESS__)
+
+#if !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) && !defined(CONFIG_GENERIC_ENTRY)
+extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
+extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
+extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
+#elif defined(CONFIG_KASAN_GENERIC)
+extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(__asan_memset);
+extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(__asan_memmove);
+extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(__asan_memcpy);
+#else /* CONFIG_KASAN_SW_TAGS */
+extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(__hwasan_memset);
+extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(__hwasan_memmove);
+extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(__hwasan_memcpy);
+#endif
+
 extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);
 extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);
-extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
-extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
-extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
 extern char *__underlying_strcat(char *p, const char *q) __RENAME(strcat);
 extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strcpy);
 extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(strlen);
 extern char *__underlying_strncat(char *p, const char *q, __kernel_size_t count) __RENAME(strncat);
 extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size) __RENAME(strncpy);
+
 #else
 
 #if defined(__SANITIZE_MEMORY__)
@@ -110,6 +123,7 @@ extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size)
 #define __underlying_strlen	__builtin_strlen
 #define __underlying_strncat	__builtin_strncat
 #define __underlying_strncpy	__builtin_strncpy
+
 #endif
 
 /**
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240517130118.759301-1-andrey.konovalov%40linux.dev.
