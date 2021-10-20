Return-Path: <kasan-dev+bncBCF5XGNWYQBRBIXAYGFQMGQEBWVQS2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5201D4353EA
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 21:38:12 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id j22-20020a62b616000000b0044d091c3999sf2423844pff.16
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 12:38:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634758690; cv=pass;
        d=google.com; s=arc-20160816;
        b=S9mjuNaWvvVa3y6C1MqRDpTSQcbXsUnculvi3WLyJqWB3o+jN9PYl1yDoA3qWLPJ1q
         yyVA6TaDslBcxyNQWCETNpUqVHF08cznZo0w7DF0xsVKTe/IqsK4JFwlMkunyz6Cjw6e
         JJ+iWU+kisWoXoEUQsanQ0VexVQqIJlXk4nKZyjQnZgvHGP1t2ZR0otF40LeSY30otBa
         zLsD6tJVET49wdDIWXa40WeViUzxdahz6RSJT7oGQ2f7/ZYO4R8we/meNOE18uNYdt4E
         LzgqJbi7fb+oNmv23coHSvfLemmIvLvPqo4RJA1wWbOfd//sfQJGwaHjUliofMLSvgCT
         VW7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=h/rGx3+3W1cjOQ71C+uAU4OSA8ieDrIITxmYyis0aFU=;
        b=Z2aheESontPEFXNjdiyw99xw88C3CxzmlmsEiJIX87hRfZNHRhpaVQ1tFzx3ZVOkkP
         YEbJ7wm8Z5hbPGsSzP2Whkh3v+D544O3rQ15I0W219pMu8QO92n54A2LtHQISWxJlm5r
         ouUzdABm2l3YLbZjCIH8GB7gS3YGy/jp5PSYGA2W5mEEUypyGZVjRu6XdVPeOzHPq4hp
         yqeGO5YFy4gLIanhWVINC6qFsZgf8cy6JtcvSJpRmzTiHSKc/iI1alxmcCfrMHDWVOK7
         y+5nq1eYtwXGyN89UZoHpFKA3BBkY4CcSHzFn/rq8+hhWFJ1bDFiEW8YvPm5gJ5yoUgG
         nLig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JKyb1SkF;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h/rGx3+3W1cjOQ71C+uAU4OSA8ieDrIITxmYyis0aFU=;
        b=sFrDUULcnPuiGGIEKbZ07EidG3j2KeF+Be+a+14+1i1Tdks15lzo5+PqbF3zOXEDBA
         WOHdqiwZWnWB9g+Dvnxm6Zb4gDNloltZjhesd2ibWX/KoD8aaTmzFghNYZP90hzSRh8V
         kVz96oKNe7Ux+jeCu4+BFcnzVi4wCpYQSVEZNIs5RjsUDslSPM5ydUzwxJS41aMtmN7l
         L7IFrzJOEuBVXWp7Z9+jkWLCnMWkNQcobWab0L4OFchWLfTJn93iFqqeV9zwtMPh0f0L
         ItrsbQ0EtR9omO+kA9vuvTJLfwke98EdmnBJybvmhH9F29sLW1xK8SujVBTwdFSt4ZRY
         KxMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h/rGx3+3W1cjOQ71C+uAU4OSA8ieDrIITxmYyis0aFU=;
        b=AE4bThgsZF+Tf2+5/sWsRGX+mcS1ez8giSnqtSrC1eQ7hGEyRxXGhdpNZUb4EQ0BiG
         DpxBaiGyYWaL3srKhJ8szsqXDzGVKWlJtpmK8e75svctlLCHHoM6H3VtHr12+CNdw09L
         j2xTwLwg+oJRrzJMosFtARBDxnw0SIcDTmpnSylGKZedm7QZchE/7CQAhm3D5s68wzwh
         IYrojS969eophLkpSQqOwnXXP3ghZLDKhex/puMKVe4/Qd3M+ksCAquZp6RKUsuC1yeH
         uKNPQf31bZErM0WRQbIucOCgsigvpjF6gBtOqCERjXlL4nR+desYb8vpX7o+ch921jaC
         2jmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bgx2wUtHy3ptZ9y1Di+x6qoe2X27wcLVq1Ng7vdYtm3oOp5C2
	NEwkcpZ6NjM1mOKVVIdwhBE=
X-Google-Smtp-Source: ABdhPJx+NrCOz+3irbIGqoKK8TdtAs48n9xOuY9xNmprgVSwjiq8XRnZE6S5rLxQ2o/rz8xRYRyjZg==
X-Received: by 2002:a17:90b:3802:: with SMTP id mq2mr924386pjb.213.1634758690599;
        Wed, 20 Oct 2021 12:38:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6401:: with SMTP id y1ls1472128pfb.10.gmail; Wed, 20 Oct
 2021 12:38:10 -0700 (PDT)
X-Received: by 2002:aa7:8189:0:b0:44c:293a:31e4 with SMTP id g9-20020aa78189000000b0044c293a31e4mr842407pfi.51.1634758690034;
        Wed, 20 Oct 2021 12:38:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634758690; cv=none;
        d=google.com; s=arc-20160816;
        b=FbBiRYvqwFoLaWDjH0FhU0TFzPM8tj9FwvmfWrZ1EN9JnEs+yosW4lHID9tHwrsUCf
         Om2UY7FXhS6pqhXQLqujU2hfaDK2ZRCcYiuiLIBS4XN6As6Vo5M1HUJQ+IPCcHG7q1HJ
         u4MDuFWBiqkHjHI59HRQBp6CfRbAZQt1elhtLhmC1lyGqpMO+xpzCLaHHIXwMkg5doXa
         9VuT5ONF3sV+twuKYDkRwI7zGhCaUL0HlOPi4Byyy3J8OcKP8bZy9EF/jlDlNzSLNfGK
         xzcyUVfQkYy/9q8Qxc1ii+gYL5GpQYenbeXvTXUr2QWf9BTVJ0t8a10aODVajzfCnqCx
         9oqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=AieI3bvElbBAFUYr7qnOh/7i3cSfGy56FTR3mT6hwmE=;
        b=yBaSZi1wCe9xywa6NbnpE+OzIf0inrQ6OAcJj035EfW1eVAkYnSYbJ6r8JCdYNI2td
         g98CKCjKjCh4I+U7g2bSqf/+sErD2LUtyyecwF+lL0rpkHqeK4sU0+qJeEHrY2CeRkDI
         GWcUgQtpecMGxbKSAeQukO11ebUYZI1o5JnLB4l+uLa4VCUC5gvU5x2YE43UxCy03wdZ
         3iJWVyVoKbvOQ7HrGocVc0wcylouvGYENNnoCOXNaG0rM5ynhZSOiRhBfvwIHpzG8PyU
         K2fyO8pILz9oZB2FsNi6PHHrSrddmz848zgUKtsm7lzncMGz8yeGVg7KIBfjM/NcAgjd
         0heQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JKyb1SkF;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id q75si267807pfc.5.2021.10.20.12.38.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Oct 2021 12:38:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id c4so16387310pgv.11
        for <kasan-dev@googlegroups.com>; Wed, 20 Oct 2021 12:38:10 -0700 (PDT)
X-Received: by 2002:a63:720d:: with SMTP id n13mr940824pgc.470.1634758689723;
        Wed, 20 Oct 2021 12:38:09 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id hi1sm3116213pjb.28.2021.10.20.12.38.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Oct 2021 12:38:08 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] kasan: test: Consolidate workarounds for unwanted __alloc_size() protection
Date: Wed, 20 Oct 2021 12:38:07 -0700
Message-Id: <20211020193807.40684-1-keescook@chromium.org>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2714; h=from:subject; bh=iLZ4NeBfkWYVPoHEvytY6uZRaHHHRpbBD9aJk8sFCo8=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBhcHAeOncBqloNqe5Jh5YTZozruTg+mIo+5x7FRFmv mT1TQsyJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCYXBwHgAKCRCJcvTf3G3AJjHvD/ 4vNtVszulxNrfqy5Wok6IMFaTdPBhyb0/9pmGXt/kGQ+XSo/013n5wISDITIGlAQaUr7fdJ+x+dwR7 rutGa4psrboVf6tFgP1/krBnCqXLvFJUGtLUAmNXkFQuD6MNd1EKbh1rnzuH33A+rWlbVWaN+liVYk 9LUaozVSdQQMvuCQMG6WYxUV2rbZ4hxsfnbTJxV06MgEefnOaatyC5sk68te9ZZzvITNXX0uBSpdKL fUlWPVqG19X3Rq59o1X6V9oCFQsFBKRjB2AaUFHfMdob9r7fsND8SgxXO46Rin+cVV61lVy6+NrVtz m25U3dihpLRJYtWagAZkdjaAdAR/s7tFILPHPmRhITTMpq8NhvBVTvNSsdLph0w5JkDWN+vE0yui1e k2ar8i8TTRN8sQnJg3EsWRHReJqdDTOaU58KROqbhGTRsfar2gKPzpA63ApdwKOAY4JWNcPWeX1nPO Oj99NLNw6WyPXQ9Zh01P+0e/ywi40AoShv3TLDy5LSC41ksTOgu9Ts9MfealpwqzoyEebs5/vMRXmm w2/FWZh/2vIAMsWwV2kQTCXNpIRyOqxtb6bt1ZnYW+YaTgVEdAxssuZbeiuZzMWjrLlpEwuTq1AZQE 7dcMAf9nOO8fICycy8lx4p1CdESG3md29TTylk+fFKD7c9KqOXyRtHpWYGkg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=JKyb1SkF;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

This fixes kasan-test-use-underlying-string-helpers.patch to avoid needing
new helpers. As done in kasan-test-bypass-__alloc_size-checks.patch,
just use OPTIMIZER_HIDE_VAR(). Additionally converts a use of
"volatile", which was trying to work around similar detection.

Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
Hi Andrew,

Can you please collapse this into your series? It's cleaner to use the
same method everywhere in this file to avoid the compiler being smart. :)

Thanks!

-Kees
---
 lib/test_kasan.c | 24 ++++++------------------
 1 file changed, 6 insertions(+), 18 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 318fc612e7e7..96a1f085b460 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -525,12 +525,13 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 64;
-	volatile size_t invalid_size = size;
+	size_t invalid_size = size;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
+	OPTIMIZER_HIDE_VAR(invalid_size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
@@ -852,21 +853,6 @@ static void kmem_cache_invalid_free(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
-/*
- * noinline wrappers to prevent the compiler from noticing the overflow
- * at compile time rather than having kasan catch it.
- */
-static noinline void *__kasan_memchr(const void *s, int c, size_t n)
-{
-	return memchr(s, c, n);
-}
-
-static noinline int __kasan_memcmp(const void *s1, const void *s2, size_t n)
-{
-	return memcmp(s1, s2, n);
-}
-
-
 static void kasan_memchr(struct kunit *test)
 {
 	char *ptr;
@@ -884,8 +870,9 @@ static void kasan_memchr(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_ptr_result = __kasan_memchr(ptr, '1', size + 1));
+		kasan_ptr_result = memchr(ptr, '1', size + 1));
 
 	kfree(ptr);
 }
@@ -909,8 +896,9 @@ static void kasan_memcmp(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	memset(arr, 0, sizeof(arr));
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_int_result = __kasan_memcmp(ptr, arr, size+1));
+		kasan_int_result = memcmp(ptr, arr, size+1));
 	kfree(ptr);
 }
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211020193807.40684-1-keescook%40chromium.org.
