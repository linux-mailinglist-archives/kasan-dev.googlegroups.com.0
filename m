Return-Path: <kasan-dev+bncBCF5XGNWYQBRBVWP66FAMGQE6A2UURY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B59F34245D6
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 20:15:51 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id s15-20020a056808008f00b00290ef96e303sf7885oic.21
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 11:15:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633544150; cv=pass;
        d=google.com; s=arc-20160816;
        b=rmb3Ju7DjyyCDVVolZ+igfdu9jEqjSeraEUY6Pwu9Io9ne9RPYa9Cs85PoNZ9ny1/s
         3SUoBdsGFEWTlVR362K3vACO3Es+mc8uxsdIWCjsv/6WdSSNd3riX2VJ6evv6m/3/HhC
         X+0tkvFuaUNFxCrFRvHAOWK2BDoTcYUtvDPJwCEgQrnLmxGoi2MTe5T1FzkmyM7sQpY0
         EMaeXWtpdWmIkYwG4Xq6T4Qnhoiio4Oj8wQo6YZqQbp/X7gv54kbs1kbccodXRAP8imN
         apbyzHAJfONWKsC3YL2skSoxCYNrb30exTpXx/1Y1+fXIWzLw9/fpJHe1JVNFtcVgHSQ
         rwNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=lw/8bH27Y6hdGVqX6rk+rIoNVuDwP7ApwEfvXgTEg5M=;
        b=FUisU3e/eD7AD2EGNzTi2zdyYCLDgJ9Xj/E2oGM27mT57NhqU87sezqbtvB3pXXJ/h
         /bodXR5zPqjJri0WB14NfogTEt8wYj8tWvLEtiJJOL80LU0DOB9UkV67uLZrT8NIPa92
         kyuF3UWRWJF8p2srYmS3foywVx/5MTKZVRli7tTW3ReZw47pSZRGE/WTrSviJN96YCZO
         iUNelVygQo47D8+z0b0YnRzwaB9dKVTKYXMnEcalibnuJSw+2cSQnYs2A6Jw/YC4DuIN
         fResWlO5uGT6N5BKqPi5m4oVeohbhFUXXb0p4TQkuRs+4bIyEZKlxpZIOnrZDCdzFnVV
         bX6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=S45eY5sx;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lw/8bH27Y6hdGVqX6rk+rIoNVuDwP7ApwEfvXgTEg5M=;
        b=eeq79cd3bA/HB4jYgQooPjdAXnF1+mBB/M0QJgBdpfITdvGoWKmSZL4VZON++E2iGw
         rxKRCzO2ovMTda9c7JrE5VnJGH4ErdqzJb9LtHsWfzgsiEz3sU4iDTxWgh3zWOQ8IGXu
         qk+V5jX68dnihij5AWV0p7M3P4nMAnMhw0R6RWlmzojtbmpT+HCrGbpTgpEPHu0+PetT
         H3+vVD70jB8uqrccRQHUkm6LwO8PTIQtnX8Q/OS0R8h8Re1x2yJuJNnZnR4jBe4k2GWd
         abdcY49d60AFU5MemKIoamkCSd6UcvfNnUPKW3H/IEjmU6cipopeMpIc1NBxYz/JBIV2
         dflA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lw/8bH27Y6hdGVqX6rk+rIoNVuDwP7ApwEfvXgTEg5M=;
        b=1DzDldaIveMSTVnR519yR8ly3KDFL6HX7EWWd0U+wOEM4Y+vjvlBtt6utvNfqGmVpS
         bE4DhYM4lQIwz099hKMn2pASU6YW8whNxwCdufjjuKR2a7YvqSefIAmxA0LakZ/SMrcR
         iypTUqxjkPtOGi/jLy3UDsApXvfp9m4uIIh1PcRgt57QnLCQTTTl1o19h3789sFTxwF8
         aQoOOoUse9c59GlsWo5590D+xvzb3mmrgbnHI38YKxeIqfIrFlq/IZgbbJne2aOZNYAP
         7YyYOcX1mfajtFFAZQ9X3A3qFGqafq0un9qwRsnxCI6Qvn6kdXpWfC4JKiHsZTxPFxBy
         sxYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313QwsYFNEnucopokcY1krGo8CQUX5vCijaltrAhmQApFXdVWg/
	ZBziHxlZojye+42nN75JOZY=
X-Google-Smtp-Source: ABdhPJyOIW7jy3PzD0oTYoKfyzhxRyaOcj+f2vlle0ZCIfnjXa4o7IrXdWsh6VYrbprXqrfjRPsk1w==
X-Received: by 2002:a05:6830:246f:: with SMTP id x47mr134112otr.287.1633544150289;
        Wed, 06 Oct 2021 11:15:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:39c1:: with SMTP id g184ls253115oia.8.gmail; Wed, 06 Oct
 2021 11:15:49 -0700 (PDT)
X-Received: by 2002:a05:6808:168d:: with SMTP id bb13mr8638339oib.94.1633544149868;
        Wed, 06 Oct 2021 11:15:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633544149; cv=none;
        d=google.com; s=arc-20160816;
        b=vde/rAq/L7rcYHfhNFXmtO6YrS60DbMGImyB3qh+YFg9k4/Yp0USHfGFw2m0K4TjoY
         f0qzFkmu+iUsG3HlKyiZjk75WedBdSPSg1v/1Bh9yLWG52kqXIvgArhdI8CSqhMQsTZl
         mCKvvPzs87q/UPbsgl7zBnVDGmFdEDtMNZ0eDSU4e2ZKxnKN8WXQcIqMqYlUuvXiZBHW
         mFSjROLJP34uyQoe/7WKjoTNv2iklrYugrdoACwhXU5/0m6v5cdYHCEjpdVoIUTzq86c
         dVDAZAwA6kn5cUmMtbzvGm8SQhcvUaTjxbjeOp9O7bjoUPEmHViYTMs/U/t6U6nxfAP/
         F9Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=cdG7EWDcW6BJEY9ksYClAuQgmEOu2o4ECgX6UcvZ2zk=;
        b=mqIAzayFJpa5LVxJ0Ky4JvlCFIihfayLa8+amOTDJY4d68RJ+zS8N3wFTV/WGbiK3U
         5SxpnkKNFvUdyU5CuPekwA4rBwuskhWvYuMmQUqYxsYQV0ELUOhYPDcJiyImuKuYVwjp
         J4/QlnMULcXA6jbeXN6clr2ZDKvdUb/lMMdwYQYgBJlw8kut+O5O6wphYgQb9wofEoDH
         YBDlYB4teLgJfD3CLcU11vP9ni3W7LtseRAb8CgVuHYR4c3xvXKDxJj1FxdsTc6O5JgF
         mOb+sV9BXVc2HoguhfqP55gLOF6M3LfwfpzJ+JUmGTWcYoz0kxS4sxMB5IeD0hRbHkJR
         2gjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=S45eY5sx;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id k3si556918otn.5.2021.10.06.11.15.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 11:15:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id u7so3058932pfg.13
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 11:15:49 -0700 (PDT)
X-Received: by 2002:a63:74b:: with SMTP id 72mr152871pgh.290.1633544149174;
        Wed, 06 Oct 2021 11:15:49 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id b23sm21869363pfi.135.2021.10.06.11.15.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Oct 2021 11:15:48 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2] kasan: test: Bypass __alloc_size checks
Date: Wed,  6 Oct 2021 11:15:44 -0700
Message-Id: <20211006181544.1670992-1-keescook@chromium.org>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3355; h=from:subject; bh=B1T1hxgxVDfQrLSNj+ORHFTRqT7J4uui00+KgHGqQ7E=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBhXefQSdeNtSXEzc4wkAzSvCwnIV5nf7JNgxhaY2in pL0uC/WJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCYV3n0AAKCRCJcvTf3G3AJj0LD/ 9gOXto1WuRJBbDz2HibWKwg/R/X8gbdg5zE7FdTyyVbz0LNGbuTXVroklxd4SG9vle3bPb++KqJLiD rapIUX1iI3LpUGydJo5vtyr7/DMJU2IHottLCAUmDbBfQxlJfErfV9cooDSiBTryFX5wLA2DUKA2uf c632273fduEfmsZFj8u4CaKCrGzjQIEP6rFA9E2Nx5EF8wJTKDGZEfX53guKBXnpNQStXw6NriB6hw GRH0IDNDGIRquhyPsG2kbDkWz8eud3kdMfJxjMr8ih5zZkQOdkH2bG7WWZVjveU/Cp5iWLAiKDW/Bw lkmCDOwaXMM86h2AJiqlXjtwMqussFDImN+PQ3fFLHgQz8yGtehxjrmJlMsLmMhnEyMvkgclXYvphF gBm6pon54h4Dc3Fhs5gz4j9Gv8TCdw23d83ui6GMZhC10ezi9kV4um1llDWFbpkrD8G68qTCArSEYU IjwT+x4qy1H4lpmghfs71tyikKFEEDiI9+xJAgpMMuFC8oqsyFTwmGVWErrVR+CxsQh8WbtTU6tZY+ 0vV9fCiolMiZUKnnzHoQE+93YOq5kNQFrYbnzvFArd8VIpaKDXEdlkEZ6iayoj/dYuX55gkRJOfSuu PL36GdgeckkrVvNaUZbucMi4zHU67KK6zC/INs8uAVyMNDA+O+MBokbNmOtg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=S45eY5sx;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c
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

Intentional overflows, as performed by the KASAN tests, are detected
at compile time[1] (instead of only at run-time) with the addition of
__alloc_size. Fix this by forcing the compiler into not being able to
trust the size used following the kmalloc()s.

[1] https://lore.kernel.org/lkml/20211005184717.65c6d8eb39350395e387b71f@linux-foundation.org

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
v2: use OPTIMIZER_HIDE_VAR() (jann, mark)
v1: https://lore.kernel.org/lkml/20211006035522.539346-1-keescook@chromium.org/
---
 lib/test_kasan.c        | 8 +++++++-
 lib/test_kasan_module.c | 2 ++
 2 files changed, 9 insertions(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 8835e0784578..8a8a8133f4cd 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -440,6 +440,7 @@ static void kmalloc_oob_memset_2(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, 2));
 	kfree(ptr);
 }
@@ -452,6 +453,7 @@ static void kmalloc_oob_memset_4(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, 4));
 	kfree(ptr);
 }
@@ -464,6 +466,7 @@ static void kmalloc_oob_memset_8(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, 8));
 	kfree(ptr);
 }
@@ -476,6 +479,7 @@ static void kmalloc_oob_memset_16(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, 16));
 	kfree(ptr);
 }
@@ -488,6 +492,7 @@ static void kmalloc_oob_in_memset(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 				memset(ptr, 0, size + KASAN_GRANULE_SIZE));
 	kfree(ptr);
@@ -497,7 +502,7 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 64;
-	volatile size_t invalid_size = -2;
+	size_t invalid_size = -2;
 
 	/*
 	 * Hardware tag-based mode doesn't check memmove for negative size.
@@ -510,6 +515,7 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
+	OPTIMIZER_HIDE_VAR(invalid_size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index 7ebf433edef3..b112cbc835e9 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -35,6 +35,8 @@ static noinline void __init copy_user_test(void)
 		return;
 	}
 
+	OPTIMIZER_HIDE_VAR(size);
+
 	pr_info("out-of-bounds in copy_from_user()\n");
 	unused = copy_from_user(kmem, usermem, size + 1);
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006181544.1670992-1-keescook%40chromium.org.
