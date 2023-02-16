Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJMAXOPQMGQEK4MWJLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 3024C69A29B
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 00:45:43 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id bp18-20020a056512159200b004b59c4fb76bsf1364357lfb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 15:45:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676591142; cv=pass;
        d=google.com; s=arc-20160816;
        b=xWXN6iOspUFjlP/xbqT6KJtE5PQR+HMtrz2f0PHMqj2+qw4rSYWTs+ESdQLIYl3GfQ
         22kWWjUQ5Ary71G7Bk5sVw9taCafHfyrYt0Hi2gTPVx3AxLILHpK72Hx6wk0sUTYxOGG
         +seX9cJ5VI0H6qMt7BMqo/hlq44PGzS4+U36cX1SYspOk2uz/d7bVwIx8U9/aidcvuoy
         OrfXsxIRHKM0JPuCdZRTXb18DJkJsatDg392bEZF/lo6fYVEiie7ftVsLT2xFLFg9ioG
         gyVxh8XDeJn/N0OeHj578CWB1c+y6HsVI7dfnj3k7N2FNBlyXFO00v0yUiE0uOVab/5m
         PzSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=UrV0Kcf47E7ppjAgTrIqytelSfF5OEFwjm4v7T2K+5k=;
        b=zM/Q1q5rUy61pwlwHNk5E6GmpLg9RINZ3Qy6P44GJ1HvCAnXpMhQYCA6PKWdrahtYE
         0wq5OVhNUF6yxx6slNd8hxs5PzStd9Co/a82mcey+EwWYJ3xWlSb4WVr05OlgqxxJf4G
         GEjh4jAU0O70UyCtC5T63ogfFaVLEw4gjElSQR2nZMJhSOen3ReHmKtxsgFUi2XUrKuR
         VKN+0oDrVkp2uqDmickyUon3vLPQaRScxHQUyqSoXKYunRECU2O/NdtnJmeScWccoQ6+
         jBOw00HNgsgbY4TEkiHmktNVoRouF/5ZG3LNA6rHEo8S3PnG1fN3U13/hRcQ6GV0wIJi
         FZMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kxkMJWrb;
       spf=pass (google.com: domain of 3i8duywukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I8DuYwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UrV0Kcf47E7ppjAgTrIqytelSfF5OEFwjm4v7T2K+5k=;
        b=OKR8FhhSQusFe3BeRo/DXHsOZbG63xGxrNxf/X40mMLeoSQd+fUgyO9dH5vT2q3BZn
         DlEyGUlMP3lejX1P4ROhBROBUb9UATGhERhxyY2/OZIfhEsl3QGJWlAr32ha/xVrwWZM
         p8+rvyDQJxiWqNEEQUhU1nkZNMLMI0PzIby+gxzhUVLZXzC0oPxSKKlfJeuO5D3GsMqQ
         ccalicYOnuzGJMtTM5K+qkCKdFsSGFL6vOW28HmejL2/mZEOUK1Y33Ps5tpDKkc1Ouy4
         fCQ8yjC2i4fusi8jnqBqkuQWk63G01AvRjOmqF9+S7dpbwaM2XTw0hpxReJDVvbA7urs
         e+nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UrV0Kcf47E7ppjAgTrIqytelSfF5OEFwjm4v7T2K+5k=;
        b=1iiMyVB1Z5UnC80+4u+IDv+s2FykgvlzG6pr8a7mY7RpQDtO2RROJmYIpusmk9DoKy
         he8Yr4a2/0FAnDVgMXQoY2tGo0niUx45wV2S2L+sy8NcMIczneWyf5lJPIIVUyuVU3/K
         +C/4dl8wriJIyDNn/33rjQp/bw7PBp0tP7fHIG+1bycwO+4UlEHjyacx17U3ihDoDdPm
         KpdXi85iO9M0wlN6RtXhiaET7aX2djgHSrSmzHeA8N/3ragBBlHWCItUa7fY1RmY+cIV
         Lbglk2kXliQFD1N9isRzu3F/9uIBWrQCDpFqqbj6rsHefxpRGWFEGWB9TAWufI+UZbwO
         OaSw==
X-Gm-Message-State: AO0yUKXqwHWzSFsJ8uWJLpfEx5q1lGtX0/PMD6MaxwYkiTPqU45Z8P8+
	rVFTjjDEqpzApx7FfZ6xZVoP7Q==
X-Google-Smtp-Source: AK7set/jumaH48UQEVirjlGLYfW3xxiqPazd3eooqy77B87Z9S4wEB2ArZ5x6mjkJAc3uZriMg+1Ig==
X-Received: by 2002:a2e:a593:0:b0:293:7477:97bd with SMTP id m19-20020a2ea593000000b00293747797bdmr1854769ljp.3.1676591142140;
        Thu, 16 Feb 2023 15:45:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3da9:b0:4c8:8384:83f3 with SMTP id
 k41-20020a0565123da900b004c8838483f3ls1859531lfv.3.-pod-prod-gmail; Thu, 16
 Feb 2023 15:45:40 -0800 (PST)
X-Received: by 2002:a05:6512:3ca6:b0:4dc:790c:9100 with SMTP id h38-20020a0565123ca600b004dc790c9100mr732195lfv.12.1676591140358;
        Thu, 16 Feb 2023 15:45:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676591140; cv=none;
        d=google.com; s=arc-20160816;
        b=daKchU+mmpm0CEHXPNanpOVmAC/ukF+h2roT6cIPCyRd4xjs1nc+/5zInHyWc8Z4Gt
         Jzj+CBW9S6J0BuVfgXJBFmnuajwsBBVj96qLHxRujCtEa/K2lYr3+nd9D+0/8SDojzpa
         PCS/ACJD3RixA5tpeTK30EHBv3KtWD9+wVKD2FESVMgRzGY9ul28VeUhfZU1WdZ+/n4m
         qtJiYPhvSl4UzZrfCN8wGbYOX5k/+Kj4yjXbkLQUdMH0VToIkfAcw9OVIEBIINpT4vzj
         NN0j/bNpj2cYqMLFjx90z2yPu/WPjYFGvqX68W/cCKipaBmEAUug9CX7tKPJYZabhGmg
         pHAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gW18Fl3dm52InVgglE8m5dF8kxrMU+Nd8TZ0107EoLE=;
        b=MwS9PKdticHQGLRovXyOZK/aC3V4l3qWCcTeWU6rt9H55To57ueTtd8onogGnF6+3h
         lzcEAYfst/Xhzd0JukrrZot5cvSwANIY9P5RwoYj6IxK91JPcJc5dhbTfdNiVPSi6G7r
         a6wp8K2S4f7+PncigyNCpARjq4PH86eymWzTORRF5urZ4LyjtqQbjzHqMw0YeAsFYvF8
         on80Jd7ZzNjkGrtu7KAhnYZ7/3+M6tyAFSv3BFtVq6J1lGtStJ7E0fed/y11r2lX62RT
         HDMDX+mxdLMoviRoS2Q6PU41oOL4YE/vtDhmneBelJ58mCZQDJQwrMHd7xvaIJBTZCoh
         bLCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kxkMJWrb;
       spf=pass (google.com: domain of 3i8duywukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I8DuYwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id b14-20020a056512070e00b004dbafe55d43si140084lfs.13.2023.02.16.15.45.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 15:45:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3i8duywukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id i36-20020a0564020f2400b004ad793116d5so2020739eda.23
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 15:45:40 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:34a3:b9c:4ef:ef85])
 (user=elver job=sendgmr) by 2002:a17:907:206e:b0:8b1:2653:c5f3 with SMTP id
 qp14-20020a170907206e00b008b12653c5f3mr3693391ejb.4.1676591139804; Thu, 16
 Feb 2023 15:45:39 -0800 (PST)
Date: Fri, 17 Feb 2023 00:45:22 +0100
In-Reply-To: <20230216234522.3757369-1-elver@google.com>
Mime-Version: 1.0
References: <20230216234522.3757369-1-elver@google.com>
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Message-ID: <20230216234522.3757369-3-elver@google.com>
Subject: [PATCH -tip v4 3/3] kasan: test: Fix test for new meminstrinsic instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@kernel.org>, Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-kbuild@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kxkMJWrb;       spf=pass
 (google.com: domain of 3i8duywukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3I8DuYwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

The tests for memset/memmove have been failing since they haven't been
instrumented in 69d4c0d32186.

Fix the test to recognize when memintrinsics aren't instrumented, and
skip test cases accordingly. We also need to conditionally pass
-fno-builtin to the test, otherwise the instrumentation pass won't
recognize memintrinsics and end up not instrumenting them either.

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* New patch.
---
 mm/kasan/Makefile     |  9 ++++++++-
 mm/kasan/kasan_test.c | 29 +++++++++++++++++++++++++++++
 2 files changed, 37 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index d4837bff3b60..7634dd2a6128 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -35,7 +35,14 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) -fno-builtin $(call cc-disable-warning, vla)
+CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) $(call cc-disable-warning, vla)
+ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
+# If compiler instruments memintrinsics by prefixing them with __asan/__hwasan,
+# we need to treat them normally (as builtins), otherwise the compiler won't
+# recognize them as instrumentable. If it doesn't instrument them, we need to
+# pass -fno-builtin, so the compiler doesn't inline them.
+CFLAGS_KASAN_TEST += -fno-builtin
+endif
 
 CFLAGS_kasan_test.o := $(CFLAGS_KASAN_TEST)
 CFLAGS_kasan_test_module.o := $(CFLAGS_KASAN_TEST)
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 74cd80c12b25..627eaf1ee1db 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -165,6 +165,15 @@ static void kasan_test_exit(struct kunit *test)
 		kunit_skip((test), "Test requires " #config "=n");	\
 } while (0)
 
+#define KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test) do {		\
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))				\
+		break;  /* No compiler instrumentation. */		\
+	if (IS_ENABLED(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX))	\
+		break;  /* Should always be instrumented! */		\
+	if (IS_ENABLED(CONFIG_GENERIC_ENTRY))				\
+		kunit_skip((test), "Test requires checked mem*()");	\
+} while (0)
+
 static void kmalloc_oob_right(struct kunit *test)
 {
 	char *ptr;
@@ -454,6 +463,8 @@ static void kmalloc_oob_16(struct kunit *test)
 		u64 words[2];
 	} *ptr1, *ptr2;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	/* This test is specifically crafted for the generic mode. */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
 
@@ -476,6 +487,8 @@ static void kmalloc_uaf_16(struct kunit *test)
 		u64 words[2];
 	} *ptr1, *ptr2;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	ptr1 = kmalloc(sizeof(*ptr1), GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
@@ -498,6 +511,8 @@ static void kmalloc_oob_memset_2(struct kunit *test)
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -511,6 +526,8 @@ static void kmalloc_oob_memset_4(struct kunit *test)
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -524,6 +541,8 @@ static void kmalloc_oob_memset_8(struct kunit *test)
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -537,6 +556,8 @@ static void kmalloc_oob_memset_16(struct kunit *test)
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -550,6 +571,8 @@ static void kmalloc_oob_in_memset(struct kunit *test)
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -566,6 +589,8 @@ static void kmalloc_memmove_negative_size(struct kunit *test)
 	size_t size = 64;
 	size_t invalid_size = -2;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	/*
 	 * Hardware tag-based mode doesn't check memmove for negative size.
 	 * As a result, this test introduces a side-effect memory corruption,
@@ -590,6 +615,8 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	size_t size = 64;
 	size_t invalid_size = size;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -618,6 +645,8 @@ static void kmalloc_uaf_memset(struct kunit *test)
 	char *ptr;
 	size_t size = 33;
 
+	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
+
 	/*
 	 * Only generic KASAN uses quarantine, which is required to avoid a
 	 * kernel memory corruption this test causes.
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230216234522.3757369-3-elver%40google.com.
