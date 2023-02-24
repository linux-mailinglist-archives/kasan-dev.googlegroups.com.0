Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFXZ4GPQMGQE7V7CH3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C04616A1861
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 10:00:06 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id g6-20020adfa486000000b002c55ef1ec94sf2881249wrb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 01:00:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677229206; cv=pass;
        d=google.com; s=arc-20160816;
        b=sJWIw2Afxy+hJaLtlAVOL3v3+9UTi4HuV4smOHvUSAEruzhp7hyIJX0r6qgUirXLQc
         KN2wxRIYrr54jTfZ/8GH1cAwtqRhFvhWjRLGOMxuX+z1j6dZbgaaNZE7tjRoS3cmPR5L
         OvBvrc+uY55VkDg9AlvUroLQ/+JCBFC3mJ3+8VKhh2AcfrU+/G/4C/rbSCih8KixKBs/
         XryhxIYD1JXh7rUrBtjm45VNyDX51mS1FoB3Mq+2yt663SEAuMzV4Ro6jLi31osBwU/H
         tqyiBrHFP05SV4YY0pN16/RmwQf+MV4qSdmFJbt4pNzIb9zpWRyWY+bZDx53x/UT0/zo
         CRoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=hPobMtTtqZAFrd4AQeZKWsTL/5tcn6tEK46JBAqfaqs=;
        b=xtEkqd8EDrFD/kBOg4PZqsiU18cpQrm3UsKc318hnAS+9tAP6vRgAZ1zaQgqVNsxNg
         NC/sHTYy+h6ljrmAMl9NFK8CHmMOt0rR0T7/PSf3/4tWY9Bwm+DZ+3K9paFUrQtVheu8
         RdUHm97kjUNT/9JQqdS3Wfh+9b0mDeBQarhJsejsHdSYen4jm3B0vsdpGVOw529dHZwa
         H71Hjup+QiIoC1FALZg1W/+TvVZSlNdl3r4AH2aBC08wiO9sDEl1MlkEmtjkQTqRrc48
         Dh1dZwWlQgRgbDRLwzgNvhR5zM4DjDn4GREWEqv0fUf2b+u/Dm8ZR+g4ehmXzWdHXKoY
         6+sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="MeczQ9i/";
       spf=pass (google.com: domain of 3lhz4ywukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3lHz4YwUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hPobMtTtqZAFrd4AQeZKWsTL/5tcn6tEK46JBAqfaqs=;
        b=d00ksdNkaDxm/p+dA7v1Y9Ck/JxYw0tnNkhLgrij5BSPV+Diu9lsMTtIBUTpElB1BF
         wU/s0c6D3rwaDyWmiKAFldXDc2CRSQoaLbwCPYCnqpDJ/iUiGYBS9ZYeobZKmNXdx+41
         ad1pBoPFrUWUAzE6I22jU2NLIhaQCEzdPiXcaRQdgwcH67Ryb1vVE1Lif6mbcNGeVjO1
         L6IisTkV4Sz6kEHO67ue2ekTBGrP0dG0acC0dEc6Z1UWGdYFBlsaqubnPue1Em2JGptE
         GZBExghbyEy6iOE28xD2XPXcHBS9RaA4IzuRiONJEwl4m3bFOcRzILKjq7IY4TxN49Gt
         MBoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=hPobMtTtqZAFrd4AQeZKWsTL/5tcn6tEK46JBAqfaqs=;
        b=W80w71qXDzyi43m0Zb76mZRb+FHHEQt6PVlluGpbcXIglRJcoldBdKF4iegdOInUcf
         kWNxm/qXKTVhb5DPLKpQkbANp8MR5AcatSRlRasyrgrTfmYmTQUpyPPBhokd13DBuLzM
         SY64oit8kftH3RUTUtVNaxBNmAouZY55xcaTpYiRlaOiE1lhiyWDt8NJuzB60+NpkYeh
         xRLD9a6vstQhjdm3TjewTyuohw7Vnc5RztFQD6UmSkWLivZUgMhEDVzttvDHAg/KvYj1
         UMjODDegfCKYKbtJhg7dnYM3e5BbD7CC/z/XjAO5VHjRsYv3NRhDg0G/b/Zww2tHQWQe
         X2RQ==
X-Gm-Message-State: AO0yUKU+QksITIv3OX3uvcz+PgB4Srm5clKXuEm2K//QJxZixiU4VhI1
	ox1iST8Pt647jDQ/v1/xoGY=
X-Google-Smtp-Source: AK7set+sxndZmrnCMLiQ1togCsdJE9U6u27RjVu2l/CU81zPaSJA59EwZvRFA/YpxXtq3ppnP5choA==
X-Received: by 2002:a5d:6791:0:b0:2c7:3bed:481d with SMTP id v17-20020a5d6791000000b002c73bed481dmr121879wru.9.1677229206236;
        Fri, 24 Feb 2023 01:00:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:a18:b0:2c5:55ca:3a3b with SMTP id
 co24-20020a0560000a1800b002c555ca3a3bls550151wrb.1.-pod-prod-gmail; Fri, 24
 Feb 2023 01:00:04 -0800 (PST)
X-Received: by 2002:a5d:4805:0:b0:2c5:4e3c:d390 with SMTP id l5-20020a5d4805000000b002c54e3cd390mr13507134wrq.62.1677229204621;
        Fri, 24 Feb 2023 01:00:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677229204; cv=none;
        d=google.com; s=arc-20160816;
        b=fJATS9q5Tfkky6y9eHIAMa3F5+ocb9GSqK/QlMliezc7M27Gu8hoEfe2mNWtxuOUPw
         d6GrERBaztAjT85X3TLSV6Rzme4yorQfBkZQe9k5IcJR3vBFFwskQsdwNFy/c4TaSDnf
         K4GFg1jOrJourlzrR+JHPqrjlwkiXSb6sY+1BC2se77UKRhEHQ4pGJvtO1IOhH6AjBs6
         dEmosrSTfLaal5F0B2bu2nV39S2Qe2NOfz3I0WDRl94nemmM+nBvqVbseECieEtYCTr/
         GeiTbxjQ3z1LIoRc2vfOL4WvEx86V38SOpc8w2ErCdCsHHxVxAIn1jZ1jQ+PYNiyU7a7
         HzvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=U+KSe6yW61OhH8F5xK9sHNFGGyhwmdu+LoC5TlHU1sA=;
        b=V2y/gavEsk4H7cOe25FE9FUhAXJbO1Gyeg+g9gOyQWxewp14c9sn7b0dKpPHTp3aJ9
         KV00UNCGX15Svo6NirKRtOrKi20sxawEd8mpN9qjWxiWUyq85iOEwmKd5V6SqtydvsmM
         fwROaz6fVeAWRDoYkXUooebhIFReFcL4k1I1VDwDRQYMMREJ61SsNLGnlZtxiQIMfREq
         F1QhhvnYyv6/Nj5vDKNfvxPt+CHRplNBhTmi77Rnnm6FjGGg5aI6CAkrtq+DalXxe6c+
         2O4OVqXxZeyFKkDhAdbE0yYLOopcDkHGt0QLop7xpWGxEQcCKxxaibyAPoGVSicHqJ9M
         1L7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="MeczQ9i/";
       spf=pass (google.com: domain of 3lhz4ywukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3lHz4YwUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id d1-20020a056000186100b002c6ec127706si422952wri.0.2023.02.24.01.00.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Feb 2023 01:00:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lhz4ywukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id t9-20020a056402524900b004af59c073abso13205600edd.6
        for <kasan-dev@googlegroups.com>; Fri, 24 Feb 2023 01:00:04 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:53eb:6453:f5f5:3bb9])
 (user=elver job=sendgmr) by 2002:a50:c301:0:b0:49d:ec5e:1e9a with SMTP id
 a1-20020a50c301000000b0049dec5e1e9amr7086377edb.7.1677229204289; Fri, 24 Feb
 2023 01:00:04 -0800 (PST)
Date: Fri, 24 Feb 2023 09:59:41 +0100
In-Reply-To: <20230224085942.1791837-1-elver@google.com>
Mime-Version: 1.0
References: <20230224085942.1791837-1-elver@google.com>
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Message-ID: <20230224085942.1791837-3-elver@google.com>
Subject: [PATCH v5 3/4] kasan: test: Fix test for new meminstrinsic instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Jakub Jelinek <jakub@redhat.com>, 
	linux-toolchains@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kbuild@vger.kernel.org, 
	linux-hardening@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>, Naresh Kamboju <naresh.kamboju@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="MeczQ9i/";       spf=pass
 (google.com: domain of 3lhz4ywukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3lHz4YwUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Linux Kernel Functional Testing <lkft@linaro.org>
Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230224085942.1791837-3-elver%40google.com.
