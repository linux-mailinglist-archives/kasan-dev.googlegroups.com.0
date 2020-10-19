Return-Path: <kasan-dev+bncBDX4HWEMTEBRBE5FW76AKGQE3UTA76A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 46796292D27
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 19:53:24 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id ay19sf59969edb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 10:53:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603130004; cv=pass;
        d=google.com; s=arc-20160816;
        b=f4U15zimYYNVyASvZY5BUU+MIhaxg9ejQcXFBVuEFQxsI+h3PD1BwlOMu3UXGDh73n
         2+r79FLbtSJLJpW5Dpr2VhNJvw749Ler2Oj9+cpPrL040fQ+by7ispXUVsUcWdXSHIlI
         jBn2bzUyFBiGMtPaYtEnzPNeReDIZtktemjvAUeb6WdueFxqIU5RxTkGEQtTshub9scY
         fNgBNuB7QJqHIC9HdNnG0WFiHwZpv6OuyjiezOk2ExO5yVSx9YDuncs2eDE5dyOV+J1D
         /KGBs8PjpxFfqoYF+d+h6ekvinKZkA4vcVO4Eo3bJ6n1PBoU+WDgOB3vzJwxRF6jmH18
         +OZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=Pa5fidV2Oq7MfuInbg7hfAN9BKc1qLT40NkI6eUjuj8=;
        b=srNAHYdx2AZBqAw5JT0uiKzheJjG/YBzJW39m8M55rNT7GMs2RXIKU6SAj7J/kcMLc
         MfvbFIi29Lcxh0Yd6h9jAsYrSV4PhUwlXjnpLI21Ip1LqtQs5ooCyklXuG3PXA6Lz3W2
         ZiD4AtGhpE4mEAdalhQNHnHBWoslVMVmqUSpKl6LXVfgrQKvtyQxoPLClJerF+i2qurT
         tpiNBkSUF2JnzR0DoE2ld45gkHvmk/G6YqBOCVuVhEddE3oim/CJ2GbxCMm0vqp5Ki3/
         F5dgBgCLWbH5xQzMdHbXJ6ffVSiUXJ2WZX9wjUKGNHLRV5rpH5NyhofmiLzJ8e8uk0uP
         PdqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HXsubSDI;
       spf=pass (google.com: domain of 3ktknxwokcxepcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3ktKNXwoKCXEPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pa5fidV2Oq7MfuInbg7hfAN9BKc1qLT40NkI6eUjuj8=;
        b=fr6dIp+tH0g/9J8GKvHJf9o7uw1gedqQO01Kz6X6FJeMXywvg4k9MprpPUj64aIYSM
         asqwtObjyQXh+K2t/pRR9eJKxz5vfDPTcjg9FtSNGMSeeborOZjdguzNvBI74MEBTjRi
         mZPd57+FKopbGBEvRF3NS5d3/ta890lGDmD4qQ4pI2vv1bsLDkGPLmFKjTSTCzJ64tFg
         7ZdyH2dqZGqbtKNTluR6wcOea827/AYJEo+UviBOzI2e/c2usmx+Nylv6X3hix7Z4dNY
         JiSEDV0Vx5cAtkVWj4oGkXMQKkotrJkdWcLacpc/pHcvxWvpJd8UbWfo8b5SwtoRIk15
         RFzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pa5fidV2Oq7MfuInbg7hfAN9BKc1qLT40NkI6eUjuj8=;
        b=j08719OAUXi2rqcI8qnxqINlT3bzpnhkRKlSH+hOZ9FznUcVmvZF2vSuxlXNCUDNIx
         FPKNzFfuONOx96vquQe4IHljrZi4h4ObT/LmwC8XTXegRuLo2/9l7+ySVc07sCbmzR+7
         /QszZOqdthx0CwyK9d/3B9FQ9kKZzllLE3BQFjG1jeFPEU/m9UPF4ko0O/qpaLawDmjD
         JWj4zcE50BkBd//f+X+n7I2CGvCTuyx616+tue99nexj0B/X7UhR6aZzSYtOSTCuPZVY
         i3MFNTT7HgqVIZpGzxNnHRd6yTTCdxHt4ZKd0w8pzSW0vKZRFCQvNde/DAAxsOVG2Kcr
         a09g==
X-Gm-Message-State: AOAM532z7dBqzoUzfGibtNn3Jh8CT9fyTT/Qul1OCgbcMfZG83RNVatt
	CEY15uFbpThdjZZGPttWuno=
X-Google-Smtp-Source: ABdhPJxVyrbvKLQM3AXV/12Cg33BXsAyEslKjYHKMdFf2yv8FgMjUARHAgIiPBJ5EyAUTrMVaySqng==
X-Received: by 2002:a17:906:e24c:: with SMTP id gq12mr1063600ejb.359.1603130003939;
        Mon, 19 Oct 2020 10:53:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c04e:: with SMTP id k14ls791820edo.1.gmail; Mon, 19 Oct
 2020 10:53:22 -0700 (PDT)
X-Received: by 2002:a05:6402:1615:: with SMTP id f21mr995890edv.257.1603130002876;
        Mon, 19 Oct 2020 10:53:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603130002; cv=none;
        d=google.com; s=arc-20160816;
        b=sYT7DmTKLGE3hX/HrywWGYtb5CWG6jBK/LciAc9yeuA57XC1wn6zSXjR5u6n3NJUw0
         /1e5u3w6MV6eUUXwCV2TLwD2HI30xnurt5D3CP6RpQqmAf0U0YkErVQ9RJD5X///ozoW
         1hzgZrYpOhh/QQbdY0W95NmUAA1MNAw6bhnhezjqatlr5EySH1zHUuTBjfkslcpmaH7q
         i1TF5PQFkBUkk8JHEZV7Prx3+BuIDKyNhtHWRwxcLQgemLDUbDXCnioKCn4Qlujeegyq
         O5HKvtaX/esmfl8NhYMQN1SPu+SyEd2oK/yLA5LMsrq0tsb9fJZvMQixQw5uhJqhy4Cy
         Go/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=9+UDdS+l5mUdoefczQoyUzdbVQoDy0qQmASeL8V17TM=;
        b=0Rw7quaJpwkjCYKHUU3F6/nOqZmJyH9B24Jh6gExokmrQ3M6mfBo0TRD9v5EPox1I1
         SP7ra2AB3tV3bnIl/vEQCdDAyEelI5sKvSaS+fwJE8GC8jdpR7O96IRqbjfGKAGOdBBv
         eam25Fieomz+ncn8CdRs68uX2UI0LaiZBfxEvmRHRKA5N2XoQ0EDnkR3Yd7z4uxFXCEE
         v1EVXOinkLYj48ZvJosRIopxcb0orpGvzhdcPUlQ8HA+O5J3e/fdo/8BBv6gcFQbJzbd
         X2wIO1mwz8uR0yExBW59d2c290sGRCJmgGyVC1oqplLyTZONZw3Z6qZCab/TzxvUFN8S
         +yog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HXsubSDI;
       spf=pass (google.com: domain of 3ktknxwokcxepcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3ktKNXwoKCXEPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id g25si15823eds.3.2020.10.19.10.53.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 10:53:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ktknxwokcxepcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id z8so116188ljc.10
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 10:53:22 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a2e:910a:: with SMTP id
 m10mr476193ljg.385.1603130002262; Mon, 19 Oct 2020 10:53:22 -0700 (PDT)
Date: Mon, 19 Oct 2020 19:53:18 +0200
Message-Id: <76eee17b6531ca8b3ca92b240cb2fd23204aaff7.1603129942.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH v2] kasan: adopt KUNIT tests to SW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, David Gow <davidgow@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HXsubSDI;       spf=pass
 (google.com: domain of 3ktknxwokcxepcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3ktKNXwoKCXEPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Now that we have KASAN-KUNIT tests integration, it's easy to see that
some KASAN tests are not adopted to the SW_TAGS mode and are failing.

Adjust the allocation size for kasan_memchr() and kasan_memcmp() by
roung it up to OOB_TAG_OFF so the bad access ends up in a separate
memory granule.

Add a new kmalloc_uaf_16() tests that relies on UAF, and a new
kasan_bitops_tags() test that is tailored to tag-based mode, as it's hard
to adopt the existing kmalloc_oob_16() and kasan_bitops_generic() (renamed
from kasan_bitops()) without losing the precision.

Add new kmalloc_uaf_16() and kasan_bitops_uaf() tests that rely on UAFs,
as it's hard to adopt the existing kmalloc_oob_16() and kasan_bitops_oob()
(rename from kasan_bitops()) without losing the precision.

Disable kasan_global_oob() and kasan_alloca_oob_left/right() as SW_TAGS
mode doesn't instrument globals nor dynamic allocas.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: David Gow <davidgow@google.com>
---

Changes v1->v2:
- Don't do UAF write accesses during tests.

---
 lib/test_kasan.c | 149 ++++++++++++++++++++++++++++++++++-------------
 1 file changed, 107 insertions(+), 42 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 63c26171a791..662f862702fc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -216,6 +216,12 @@ static void kmalloc_oob_16(struct kunit *test)
 		u64 words[2];
 	} *ptr1, *ptr2;
 
+	/* This test is specifically crafted for the generic mode. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
+		return;
+	}
+
 	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
@@ -227,6 +233,23 @@ static void kmalloc_oob_16(struct kunit *test)
 	kfree(ptr2);
 }
 
+static void kmalloc_uaf_16(struct kunit *test)
+{
+	struct {
+		u64 words[2];
+	} *ptr1, *ptr2;
+
+	ptr1 = kmalloc(sizeof(*ptr1), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
+	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+	kfree(ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
+	kfree(ptr1);
+}
+
 static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
@@ -429,6 +452,12 @@ static void kasan_global_oob(struct kunit *test)
 	volatile int i = 3;
 	char *p = &global_array[ARRAY_SIZE(global_array) + i];
 
+	/* Only generic mode instruments globals. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		return;
+	}
+
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
@@ -467,6 +496,12 @@ static void kasan_alloca_oob_left(struct kunit *test)
 	char alloca_array[i];
 	char *p = alloca_array - 1;
 
+	/* Only generic mode instruments dynamic allocas. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		return;
+	}
+
 	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
 		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
 		return;
@@ -481,6 +516,12 @@ static void kasan_alloca_oob_right(struct kunit *test)
 	char alloca_array[i];
 	char *p = alloca_array + i;
 
+	/* Only generic mode instruments dynamic allocas. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		return;
+	}
+
 	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
 		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
 		return;
@@ -551,6 +592,9 @@ static void kasan_memchr(struct kunit *test)
 		return;
 	}
 
+	if (OOB_TAG_OFF)
+		size = round_up(size, OOB_TAG_OFF);
+
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -573,6 +617,9 @@ static void kasan_memcmp(struct kunit *test)
 		return;
 	}
 
+	if (OOB_TAG_OFF)
+		size = round_up(size, OOB_TAG_OFF);
+
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	memset(arr, 0, sizeof(arr));
@@ -619,13 +666,50 @@ static void kasan_strings(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
 }
 
-static void kasan_bitops(struct kunit *test)
+static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
+{
+	KUNIT_EXPECT_KASAN_FAIL(test, set_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, change_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(nr, addr));
+}
+
+static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
+{
+	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
+
+#if defined(clear_bit_unlock_is_negative_byte)
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =
+				clear_bit_unlock_is_negative_byte(nr, addr));
+#endif
+}
+
+static void kasan_bitops_generic(struct kunit *test)
 {
+	long *bits;
+
+	/* This test is specifically crafted for the generic mode. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
+		return;
+	}
+
 	/*
 	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
 	 * this way we do not actually corrupt other memory.
 	 */
-	long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
+	bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
 
 	/*
@@ -633,55 +717,34 @@ static void kasan_bitops(struct kunit *test)
 	 * below accesses are still out-of-bounds, since bitops are defined to
 	 * operate on the whole long the bit is in.
 	 */
-	KUNIT_EXPECT_KASAN_FAIL(test, set_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, change_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(BITS_PER_LONG, bits));
+	kasan_bitops_modify(test, BITS_PER_LONG, bits);
 
 	/*
 	 * Below calls try to access bit beyond allocated memory.
 	 */
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		__test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits));
+	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, bits);
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+	kfree(bits);
+}
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		__test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+static void kasan_bitops_tags(struct kunit *test)
+{
+	long *bits;
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+	/* This test is specifically crafted for the tag-based mode. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_SW_TAGS required\n");
+		return;
+	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+	/* Allocation size will be rounded to up granule size, which is 16. */
+	bits = kzalloc(sizeof(*bits), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_int_result =
-			test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+	/* Do the accesses past the 16 allocated bytes. */
+	kasan_bitops_modify(test, BITS_PER_LONG, &bits[1]);
+	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, &bits[1]);
 
-#if defined(clear_bit_unlock_is_negative_byte)
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_int_result = clear_bit_unlock_is_negative_byte(
-			BITS_PER_LONG + BITS_PER_BYTE, bits));
-#endif
 	kfree(bits);
 }
 
@@ -728,6 +791,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_krealloc_more),
 	KUNIT_CASE(kmalloc_oob_krealloc_less),
 	KUNIT_CASE(kmalloc_oob_16),
+	KUNIT_CASE(kmalloc_uaf_16),
 	KUNIT_CASE(kmalloc_oob_in_memset),
 	KUNIT_CASE(kmalloc_oob_memset_2),
 	KUNIT_CASE(kmalloc_oob_memset_4),
@@ -751,7 +815,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_memchr),
 	KUNIT_CASE(kasan_memcmp),
 	KUNIT_CASE(kasan_strings),
-	KUNIT_CASE(kasan_bitops),
+	KUNIT_CASE(kasan_bitops_generic),
+	KUNIT_CASE(kasan_bitops_tags),
 	KUNIT_CASE(kmalloc_double_kzfree),
 	KUNIT_CASE(vmalloc_oob),
 	{}
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/76eee17b6531ca8b3ca92b240cb2fd23204aaff7.1603129942.git.andreyknvl%40google.com.
