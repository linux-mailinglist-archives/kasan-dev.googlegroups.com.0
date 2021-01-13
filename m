Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ547T7QKGQEIHJ5PVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 76EDE2F4FBE
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:21:59 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id r11sf1174312wrs.23
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:21:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554919; cv=pass;
        d=google.com; s=arc-20160816;
        b=wXVkQ5Zmn3r7BAiLnru5gr2Eazlqde8qZS/ZPv+BccvVO32h9kIJwCEcgjKvd3IYPb
         pNWh3IfpzprcmoJqZXpxFpKcnZlDUKRJ/tobqH8QTbBSd+fuKtqbCgVFLWOZLCtUdLmU
         62wDx2wEuPaEh3gxszNhXWpriL5TiLq1SklI44Y337oXE7MXSYxCh7gluhOcc7nmpVST
         yjm3p9Vay2gTGx+dWfJtDce84R3NB+CqibR4qSRjXn0HIBJVQ9XJfhgrI1ENm+a4+Tgl
         aH2PRg3Xd14ityubhzrgjXUKNdcf8duEae34e+Mp7LB8YlkuXwjN+2/21pRTbnvFCVGV
         LC2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=d4zdlq7J2s9fJLQCxL42oYugue2n+jmMEiSvoTtMLJ0=;
        b=Yc//EplFZOGs5rsi1rfmhh4nxfUyUOJ3FBhNTHbg512j0LdP4pgBlmd9Zz4E/S51R+
         0PoXrebtR6IyWt3HgHLfGgUzvQHGjL3wlt7mgD9dx+qSLFGN3eOk0RZE48T/O/z7F/F3
         C6QCCe9QheXi37et8uF8/qblvLRcMOvVM1uriC/Qr6ofilhsCG3a80NlldYtHHJU2lwu
         H8gDuPyIHnf/QySBAXCJzRB4jgxjDTCYHzrhLAUxb2oCB4DY4L4X2068FrmGbj+wLvxN
         inct+y56XIhTQQuR+TxAJ2QdBduZBXe58B4NKzJNPqSHuXGIlob3tarXwD4tqMdWoAj+
         G6lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oqenNaEF;
       spf=pass (google.com: domain of 3jh7_xwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Jh7_XwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d4zdlq7J2s9fJLQCxL42oYugue2n+jmMEiSvoTtMLJ0=;
        b=eL/dBmZjVpTZrpoB2Iaj1uNzwl0ap1s5RE13Xy1URiTzZeg3f2EKuLOif+1pwGiXW3
         etKSjNPM1tjFfMgr8rQxiXolOq6i/LVAVmgga2UaSkaMImOt5udn07g/TjxwZUv1HIHv
         Ks4KkaG9U7QnSJcg+rHkP8IlJt/o1n42ASDvoPVskDTdG8hf2UkJsCWeBoEqcmc63zrP
         mZuupU1ec2yMCkEQ8JPZQFzNA4n2VAV2orkTmNeZ5/eMwJSqJkXlBBAmyosmgJuJnQtr
         Pj9Xe7KKesLg+yWlZ/H3t7BwVQCZfMEgr19f5PaXHM8WjAS/AJZ5HfJne7h79dLApedz
         OGCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d4zdlq7J2s9fJLQCxL42oYugue2n+jmMEiSvoTtMLJ0=;
        b=Ct/5yzesxecocTB+4jscLppwu0wMzu/vmoFu4ByW2o7y1v3GdT9I6lVGUeBtu3k6/m
         67SNdrUXOxsUji83kEtm+OqE1EzUoKElFst8XGntD1CmNDqp0D0OePtmrUBoFNJxow3v
         W/rnfGlnEPjCXimAATMJ+7RrKBGYsXpu3/btp7MsyCNdYqwQKtwWdErBkgAKAerQxRnr
         AdaWbWEMZI8jJPviSLlVshmtA8Vz1O3qubsrNfRAYxVMvlSdZDjtw6vZbnhp+85z8SY6
         mpfs9V2aZIHKaMJ1viX180M2e96iF/fKu2qoXURhH+dq27gX5BI3Yrh9O1mBrREbPgiJ
         20lA==
X-Gm-Message-State: AOAM530KQZxWCbCj29KCt83hNmK66b1jnQ331fO13bz/WZB9UgsfQIqp
	f2hDdJ8tx9TcSyI+A9hnCbw=
X-Google-Smtp-Source: ABdhPJzIRokkQE68E/g0CEetntV7NxCNBRTpcqRve2NH8kfM0WDYqUkPYoXqckuAE5rwCx8qd96zaw==
X-Received: by 2002:a5d:660c:: with SMTP id n12mr3472559wru.291.1610554919269;
        Wed, 13 Jan 2021 08:21:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:b688:: with SMTP id g130ls1334011wmf.3.canary-gmail;
 Wed, 13 Jan 2021 08:21:58 -0800 (PST)
X-Received: by 2002:a1c:1d85:: with SMTP id d127mr31316wmd.49.1610554918382;
        Wed, 13 Jan 2021 08:21:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554918; cv=none;
        d=google.com; s=arc-20160816;
        b=pymqzrteUkSE9QOhEgdSg+p+6fPxoJQM2LK2875ng9J5GmTvpABrKevJQSjoSrbAUE
         Nu4YAiKhu549VukH6k4FY1DdKLlrvZxGMnBV2M+Jr1Wz8B2Jw+TAByLs0olfiJGhhFwp
         wBevkIpQjWLoo5afX4VijcEz57GBT2oHJIj0UqnLXNEYx2AgxS3utmxPx9Y8KoHBgVcA
         KB8DQhWFCuMkpUxxTXh1QfASCgGrV4pvW+3XbOr70BAZKAVrkOcQ0/9UehN6sbZ+i/Ua
         q3PplJD/khZsPrAxTE9YIH5eijvGVM0PfmWtihlHzmx6RsR7dAPseYpFinDAnk+QHW8X
         FMHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=E6PEqEqFHrDPfEKN3Pzg4816pnBi/pD7toF/sOUvffA=;
        b=X5PfynPeS534NnxJ5f1VJTHgprn7Ouy/9HfHfXISZORzXszVfyBkSzyoZ9dz7efv1Q
         Wn/NJBHiazx6ct6ASdnIUZouXyKQATpd6V42vliq31r5QQ6+1JNzE4LApFDJaBkDoGU3
         DdJqzhaC/XWulBXNKxAZ1gdA4tlc65PUbVM/kU7qTkr9CXSROqlFJWqT9Ixsu3JHwHED
         eQOlIBOdMEYZYiTBwZNaw2dx54FjzD1Fa4bCfYNicMZ9Xap6/bsswygCEkdnL/0MtJmF
         vJS/09XchsyEbkuQWwdiDh4OtD2esT/1zFx9nOyJAqwg7q2LJWA4XREeMoX+Mv2P9VG0
         n7Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oqenNaEF;
       spf=pass (google.com: domain of 3jh7_xwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Jh7_XwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z188si178000wmc.1.2021.01.13.08.21.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:21:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jh7_xwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l10so770203wry.16
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:21:58 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:a7c5:: with SMTP id
 q188mr57188wme.108.1610554918111; Wed, 13 Jan 2021 08:21:58 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:32 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <351f554b6e4c4c0581d15d7b70cbbacf238c887f.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 05/14] kasan: add match-all tag tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oqenNaEF;       spf=pass
 (google.com: domain of 3jh7_xwokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Jh7_XwoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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

Add 3 new tests for tag-based KASAN modes:

1. Check that match-all pointer tag is not assigned randomly.
2. Check that 0xff works as a match-all pointer tag.
3. Check that there are no match-all memory tags.

Note, that test #3 causes a significant number (255) of KASAN reports
to be printed during execution for the SW_TAGS mode.

Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 92 ++++++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h |  6 ++++
 2 files changed, 98 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 714ea27fcc3e..f5470bed50b6 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -13,6 +13,7 @@
 #include <linux/mman.h>
 #include <linux/module.h>
 #include <linux/printk.h>
+#include <linux/random.h>
 #include <linux/slab.h>
 #include <linux/string.h>
 #include <linux/uaccess.h>
@@ -754,6 +755,94 @@ static void vmalloc_oob(struct kunit *test)
 	vfree(area);
 }
 
+/*
+ * Check that the assigned pointer tag falls within the [KASAN_TAG_MIN,
+ * KASAN_TAG_KERNEL) range (note: excluding the match-all tag) for tag-based
+ * modes.
+ */
+static void match_all_not_assigned(struct kunit *test)
+{
+	char *ptr;
+	struct page *pages;
+	int i, size, order;
+
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	for (i = 0; i < 256; i++) {
+		size = get_random_int() % 1024;
+		ptr = kmalloc(size, GFP_KERNEL);
+		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+		kfree(ptr);
+	}
+
+	for (i = 0; i < 256; i++) {
+		order = get_random_int() % 4;
+		pages = alloc_pages(GFP_KERNEL, order);
+		ptr = page_address(pages);
+		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+		free_pages((unsigned long)ptr, order);
+	}
+}
+
+/* Check that 0xff works as a match-all pointer tag for tag-based modes. */
+static void match_all_ptr_tag(struct kunit *test)
+{
+	char *ptr;
+	u8 tag;
+
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	ptr = kmalloc(128, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	/* Backup the assigned tag. */
+	tag = get_tag(ptr);
+	KUNIT_EXPECT_NE(test, tag, (u8)KASAN_TAG_KERNEL);
+
+	/* Reset the tag to 0xff.*/
+	ptr = set_tag(ptr, KASAN_TAG_KERNEL);
+
+	/* This access shouldn't trigger a KASAN report. */
+	*ptr = 0;
+
+	/* Recover the pointer tag and free. */
+	ptr = set_tag(ptr, tag);
+	kfree(ptr);
+}
+
+/* Check that there are no match-all memory tags for tag-based modes. */
+static void match_all_mem_tag(struct kunit *test)
+{
+	char *ptr;
+	int tag;
+
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	ptr = kmalloc(128, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+
+	/* For each possible tag value not matching the pointer tag. */
+	for (tag = KASAN_TAG_MIN; tag <= KASAN_TAG_KERNEL; tag++) {
+		if (tag == get_tag(ptr))
+			continue;
+
+		/* Mark the first memory granule with the chosen memory tag. */
+		kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag);
+
+		/* This access must cause a KASAN report. */
+		KUNIT_EXPECT_KASAN_FAIL(test, *ptr = 0);
+	}
+
+	/* Recover the memory tag and free. */
+	kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr));
+	kfree(ptr);
+}
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -793,6 +882,9 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_bitops_tags),
 	KUNIT_CASE(kmalloc_double_kzfree),
 	KUNIT_CASE(vmalloc_oob),
+	KUNIT_CASE(match_all_not_assigned),
+	KUNIT_CASE(match_all_ptr_tag),
+	KUNIT_CASE(match_all_mem_tag),
 	{}
 };
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3b38baddec47..c3fb9bf241d3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -36,6 +36,12 @@ extern bool kasan_flag_panic __ro_after_init;
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
 #define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN		0xF0 /* mimimum value for random tags */
+#else
+#define KASAN_TAG_MIN		0x00 /* mimimum value for random tags */
+#endif
+
 #ifdef CONFIG_KASAN_GENERIC
 #define KASAN_FREE_PAGE         0xFF  /* page was freed */
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/351f554b6e4c4c0581d15d7b70cbbacf238c887f.1610554432.git.andreyknvl%40google.com.
