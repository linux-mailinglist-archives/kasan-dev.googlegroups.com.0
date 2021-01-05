Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPW72L7QKGQEGWKV3PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A9CBF2EB287
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:14 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id y5sf1746708lfc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871294; cv=pass;
        d=google.com; s=arc-20160816;
        b=hUzJ3zIs7F81ECqrB7JbTRMXDc/nZFyJ0/A9NFN5NtV2z3xcnF4QWIDNSUSwsQuAzS
         efKV9+H2mpiYd21ev9Vrwa6ftT/l5dHvS/0vSFTZeQKOkFLmse+z7xlEaYgJ0v7xWia3
         ah8NnLfxLO/8NT3sawCLwNEDelc2RTtGWcalwwmpbPIcarP0Dwb4KsegJ48UShBlpS6h
         TrLKqQx3yxS+3q3vzm5nSiC11llkeAd2RLf3+oaLWzMaltHsSWQ7fBcnf9SyUSFWrAiL
         vk1zMiXZ3to0BlupyUX884BjVCprzH89uyu9gSHcsOkX2adfg8GZ19ZAC2Jke4YafKMY
         Y5Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qlYdazNP54U8l3NNz3YiqpmHacEEwRjzXJO3rHAR6LY=;
        b=zwlak+DpxgOIdPhWsZxlrQt+f4ZtbI44vvCcT81s5HlPK6kyXht/CO9pWwrA1LQ/oo
         ZNTRcUL/+KdGadPPsPQpgYvvbz4MeqVIBYA3hXRDsD8F2wyeFIEOUaLihZwUvEbqLcXB
         /4w510RR+MNaixb5n3eVEfiCSUOLg8vWph0oRNrsGpSUT7OdIj988aYRxQM/akF/Uzn6
         fjFe9wmnasz9DRp8el7xh3AnAwQWz7kahAzkz/F1lAEk6JKMa7s7kapmkPWPqXuhW25T
         /jD/F4dzMxmTp0XJiGytrX6tLeb0jfz+K1LiIhzFj71GKBSTrgGRvTGlqhBU0OICYAQ0
         HTyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JoaeuIG7;
       spf=pass (google.com: domain of 3vk_0xwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vK_0XwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qlYdazNP54U8l3NNz3YiqpmHacEEwRjzXJO3rHAR6LY=;
        b=J/zQ1wqLzEslTh9wNPquvJbXyTJX8LlxKm17T2WzsnrEo8rQNaUSUET9N8DgQ69LTh
         0zup0DPEkkx2E1zSHLLl86f1FtHmUiHr4dQqpdoSPv8VGuciUSmw/BRaUEKKYrWxB8xJ
         DS58MBt77+bXsAKwvlfhXECNm6D+1yPgR5ZOEzuS03393ccihg7gFPKAGu1q5SsBGQjx
         cmPagwFBh5JYRP9AVjSFtMISgx/GrNt0Dxwqpjg35fbMQMQ0sDRPGKn/m227nsfEq7bE
         O8UEBQEAfHmn0quZMyoN7+TuEzoq73Taf6ya6S5yifRDmMd5dXB6j9gs2NpTs1f7hKox
         cDtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qlYdazNP54U8l3NNz3YiqpmHacEEwRjzXJO3rHAR6LY=;
        b=EUG/N2RGThzgg0mfnaH78rcNu3uJW67Ia80pv2B4VWbfEJEIySj7vnRR1JiUaZ/s4i
         o+Fc2EAE3p4OOk7ytP3bJ6fjond2sU5tRpTduE4v4nYa3smGapewpf96jongMAk58BcJ
         5jXcsrr7D1oQEcYHmnejcYnWcrFqeWtPJzA8zeeRC6B/IYzXJVkTxfveK0MgEOWvC03k
         kvIlLzj8zc0nOqMJ5UmUTMJt3ZwxhY+MBCakcFfaTWOglg6dx+I/iHkRPpLEOl9ehOp+
         7dllP/ud47iU+96mk4XwAQr6E0bQfVpPftxdfOwrJFkWih6IEVdUkb4u4uPT68DRrLgo
         ME/g==
X-Gm-Message-State: AOAM530tXZ45iaMBCeUathz/4pKpMZu55NujyFaq2TCxkUhY0L9IxPww
	Odpi4nkkaM0i/C6fwPggmoo=
X-Google-Smtp-Source: ABdhPJyf8+LdCFZeBEFQZzOfZnB1UiUEZLK07LfphZy3r9l9I52/g+wCNlerQv87EhoJH6PlH4BOzw==
X-Received: by 2002:a2e:8e72:: with SMTP id t18mr387851ljk.317.1609871294281;
        Tue, 05 Jan 2021 10:28:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c886:: with SMTP id y128ls171683lff.0.gmail; Tue, 05 Jan
 2021 10:28:13 -0800 (PST)
X-Received: by 2002:a19:d4d:: with SMTP id 74mr224495lfn.403.1609871293230;
        Tue, 05 Jan 2021 10:28:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871293; cv=none;
        d=google.com; s=arc-20160816;
        b=T4+CgIZvTupP+BGj8PSqy9X+ud7FdEXES4iIKIwtbtGebVyezr8sBjdcUNZ/hc2qa5
         uM2h3tvV27QUl1uj1vh0jp+zb/nSmOWiGD/oDVIxO2ViCQHR7NuoifX7B8nNesWvJ6Vo
         xcdsFdtF1kG8SyXUvBQ7OXRMv/dUvFtaMxVkVkIG51E+xYnIB8MFzFmIYLZK4s8TB3NQ
         0YVBjXdlriG9lNn7bm1B6dNgO/ime8fPo60LmdOame1qlIcp0uym3fDEjyIHr9VLuNw+
         5+KIuKgQCWY6+p1jJ7jGBub7B3uZb9tk9i2zNJW2rwYCr+mWNnGZkJul+OZguw4Sj1o/
         Pppg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=GQiVJTM9ZOPgYdzmXpL1IlsdxHwSRDXsv5mwJrm9Wwo=;
        b=iQGLK7dfkTFGACuc7YQ2/Q9pvo2PEgFSF/su8oD8uQWMfXC2x1VVvlORD5vL/ju+ZI
         lHUzktDq+0piNV0QTvDoqnCy/Fwpz9+mkDa8mqb5/GcohR6qzmAgHan7Hgv6+jX85Hvv
         jcPrvIXgmSi7Ljrq/XB9DZddWOztdjatt62hi7UCKt+f+l/EmT+9c1Ycd39yOTOgPToi
         qUegZwPqgYh5DgNf84QpCFUvqneBMk7iUh+yCcJzUP6fGPE2y3FtEFm0ay/Dlb2r8dkD
         FGM8Dlh8W3H/eqrCKV23SNoz/WvZ5aSC9g8zHOmsDAp1BEfmd3W2W6IR5EffHC1NY44V
         vTYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JoaeuIG7;
       spf=pass (google.com: domain of 3vk_0xwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vK_0XwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r12si19ljm.1.2021.01.05.10.28.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vk_0xwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id r8so169906wro.22
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:13 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:804a:: with SMTP id
 b71mr394950wmd.21.1609871292711; Tue, 05 Jan 2021 10:28:12 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:48 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <0f20f867d747b678604a68173a5f20fb8df9b756.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 04/11] kasan: add match-all tag tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JoaeuIG7;       spf=pass
 (google.com: domain of 3vk_0xwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vK_0XwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
---
 lib/test_kasan.c | 93 ++++++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h |  6 ++++
 2 files changed, 99 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 46e578c8e842..f1eda0bcc780 100644
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
@@ -790,6 +791,95 @@ static void vmalloc_oob(struct kunit *test)
 	vfree(area);
 }
 
+/*
+ * Check that match-all pointer tag is not assigned randomly for
+ * tag-based modes.
+ */
+static void match_all_not_assigned(struct kunit *test)
+{
+	char *ptr;
+	struct page *pages;
+	int i, size, order;
+
+	for (i = 0; i < 256; i++) {
+		size = get_random_int() % KMALLOC_MAX_SIZE;
+		ptr = kmalloc(128, GFP_KERNEL);
+		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+		KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+		kfree(ptr);
+	}
+
+	for (i = 0; i < 256; i++) {
+		order = get_random_int() % 4;
+		pages = alloc_pages(GFP_KERNEL, order);
+		ptr = page_address(pages);
+		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+		KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
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
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
+		return;
+	}
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
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
+		return;
+	}
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
@@ -829,6 +919,9 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0f20f867d747b678604a68173a5f20fb8df9b756.1609871239.git.andreyknvl%40google.com.
