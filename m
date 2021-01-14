Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT52QKAAMGQE2YBLAMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 23C282F6B19
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:48 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id l10sf2640962wry.16
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653008; cv=pass;
        d=google.com; s=arc-20160816;
        b=qXstOdeNRBFJsTrLhzkE6/6Ust9B6fhe+RP6rrblpbvReorkIvTorfM7XNjvJix1RK
         f4O35JKShSUrOngIE9I3u0ul3hO8BeZ2QwmNqntAeO5tyI+8nrrZ9debl8mbafDJYtf7
         eyNT/UqsfF3lahIbYU9SMB39Mzu6M9Ml8/8IpLGSxltcDih5duVy6iV7qCFEF3tRJk6i
         j4DqYrb7QpgvuapwzYgPv4POKMO9djtwzeccVaQ4zfj+AGCKvMv9rpJs5Fry8LdR3836
         mqCZ98bHmAWD37ctdJoS1DmrztjU9v6FzuEOgh1pgFK1lHpz4oWD2qR/HEjcF5yj/N5N
         dY5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UaNSck7SVTkQdaO9PJyCRDC+MlM/F8xVxUcLirRp5To=;
        b=yxSIg0C8N3gzV3H2cJOBpkstHyYecoynhkPUzSi9dn6UCq1l3NL/Fgxilk014bf2EE
         OEHKLmrYNXBXvJibL9H/gL09ns0eTQPpTDpXyeTMhmlKzD3HOkpD0Z9nKpPH42iKlYfl
         HxghpiENXOJbFFmWNW04HiD9O8fQ4XQcYriYWcOsThL/gqwkPgwCPOGoUjEgLgKNZCgg
         92ZHFuNCmQyfUgBYBK7rq4veMAm70o7Y1/6wW2dig8j5uJYt9wkOYtKOY+06vnGarNCc
         3388iq6X2GpSZdnbyIYGv+ywf0O+NMqYxbt9RPKti5pvy3RDmJg2jnYI6fP7Mt52O0hC
         elvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XqPiQtw9;
       spf=pass (google.com: domain of 3tp0ayaokczev8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Tp0AYAoKCZEv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UaNSck7SVTkQdaO9PJyCRDC+MlM/F8xVxUcLirRp5To=;
        b=nlujoj4dgBrpEn0cQ+CJUKMW/VOmwypg2NrL+RSjUWqit6oshPYejWRckb/4xU4Oeh
         BzdBjAnflZJ1qoG1jIr+a5WHhKKV/lHNxrbNHhVpC22XIt5rQA/o4r1E6fsWbuNmgNXl
         Q3ftF6N7y7OX+g+X10BXwYSH4EdNu8KOTkEXrypnzs1FFSmNn/GtXzmP6V7jrXgJEqQy
         0ukCIbQHe6AR4tMrYRdzG++zwkn9gXGXr3HkDvCa7oxl7XOAzB3DY4BqFNMotfVcAzhz
         k11HSM4usvYYpwP8y6fHkFaf491RfcXRJC7ceev9t0fVB3rOC+mitVhgqxIb7nbglk1O
         jIoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UaNSck7SVTkQdaO9PJyCRDC+MlM/F8xVxUcLirRp5To=;
        b=YfviKfLmUDQT4mTMCVHzO+jTp5diUuzCaJr6gT1nci5YSMYxJGpeW3/eFcRiTqBJAi
         s1Zv17MyAqAHrVOEUbMii1W47u0EQPxbhR0dZmCvq33vY54eDE+h/wh+F4Ko4wC/8ujP
         3oKhVSki8SxzUv5u87IXON5zWySS5mTmJxjTbuoZmykYS/ikm7OEVDHI1FcMEGoBVI71
         nxiedpIC1zVHCO05Cug7LJHRr+4XnWpnh8Shs3AKMI/grnoSM+2je93Tmwei9u5bixeO
         wKpmYZECJRpGs4ZK308QeZ/rs+W70t8NJue20L3hk+RHjZlI8ncZFu1Y8aduPb2a5Exc
         nuCg==
X-Gm-Message-State: AOAM53345ZquF+F42kbrtG1PFYhDpPNB0SYmal6BNlZSWoaieFkEGOTt
	72BfozxfXdMQKAnZpfUWFZU=
X-Google-Smtp-Source: ABdhPJxDRSav0vgRKaa2SHaZzRZFUhVPWgFyldKD4A7Zqp+sF53ND+WDPeRVaVy3IlzKRaO4xvT1kw==
X-Received: by 2002:adf:92a4:: with SMTP id 33mr9407462wrn.347.1610653007936;
        Thu, 14 Jan 2021 11:36:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2094:: with SMTP id g142ls3192695wmg.2.gmail; Thu, 14
 Jan 2021 11:36:46 -0800 (PST)
X-Received: by 2002:a1c:3206:: with SMTP id y6mr5234157wmy.127.1610653006471;
        Thu, 14 Jan 2021 11:36:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653006; cv=none;
        d=google.com; s=arc-20160816;
        b=VY2HwTMkb9GtKlKazI6imh1ccHW0DudgZWfIIwV077KDGzu4IaiPTbuOyMN2bHryLE
         nexI3QA1GHIN8Va4gkeHKtwMy3UMX2mZF9S+aLbNPmA/W4hvlak51FvqNOwcD8/UYD6Y
         Qqlmjsdd34RPd9qii9Lj6pY9QkGypJbK4DNIxTV6G8AelWtWLQ15CCQSYhM46XHrtO8m
         yZtVr1EgAe4GfCKoI6rBA8Df+7+bt9/WR1v29Tp+runQOn5JFmDTRHYql6E3Hkz5B0Vr
         xLT8+gIJSSf3ayymcTY3Tuw2ylh+hiHNc86z0e9/UimOjsbonk8PODAfJN4vTl1/UX7I
         MNlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=An8QbssU3Paiod4E1kUAdvkgOfXtx5Y6R0zbziTz4iI=;
        b=0OVK4WtKnETT3zCQYtNU/cei89mt7/hSalQMblmvIWMj6nzMvsepMXZ4MPc6eHwRH9
         sJo0tk7DikRFtq4FE9WZ9N68l6Hhzrgkq1ex2GlAmNKd5hsfQIhtQsJkjND5c++spoNL
         n+K28bunxAE+T0pobDPr+Z6dxkMxsEoQDvMcr/MnG5pEYSKd/IiVUkyT4TgbGyFWQW8U
         8EUdtLgMdNPczTxS5Grq/HETanDcKXxpoVdga8fIfAulXVr8In0585wmq3CUbS/HIw5D
         gkP4OgLKxvZLj0iDMxbCaon7Lbh6YcZXs4rhU9UlIqKBvRpy94PzcT+PhjLmYWJgu2ae
         OBfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XqPiQtw9;
       spf=pass (google.com: domain of 3tp0ayaokczev8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Tp0AYAoKCZEv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id b1si355222wrv.5.2021.01.14.11.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tp0ayaokczev8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id g6so2801035edw.13
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:46 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:3949:: with SMTP id
 g9mr6032701eje.493.1610653006118; Thu, 14 Jan 2021 11:36:46 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:21 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <5153dafd6498a9183cfedaf267a2953defb6578e.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 05/15] kasan: add match-all tag tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XqPiQtw9;       spf=pass
 (google.com: domain of 3tp0ayaokczev8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Tp0AYAoKCZEv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 92 ++++++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h |  6 ++++
 2 files changed, 98 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 714ea27fcc3e..c344fe506ffc 100644
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
+		size = (get_random_int() % 1024) + 1;
+		ptr = kmalloc(size, GFP_KERNEL);
+		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+		kfree(ptr);
+	}
+
+	for (i = 0; i < 256; i++) {
+		order = (get_random_int() % 4) + 1;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5153dafd6498a9183cfedaf267a2953defb6578e.1610652890.git.andreyknvl%40google.com.
