Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSMD62AAMGQEGC7PLDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 62E14310EC3
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:06 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id d7sf5742829wri.23
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546506; cv=pass;
        d=google.com; s=arc-20160816;
        b=sidmP6PDmR/4j/3FegSBp51n+GjEv5uQtXOK6BtIZ8qwzZszckpqjdSjyQguucCmll
         Bi49Gg1ZJO/ZnfC6EtuxWI2cN5O4cf10GJTu6N2+xYArzb/umVELCqs/ZJPGpTrg3wUH
         TbOwNayE88jf1F4EpGnFWJP0kV2FDhXMVpM55pEVDGTWAjcBSzzYZP5yGUlJ8zHghwA8
         zMV63h4RAoBHk4MkJi8sCkhs39Tunh7QV6WqkQLVtLDbHEhvUQHPedAiYbKFmJ1sJZ7+
         0Z9evUV0TtFXkC3CNNISUB74IoUUJgwydfcujX/UBgzLMCNR2J0yHkOs2/dywDyEeHZ1
         j3EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Wc9uNsZww4WQI+svGQqxCg9wyfAimQahOa61tx7Xa6A=;
        b=YnzRamh31feGaIngVGu84McMFmwCA1/VhmCJy5o9OlnfUs2pkO0ur/bsf5aHvbbcQd
         o6lzKxeitnVwrJRIf7ge3QzP+iYxdG/8+ZQFPbMTJwL2QEUUFO02f/Hk39zAy1hffsa3
         DsDOAYut1BFC/2DlnOWv6lleywxqWtp4W/+uRT4DCFHdPIK749QJ2oW1Oi+gVBJUKm2f
         8eBQGGIDKJmKxDQYxF9tq82gv91nsuTwwN91cuMqfWFulhOMLG6Ac0ucGTEYqcV/3TAM
         Iszo6Cn4RZn2jqO8SobqlxiDgPJzHVs2JAv5r14kbg3dpsu3tXRKjcPYtJo9dnIKQvl7
         /Vow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NNedEXHn;
       spf=pass (google.com: domain of 3yiedyaokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yIEdYAoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Wc9uNsZww4WQI+svGQqxCg9wyfAimQahOa61tx7Xa6A=;
        b=qvdrAEIcv6D6CXipznVFo1yMOxdbgUK33XztZD4hH/5rIrv8Xip8dsPpff451dnkyg
         dcWd6Jr/4Cx0Jp+7sl90WNcoaJSlRizJUoua7e1MjL66d0CiEuIpzvgzEVbMc3vfWlnK
         ro//erIwKxDum0akSi5mjwwTLjZND3kmZlRtz5AaIfwEcEI9WRoVBulW75aiBx+uq+YX
         tmpu4mCOnL2XikJcGrzb2h3luBCv+zz8LWhsJahyqHiuRnucSdxbAUI+3IlrWffy7a7F
         EnzFb9ypS6vboXi/n5qSQf8csBO/vO5i6sy76sliMZZvZmuwJo5UkbcqwoxFa6iuJ+C6
         Se3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wc9uNsZww4WQI+svGQqxCg9wyfAimQahOa61tx7Xa6A=;
        b=gmHyfNIrQckLwEKq1huwuTZmUpdd8ibEJ5Qr2TOAk1aQx8uEGPBOmjx9YzGbUUIaZE
         +aupRHJ/yAgKxB2glKHJNkelBQvY6LNobBmdDLxikIXNGTWwsMAHKKYwZJ3aEr66G03U
         Q//opj7ggwzpUNVfcbC+BQ9Vla1PCO4cEr3VZuTFA+e59BXn13Ls+q00bU6GbHyodIJ5
         +O5SclkZqa+AfFRO2cfHb/MzgUWW/o14NnsOsllXVV3rhGLiU2zdzf3ul3NZJw44vAvV
         U7lbVboc1QlNeJTgmmsid1ahCwdEAiR+dAVbdP3qhGX5UOQsCbv7qb0vvQe3AUJcXmhq
         PSfA==
X-Gm-Message-State: AOAM532gdt4o2UhLrKJGfShVRY075ZwV4LdzJ82RY2tTo/78308O3qUD
	zCq7/Xby+OdkK8UaUqIa9rQ=
X-Google-Smtp-Source: ABdhPJx09bullQ8PsR2yJ2C4r4jkNUEO7f/qBR+5CIvamJxS0RyWqmNtgfOb2iKZcJKI+bpCD+K16w==
X-Received: by 2002:a5d:6944:: with SMTP id r4mr6174201wrw.399.1612546506129;
        Fri, 05 Feb 2021 09:35:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fd09:: with SMTP id e9ls1261642wrr.0.gmail; Fri, 05 Feb
 2021 09:35:05 -0800 (PST)
X-Received: by 2002:adf:f9cb:: with SMTP id w11mr6233720wrr.199.1612546505385;
        Fri, 05 Feb 2021 09:35:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546505; cv=none;
        d=google.com; s=arc-20160816;
        b=CCDFMG+zQO6utDVAk2b/7LH/nrMasBZ7SpMIzN11jp7jlhfepF8INnRnz9B6z2vdVo
         QO0Ny9onOq2A6wJw/br0jMZFOyVpz+hz3BXb1lwDwSA6yuS9jlyl8F4cVPZGLLbuf054
         /bFu1b940mCgrujEOPkeg1vk2TgsFZU5UlBxaIm/w5ImJf0qWZfB51jNjevlGGUhv8w/
         yKQCLVwVmLoQKx9Ors/JCkLvW9JsKJ/YHhvt1poAv9pcSnrr0NstTEBY8ojadZGE2ceZ
         qusWBQrzzrdyHWwhoGgZTgO6vmuRyinWcMbZEOCbc+0NEf+sdbuxVdKEhHNdkoStrUYW
         rboQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=WvobzSj421U2nh52f1sEoHIHe/BM9iFVUw3RqQILbkc=;
        b=g9rAzPXlVz/yQL4j9gcWqLkg895M/lZYkuA4RUpog6rHOFh2jKrQha/l/xj1JMN2xX
         5aVq8FM1Hn/sf7WxbAVymgR8wxj+/x+KYKd6Qn90g2RXtKM9/CUNGQLQTikTEelwcqTC
         e3y+FgDuGE4eOKBoOcFqrRBTCv0DI7MVqkXBruUL83J/3vRqa7qYIeL2RHuqp1uLF+48
         POAm6Owgh/+hTOGYzCYcYF227TF4FUHvk/zJmnBatqnLAHpcbbth/6Dri8pOF8eogfV0
         jIE6pLWrjMvxUHGWacIe7Aal2Nxmv64r2avDHjxkW/Pjb8mPG06qrvLw+VURHj6DS9lS
         O7Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NNedEXHn;
       spf=pass (google.com: domain of 3yiedyaokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yIEdYAoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id t16si1073321wmi.3.2021.02.05.09.35.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yiedyaokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id j204so4121556wmj.4
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:05 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:154f:: with SMTP id
 f15mr4396184wmg.20.1612546504994; Fri, 05 Feb 2021 09:35:04 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:40 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <c707f128a2bb9f2f05185d1eb52192cf179cf4fa.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 06/13] kasan: rework krealloc tests
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
 header.i=@google.com header.s=20161025 header.b=NNedEXHn;       spf=pass
 (google.com: domain of 3yiedyaokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yIEdYAoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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

This patch reworks KASAN-KUnit tests for krealloc() to:

1. Check both slab and page_alloc based krealloc() implementations.
2. Allow at least one full granule to fit between old and new sizes for
   each KASAN mode, and check accesses to that granule accordingly.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 91 ++++++++++++++++++++++++++++++++++++++++++------
 1 file changed, 81 insertions(+), 10 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index d16ec9e66806..ffebad2f0e6e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -252,11 +252,14 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	kfree(ptr);
 }
 
-static void kmalloc_oob_krealloc_more(struct kunit *test)
+static void krealloc_more_oob_helper(struct kunit *test,
+					size_t size1, size_t size2)
 {
 	char *ptr1, *ptr2;
-	size_t size1 = 17;
-	size_t size2 = 19;
+	size_t middle;
+
+	KUNIT_ASSERT_LT(test, size1, size2);
+	middle = size1 + (size2 - size1) / 2;
 
 	ptr1 = kmalloc(size1, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
@@ -264,15 +267,31 @@ static void kmalloc_oob_krealloc_more(struct kunit *test)
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2 + OOB_TAG_OFF] = 'x');
+	/* All offsets up to size2 must be accessible. */
+	ptr2[size1 - 1] = 'x';
+	ptr2[size1] = 'x';
+	ptr2[middle] = 'x';
+	ptr2[size2 - 1] = 'x';
+
+	/* Generic mode is precise, so unaligned size2 must be inaccessible. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
+
+	/* For all modes first aligned offset after size2 must be inaccessible. */
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
+
 	kfree(ptr2);
 }
 
-static void kmalloc_oob_krealloc_less(struct kunit *test)
+static void krealloc_less_oob_helper(struct kunit *test,
+					size_t size1, size_t size2)
 {
 	char *ptr1, *ptr2;
-	size_t size1 = 17;
-	size_t size2 = 15;
+	size_t middle;
+
+	KUNIT_ASSERT_LT(test, size2, size1);
+	middle = size2 + (size1 - size2) / 2;
 
 	ptr1 = kmalloc(size1, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
@@ -280,10 +299,60 @@ static void kmalloc_oob_krealloc_less(struct kunit *test)
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2 + OOB_TAG_OFF] = 'x');
+	/* Must be accessible for all modes. */
+	ptr2[size2 - 1] = 'x';
+
+	/* Generic mode is precise, so unaligned size2 must be inaccessible. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
+
+	/* For all modes first aligned offset after size2 must be inaccessible. */
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
+
+	/*
+	 * For all modes all size2, middle, and size1 should land in separate
+	 * granules and thus the latter two offsets should be inaccessible.
+	 */
+	KUNIT_EXPECT_LE(test, round_up(size2, KASAN_GRANULE_SIZE),
+				round_down(middle, KASAN_GRANULE_SIZE));
+	KUNIT_EXPECT_LE(test, round_up(middle, KASAN_GRANULE_SIZE),
+				round_down(size1, KASAN_GRANULE_SIZE));
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[middle] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size1 - 1] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size1] = 'x');
+
 	kfree(ptr2);
 }
 
+static void krealloc_more_oob(struct kunit *test)
+{
+	krealloc_more_oob_helper(test, 201, 235);
+}
+
+static void krealloc_less_oob(struct kunit *test)
+{
+	krealloc_less_oob_helper(test, 235, 201);
+}
+
+static void krealloc_pagealloc_more_oob(struct kunit *test)
+{
+	/* page_alloc fallback in only implemented for SLUB. */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
+
+	krealloc_more_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 201,
+					KMALLOC_MAX_CACHE_SIZE + 235);
+}
+
+static void krealloc_pagealloc_less_oob(struct kunit *test)
+{
+	/* page_alloc fallback in only implemented for SLUB. */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
+
+	krealloc_less_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 235,
+					KMALLOC_MAX_CACHE_SIZE + 201);
+}
+
 static void kmalloc_oob_16(struct kunit *test)
 {
 	struct {
@@ -977,8 +1046,10 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(pagealloc_oob_right),
 	KUNIT_CASE(pagealloc_uaf),
 	KUNIT_CASE(kmalloc_large_oob_right),
-	KUNIT_CASE(kmalloc_oob_krealloc_more),
-	KUNIT_CASE(kmalloc_oob_krealloc_less),
+	KUNIT_CASE(krealloc_more_oob),
+	KUNIT_CASE(krealloc_less_oob),
+	KUNIT_CASE(krealloc_pagealloc_more_oob),
+	KUNIT_CASE(krealloc_pagealloc_less_oob),
 	KUNIT_CASE(kmalloc_oob_16),
 	KUNIT_CASE(kmalloc_uaf_16),
 	KUNIT_CASE(kmalloc_oob_in_memset),
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c707f128a2bb9f2f05185d1eb52192cf179cf4fa.1612546384.git.andreyknvl%40google.com.
