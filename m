Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNWN6WAAMGQE5OEON7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id C9C15310D3F
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:34 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id s18sf5701658ljp.7
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539574; cv=pass;
        d=google.com; s=arc-20160816;
        b=rE2XcrptjGP4iBz0J1C0hkthVivlm1BSds1H8sgYhVbZiPBxlKfG/fYY78KBt/pRQg
         17P3FHMGAkArfFGlcCpP/lFv2nyCi/CpS3eRz3IyMhZYoi5hcBKz8SFVovQnZ3QSHpN0
         XbhoNRRUuDe322d6s+C8k7hDzzpxNKYn0BR0XxRi+Sx1CnsrnprFlCNywsUMN5/2SuwD
         K73m3DOIBJ6IfKyrvxVQJqhXOZoE6CB/E41ubYm74E359Yfk6dgqCg4rVBxnJJMVZkK2
         7mZIyZ1CwqGIqCQQMv0P7jMg9DpgaDHRG9xpCgjON9G0vqCbwzOeheLUX1uUxBVG4AVh
         Dlwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ytHI2XymdH67v8IWc5jS8bD/iW+e1I6CwsvO2SIiXmk=;
        b=sF3gHlUA2XHFttePvB+eHvIoiwfc4/J8P2S94l5iWRjFnEbY0Hu53v9J+FSLVNTwG5
         jbeifHKyXOrvABrEa25H2/8e5vQK4aWCOKTrTV/4VVepjZhUjuVrHUvWruUXqqswISs3
         1AbPIg3SN2lt/Ce8070vIAUmudDI8oWeoiLPCdRZJyF+RP6QkdKjiWoWxks3hmMJNsM1
         F/1bTqTZ0ve999QWLjea/33TAdlHxj9M8WXg1/ZmG2m9ErtULHFH9eIEIE2/YP1j2VLj
         N7j4PyPrPA+gnEmXjcr7vME9lSYQX0slp5gBDkbrUSyZMOL/QbmqCir0CUJ1EygQwKNG
         HMhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QfjYpmjX;
       spf=pass (google.com: domain of 3tgydyaokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3tGYdYAoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ytHI2XymdH67v8IWc5jS8bD/iW+e1I6CwsvO2SIiXmk=;
        b=XNubBqPptLuNs+UFzYIRoh2UY8U94LhwwyIQdBBqMamSZJCuxk5uM5f0HmxZHQb6ff
         h/PJ7yKpsoxhCBjEonGY3JgPXXQj2q2HYxOADimhCjQTB/EXhjWS5v1IrwrZIpEck2mg
         H1cQZNcPDHuRUrbMKKL+mCWteGXv07Tla1AWw+kHB0u/ja+mY7Kqg0L6sWVm41qNgpI5
         xpoCxt/1ZVOgtk8eMzxx9x01HHD13D4SD3xqiNvUTPOaaM3XqUNNHhY1CETxgWhVhi/9
         fYiiMZoaLgqueTN/Rv18N32IHTYhAs1+B1P8AZqTu+4UW3Pt6kixHvFV8rL25e9vg6yL
         jt+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ytHI2XymdH67v8IWc5jS8bD/iW+e1I6CwsvO2SIiXmk=;
        b=Q3U2hOXi05pBF337uVe6NzutAYXHv1gc7oNi//8p5mnvG7IEM+IwFMzx3BIA+dxKsz
         yxZURdKNhlovoGbAbvY0FYLY8OuumDILgGMfnnijCqgnyIenbLsFFoWlSz4lF0NLXYMD
         BAIsgYKAvgMamf6egwxs1SCWQJ1iA9QhDkNv5ljkaPDn85KVJwtK+nLFcVG9QMVY2tpP
         W1NveNYn9yLtZvJLvuH7PFinI7Q4cP2zuR+UMQfR5B0KG9TuqnZo/tt+ad6WoCb9myil
         NfFBUQCV+UqEkm6JFMcnm2W/2My08YT1nPhjM39hR3jqs9QzSO1tXWicxFFzS73derCW
         szhA==
X-Gm-Message-State: AOAM530InX2qvq15cY8hvnXcHYtZdWW1ly5tDJjwAhNTuYEiaIFlMeXQ
	oxFIlHXpVH9PdO5mJCDl3bs=
X-Google-Smtp-Source: ABdhPJwl6O3R+rvtUq2D0gZzvHshsNTHQOe+OZz1PTk/Cs/Vcyz0VdUO430oA6G23Q0+ie/0emJ3aQ==
X-Received: by 2002:a2e:8e26:: with SMTP id r6mr2864472ljk.451.1612539574321;
        Fri, 05 Feb 2021 07:39:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8952:: with SMTP id b18ls1761190ljk.3.gmail; Fri, 05 Feb
 2021 07:39:33 -0800 (PST)
X-Received: by 2002:a2e:85ca:: with SMTP id h10mr3120030ljj.474.1612539573363;
        Fri, 05 Feb 2021 07:39:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539573; cv=none;
        d=google.com; s=arc-20160816;
        b=zUjmMZHywcy8fyS/H98KGliLS7970xb8a2OmGvAtcbJCiJ5d2tqHMjxDzHJoPXjkqu
         0ASfZuLipgzSJfmdIVojxL9nBgRyQ887EdbOw+GTmDntOEEBa7ZQhlNQY0INnI8iuOGD
         OyKoFdCM8gWv3n4GP40QvnBTGbaOZa0+md2/0t8qI1fO6h7BJzJFWf1ugCUUXsTQ+TAc
         w5rgvPB2YG+ea7CMTZ46O+0BZo4oZqZSNgA8OcN7NTVUH37JcRnc5zCmM4PO4fpziVBo
         FiyCsB6qjwkuMFBxYTyU3SiZbRjBvXtgSeE+4GKwYuTEO6T9eTUoV7HpMu7vfEn2LBr0
         u7GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=8mKaNk2QrOQTwEWb38aMmksU7/sGdVLcyph/DgY5wHs=;
        b=cBYJyUQV9qYKffRaUvsoZfBbn3KrR+1FPh/g8UfhwDu/bokOj05PD/5b3V1IhtvyM9
         S8YVzejOuc/ffAPdf+LinY36puERaRFSn0l5KJUE8g6PLyoMt9TkNajXEcIjPe+E3GRC
         uW5p/2+8kjxIGESpCB6UR0XJxCRvolAC3iyrmluG936ItYeJDMT+FUdla+JGM+fP0ryO
         QRvA/c6Q212ejKLb96P29Vuj+jzlkjEun5gl2vFo4Lb9QTShKx1eyNvcI4dBd6E9EcFE
         Bt/oGVeGKnM1F7CWRYimWRjA8PoRypvFrL8BJASDZEdEAOnZUiPJeDXSh0pQmdzSfqUH
         2dIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QfjYpmjX;
       spf=pass (google.com: domain of 3tgydyaokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3tGYdYAoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d24si344521lfa.9.2021.02.05.07.39.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tgydyaokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id o17so5595211wrv.4
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:33 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:35c9:: with SMTP id
 r9mr499080wmq.0.1612539572043; Fri, 05 Feb 2021 07:39:32 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:07 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <dd0784c422133ca65ba691650b87989320d0714d.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 06/12] kasan: rework krealloc tests
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
 header.i=@google.com header.s=20161025 header.b=QfjYpmjX;       spf=pass
 (google.com: domain of 3tgydyaokcf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3tGYdYAoKCf0fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
index 5699e43ca01b..6e63ba62db09 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -258,11 +258,14 @@ static void kmalloc_large_oob_right(struct kunit *test)
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
@@ -270,15 +273,31 @@ static void kmalloc_oob_krealloc_more(struct kunit *test)
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
@@ -286,10 +305,60 @@ static void kmalloc_oob_krealloc_less(struct kunit *test)
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
@@ -983,8 +1052,10 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dd0784c422133ca65ba691650b87989320d0714d.1612538932.git.andreyknvl%40google.com.
