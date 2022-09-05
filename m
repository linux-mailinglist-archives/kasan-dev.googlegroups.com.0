Return-Path: <kasan-dev+bncBAABB66L3GMAMGQE5O576OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 193BD5ADAC5
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:11:24 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf1973354lfa.10
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:11:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412283; cv=pass;
        d=google.com; s=arc-20160816;
        b=pDa+BHwjy75gVIvzSoew+cfyMnXbN1qwDBVE/eBB48VwqHLGI/Me58c7Ff6RGxEJxs
         wF+m9mVjEP7HiPQXkNXsKyQAdTt/kkMFu0vU9GGvi9vInZsNYUgEIYgoH/Yd4m/wfEjZ
         rukWLw/dj8mg2vf4p0KndzgjIMFwzKOn/DcVbJAYUs5abjHs4xkB0JGvZvSdxn64/lC4
         99/YdyqTacHLxQ16gcBgMhEvfsoRtjvFO7mnD0TKmmimYQn/+a7m7YwXA3avQxmuV701
         YJ1KRmNGfl8HvysriX9dJ8GjfIffrNK3gZxbWPR24TI1Ff3pseOzcVpUATLbibUf8NSq
         /OuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OPgn5NbZjAmH1kv509/352RoaQDH8FFPT8b+HwdPuPQ=;
        b=TcfNY8odBbioNErZlnAaGRcAP5VsFkxB0gTYYWJyGCNG32JzI67te6VvqOBZGOJY15
         NF5iuwak5q5fZflTMRiP6nl2gpJEjcIHxvJXs9YusFuE881u1xPYvQTM44PxUxYzw6AN
         nEUWvv3iUOWEDkrPxJHUUlCecgfdx7iou5sExfB14i4YNqjqURXSOvNcA91auEj1X4rU
         62jhJsPtQvT7ApjKOht5urJbnXnChSpFP68mzw79I+kDUMuYssInlXbIU0rXXaPZfKgU
         7lo+fgND4vSNUo9FzHLomREzYq3bUGuxV7PU4EKxOyonzyQzZayOBPxOxmVq3QJijiYg
         J+IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hFYsB+Fz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=OPgn5NbZjAmH1kv509/352RoaQDH8FFPT8b+HwdPuPQ=;
        b=XoOi/6ipGR9FBOU1BNziD0wtJ65GVhwLKni5UiA8zlSb/kWNfSL9k4VEvuYQrZKm2z
         iCVwSBSJpEaZxVwbb5WJX4tb6uOdrfEDfmVGlpztKtfCkokPRFXgvngnI1jz8SB1aq67
         UZ33KJL5dNuz6hLx0vXJZyU0Ry+BwzQ7JskCfm56hOcVXYwpk5BGr8lhLHVh25zUegtD
         dkkz9AylmXr0ik3htqfAQfMDpGAi/DT0uQr8m1jsDfSck9RJfHJ5rC0gZ3OPVgO+Iplf
         3OfToOm3JxjeqoYkjifgJYp2DOd57thGQMy6shXH9cYmrijndwh6Vyujy8ZcD/zGubdo
         4CPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=OPgn5NbZjAmH1kv509/352RoaQDH8FFPT8b+HwdPuPQ=;
        b=KZzHhk7w/CtRT/66QfWHJEaarbiFfBcyHLEy/e06J0+xj2yqZmOjn9yOzFc8m80I7x
         UhFRom5O4wT3bKsBrmNrqsof0JOzduBbnb3nI25K8Ij9lIakw4u12lvOBhwUwLS9EqUS
         asij5Cq5dkbBuYjrPbi3DSgm9+6k97gcCt503IEGqoRKUN2xFWuLbsNTe9NSi6LLtlZV
         GQCHsLBxT1bPsdnGpp9PI+Yu/j+MCBQznqMLp4m7002DuNUShnmCj+bZBFh4Nm5fwfmy
         yY4Hj6OxhpSQHfbtkUelB8AbQmeOrwK5nvK4xaw2gFXzdwr3MWhiPm6aEgLBnAvoxg5n
         K9Mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Pfl09o3fB3bBhse6ReiNsLiYZwBQHsRwVgL+o3u4uaMU3umQr
	0GKV/xl+k19EOqAKTATn5mY=
X-Google-Smtp-Source: AA6agR5KSTkyVmnttNo9MVwjaJeEL+jvVs7wY/FQkitVxXEWEkoDudvW/nq6uaeunh8uEA6SeRw5nA==
X-Received: by 2002:a2e:3808:0:b0:268:f30d:a3e with SMTP id f8-20020a2e3808000000b00268f30d0a3emr5023063lja.486.1662412283602;
        Mon, 05 Sep 2022 14:11:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls5363164lfr.2.-pod-prod-gmail; Mon, 05
 Sep 2022 14:11:22 -0700 (PDT)
X-Received: by 2002:a05:6512:2307:b0:494:6afd:7b2 with SMTP id o7-20020a056512230700b004946afd07b2mr13376659lfu.559.1662412282896;
        Mon, 05 Sep 2022 14:11:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412282; cv=none;
        d=google.com; s=arc-20160816;
        b=Io1eNH3r+gbeZSAmOcjLWCCJ7y+PTlO3IJG+ZwtwZl35Ecbgd42Y+h2tacTufLTxLp
         9Tsho99ednsabf4DJpGR3mzV4Iaqow5PXm5s7hDi33xj2KJnG3uH8q0mH7CueZ9+N2M6
         u/QvmcoAJLfbKfMvr0RmRZZ5iouV86GUzBbQI4p3O/KL+YP/76f1lcDh5azy3fRlU+oh
         YeSkyALiyUIYmOtuQNw35KMA2iTUa9cP7gHDxN16zfAk6yruNCoSisrdtHLEKb9mZgI0
         PUExbXHieSq0c5LGprLI7QKXgQRrDQqZZYxfPPXVVzbrhOqw9jwYj0QFotUYEpi+rFtd
         aYiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TrkbSYuQGAnlXN7bh4mnqFPtjr4fL87+nLp2f5EX6NA=;
        b=pjyYBCEp9yB71WFM2IH8NumAC0xhFsmDXTUDT9KZRS6XiiuQ55WzSH1A2rRR+MIo4j
         QBhUlgLUQ+Tl0Lz6pft9fXsViCVbzBB+HwmFmQIRQ60QQVD8xJi+y5+/leTHvf9OLb/7
         EBt3mmmy6QRupQB5wuKBBk1zprnmwLU2HUtH3Dm59wQsPQs1aYjkkyBvKoZgn5l4ZPzN
         yy8ode2Th8QPShf+uVAV0AUPyF1hEb+d1lRodubeqesBNc/OwcBir/wXzYZm9kJRf0Ub
         TflsbEiDO3EduQRkV03BI5eLcKO7ORWWrqKOxqzS+bBrC0KOcmqUnIqEZmWzDQctnCnk
         UGlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hFYsB+Fz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id o4-20020ac25e24000000b0049499c0cf28si383891lfg.7.2022.09.05.14.11.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:11:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 34/34] kasan: add another use-after-free test
Date: Mon,  5 Sep 2022 23:05:49 +0200
Message-Id: <0659cfa15809dd38faa02bc0a59d0b5dbbd81211.1662411800.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hFYsB+Fz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add a new use-after-free test that checks that KASAN detects use-after-free
when another object was allocated in the same slot.

This test is mainly relevant for the tag-based modes, which do not use
quarantine.

Once [1] is resolved, this test can be extended to check that the stack
traces in the report point to the proper kmalloc/kfree calls.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=212203

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- This is a new patch.
---
 lib/test_kasan.c | 24 ++++++++++++++++++++++++
 1 file changed, 24 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 58c1b01ccfe2..505f77ffad27 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -612,6 +612,29 @@ static void kmalloc_uaf2(struct kunit *test)
 	kfree(ptr2);
 }
 
+/*
+ * Check that KASAN detects use-after-free when another object was allocated in
+ * the same slot. Relevant for the tag-based modes, which do not use quarantine.
+ */
+static void kmalloc_uaf3(struct kunit *test)
+{
+	char *ptr1, *ptr2;
+	size_t size = 100;
+
+	/* This test is specifically crafted for tag-based modes. */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	ptr1 = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+	kfree(ptr1);
+
+	ptr2 = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+	kfree(ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
+}
+
 static void kfree_via_page(struct kunit *test)
 {
 	char *ptr;
@@ -1382,6 +1405,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_uaf),
 	KUNIT_CASE(kmalloc_uaf_memset),
 	KUNIT_CASE(kmalloc_uaf2),
+	KUNIT_CASE(kmalloc_uaf3),
 	KUNIT_CASE(kfree_via_page),
 	KUNIT_CASE(kfree_via_phys),
 	KUNIT_CASE(kmem_cache_oob),
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0659cfa15809dd38faa02bc0a59d0b5dbbd81211.1662411800.git.andreyknvl%40google.com.
