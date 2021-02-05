Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOGN6WAAMGQEBTDFHOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id EAFBC310D40
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:36 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id r23sf5737025ljm.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539576; cv=pass;
        d=google.com; s=arc-20160816;
        b=JHbsobtdlTt0jnBs5kuDMV2xWMDrIbCw0JlfK2aTVKyAxoQcMDYq/vrAO1EgP3pHeu
         d1WUbWw3oQWYcv+M0gp7dfxfgkm3B4SWaWd+ePCubjR9vOGlh0RLmTuh3z7+eIKV1eA+
         sgeAiD6Gx91876FvMUN4f6nOQFlZlJjynBsEAE9cuMp1845EzbRHLfnstCqlxH+IgCyC
         0mUOGUvqhnT01zNJ5Sw6TJJuKuIrKUoysdHz7fJGMbDsqX3r+77bIKi+NDMnzgaST48+
         R5aosIfdIMEHv+EsDzm3Afhffi/W8ZqgeiJ/feI1pcZU5XU4a1RZtGXsagT2ioREXZXB
         bG+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=u64Ze80GgghFN/ouyHJfehZ51KRGJEeq7XauCg2ccbc=;
        b=W+tHh5QgTImzQdmfHIolSfCKfuyB2xcJ64uitwbj8QbV8XuRR9hWeUSgwHE25gaZUj
         mx2WFKAFNlN9V2wzuUkjtTciaXplDFWW2WZT/YNsNTjn8f/yJC4jru7xGP+uXI0zO+yb
         0vx+mbH9ktPxhQQsLGKooSdOs4FZc07vzlmmFWIzwG4ZQFfCJWBWvRFNCqMjSk8zoa3G
         CHAfhZPM1XyfYshSCzpig2x1PC8dHIhGYYqLLuCxe4FTNl/EHmOQhYwFo9cQ/T4Yh8PC
         4GnPVQ+hVk/ziq7EfEkjePTRvCo+VLgG9LWEq2qWG1UKaMd1sMg0rVrYNcvaWq3u6nFM
         hcuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SekTvXiN;
       spf=pass (google.com: domain of 3tmydyaokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3tmYdYAoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u64Ze80GgghFN/ouyHJfehZ51KRGJEeq7XauCg2ccbc=;
        b=N3PNnkq2g9PmwbDynK9sHsbKxoj430J7NWKJ5i/o6iKZZGk+hTvYIaNx9Srgu/pbUs
         0xGXv0a9Zi0R3F4Ru8JAftHsdnJ3VurOn9urs7AZeDIXLj6Xi+zbgT0Cv+zvtIBjjhRL
         a+RCLVIDhsUMJbphEHKKkhQijHuUc2WwlNtqLIRGbJjcWixsuZyootS797xeBfrqI0ut
         2+gwYRwhG1RT+sT66IVnGA6xoOPdYGsROl7c70C51cLMPB6fjLt9TfvZMy9Rn1IsW9FJ
         V7FeMUfXobZiJfQs9eXKqifG2XSMCzsjSaBN0mEULa6GN7aPsxF37RhYBvYazjOsa/ny
         9AmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u64Ze80GgghFN/ouyHJfehZ51KRGJEeq7XauCg2ccbc=;
        b=fyegerP0frU7Buqr76GOUMcQSXvwz0b8Eb1UHuk4RGDkSzCbWnP0O0rRwAAN2mIuyg
         xQZF+oSNSwPqDm5YMMI63wmuu27JAexgmbwPxflFJaDgDCYdl+SIUvePlMZjwZos1d2A
         hhtDC1Rf9qhs5q65clcVE+fPfVZCvL47VoBrwBEnvMhn+nCzihbQ4G3G2AmMHiC2vPGK
         8/wjneIgU2tKbn4RfYI+VzwjNl9U0XVyO3WYmX3mNCJjSHXvIpseWM6iiz/ZV21aJCQB
         ZQH4ml9ZB48tldnFe3YN02C+PbZebl9BTuowFuAAl/xGlwtWWAgYis/kih0pLeNoLi3l
         p8ww==
X-Gm-Message-State: AOAM531XZ19A2tU64nKyyDPMhq2wyjuWEyGzSl2IbzxN7533P18PEsBZ
	z70kyix80irM/ZyWbNxJaUk=
X-Google-Smtp-Source: ABdhPJxFVOkrk2qsKoVGDzMacJvfAE/LFprjCMFVx1n6VJCnHSOIP0YCVh9tT3sDOgXLOsHmF39wnQ==
X-Received: by 2002:ac2:4c2e:: with SMTP id u14mr2727530lfq.294.1612539576552;
        Fri, 05 Feb 2021 07:39:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls2641032lfu.3.gmail; Fri,
 05 Feb 2021 07:39:35 -0800 (PST)
X-Received: by 2002:a19:7602:: with SMTP id c2mr2620545lff.519.1612539575535;
        Fri, 05 Feb 2021 07:39:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539575; cv=none;
        d=google.com; s=arc-20160816;
        b=oyV8yh4qispninYf8geITcXietITSIFA0Vdxg+YcaU45vjBKSPDQOfLgDGiTTXBAOZ
         +ARklVFh8T9h7+x5Uktc6g2O5j4KfZcY6Ybafp6LF6RI7XTbeh+dfe2puHEozsEK0d9k
         osned3+akXA3bQCKyL/Ov3Y4mDw9l8e7XT7V8kRYjTxpFsMGQQ21jmKRhwOrHeDqu08f
         6f7Qv4JSoB4kIob58KMEraYnKO12BFfhZnlPYcmx99Ozx2r2blK1uQbowhbacbVHZfY9
         HcDQt1xBkA8cnLF//yK6cubt9u+BDXRtyJDgRZPtRLvrkq1y1BLSn1eviPU9o8DORbC+
         Zr/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Eem+CPI6cqDr3+sdydeGQiL8gIW8yui8+/Xm+DAKB7k=;
        b=M0fep0ewr9m3jVlmCuKOeO6EKEpDNe7Ot7Z4XIsernPv8Ej+MYvprTNMDQJzZi571p
         z3Ly1MpNP/PPTF9vSa//pDZn9Smtb2BoSB0A3DMjtq2PHGOuY2CeC3wMbq1HFxXkNvCw
         njz5+7dkjYjEM/sJET6nCelZhau59DvnaBX3FVJK1F0W4oRHzwpFyrBDI1zfUVejDL65
         A+EOB2JSLRrXUyxuIsX/AEcRG+EatFFyNnz1jKc7qDOula5CX7JB0zCqFfGf2jfsQ61x
         ZNzACFNUUW/6cQM+p+zhwnNpN8tYF95f0O7EAAckYp1g3rCXtPfkogEzbaMqis/HvN0A
         DrzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SekTvXiN;
       spf=pass (google.com: domain of 3tmydyaokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3tmYdYAoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id f18si543101ljj.1.2021.02.05.07.39.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tmydyaokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id j204so4003855wmj.4
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a1c:25c2:: with SMTP id
 l185mr4086468wml.62.1612539574962; Fri, 05 Feb 2021 07:39:34 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:08 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <419e4e7ac9ff7596a1a0956c117fcad1938e5d77.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 07/12] kasan, mm: fail krealloc on freed objects
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
 header.i=@google.com header.s=20161025 header.b=SekTvXiN;       spf=pass
 (google.com: domain of 3tmydyaokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3tmYdYAoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

Currently, if krealloc() is called on a freed object with KASAN enabled,
it allocates and returns a new object, but doesn't copy any memory from
the old one as ksize() returns 0. This makes the caller believe that
krealloc() succeeded (KASAN report is printed though).

This patch adds an accessibility check into __do_krealloc(). If the check
fails, krealloc() returns NULL. This check duplicates the one in ksize();
this is fixed in the following patch.

This patch also adds a KASAN-KUnit test to check krealloc() behaviour
when it's called on a freed object.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 20 ++++++++++++++++++++
 mm/slab_common.c |  3 +++
 2 files changed, 23 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 6e63ba62db09..791164ef191b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -359,6 +359,25 @@ static void krealloc_pagealloc_less_oob(struct kunit *test)
 					KMALLOC_MAX_CACHE_SIZE + 201);
 }
 
+/*
+ * Check that krealloc() detects a use-after-free, returns NULL,
+ * and doesn't unpoison the freed object.
+ */
+static void krealloc_uaf(struct kunit *test)
+{
+	char *ptr1, *ptr2;
+	int size1 = 201;
+	int size2 = 235;
+
+	ptr1 = kmalloc(size1, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+	kfree(ptr1);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
+	KUNIT_ASSERT_PTR_EQ(test, (void *)ptr2, NULL);
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
+}
+
 static void kmalloc_oob_16(struct kunit *test)
 {
 	struct {
@@ -1056,6 +1075,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(krealloc_less_oob),
 	KUNIT_CASE(krealloc_pagealloc_more_oob),
 	KUNIT_CASE(krealloc_pagealloc_less_oob),
+	KUNIT_CASE(krealloc_uaf),
 	KUNIT_CASE(kmalloc_oob_16),
 	KUNIT_CASE(kmalloc_uaf_16),
 	KUNIT_CASE(kmalloc_oob_in_memset),
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 39d1a8ff9bb8..dad70239b54c 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1140,6 +1140,9 @@ static __always_inline void *__do_krealloc(const void *p, size_t new_size,
 	void *ret;
 	size_t ks;
 
+	if (likely(!ZERO_OR_NULL_PTR(p)) && !kasan_check_byte(p))
+		return NULL;
+
 	ks = ksize(p);
 
 	if (ks >= new_size) {
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/419e4e7ac9ff7596a1a0956c117fcad1938e5d77.1612538932.git.andreyknvl%40google.com.
