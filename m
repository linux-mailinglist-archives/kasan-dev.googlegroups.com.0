Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH5NQ6AAMGQEWHZ5N2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B5CEF2F8306
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:35 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 198sf3342407lfj.19
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733215; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZHzJkCMsBqa0foC4wPWL91ZAcJRErZbZkHaXYzmErvyBuAV8O2hBGZwDNI0Tj6307i
         YBIi/GBE/gjuH0ek5Z+WeMuNfmoKvNUvcb1BVjnPhWAEtCT5tGa72nSgpNDJ63hZGPQk
         GzKmcyfKCyysoP/jgezjLVmhD8g8mDl8Vt2spLhvxycous82QdiJ5fsLLj3KQjJelGPZ
         9WGF4fOSnNss/JSudvLXcfPzzXDHSAxHjFc2V/9wPTh9VvE2Kyaa8WYU97TBgevMGHsc
         lfbfw4kAvQbfjX6xBY+fwwizewLw7y+WZWDSqXFXJxeuOTcn1oYTWwid4A/YWrJC2ip5
         4NtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=CLGd13lhYfWfAhvmSqFdtDE5cn4GzYG8Cvag4mR5zac=;
        b=D6kzU7Z+ZMj8npSGlHrV5tVDW7rYqPTW34N2cGt4siKSedbifOmdo2UlaCgEWCFNBz
         bKHtvlZkU3FonoHuQyZBmpJUQ9y8r+apU59UQA2bZ7cbJMQKJ84Ip9ILE6F6vJZs3QJV
         ziZ0T2UY9brZEvv77W1o2Eb12js1vWUQW+giYdK0/mQwhCyzVrHTJvCGp+AUqz1zPRZy
         cdWoFQl66LKKNfL8Lou8guKoQSfVvauYngIh92j6HJ1mnQ0u91vJkHWH+8l51pL4Q4TJ
         84fI7LULWBuqi64OBosWhBbKcS3pP6W/lfBURsx9dB0mh4HK+l6PK2DT2rtO4P5RJfCm
         KUhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ed3Febyp;
       spf=pass (google.com: domain of 3ndybyaokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ndYBYAoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CLGd13lhYfWfAhvmSqFdtDE5cn4GzYG8Cvag4mR5zac=;
        b=tQ/ZoYOS1be71XCizt9L47eBgwfZ6aOfd88ZLW6YJkyDUa9dD4D4kkAFpEwfaZ9urB
         tr2i+nvzKxnwQgtBJE9jCRN/Yza14uDZnPq7vhV+nhxNyZoqd7Q36wxlHMMyAyRb78z5
         1eSpdTUAwrLo+MMN3OjlSWdsFo8+s+lhEGerYXhnxooOufQdU/PNd05cXWpZO4okSd9g
         eiBFy1gTl1STuIZH9wjg33/XcWyL58ByFWy3y0BNHspW8cYbzCloU756Lr83WQJVSCX8
         ru+hE5QETZ2EEliD0N3CAhoFR/Q7lJI/S3o8bJXpvV6hL6uFB63gOyy9WFTfKWvBktCp
         00Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CLGd13lhYfWfAhvmSqFdtDE5cn4GzYG8Cvag4mR5zac=;
        b=p1zMKkhagBybsOEI0fhG30DHthDiNa/OeobugmbB5EretBbUkjbXUXSi3BmUqHK0+q
         +ZxZIHRs3zqvIzj2BsCBNtTTXs8cqidfjNaEZTIaouVS/mn6KTvy9hklVcTo6DIHU8Qv
         U1CSlBjvPG8fbvV4UdBgwBoFKSepvdXEO1w993aFn33ECnvi1lDaEg8CGC+JbmYqy/bR
         HeFPUEXpBMWDhlgfDPGEvcJakPxPBmnTwwXFzjWGnU4KnAAbf8e8c9vTBCIRE8fSRUWK
         Grz4kW1oSWsLjxiAuhBEwrwEau9JABL4nEJZTMVVdo9SwtLv6H6mNipa/JLwjYAVzlTO
         yBcw==
X-Gm-Message-State: AOAM532JRSeIz0dG5PyObnwPJUABvkuKOvZQzpMpaZt3+wGpYD13ZevQ
	OMwlxiXVAdL/dJdYZ+IMl6s=
X-Google-Smtp-Source: ABdhPJyHRJOLPVG+cNs7J1JuWi4LJtwqJceUM32QmShm8NQZNmV1VJI7xtZ3ORRj6/1SBjtysolbTQ==
X-Received: by 2002:ac2:4463:: with SMTP id y3mr6121905lfl.94.1610733215294;
        Fri, 15 Jan 2021 09:53:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7806:: with SMTP id t6ls1703011ljc.8.gmail; Fri, 15 Jan
 2021 09:53:34 -0800 (PST)
X-Received: by 2002:a2e:6c03:: with SMTP id h3mr5974586ljc.360.1610733214407;
        Fri, 15 Jan 2021 09:53:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733214; cv=none;
        d=google.com; s=arc-20160816;
        b=UYOzsvyalHECS1QfSTVp50+yzw0BE28Z9PdvWkazFrFbQDlt1nS/k0uP5Bq7bwAOlq
         AsfRgkq93aqqp1o+RH89TSLrUemZBWGXPLYGU/A8G2XVGaJV8Zjw+sVxLZ4Ad91ku18B
         P6Yx86hjDZB/x+mkDfWw1KIVH2jviLG5+tuc9gnLTE/m69owlzaF7gjphpVl0wdCQqVi
         jciRNWny52m1gnFEBwmsyRRxxTZ83VqXldpuoExPjsHT77HgLdO+HAQibedRTL69qe2W
         k17ImjYhHCOf5/0qoBNal8NMYiqfJ7pm7z1KqE1hdbfgfCQJNRoFQCE+4PzX63fAVgtL
         itMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=KKvTna9pOG94VdqPVmZRxWtkege1Cyuqg2hRO1ClK+0=;
        b=VeErMvLEumEXO8Edpm3GinDtG4gz35YzRvcomJkxke4RUeDRtCGwHcLvCvI0JaXxP8
         psITuY5IzCZGois1hPgTJ+vqN4NzD/40S2fkhmPKCb3dn91CRz0kr81x1zQbvKEpDgiv
         WduOmXrEC/dlqKk6sgKCgz/LaEfzkB2o0zWMG3lKj8x94jCiolVwbcAuqdUnaxRQ8EOP
         JNDzqg6uqwFTsj9nmAHd17boasDtnhIoNqfBPXEeYLa5JgniegShBhgxZZAbbozowvVP
         +h8iZutpcQmkfdLHI2YdEaLFu/KhuRMYTWYE2xAC8RuASRWxxY2NgouIU8yBxoUUqacQ
         A/vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ed3Febyp;
       spf=pass (google.com: domain of 3ndybyaokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ndYBYAoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id e8si504232ljo.5.2021.01.15.09.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ndybyaokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id o12so4424612wrq.13
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:34 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:11c1:: with SMTP id
 i1mr14588719wrx.16.1610733213887; Fri, 15 Jan 2021 09:53:33 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:51 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <418122ebe4600771ac81e9ca6eab6740cf8dcfa1.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 14/15] kasan: add a test for kmem_cache_alloc/free_bulk
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
 header.i=@google.com header.s=20161025 header.b=ed3Febyp;       spf=pass
 (google.com: domain of 3ndybyaokcvg0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ndYBYAoKCVg0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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

Add a test for kmem_cache_alloc/free_bulk to make sure there are no
false-positives when these functions are used.

Link: https://linux-review.googlesource.com/id/I2a8bf797aecf81baeac61380c567308f319e263d
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 38 +++++++++++++++++++++++++++++++++-----
 1 file changed, 33 insertions(+), 5 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ab22a653762e..4ba7461210fd 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -479,10 +479,11 @@ static void kmem_cache_oob(struct kunit *test)
 {
 	char *p;
 	size_t size = 200;
-	struct kmem_cache *cache = kmem_cache_create("test_cache",
-						size, 0,
-						0, NULL);
+	struct kmem_cache *cache;
+
+	cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
 	p = kmem_cache_alloc(cache, GFP_KERNEL);
 	if (!p) {
 		kunit_err(test, "Allocation failed: %s\n", __func__);
@@ -491,11 +492,12 @@ static void kmem_cache_oob(struct kunit *test)
 	}
 
 	KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
+
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
 }
 
-static void memcg_accounted_kmem_cache(struct kunit *test)
+static void kmem_cache_accounted(struct kunit *test)
 {
 	int i;
 	char *p;
@@ -522,6 +524,31 @@ static void memcg_accounted_kmem_cache(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void kmem_cache_bulk(struct kunit *test)
+{
+	struct kmem_cache *cache;
+	size_t size = 200;
+	char *p[10];
+	bool ret;
+	int i;
+
+	cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	ret = kmem_cache_alloc_bulk(cache, GFP_KERNEL, ARRAY_SIZE(p), (void **)&p);
+	if (!ret) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	for (i = 0; i < ARRAY_SIZE(p); i++)
+		p[i][0] = p[i][size - 1] = 42;
+
+	kmem_cache_free_bulk(cache, ARRAY_SIZE(p), (void **)&p);
+	kmem_cache_destroy(cache);
+}
+
 static char global_array[10];
 
 static void kasan_global_oob(struct kunit *test)
@@ -961,7 +988,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kfree_via_page),
 	KUNIT_CASE(kfree_via_phys),
 	KUNIT_CASE(kmem_cache_oob),
-	KUNIT_CASE(memcg_accounted_kmem_cache),
+	KUNIT_CASE(kmem_cache_accounted),
+	KUNIT_CASE(kmem_cache_bulk),
 	KUNIT_CASE(kasan_global_oob),
 	KUNIT_CASE(kasan_stack_oob),
 	KUNIT_CASE(kasan_alloca_oob_left),
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/418122ebe4600771ac81e9ca6eab6740cf8dcfa1.1610733117.git.andreyknvl%40google.com.
