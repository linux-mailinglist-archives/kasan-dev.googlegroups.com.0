Return-Path: <kasan-dev+bncBAABBPU2XWMQMGQENXCBYVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 28A025E8F58
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 20:32:31 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id h133-20020a1c218b000000b003b3263d477esf1808047wmh.8
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 11:32:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664044350; cv=pass;
        d=google.com; s=arc-20160816;
        b=csW6yr25R+hSdZ8W6WG4RxFS75BA1T7JWJW7+3uVU9uv9+QpaD+GyQGup6jZW4+Vts
         aHCY5xh/wn2NV5q1bSen6FVQA1yRJJiS1C0wY7cudAurqNEY7zy6WDFf/Nv9Ln3JzjPt
         VWG05eN0yBVDbfEDrgZsDXYCDQIUvm3E/H7yRlF6kiDue89G+Jttsl9ompQKfVRkMdXe
         Srl5Yw1ZoRPUdWzk53UbqUYNnYQS77wMHKTdnyZMMe9RWmfiqe9/NBQH1hCEQVPY3Tm0
         YoDghZLmr/8fUGa1I6QPyH6eWxTBiG/NRIbJHe3sdO7uhqoe3SDaNBI8fNmZu06ImQXz
         2AFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OSaOtcshm7SZVLoFMUXsQGGQPZSORBOUeNW+htc/pCU=;
        b=ZfISKbdhSryUGUIJdhuNxzHVQ519uCNRmgZJQF17gQMVVrsqcHq3O0KgKxgGOX6lF3
         6VH3Z0bCfcXXmZ76SsE9iNd1RkX2WeuolT3BcwTH86zP5u5Zryc4WO0b9fa7oyhO6XuA
         ky6edcpWNdgwKmZ3Dho5EbYvoV/ypD2/8g8+2rBpNaqOUNUTo0itdKDlPrguzJBHTfsE
         F8jrIg57oe4WXsMQpXE6iksmwO95xAi1C4zZADBHeEO9GakyRd8YRmWg2KCUWeu0Bfva
         6RHw/4LD1b2o8KhvGykD1oApDwJxB3KNEslOWORu7ObMeuornO79orzjzZ6gW7Omuvl2
         3RGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="wm4LrK/u";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=OSaOtcshm7SZVLoFMUXsQGGQPZSORBOUeNW+htc/pCU=;
        b=e1Zmf1kxbfNO08TVLD+WFvcgRyqcFAN/Q7yP6w+7sX+DoeohqrtizfIu720MP8FM8t
         8B4gF5ctgjJs77eiFLj9UMiRkbR9D2zkNUdF3o/0YegW/LBQ911fMPH1Q5sgparof76K
         mYnasx+JbK2Lh5Pmap3G6HIWt3PpXFbIvo5iyNmsdrut20JI28flAfX4ly3V1pGyOFt1
         cXkTU9XdvpY5eNQAbjGmErFPx7QYOH9JE+K06Yb09DMzlIaTG/GsFIJuqhs9opre1OZB
         d9JGQqgolsLKw/kaUVuVFPUMBWWZl7eEApV1K5THFn4dBOfAP2gCjxxkqR+2Sl4k7mWq
         plrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=OSaOtcshm7SZVLoFMUXsQGGQPZSORBOUeNW+htc/pCU=;
        b=XgkYdGEa55l/GhQfCmMkae5B9AwZpNwwmzIE+A4EDtN0SMsfD4ciFf2LE8nxwwzyqc
         CLXzOIZH7o8nhO+9h8Ed3rgGJgCLC41XySyYCB0Z1wm8ovvMQncOUqzoX/2fcOk38mLF
         3l3IW8fN8F2XszD8Ue5DhpTnLp9cIZFNO5FuOwQGJJfwVLXaa6yVVyaUgzDWkJ1PSFKp
         BSReodQ+HIGzEA3yFJpcBtZ9W7JJXDLzXqZY2hNJsVF1xNDLOxcdGqryR48Fy3d+WaIr
         Munv9yDFlpqrYldkAsWR+VxFN1t0KBEdVPys7AAmBHowLtT64JLRB4+982mIBXVjkMEg
         4TdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf08vQyQd8RDdukg5FoqQBoIZpTvvXuooqA9/a8+nU3xQB0iRbjG
	RckMiRLHHyrQGk3fYkkeJe4=
X-Google-Smtp-Source: AMsMyM6Xh/MN/l5lC3QXhYPoxzi6fKjdzOEIqbs5C39kWPHmvekQWK413paSnZ0BAQeymv9JZLoMHQ==
X-Received: by 2002:a05:600c:410d:b0:3b4:9454:f894 with SMTP id j13-20020a05600c410d00b003b49454f894mr16501706wmi.111.1664044350724;
        Sat, 24 Sep 2022 11:32:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f615:0:b0:3a6:6268:8eae with SMTP id w21-20020a1cf615000000b003a662688eaels6766909wmc.0.-pod-prod-gmail;
 Sat, 24 Sep 2022 11:32:30 -0700 (PDT)
X-Received: by 2002:a7b:c34c:0:b0:3b3:4067:d473 with SMTP id l12-20020a7bc34c000000b003b34067d473mr9772161wmj.52.1664044349990;
        Sat, 24 Sep 2022 11:32:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664044349; cv=none;
        d=google.com; s=arc-20160816;
        b=yRCajlgnecexsYb8hMra1uze6OyfiszXlK/B7WdYqZQg1KmJkFPDjaamPMSdAlTEMN
         ZJ6fFm54EppE0lKOZZGKfKozgDrtg3BeTuuENFuoY9buHJHyTGRNbihVOCbaSfZqhvWf
         OAMv3mMm+ZdiiJhQya+fBsuCfDrBCrTxBdrcFhQ4Mu/MDufmn8/mPqSvePEOy3hgB+Dy
         cuqNeDBGfqsOXUMiQNUOT7xJkRfn6Ov5zyqro6r8ex3IXw4CpCWnjwcKYrZiA1PRuS3e
         6TdF1914ZdHO8cbdLcKiLdXe1c2TrrrYEYnYbclc3guzqdxWsj+ILpIsxwXaW1x5kgKe
         Pprw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hSHn8pdWEz/EAWLe2z3ri8yOC1WGCkjx3I21+gYS0z4=;
        b=T1XInr7EVAjqzur1vAMguW7zDSilzk5MJfl52zcAikAr0eIxWkXyQNSZHXcsrlyeY1
         Lxcd6SRT+4M8pdXfYGhyv9TeT7mWcR8sNCSnZ2SseRh/B9hpm7ld9EsIQMr8mdaaL13p
         RIHlDUr5y7L6UP5yyeW/M9JWc5jyHV3nyB/WJGyEBBIhpKkLciDjluNgBcBbbpi3XWes
         slawk95JQ55U2YNSkuHhKNseWSV6vUQ9fgFayp+XTW+KxQLnYhffU379dc82fBAtGDtb
         YleVs40Hhf6ZsVSQ9yiJ3eoAl0WdvubvTt6jvFVELThELuoKOhIe07jm19BCKlH3G2um
         cuhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="wm4LrK/u";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id m25-20020a7bce19000000b003a83f11cec0si190709wmc.2.2022.09.24.11.32.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Sep 2022 11:32:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 2/3] kasan: migrate kasan_rcu_uaf test to kunit
Date: Sat, 24 Sep 2022 20:31:52 +0200
Message-Id: <bc3b1d29d8addd24738982c44b717fbbe6dff8e9.1664044241.git.andreyknvl@google.com>
In-Reply-To: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
References: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="wm4LrK/u";       spf=pass
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

Migrate the kasan_rcu_uaf test to the KUnit framework.

Changes to the implementation of the test:

- Call rcu_barrier() after call_rcu() to make that the RCU callbacks get
  triggered before the test is over.

- Cast pointer passed to rcu_dereference_protected as __rcu to get rid of
  the Sparse warning.

- Check that KASAN prints a report via KUNIT_EXPECT_KASAN_FAIL.

Initially, this test was intended to check that Generic KASAN prints
auxiliary stack traces for RCU objects. Nevertheless, the test is enabled
for all modes to make that KASAN reports bad accesses in RCU callbacks.

The presence of auxiliary stack traces for the Generic mode needs to be
inspected manually.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c        | 37 ++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan_test_module.c | 30 -----------------------------
 2 files changed, 37 insertions(+), 30 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 3a2886f85e69..005776325e20 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1134,6 +1134,42 @@ static void kmalloc_double_kzfree(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
 }
 
+static struct kasan_rcu_info {
+	int i;
+	struct rcu_head rcu;
+} *global_rcu_ptr;
+
+static void rcu_uaf_reclaim(struct rcu_head *rp)
+{
+	struct kasan_rcu_info *fp =
+		container_of(rp, struct kasan_rcu_info, rcu);
+
+	kfree(fp);
+	((volatile struct kasan_rcu_info *)fp)->i;
+}
+
+/*
+ * Check that Generic KASAN prints auxiliary stack traces for RCU callbacks.
+ * The report needs to be inspected manually.
+ *
+ * This test is still enabled for other KASAN modes to make sure that all modes
+ * report bad accesses in tested scenarios.
+ */
+static void rcu_uaf(struct kunit *test)
+{
+	struct kasan_rcu_info *ptr;
+
+	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	global_rcu_ptr = rcu_dereference_protected(
+				(struct kasan_rcu_info __rcu *)ptr, NULL);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
+		rcu_barrier());
+}
+
 static void vmalloc_helpers_tags(struct kunit *test)
 {
 	void *ptr;
@@ -1465,6 +1501,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_bitops_generic),
 	KUNIT_CASE(kasan_bitops_tags),
 	KUNIT_CASE(kmalloc_double_kzfree),
+	KUNIT_CASE(rcu_uaf),
 	KUNIT_CASE(vmalloc_helpers_tags),
 	KUNIT_CASE(vmalloc_oob),
 	KUNIT_CASE(vmap_tags),
diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
index e4ca82dc2c16..4688cbcd722d 100644
--- a/mm/kasan/kasan_test_module.c
+++ b/mm/kasan/kasan_test_module.c
@@ -62,35 +62,6 @@ static noinline void __init copy_user_test(void)
 	kfree(kmem);
 }
 
-static struct kasan_rcu_info {
-	int i;
-	struct rcu_head rcu;
-} *global_rcu_ptr;
-
-static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
-{
-	struct kasan_rcu_info *fp = container_of(rp,
-						struct kasan_rcu_info, rcu);
-
-	kfree(fp);
-	((volatile struct kasan_rcu_info *)fp)->i;
-}
-
-static noinline void __init kasan_rcu_uaf(void)
-{
-	struct kasan_rcu_info *ptr;
-
-	pr_info("use-after-free in kasan_rcu_reclaim\n");
-	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	global_rcu_ptr = rcu_dereference_protected(ptr, NULL);
-	call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
-}
-
 static noinline void __init kasan_workqueue_work(struct work_struct *work)
 {
 	kfree(work);
@@ -130,7 +101,6 @@ static int __init test_kasan_module_init(void)
 	bool multishot = kasan_save_enable_multi_shot();
 
 	copy_user_test();
-	kasan_rcu_uaf();
 	kasan_workqueue_uaf();
 
 	kasan_restore_multi_shot(multishot);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bc3b1d29d8addd24738982c44b717fbbe6dff8e9.1664044241.git.andreyknvl%40google.com.
