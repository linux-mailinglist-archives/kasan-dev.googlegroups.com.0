Return-Path: <kasan-dev+bncBAABBF57XONAMGQEVDAKL7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 34F2160316A
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 19:17:12 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id l18-20020a056402255200b0045d2674d1a0sf9533380edb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 10:17:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666113431; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bi7XCWSuPQcruIAFX7JQ06uMzqKlXRnLVdFirpi4rTPe+LqOJsNl8z8XSewNdS775n
         igdYNqIDeXK/jRG7vvTXpIqUKwy5ldr8EECb1axG/3xRiGijq8ZS+H89uexO3Pjz+u+h
         fRd8Uqxf0iF6+AlhVeaFN3ROKAoxBd3p0Pc91rmMG+vQiEa1WFGHTBbUcepYasNqiuYi
         pd+UoUDuOtIAwXwutK16jPB4C2QVQjWydnW7fsYBC/PM089GXdMJuuRW8Iy5oCfHn7aP
         NKrBRQdmEyyLpUhkOl+WRC8QqU5rztPtYY537NCSBuNsruo7HYG64pkZKCLTr4lll4TT
         nCVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=v5zsG3+PK8lwBywkRJlUZCJEncq9OLp1/3pSBVG/XFY=;
        b=YloKeov14Fo/jczUOY4EpBzz/m8VTNl37W8BTY/wrwsc52HKQxksAT3BNW706QF/oW
         5NpRO3YkeX1CE6s2nPhKnmjqEjxR0qgDjeDNJHfbk7DHz6UZk7i8TIdF/6U2SU9rkZ6t
         wiN1eR/gEGl6TP1of2URn4hj0Zy2AkDhmOwWtOoi+xOGMriNwI+Nn3W1qPJI9TKqWcuD
         FOeXx1JqmmC0JLnikrrD5zNIbmdeDBYICpFyclweF/x4nUCxAwRffxuCjy/LT6gl3hQ4
         tpNLleXfeI+93jv6fG7kdMFB4sMkhU73hJmsDSddbIxS4O6P0ctLbYBEghXAM0dB1jkI
         ULGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iQpOwSCL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v5zsG3+PK8lwBywkRJlUZCJEncq9OLp1/3pSBVG/XFY=;
        b=o1ZGsLRS2sP7V0ZG4OQ7SuB8Aq02sBUA8khpYU0U9eeTvZbr5fHkfo4+DCdmShkhie
         4fJxsljxtIeIdv10Zw4wJTuEfoXH95nMNX8sDMe4HjjBa1EDqcWLBLEOnVlNvfbjRT45
         6Bj1bvIOMYrq7BB7MFats0sU+EjvuhbuHLum1M0ESCYVPjvKDfjsxU4lpR58w3x9QqSf
         7WF/zGq4f4H1OofHtawjhJQ7oFbRDcDOFpEiDWs5G68i08lEb1iqGrVboDhosDmTKObB
         r1FTV8sqlaqzAXTn8pqjth5tZiqs2cEOHjClNNAEILFi00udtKdztrQPlSIUvk3Spwnp
         +BKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v5zsG3+PK8lwBywkRJlUZCJEncq9OLp1/3pSBVG/XFY=;
        b=rg3X6oN/3masKR1GZM+cr6jREKg8iW0jBAnHooru0JX81BkCs1zkWjoCV53Boszjdq
         geoNW7k5gCd6RIQttl3ErSAhkxEDYjLu5rx6ufY3WbsbofoUTn7uAJ3FIs5sha8/Zjy7
         mAkZwxmiUd9tJZE0MxJ1kjBwYsX1dePK1yl93+hiFlGnO7vQbd4SOop0rn28q8DvSzEb
         OLi12uvbdiowktucfXd+hgGkeL7ck7xFT70iR+drj3BxoURjw8t3G1KWjvlyISybyL6u
         BsvD9VN1WK0UDkFsko2Qzg1FPLxOcYlLUyq/TUENtTJT46etDg9N5Ve9stsEQsaHHJ+k
         ZWAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1rQB2vxnCAmKks/pVioA3yPBiT2F5q03qkmjAJTMc51vep1rhf
	VG4x2pvXKRdiFs8u95Jpc04=
X-Google-Smtp-Source: AMsMyM4lokVGESaTz2PLAkV2Ie3+AojinZWRP3GkGAiHUl5OIUTlZKWjZtKJmEijD3jTPrLVsA2/6g==
X-Received: by 2002:a17:907:7b95:b0:72f:9c64:4061 with SMTP id ne21-20020a1709077b9500b0072f9c644061mr3311171ejc.351.1666113431687;
        Tue, 18 Oct 2022 10:17:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:430c:b0:457:99eb:cba9 with SMTP id
 m12-20020a056402430c00b0045799ebcba9ls2968697edc.0.-pod-prod-gmail; Tue, 18
 Oct 2022 10:17:10 -0700 (PDT)
X-Received: by 2002:a05:6402:b3c:b0:458:f680:6ab8 with SMTP id bo28-20020a0564020b3c00b00458f6806ab8mr3697985edb.267.1666113430883;
        Tue, 18 Oct 2022 10:17:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666113430; cv=none;
        d=google.com; s=arc-20160816;
        b=Spqk3U5XJw86qsWddmQ5vXUhm6vZzZGeySXB7//tcc3Psbmao9+eb+dGPNzIK/uw5s
         1ye8ssuYG7MmV2UwwRI9U+kKeVEcjBs3FRY7Xbo51ZhcBFaFj6impxse4cmZBEoi+9zi
         NM34UGUfDlSWWqkbMWwPRNfs4y7N6q71d9tikNFxVE8o3HAoBdljWQq8+nsWzgnPlDae
         bQH5wHrc/K8r8KFbEcdJ/8g6oQLaGYiDz21ulCTDgWygrFFY7xGYgWLSDBfyvfaOHSQK
         gumP4enMChMlFyO/NA97BgcpHfXlptc+UslB/8sjpuMmWXajRPLDeazvMyq+fr+hr6fx
         cskQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7sMEqDPOnA0B1xo/BBovBSGH55UI1F4ZzoT+c6nAvV4=;
        b=lcueT8yM6+Az3UaKWfKos6U+pmtrE4iycN+uBerRcEa7xKkJgbPBeu//dg1njG8sF7
         zcio9cZ34yXSflPCuUSR2SOxn1dEn3L1BmcN8nCW0jxQwsffJU7LzQD3pOHLC6/9RpvH
         0PW+Omt9b5g78s7oCWQjqO5N3pdyk2D00526fRu/nQ1tNSI692YuN1FHRSXxaKLl51l+
         yC5e1VdivQ3jpyDWsrt14PidtydagXgWM3WV1UUj2c9u1/QCFswO892a10BL85yAYbwI
         Q13jaholWUxMWAg/wJ2GdAUFMHUJDZughkl+6IlVCrj1faOSZUtKErjfPzfFhhhG0YHf
         GS3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iQpOwSCL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id j11-20020aa7c40b000000b0045bcf2bacbasi485207edq.2.2022.10.18.10.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Oct 2022 10:17:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 3/3] kasan: migrate workqueue_uaf test to kunit
Date: Tue, 18 Oct 2022 19:17:06 +0200
Message-Id: <3a28fa0c89771e47418fb2d5f0e009c83aec5eba.1666113393.git.andreyknvl@google.com>
In-Reply-To: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iQpOwSCL;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Migrate the workqueue_uaf test to the KUnit framework.

Initially, this test was intended to check that Generic KASAN prints
auxiliary stack traces for workqueues. Nevertheless, the test is enabled
for all modes to make that KASAN reports bad accesses in the tested
scenario.

The presence of auxiliary stack traces for the Generic mode needs to be
inspected manually.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changed v2->v3:
- Rebased onto 6.1-rc1
---
 mm/kasan/kasan_test.c        | 40 +++++++++++++++++++++++++++++-------
 mm/kasan/kasan_test_module.c | 30 ---------------------------
 2 files changed, 33 insertions(+), 37 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 38bf6ed61cb8..e27591ef2777 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1141,6 +1141,14 @@ static void kmalloc_double_kzfree(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
 }
 
+/*
+ * The two tests below check that Generic KASAN prints auxiliary stack traces
+ * for RCU callbacks and workqueues. The reports need to be inspected manually.
+ *
+ * These tests are still enabled for other KASAN modes to make sure that all
+ * modes report bad accesses in tested scenarios.
+ */
+
 static struct kasan_rcu_info {
 	int i;
 	struct rcu_head rcu;
@@ -1155,13 +1163,6 @@ static void rcu_uaf_reclaim(struct rcu_head *rp)
 	((volatile struct kasan_rcu_info *)fp)->i;
 }
 
-/*
- * Check that Generic KASAN prints auxiliary stack traces for RCU callbacks.
- * The report needs to be inspected manually.
- *
- * This test is still enabled for other KASAN modes to make sure that all modes
- * report bad accesses in tested scenarios.
- */
 static void rcu_uaf(struct kunit *test)
 {
 	struct kasan_rcu_info *ptr;
@@ -1177,6 +1178,30 @@ static void rcu_uaf(struct kunit *test)
 		rcu_barrier());
 }
 
+static void workqueue_uaf_work(struct work_struct *work)
+{
+	kfree(work);
+}
+
+static void workqueue_uaf(struct kunit *test)
+{
+	struct workqueue_struct *workqueue;
+	struct work_struct *work;
+
+	workqueue = create_workqueue("kasan_workqueue_test");
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, workqueue);
+
+	work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, work);
+
+	INIT_WORK(work, workqueue_uaf_work);
+	queue_work(workqueue, work);
+	destroy_workqueue(workqueue);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		((volatile struct work_struct *)work)->data);
+}
+
 static void vmalloc_helpers_tags(struct kunit *test)
 {
 	void *ptr;
@@ -1509,6 +1534,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_bitops_tags),
 	KUNIT_CASE(kmalloc_double_kzfree),
 	KUNIT_CASE(rcu_uaf),
+	KUNIT_CASE(workqueue_uaf),
 	KUNIT_CASE(vmalloc_helpers_tags),
 	KUNIT_CASE(vmalloc_oob),
 	KUNIT_CASE(vmap_tags),
diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
index 4688cbcd722d..7be7bed456ef 100644
--- a/mm/kasan/kasan_test_module.c
+++ b/mm/kasan/kasan_test_module.c
@@ -62,35 +62,6 @@ static noinline void __init copy_user_test(void)
 	kfree(kmem);
 }
 
-static noinline void __init kasan_workqueue_work(struct work_struct *work)
-{
-	kfree(work);
-}
-
-static noinline void __init kasan_workqueue_uaf(void)
-{
-	struct workqueue_struct *workqueue;
-	struct work_struct *work;
-
-	workqueue = create_workqueue("kasan_wq_test");
-	if (!workqueue) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-	work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
-	if (!work) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	INIT_WORK(work, kasan_workqueue_work);
-	queue_work(workqueue, work);
-	destroy_workqueue(workqueue);
-
-	pr_info("use-after-free on workqueue\n");
-	((volatile struct work_struct *)work)->data;
-}
-
 static int __init test_kasan_module_init(void)
 {
 	/*
@@ -101,7 +72,6 @@ static int __init test_kasan_module_init(void)
 	bool multishot = kasan_save_enable_multi_shot();
 
 	copy_user_test();
-	kasan_workqueue_uaf();
 
 	kasan_restore_multi_shot(multishot);
 	return -EAGAIN;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3a28fa0c89771e47418fb2d5f0e009c83aec5eba.1666113393.git.andreyknvl%40google.com.
