Return-Path: <kasan-dev+bncBAABBPO4ZSMQMGQET33CROI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 40E615ECA83
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 19:09:18 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id h23-20020a197017000000b004977813cd43sf3778078lfc.4
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:09:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664298557; cv=pass;
        d=google.com; s=arc-20160816;
        b=RTRS0PxTpRmo74T1wXpheAL+spmmD2aBdRHGjJ9ucntErwbha4vCVzyu1pGC0jPnWP
         FiKKc+D3h+y+3I/llohuLwhavIhaM7vO5velr1zRIC1WlnH9e93TrBI3Pq1Hdaqh5FnG
         RGYSvsYO5t+71UiBjxOwSEZmfEJCwuWXF/pkSS4cqDZoJMCCHawSNmt/R95GddxVQCex
         /DkVZ/PsdtzakpaUk8T1kMQIig4JoBdBU+4E1LhOaIizSVlyEagYQcw4562PDRN6h7Y5
         5Jf+LmerPNQLIW6gc0iXC9ImGLpJMbvlur3QoNOGMgnbzpyNogWT/KkmVFHDoN1vvklE
         D8lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=L5uQOmBv7K/XqUQbTKRf0lYEYTppGn9K90y+1mUMflE=;
        b=1DylIGt3UqCHqjuyIKyxRsLEwuR7YW2+CICYN4rRSp9YVeMajETHqdT1zctRJVLEmQ
         Kp2fveHN01Z/jfgXoZUar4uCw5LQL3gEC4WRabK1dKhRm7jOsrZxZ2m09INPf93aAbIv
         1iwiuU9J1t7AEkr4HlVSeEksLjhSMLyYGTgOBKP//QbYSYJyj4FNoV1C02sU6NrGXGh+
         wwBjqHT4KpZcxC9Pjkzg2YbeV+HTmyh9cKSiVnpUvk5sErIN+PAYEqDabhpGnAw5eDp9
         fRwatrqZT8fStasFh7Gcd9wG/GdJKM7uCsv6h6+PO0ldnNjm7FzXGXcAzfzDUcDaswCj
         VKwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eFRsiTEb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=L5uQOmBv7K/XqUQbTKRf0lYEYTppGn9K90y+1mUMflE=;
        b=obCbCaasx//8OsFT1qTTUIobYAsWjjyjSKtcr7JCzP4zZ9zueVikWzdfIen44gi6Wo
         Kj70DHir7ocBDAPFfAZQX9in/BDH8KyTLJppMeI8R3Kwkex88+TageCjncIMsxpzQWm1
         4gTTrSGIRs8JOwDP/TvpBN6LxoK6hAP0KWTFeXRIaOb/y2zby9DxDDPqukSf6ZSb0Gyi
         y24/8jzEpENcAakwqBDvZK0D5P088vvTOE6i6/mCdfNIxUEs8t+HBT177D3UHxh/6lBQ
         I3HFg1SXIUkQN4dqhc5fiwzzXRRIVovMiXv8DhXV3CmAxBP8Iy2u/pJAu0lN7QU+NdfN
         vF6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=L5uQOmBv7K/XqUQbTKRf0lYEYTppGn9K90y+1mUMflE=;
        b=K8dvJjRMmrXIC4u3o4ELmmzNMM0CVUOhG61Y6xr7QZdPMlsA6ASH66r3PPneApfezU
         fO2bSfzQ2Kmb4yjf1f5w8+slJHK0YQRK7++TBWCgP500x5pyn/GJvz+GMXCF9crP2DjW
         Vw5bHiGVqCECvJTiSTnMvegpS4MVSBAKmjLZxjfuSSKgeM2f85xO5rFa6sfPpBpIltrs
         KJ45Haav3dfThOJDPsCvnbGseFxp7ViTlWCZg1H70E+Wl94Fr+e7fG3+iPGyxNOUw0Ye
         tjomjb1s6h+8w7FWLe0n1t4YyJwqwUbSY7LBhBZv07E/n2v0N/R7H+sTP+4BLsHyJUOD
         qs4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2APC1Oe/MFnIabZxNUDAUYJnEx9VlWgoeytOVYFAibFvP2xJ3R
	LuwZ041PF0AXmPKiU9q6AoM=
X-Google-Smtp-Source: AMsMyM6jiJwXCGksa8UE/v5ls47Ro77+aKhBVJtYPO95lHRlLIwOoF4UqgD92Ncoy5pAexQCYGAPiA==
X-Received: by 2002:ac2:4422:0:b0:49f:5c95:9525 with SMTP id w2-20020ac24422000000b0049f5c959525mr12249220lfl.1.1664298557688;
        Tue, 27 Sep 2022 10:09:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:532d:0:b0:494:6c7d:cf65 with SMTP id f13-20020ac2532d000000b004946c7dcf65ls1347159lfh.2.-pod-prod-gmail;
 Tue, 27 Sep 2022 10:09:16 -0700 (PDT)
X-Received: by 2002:a19:911c:0:b0:497:9d9e:c2a2 with SMTP id t28-20020a19911c000000b004979d9ec2a2mr11748565lfd.458.1664298556849;
        Tue, 27 Sep 2022 10:09:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664298556; cv=none;
        d=google.com; s=arc-20160816;
        b=x3FjnHfE/E2kG/Orq1OSpFXDF+dgI4pZeQsdA2EgCESfbdm/WeCZIe8r6BmW4h5C6I
         HwQQlaQlRq6buQ+H2yPyA8Wdg9BNUB2T4ih/SI4gwlsP0M0D2iohNKb3VhwvGY8e7wMj
         3mTK6qrWy296E5t7K7xtYlxlRzpbLn4M66RFdkdnR56ljriLTJD0l1XVKIsqJ2OTxnxa
         qm0YXgYQHDMXVC3wzm4XRxK2s/gtrVMRRu9Mk6ixoaYUcMJ+Xday4mjR+FnWPac7igOi
         YQsx7UCmJJ53TeTSaEwOmMwltCqtsVh0aKapWEi5l+Oq20HEqJqpMYH6R63R7sZ9c0hx
         KbKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R2fGkx5wPZy+xk3vesvKnmgkl9l2oY+h5lye3VG93Jo=;
        b=naIR+whzq3yo9T0M7Xnih9IBl47xdgqfnbfZXsrZTLZWgb7VMS+81WXktMnUde7Eud
         Q+YFatfCDPdzh4iPE+HFmCkeCBptUHBAi4RC4xXYq9tTEC3G4b1SozOeB8obGNFRIHUo
         dxG8rp/5hoovhh+ozFmyXV/r7nHPjq3iSyY3PlKFMUpWMWyWol2chIgSlRK4HX+q5pbG
         FK3RBwtsbEX2c7yLL3NEQFRKZAsmVraTfnX+WCh/BIIVmLLgrTBuNNCM9OES8Fzs/z4g
         68Bv41m2OoLx74FjY0aDYWBLKIcYgyu8SIiWSkICixG/wHw4pSIeadHd9qRf0RD+24Ph
         qXgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eFRsiTEb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id a26-20020ac25e7a000000b00498fd423cbdsi95847lfr.7.2022.09.27.10.09.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 10:09:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 3/3] kasan: migrate workqueue_uaf test to kunit
Date: Tue, 27 Sep 2022 19:09:11 +0200
Message-Id: <1d81b6cc2a58985126283d1e0de8e663716dd930.1664298455.git.andreyknvl@google.com>
In-Reply-To: <9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl@google.com>
References: <9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eFRsiTEb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
 mm/kasan/kasan_test.c        | 40 +++++++++++++++++++++++++++++-------
 mm/kasan/kasan_test_module.c | 30 ---------------------------
 2 files changed, 33 insertions(+), 37 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 005776325e20..71cb402c404f 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1134,6 +1134,14 @@ static void kmalloc_double_kzfree(struct kunit *test)
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
@@ -1148,13 +1156,6 @@ static void rcu_uaf_reclaim(struct rcu_head *rp)
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
@@ -1170,6 +1171,30 @@ static void rcu_uaf(struct kunit *test)
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
@@ -1502,6 +1527,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d81b6cc2a58985126283d1e0de8e663716dd930.1664298455.git.andreyknvl%40google.com.
