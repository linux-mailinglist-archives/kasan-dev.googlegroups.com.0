Return-Path: <kasan-dev+bncBAABBPG4ZSMQMGQELOMZF6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id C113F5ECA82
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 19:09:16 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id d5-20020a05600c34c500b003b4fb42ccdesf8871425wmq.8
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:09:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664298556; cv=pass;
        d=google.com; s=arc-20160816;
        b=nxRH2sv6RaT+S5R79VsjGFIxSzMBdbtkwVmMYVSD4gRBza/cok91dhk2wOLsTTPmqP
         5OMKkalREflvbVc2m6UvjLEa8JVOZ4pQWa/9pWJUT8A/4HxFlk947VRy9nsx7MmxrNsh
         ZSUGkm49StpZr6tEGvjLXRV8NZ0dkH2+s/XzPWeVRXyxdogOtbEecMchY8b1EHp4DYJI
         v4hyHelB3B2EyLFSSEWEZ2oKfRSBMeoNUtRVy4jjI/Ywhgxwr1SaQJUF4MqjOzrwxpBq
         9VIYQqczXiREoBJBMzHX0W8KEQq26OhW5PqpEU+salHUwosqxoVC9fum5J/E8gtg7pU7
         cJXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=L6nG08/yJZ2k137GWM9zHK4e+c4AAlTQyDUqSiY/Rsw=;
        b=Wi2rpT1zsRyEhLvs4xeMWH/ZKHoxPPhT+iHDnjOFyqSx/qFLW62w5Sfg14vdfYgE7H
         kntF8TIEy7gx4tIs8o3X4nAcy2Tyu5n01nVMx3Q9V6bIFxKldD7G88GsUIEXEAbpuQ1A
         cdJc/aMV7DT5mpZsQlAsAfWdurIoGU+OWR5WKHY90hsXEQJiyV8/iKR8yvyPjHwrEXuB
         6TLqj0cKAj06rFsfeo24GbWGT8ZNHqeS7nE71oCCQ1z6x1T/mzNBMUynmoDqf3H5Bbzr
         zH5kc8AufiCiKRKDNeQYxYDOF7ZaEG5dytYeYb7mz9TriCG+aXXD7zPk9AqVhopfzfCG
         NX1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ytygl79e;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=L6nG08/yJZ2k137GWM9zHK4e+c4AAlTQyDUqSiY/Rsw=;
        b=tsBxMiY59c49GYUbuBjAvt+5nFan9PC4z/eJAdVvAupIBs+xyMhbzrX9IqJIgrwwcP
         sYF8ugK5BWKLDTtMZ2DeSfAf3ONwfzKvGpBsSRWOYdM5tin4Shj2W5TaeG1xHLSuxVwa
         HBndmN7iGmu5Sjob0WD/HFSfn08jQ6BXiGSnKmEYLsg5CCOONeWamdtOj9rn8tNXgzXY
         rjC7xbBI54AAOIvDeDn0eTZ18jzIrEwtd5Bg/zpTf8b16VQVEvmNSxGPi7yPHFAchflE
         tyuJjgkr7hA1zU3U9jbuX4F2yXhj86pqjsXF3SejIsHPovVyx+mHRY7gKT6UrzFw1zAR
         1mSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=L6nG08/yJZ2k137GWM9zHK4e+c4AAlTQyDUqSiY/Rsw=;
        b=KzyzmuNXI7mwBaDXp8to3eTqD9LTAcAosp8gnAl5oV1L4KB3yffIZjH4kTryvwmJqa
         XOszqmDX0b3HB29YQicVhbcHvxq0AhZdhBz1JZpnS1cX8PzdrA6KG36N5QO6S1iEIBmq
         7NUCAcTbd/PXCm0wlBQOaIDh2jsLcC6Bn0F7LzsubDvdFFZuyJ5f1GykTHyel9+DhsfW
         Mke51vyxQGKHkFbaR5I3qo8uhZbje0C8rFjY+dgfDKkoQjwMgN7ZaBEf1OSTRUQOiE3U
         C4k6LRrnTvTzoSjQwKNDSzM3ggKhi4DY5/cXilxLomnYABnOD7oX2hNhbaLRSgIWWDZz
         mMaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2Q5xVPrbAYY9/vsZULwH1+eL1jS/oyAbx8d8MbO4g8OpLTFMrt
	u8njADXsjhuNCUGaIlnEclU=
X-Google-Smtp-Source: AMsMyM5LeR8JPzOC7ZgY9OtiGqt+lBG58fL5RscLlJxdN0oUFP8TmeJ8VNYK+6UBOX1H7F2EIQJBYg==
X-Received: by 2002:a5d:64a1:0:b0:228:46e1:285d with SMTP id m1-20020a5d64a1000000b0022846e1285dmr17556942wrp.64.1664298556339;
        Tue, 27 Sep 2022 10:09:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7c12:0:b0:3a5:2d3d:d97a with SMTP id x18-20020a1c7c12000000b003a52d3dd97als1074180wmc.3.-pod-prod-gmail;
 Tue, 27 Sep 2022 10:09:15 -0700 (PDT)
X-Received: by 2002:a05:600c:358f:b0:3b4:a699:3121 with SMTP id p15-20020a05600c358f00b003b4a6993121mr3576144wmq.166.1664298555571;
        Tue, 27 Sep 2022 10:09:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664298555; cv=none;
        d=google.com; s=arc-20160816;
        b=gXufDzvMBDCVRsWCqclrwbxweuZQpW3bveBGK4dl9MJETPJhfXhSSNODIUPeOxbsgG
         sO2cYWqaYI4vcNNc1ZUu0yY9Ak1tlYZzntcqtsA0AF1kj0BCGfxRR1q6v3deWRPwUBzR
         A+P7ZStn4utDKVp8xlLoZlaYVDW9s2gTE/52mtwfeY2YzDyEtDUf+2KaKSyt6saB88cK
         2NwIz6J7/9Ai7akEeafugO2CVsLKjZjEIed48FcuCSXj9CRlvUraQlThw5Q9HJ49dWgA
         sBhTCm1VBo/j9mJbGZIk1s8DaRrCJQ51fBG9hSTZxTD89jaFaG/zThLJ4qV1KQNXnkBv
         NNyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SM5jImXkTQ0dWpEX7zywQte5Om9P2FhlzYZkNaZtxVY=;
        b=useQCEsakW+pAc4ImpRWw9n4A57bqazvLwJxPGRNBTKB4+BFtSwsVpzyBeYsP85maJ
         WB4LAxbEdIfAv+gqO/EGtXKIUbZahy/VJKsPWoLiWrDciZIz8gTDtSJGKog8wk8lrvqi
         T8bVtu45Yi4r1LhBwvTNUgiACacE+B1i3ucLFmdtAfMWWKOj2p757r4mAjxKJKt5HjaW
         3zgui5ZFF90Itf9nlF8/CyOaM2LXIQDuxS44epsqftjbgc9SQYawEqZj4Vt+5l6ZDI8W
         1zYPaFqcy9fa+Yw7JiHEWl91JxWfsxK+ZJwCzfKaTvu8agJmByBQBM/RRwirv/ezCwIs
         1ZIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ytygl79e;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id n3-20020a1c2703000000b003a66dd18895si117993wmn.4.2022.09.27.10.09.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 10:09:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v2 2/3] kasan: migrate kasan_rcu_uaf test to kunit
Date: Tue, 27 Sep 2022 19:09:10 +0200
Message-Id: <897ee08d6cd0ba7e8a4fbfd9d8502823a2f922e6.1664298455.git.andreyknvl@google.com>
In-Reply-To: <9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl@google.com>
References: <9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ytygl79e;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/897ee08d6cd0ba7e8a4fbfd9d8502823a2f922e6.1664298455.git.andreyknvl%40google.com.
