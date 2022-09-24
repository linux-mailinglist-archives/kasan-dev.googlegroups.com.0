Return-Path: <kasan-dev+bncBAABBP42XWMQMGQENKYVKVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A67D65E8F59
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 20:32:31 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id n32-20020a05600c3ba000b003b5054c71fasf4073181wms.9
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 11:32:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664044351; cv=pass;
        d=google.com; s=arc-20160816;
        b=vP8lJzOawBISi0oXxlaQalTgsTjFs0lJxJdmZeDziuBfnErvJTkBMQw1W2WD5s33eV
         8LDE6fWjUtLL+tDtUCMwpKKTxqTIm0XDBPLr5F+hZH6IQb8WaPnU3kpdYc6YGqwjaSE3
         ExYn3NzSLZslsfvN5GCCjU/YCvy16ptLxI9pCFC8FXtBhGdvQ+yRtGXd+uCbmC8zEAh9
         Hq9HhcufSr4Pc0OHR1nNwPsTFsYUUdpwLHS96VOjuAWiGphMeP5nLilCTFRgJhsDCAM3
         w8GiWvddfcSPNG8SnkZIA30+ysh+to6kjfd6CYoMKntHFw2noOta9rmfp3Ym4GLWauQ4
         BRaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4/3F9i9uuxwlpv3q0pOiNHC5PVDGc09uDZUAVBqIyWU=;
        b=zCpP6Db3Q+vWXlCzMhOc3V/3Bi+EBvHcQ0I+kMUcxSH+NFDN/5MBaIXCJOttao8uBU
         w5CiSiEG42jQfTl6EbM0rMs8cPGeL9cxhfKyz/6I5lma34W0RjbTpUtmWaRCNJNYRw3u
         8gcGsg4+cwG4eDtJ2ai7ysYTwd1hkYk0dbwxGpXh5nIAMXSwh+glX0gIn3U265lmINPE
         nouV6xHACWC5TNwLnzNmddghPOX2rIUsj88pdhNLPMCBisEgy2K5Bcdu2LVBOBjHCaC3
         txwHWX4z4SsVxeKH8t0dnkw7dJ6EFlB7eKX9e4vyM7BvXdc+UyhrZXOMlxoX5CWoOKuK
         6AUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="G8sO/LbZ";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=4/3F9i9uuxwlpv3q0pOiNHC5PVDGc09uDZUAVBqIyWU=;
        b=DCN5uXoEVHMiyT5ZLjsYTahQZg+fp2nzfNeiDdfv1+8ARA1MtBHpMDCi0WpG0+RZ9V
         VnOgjremA0pt5OTrsrhU5vK9Fwt0KOiiAeoiNAY84Ayf94QtGHszi0KymH+Bkbri6t1+
         EX/ueQ3+APWLHhuFlBmeqGYjqEWpzLCWK8TBMH5643S33fuYnmCU38ce09QwD7LE+V9v
         iVTO8N8eFlDHloiJ0zoebHkBjDWurZ/lBQ3G3zA+nfgxoz3/oZ9lSey+JVJDUwnUbopG
         E5Cry2HwmSmzVax2iW/dt/CUziANZ97nXUBbiuHdIdGAtOjouqQSDpcI3olqLlrL1lAO
         IAJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=4/3F9i9uuxwlpv3q0pOiNHC5PVDGc09uDZUAVBqIyWU=;
        b=kU1bmr5aaMaijrBeD/Sehuh9hlp3YJHqYkVI7OZGFzItDM7BuDgUzVfOLx9wB5x+BR
         dh/5ZAMoRmBoPQVbb9mw4BrTg2LMmiUKxZkyIZS+lnoeG3qsh58Ca1Ns3gbkk6dYh6Oe
         hhgOMcQwIPv/RFET74AEUs9ImydL+hbYjWfvdcnduRBnNomgRLvH8TrpaknDPdcVegMv
         QEkfgq+ZxA8wfae+fdgQWNR9Fxz79h7LNk/u77CwXrXWbuJJ56kxw07lDTOk1Dfo6MaV
         pOzc8eOrPJLmfVVJAMOev5gB65GRZqRqYITcOmDLyipw73pqsmOKqjJd8Xxepi42Xd9O
         kmqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1uXodPuEfmh5SysgMPaJJnz/dm+4o1cVVriwikwbiO4MrGeLV+
	dAL5Rt7mVtEnqqq18AhwM2g=
X-Google-Smtp-Source: AMsMyM63I153wWnDDV6+uKUXGl0oQMPXJIuwLW+RSOXO9vrcaDecldPwSD+Dx3iavlcghHMqF+xSiA==
X-Received: by 2002:a5d:59c7:0:b0:229:b76f:e2bf with SMTP id v7-20020a5d59c7000000b00229b76fe2bfmr8284165wry.128.1664044351358;
        Sat, 24 Sep 2022 11:32:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:255:b0:228:a25b:134a with SMTP id
 m21-20020a056000025500b00228a25b134als6705036wrz.0.-pod-prod-gmail; Sat, 24
 Sep 2022 11:32:30 -0700 (PDT)
X-Received: by 2002:adf:e4cc:0:b0:22a:d755:aaf7 with SMTP id v12-20020adfe4cc000000b0022ad755aaf7mr8827647wrm.692.1664044350622;
        Sat, 24 Sep 2022 11:32:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664044350; cv=none;
        d=google.com; s=arc-20160816;
        b=j2y+PflaIsVcDihKEnEl4U2m0MiJBv+WWIkEgW9sB1zDyM3BFs9L6i23+VuSgJcmZO
         Zgo6r6JlINLAR9O7yw2BlJGefu+moWdS3hJBX7dG174+K6VOcLdCRcIQ8J28gNjjdRSv
         xaNjaBqMbXr/FvWIbWfG/mrVgXDwaI5x+qFnB+B8q+AzXD+MhSyniEcjwtcxiYAiUKpK
         cC4GRuL8fA4P2usZANuQ2F77Ftdt/inEgdcfvJ1PN3QLU14hVnKe1zzAINwkj1F9I393
         FJ0iEbMPaGyicI4Qmbef4HlmiISx0O0lZlpEXc48/pnnNuzAGaUF187mX2GKq38+ArVn
         jolA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wCZqMmRS53sAUXuFaKIWMcHMmvAGs3N+TjAFGrnshio=;
        b=WP5ifhtwqz0IQ73o/SuqrvPaTYJAe9i1RJKHJ0C8yffCxb1GaNgljFQytsGMe/GKt3
         +cc9kElpGWLewkNRQbVRR5Ix3P7v+q5QvgXuoPhvm1riA6CScE6knfcq14O26WZ6WJZR
         +rynoY9cch3aTqXXfNAEdik28BiCcueMelqYFoPS7E0CI36vRiI1slr9Duw2uudkTdyx
         nfXlOOGdHbTMZqWCR3fReQrl2m16+fVbWR2ALH+KoAZSB8d+A4u56TEL/wKnLVTgPbgK
         BP6k7oQTcOeBa0bQAeLodq+1HCdr+UwPpHXVNw4YR60BzGSj5D620Z6ZuFPI4AvDpxvZ
         WcrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="G8sO/LbZ";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id bp12-20020a5d5a8c000000b0022a450aa8a8si498117wrb.6.2022.09.24.11.32.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Sep 2022 11:32:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm 3/3] kasan: migrate workqueue_uaf test to kunit
Date: Sat, 24 Sep 2022 20:31:53 +0200
Message-Id: <2815073f2be37e554f7f0fd7b1d10e9742be6ce3.1664044241.git.andreyknvl@google.com>
In-Reply-To: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
References: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="G8sO/LbZ";       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2815073f2be37e554f7f0fd7b1d10e9742be6ce3.1664044241.git.andreyknvl%40google.com.
