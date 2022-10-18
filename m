Return-Path: <kasan-dev+bncBAABBF57XONAMGQEVDAKL7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AC88E60316B
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 19:17:12 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id s5-20020a056512214500b004a24e8c79ebsf4802242lfr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 10:17:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666113432; cv=pass;
        d=google.com; s=arc-20160816;
        b=V4/zNCvBso/C/c8RT9om+1Q10A4tUp7GymyXsswmntkbT6GPZVPtnqP4P6BS+2Iz02
         myQzzYwewRCBHAN0nlLnAKxKeau+OBdfJTglYeudMAJNbFYu2trhDSyvOErcQsPW8e5V
         fpC3QwtgXmM8zw3bXNVK7FzEqI2ubT8K0Oftw+oLUSaBFV5g5EK4JTyZ3Ao6IbDVCIlI
         82CM4Z1l+SdMrhWrc/ZrBsvsUxQE31+TBxrE6kKhLGJRlaXxyVhebuJPvOeo6t5a1isi
         MCSYmpMCIrga7GC8FA10xcqO9H5UnzNKNHx5fR9yZby6uxfqQrOwm8cWbN/boOay4z3R
         KS5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pyyXTzVJzfXHwEgvv99oF8YVsmf74VsR1hgpesnA8/k=;
        b=e0HW1tGW8vcFRFrFHqLDEL3f4OrztORtd3yJAS2kH0sJCIy4+H/fCLA5OTwtyLDTV1
         o0RuR/e1KkmdnHRh3g322hvg6e5FqD2y0tvlDnCNBKrEAIQFpP5L8RUX7wqNFbLxA1EK
         43pbgxQgI9dvfiAWFw4mqTFCwiMTIVeaELhvHftW5Ye2gtW3Fiz6t7WwzP+U/vwBCj1x
         vFbCd84Rqhmwjgya9jz8PE8D26KTyASArWhSjJoffvWD48o4SMMxf5lqcwkt6EKwuGDD
         Q7qPz5P/hFe7Rx0E0vFRMvvjhhbCZeMvme+odO6PbqqXIOurzZ8E0IifYTP9JpSMdC8l
         cCIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nyrPW2sf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pyyXTzVJzfXHwEgvv99oF8YVsmf74VsR1hgpesnA8/k=;
        b=HTxDhteVuN8C0JpC0QLGiqTJeoL+y8vDKPGbmYcxaylRtAkZfMXv4xyesUeIWsSJX8
         Ht+Ox3Vu7crjSc7eRhLqf4PCHFH5IrkziQvf47b5WCiB9ZFgk3X6CrnUWaeO4aFPdY8z
         4ayHcqcelJnVY/3Pz2LKnPp5tzoL7XnnFd0ydavvdHPCfYmUB6S+lfYP1up/uYloaP4o
         8IENSrY0OUfxalnQoRR+5slbXa1lM8+UhX90jgODZ5EsZ4gv1lg6Aht8tKnijmXZYjwt
         NRzFWCO/EvEnoWhVrObtmj5ykdSRkAIki1EJKyZ4uBeUz0d7RTxDGMD/Mjd0O61Xjn7J
         AEjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pyyXTzVJzfXHwEgvv99oF8YVsmf74VsR1hgpesnA8/k=;
        b=5r3cSnLcHY5WhehsdwOYO2XGf146oo6Fn4SGBxZfN/d3OJ37yXAmyUMWDpgXjTvGP0
         rYPGyxGPrS8s/+lEq3ZJKO/XoKD+D+QAGhxhB78tSQf6p4fLoPlLEJGWaakUI66RbnBw
         m6oXgGIhyGX2f9nox1qsg779batDtmOSVZWurB+sxEPVc8Sby62EBr1k8/sO5+tkJP6g
         neth30m35LZxcUQdBZOUKBYI8hUcmi9c33XOlt+nl2ZHXSxQrNJRpRd4rxy/09ym2kSv
         OMxisPQlKvJb8icfq9bhWVSYaV11lk6H1ktPm7h6R2zAMKtGdCgCGZYGlGptAoqJfhyG
         ciMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3sHu7BvSxOie5MMvbdLpJUWWhPEAWS3K2sVEsYY7m1kPj4966Y
	LV12g2KE9UsSz70nPMhoS3M=
X-Google-Smtp-Source: AMsMyM6AqBij/3akE16nx9rPjNecySQqZIWrfLV3OxNjhpP1G32LFPkPJmcNXvK03A4IhCYboUWSmw==
X-Received: by 2002:a05:6512:12c2:b0:4a2:71c2:a7f4 with SMTP id p2-20020a05651212c200b004a271c2a7f4mr1439061lfg.3.1666113431825;
        Tue, 18 Oct 2022 10:17:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e01:0:b0:26b:ff81:b7cb with SMTP id e1-20020a2e9e01000000b0026bff81b7cbls2899604ljk.6.-pod-prod-gmail;
 Tue, 18 Oct 2022 10:17:11 -0700 (PDT)
X-Received: by 2002:a05:651c:2382:b0:26f:cc74:4f4a with SMTP id bk2-20020a05651c238200b0026fcc744f4amr1391139ljb.374.1666113430927;
        Tue, 18 Oct 2022 10:17:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666113430; cv=none;
        d=google.com; s=arc-20160816;
        b=IZ+NKpZOzhpa7kUmBSC6lORb2RlzMotczFkxMqTQLlXzDVnBG76LC4mjm/106Z64l+
         pHDjF372QJLi5HLhJnRc7bnVSgwCzURuX0SCyQTi1CCS12wN6sekUgH9L6WluY4ME3ZR
         uusV66r0jri+s/35fK3KfleUNQJ1ir/7dQz/CyztJIt0Rhaxnahr/LfApRLn9hZyg9Zm
         cGljcrSAYp1d9Gy/RjaP1sN1m7QU3mKtyz0DD/+YP3BxpcDXuXZbGjDpMPNZj1MqHhtt
         rYoRJBeXkQw9C6bTIFPhoCyhjjmnYz2yLZU1lNsmuXICET3xPkZRt6PLcotRBzS4I/MC
         xdlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=trOBmB/29htB1a2FV9dsqNXlc3ZPebKRyrhVw3YMtXQ=;
        b=l3+ENK2C9CkzlTwv75iR18srvTa0HZu0pBB5xnl8umxigaDzK8JsJZXBRydYWxDDjw
         tCugvc0ticd4e+Cg3xMxmi40CodpY+O2PVMbHbcnIxYr+soow+4gpCW93ze8QxMgk0yv
         JJhTMSmVkMVSieXww3x1AJdiNGwEstoHEp2s3UZwYy7MHuUevN9tb9Wf95bu7myC7PeX
         CFdVVaeegr6td8a0PDpNM5R38GC0r3VDwRK842GVUuveTXjFCHAdhZp1Y9qdflaS5Gsj
         ByVp7dayjQ2bGWWFsi86Enc/9sUPdR2LT7AQi4bWWbBsTzhirZR8oCfv4lozYQEgDvWh
         zZ0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nyrPW2sf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id o17-20020ac24e91000000b0048b38f379d7si505097lfr.0.2022.10.18.10.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Oct 2022 10:17:10 -0700 (PDT)
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
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 2/3] kasan: migrate kasan_rcu_uaf test to kunit
Date: Tue, 18 Oct 2022 19:17:05 +0200
Message-Id: <cba364342be5e257cf6aa53ce2f01aec7eae5f8a.1666113393.git.andreyknvl@google.com>
In-Reply-To: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=nyrPW2sf;       spf=pass
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

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changed v2->v3:
- Rebased onto 6.1-rc1
---
 mm/kasan/kasan_test.c        | 37 ++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan_test_module.c | 30 -----------------------------
 2 files changed, 37 insertions(+), 30 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 0ff20bfa3376..38bf6ed61cb8 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1141,6 +1141,42 @@ static void kmalloc_double_kzfree(struct kunit *test)
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
@@ -1472,6 +1508,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cba364342be5e257cf6aa53ce2f01aec7eae5f8a.1666113393.git.andreyknvl%40google.com.
