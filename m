Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO547T7QKGQEASA2TAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 01BC42F4FD3
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:20 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id z188sf1793279wme.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554939; cv=pass;
        d=google.com; s=arc-20160816;
        b=iOfRkxYp+u1JO6uIeNDPxE13zskYeYzgr1RNaglagmn+taPSS2FBWFujrqHpNwEg/y
         k7QZp/gUfxiPgWiGkUpdFSLzvGBL5N4DyzWzP+HxD6Twm7NidpQQnwDwu3qvC3kcWOf8
         yVVVTobKk4kPwGYCOcJXz3PLy6nlnOy0XZsru81pJ/DttdwLOghJitBUUc9BtZaVZaCt
         pS2OHUeCCXR4ezo6C9TZW47qJRhFCAsoQ+JmrXj6ekOUEiSnC+gwNPbYnA1E2qa/BOFI
         hFftl9ot5xD3d1sVMsKBurVEW6x6UdvPOi6Ap1NJxHMwudhNmfZwGKw0Rr13Q+xlD8tp
         owAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=X69AEJIgyVVYa3OGBgxEqOj8jXZ9xVvUmqmd7yYkrdA=;
        b=a3p7+P1QxBNiVkc7ISbFUegKEx2kvjv3IoGbLrx7opK3uRWjF0CEYcikDmuLNgGvOT
         BZKLAKQCZlX8sLambaM9QfQJAZX860bRUkOzpWAVN9jsfkJ1CIVK+G/bP3MSxoDlf1dc
         klXA5w/iTvW6Nq8s3rPWJthABy84gA1F4Q7eTkK2NX0//4f0E1Q/1qYAhuw0bFKt8JSA
         Z/s2BHyeavGoFggznOcGe/6YXnsNgQNFhYjqwvpE3IIhHgv7dLcA4Y1JqaVlATCO0pOY
         wsqeZQZH5H8fVvXRY66rhGRXMln0VuJ8Ac8GcMEfLRHGcAfxBl0HaFliKhVEelNHuSZF
         TbAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WhXPKI7k;
       spf=pass (google.com: domain of 3oh7_xwokcxkxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Oh7_XwoKCXkXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X69AEJIgyVVYa3OGBgxEqOj8jXZ9xVvUmqmd7yYkrdA=;
        b=C0cbu9pqt+bcJpqNbNVFo135HAk9AuDjC/g5pNP4sVTE9b1TAZsgKyhYJd3kUe7OsI
         qJa5w1h+CEKAYWW3GXg74xxq9AzpdY/T7TEx2q1VbiCzQsfKnhJBsQmY0ysDlYcbRFcq
         rT7W7vzdic20mMQpnOlZzOIwCEWXYv37iGNro26Qnmd0GuxSkvtcfSxrFiHID9gzwB3s
         Qs2UeZxzwJEZdnmyn3pI9klf3hAhmMrbtUq31GNd7U8pt4f0KicvaaK13dH7u3wGMDlZ
         5WbDlTaVv0WZeDuaB39tGhB8klzU+d0iwc/im0D9mMvU91aQm15IuDI9GmxOmikcTuRG
         lFBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X69AEJIgyVVYa3OGBgxEqOj8jXZ9xVvUmqmd7yYkrdA=;
        b=KUXu4U/3//fuRHMWfeeaQQ5Lg4dba8lrVzoHTb5I310I6X0GKUBzIZNU/5H4EnQ5M9
         3+/Rdb34lEwDTWNfRXFhmVVsTtSptqN9zZ4vuXDVPbA0uf3LIuZ0s5Cuh/jOzfA4wuWp
         WIl3aYBeNp55gFfWwJaeMsfrY2ksLDmqrJjZ3fCFE3WrxE6vHpY4NoYpBVay2vs8BxzC
         vgq6zJ5I0FPfSt+60/cDiOVB2HgjvwgYakimcNbWSEvreVuT1QTg7icsIcZIX2TV/cus
         o3dBv2GvUj+f/7MKX/qiuMqHBHt+jwCnNGwkfpJKweoCEx16/fBuv2P3tOtaPfowbRg1
         Y/Vg==
X-Gm-Message-State: AOAM532eij4aG+ZViY4kwX/9qJMcBrBa5KiYVckA5g/bFlcW/07LYo+E
	HvkgUyNWC2a09hp6HM8FolQ=
X-Google-Smtp-Source: ABdhPJzEIH39fgANcfkM+srk8QQ99/MigvPEnVmq0EwimxOpIObySVxFQZ/IUeeeWuhn9+cndlaStA==
X-Received: by 2002:a5d:404b:: with SMTP id w11mr3557141wrp.14.1610554939787;
        Wed, 13 Jan 2021 08:22:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5543:: with SMTP id g3ls1705770wrw.0.gmail; Wed, 13 Jan
 2021 08:22:19 -0800 (PST)
X-Received: by 2002:adf:f70c:: with SMTP id r12mr3460180wrp.234.1610554939081;
        Wed, 13 Jan 2021 08:22:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554939; cv=none;
        d=google.com; s=arc-20160816;
        b=Zj1gvaMsg3yFo+dw+IH1pSOFTWz0tpZgxRy+e+U14WUYtssc4T6uPisbzTPqeN1Mce
         CCGvrWxpYzTqOcq43KZl6P2250Tr8DLkjLRUM9XVkVG2eb8gmRKhxE3qkXkMabyShBkq
         XUYG/QsI/p/BIt3v+0Ah+gbAgzSAgB53Bz0YqkI2hVq7pQfUhoNpPTIzo6fEDWeKmWOG
         4jdsLXFwfKiscIPerrj3tR1NYsiSRUPbPj3Zed2s7+UqSp4IuGVx9b5fCytZdBYj9liC
         +jO/u/s45F4Ga5V/36keIYtw6z8sX/WR5prvA7wufBi3L9xnK2HRjtfIGMgSz86IHZG7
         vMrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=F9RPqmmRw2Yulu4z1uWbEkv56znu+VxUo16IevqT5w0=;
        b=SxYBRhlNiBx2NszjInD2KEulgi/CUPgHuL5DX2ViY0lPL7dEF+bWzqpMEKDahrysm2
         GaBKFZOInwONcXwea6v6sSnupe37RIngtzAoECPvnreDYcDZoA0ITPkHHxymszSXufZh
         /F2LQeqPJYg1GC5hIVt7lBrAWXV17BnzTUvuBUS52AmQs9uTW905BpIJa5f8R2SJ1fTE
         2BUhnBfCtlw+IdsnTNxhzEtK0hcRqTAN7nECrz1gsz3j6k1nHcJEoq+L3RlVOldhDVfH
         ybitATXF4+QmwSLqXd8xerUX9/ACyncg2o+TJBMtBgw21z2K6lPfW7QjHIdMsr9rEkQM
         hhtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WhXPKI7k;
       spf=pass (google.com: domain of 3oh7_xwokcxkxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Oh7_XwoKCXkXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o203si125431wma.0.2021.01.13.08.22.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oh7_xwokcxkxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id h21so1025437wmq.7
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:19 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:c308:: with SMTP id
 t8mr85582wmf.22.1610554938684; Wed, 13 Jan 2021 08:22:18 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:40 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <0e994d67a05cbf23b3c6186a862b5d22cad2ca7b.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 13/14] kasan: add a test for kmem_cache_alloc/free_bulk
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WhXPKI7k;       spf=pass
 (google.com: domain of 3oh7_xwokcxkxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Oh7_XwoKCXkXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
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

Add a test for kmem_cache_alloc/free_bulk to make sure there are now
false-positives when these functions are used.

Link: https://linux-review.googlesource.com/id/I2a8bf797aecf81baeac61380c567308f319e263d
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 39 ++++++++++++++++++++++++++++++++++-----
 1 file changed, 34 insertions(+), 5 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 5e3d054e5b8c..d9f9a93922d5 100644
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
+	cache = kmem_cache_create("test_cache",	size, 0, 0, NULL);
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
@@ -522,6 +524,32 @@ static void memcg_accounted_kmem_cache(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void kmem_cache_bulk(struct kunit *test)
+{
+	struct kmem_cache *cache;
+	size_t size = 200;
+	size_t p_size = 10;
+	char *p[10];
+	bool ret;
+	int i;
+
+	cache = kmem_cache_create("test_cache",	size, 0, 0, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	ret = kmem_cache_alloc_bulk(cache, GFP_KERNEL, p_size, (void **)&p);
+	if (!ret) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	for (i = 0; i < p_size; i++)
+		p[i][0] = p[i][size - 1] = 42;
+
+	kmem_cache_free_bulk(cache, p_size, (void **)&p);
+	kmem_cache_destroy(cache);
+}
+
 static char global_array[10];
 
 static void kasan_global_oob(struct kunit *test)
@@ -961,7 +989,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e994d67a05cbf23b3c6186a862b5d22cad2ca7b.1610554432.git.andreyknvl%40google.com.
