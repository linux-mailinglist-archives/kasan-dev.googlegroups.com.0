Return-Path: <kasan-dev+bncBDKPDS4R5ECRBX7URKQQMGQE6KLC7HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D2D86CBB9C
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 11:58:57 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id i3-20020a6b5403000000b0075c881c4ddesf1493124iob.13
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 02:58:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679997536; cv=pass;
        d=google.com; s=arc-20160816;
        b=wsija1JrxCkyy7p5A0pI1OFYhSYwJEjVVtHSodmFAEp4Zxgpk81bimQVGl3kfkd6M+
         NU+T46dOCAfoCf/tIV+xrlGN7aLMnUuWKJwIXuxZEwKd8Bij7GKpToCaOJ6vblVL5kzC
         Dqx+iJ6wnbYtbJI3Y0zia/2YVB+3EXX8aCLKGbFKtHye8A/AmAAbed1Ul1utjjuTd+qH
         M3jfaFJXj7lf8UwHvtxWtX7Uy6gDmL9ZBJ0OtncG46dXhcDBuvrc7YxpI/SYARquVg3M
         zdGK0aiwnNncu/ExqMt77NA3d2Io1N/qPZYfkbUjga90oiD6voT1v+gV0NUfCVzAkAFa
         8RSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=u3jE8CtvVFB2pJJnC8XucYMMQOPIDSJS/KhKnWKV1Ec=;
        b=znKGYU9Wkp+4X+VuuqoS7H+4BBQ962TeUMZ/JlZFEsIU/NqAPa1XAYfJAbDWyoyXY0
         +z8rE+OC1Nq0PpGnZEjLhN+0i3ttKeQnumS+lvncw4QAT+tOV8pAPGzeLw8bpT92JX3e
         11YtcynHFuXTWlJNlXOY7M0/GQc2AdUGxij71iy/gQnb2nyLOd+Kp9gyi7u07uL1VDf2
         obXC9IEYyLZgYmnTLg1U8JIqvVLM3qi1ZKnc1ZJHXjWK/CKUXroHV0/zGIUbPyQkqAGE
         JZhg2p4C8LG2DUVymhlFSYACki0UBI0NwKWaEZZvAf7mouEoZwcmG83MRR9hKLfU/xBM
         KwyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=cRycGiJJ;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679997536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=u3jE8CtvVFB2pJJnC8XucYMMQOPIDSJS/KhKnWKV1Ec=;
        b=RY6BwhxXpqmqA9uUAMPK6GTOeQTbhxwpwkNs77ceq6ZyyqA2dSkP5owZLTdEdsiaTB
         JaQJ0wP3D2Ji7CmA84b50yl6obKMzRnFOw0/mLUOznjP0AjcPE/ENnI4n98pJPmy80w0
         xvQCn/nX9ohrw9Vh2kkUov/Squ2c+q5vD15msa+z1CP0PyuzgkTVY+dRu28ZWrkHrJ6F
         QwzH5znWxiCf2N/UCLGjjDy6gVFFdka5DmMGPjOhYhvlk+dgF0YkMrmMdt9jlWHamSCH
         ZOhRBKFKAzjDWWvOMv8JsQb8U0StukxBE231YVN4A3gCeaKiZRAtbAqUOBWRJdMOO0KV
         9Z2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679997536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=u3jE8CtvVFB2pJJnC8XucYMMQOPIDSJS/KhKnWKV1Ec=;
        b=AexbegP/qOYofM/iIo5H54spPD6v2TUGy5fhZtmiW/Ls2wlvdhT9hK5VbFvBvjIGtV
         FVA+lmAcp3lPIihBrkZL1kF9C511wwkEmyRAJ2X1j8uVzQTXttRTUTh5YOaJc5F4MJFd
         V1wohsZp7WNZLLCO/yRBu5B6PGeZWErbVUZ8en6EZjIBmjH0Gy5vAoQB4g9pJohYkSyf
         Zg4IfOUx9B1SR4lVf3zuBSd5QQtMp41EJExTlwIs22VHFoBKAx3qfFOoabpCCv5vcMLW
         AyFsfoELUph/LmalPaLXUBmwGXFVHI3/6IccniuQen4QwNwU/XGy2Ftz2fHmC8nzuh3Q
         MNMA==
X-Gm-Message-State: AO0yUKVRTieU/E2QK/Skt1l2bx/1x8R7Z8L63TI01R8R1t4bGD4n4ouL
	DfYGt21MWu8feXaJwlVYRlTybg==
X-Google-Smtp-Source: AK7set+4tgizECdsp9vsLMgSaSVY2joA5Cb8EJXpREXUnMrjRC8Eh6VpEE1FLdScTXPe0vlbWRJI/A==
X-Received: by 2002:a05:6638:4807:b0:406:44c4:a7a7 with SMTP id cp7-20020a056638480700b0040644c4a7a7mr13120567jab.0.1679997535921;
        Tue, 28 Mar 2023 02:58:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:89c:b0:758:f9d0:ff47 with SMTP id
 f28-20020a056602089c00b00758f9d0ff47ls1999403ioz.6.-pod-prod-gmail; Tue, 28
 Mar 2023 02:58:55 -0700 (PDT)
X-Received: by 2002:a6b:f707:0:b0:74c:7db1:47cf with SMTP id k7-20020a6bf707000000b0074c7db147cfmr11483429iog.14.1679997535415;
        Tue, 28 Mar 2023 02:58:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679997535; cv=none;
        d=google.com; s=arc-20160816;
        b=nClVMp9Ye6+p8kH9bcnSKBbVhxAeNzG4pQffnUM8/nys/34O8zVXP3YgS7ensBgigH
         XAoiDeIdE1xbIsEm9VPx4OhDj683qgDNmKWMgDLtuHVOzv+gS8+AzcRwiBQvuKZv5p1I
         FBVs3JPG4YvS6vS0n8KP7cUa2/8512ZKsQmMkNt2TjwBh9OKEeSuXq9CSRiwCQuj1hFE
         3NSXQbF/3NBxlaA0gWRX3qnbV9/nQS4IGDHmelT+UvG+94GX1zTldxdg1iQ975eTopQ6
         kvZW5V4j+7stRDNX5G3JBpxz9RZyRdDjcY1pBUM0IJSJ80TjISK5P3KGpz03d72k2Uf6
         65Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IMHBZhrpM5z4k2ZtEf9hxQYrO1Qyd30oWmty+49rOpw=;
        b=ffwnizkgT7aFs639J++dTcI9RO/32RSFAtwDLhepEIxEvDST55ZqA66nxn1Z3fXpgD
         +fttC2wenUuAy1N5ZJSE8WF35NwWZNerh/ydJSuPyLPV0RK6wyuiUe6O+WiDngcFFvI3
         ilIKedG7OdB5lSoK95WBs72cQrG7O/5lrwBMJJBkUHvMgkWE+QB9hJVru3VS18JKAN5X
         6cc1ZaG2+tMYyZPICPJtQCFGfRUVTr0itgMQcP8HoqfOj7CnrC3adxi++RTxE6fTF4Yn
         Pl9QppnKtKPj+Gh/KVjlck4V+q40voco0NOwmKeMxI+gUIB92K7ADbTVWKM90/vShU8k
         gmIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=cRycGiJJ;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id f12-20020a056638168c00b004063285e3f3si3280238jat.7.2023.03.28.02.58.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 02:58:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id h12-20020a17090aea8c00b0023d1311fab3so11940270pjz.1
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 02:58:55 -0700 (PDT)
X-Received: by 2002:a05:6a20:6baf:b0:da:1e1:3f46 with SMTP id bu47-20020a056a206baf00b000da01e13f46mr13145721pzb.31.1679997534793;
        Tue, 28 Mar 2023 02:58:54 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([139.177.225.236])
        by smtp.gmail.com with ESMTPSA id m26-20020aa78a1a000000b005a8a5be96b2sm17207556pfa.104.2023.03.28.02.58.48
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 28 Mar 2023 02:58:54 -0700 (PDT)
From: "'Muchun Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jannh@google.com,
	sjpark@amazon.de,
	muchun.song@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH 5/6] mm: kfence: change kfence pool page layout
Date: Tue, 28 Mar 2023 17:58:06 +0800
Message-Id: <20230328095807.7014-6-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
In-Reply-To: <20230328095807.7014-1-songmuchun@bytedance.com>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=cRycGiJJ;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Muchun Song <songmuchun@bytedance.com>
Reply-To: Muchun Song <songmuchun@bytedance.com>
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

The original kfence pool layout (Given a layout with 2 objects):

 +------------+------------+------------+------------+------------+------------+
 | guard page | guard page |   object   | guard page |   object   | guard page |
 +------------+------------+------------+------------+------------+------------+
                           |                         |                         |
                           +----kfence_metadata[0]---+----kfence_metadata[1]---+

The comment says "the additional page in the beginning gives us an even
number of pages, which simplifies the mapping of address to metadata index".

However, removing the additional page does not complicate any mapping
calculations. So changing it to the new layout to save a page. And remmove
the KFENCE_ERROR_INVALID test since we cannot test this case easily.

The new kfence pool layout (Given a layout with 2 objects):

 +------------+------------+------------+------------+------------+
 | guard page |   object   | guard page |   object   | guard page |
 +------------+------------+------------+------------+------------+
 |                         |                         |
 +----kfence_metadata[0]---+----kfence_metadata[1]---+

Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 include/linux/kfence.h  |  8 ++------
 mm/kfence/core.c        | 40 ++++++++--------------------------------
 mm/kfence/kfence.h      |  2 +-
 mm/kfence/kfence_test.c | 14 --------------
 4 files changed, 11 insertions(+), 53 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a4b680..25b13a892717 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -19,12 +19,8 @@
 
 extern unsigned long kfence_sample_interval;
 
-/*
- * We allocate an even number of pages, as it simplifies calculations to map
- * address to metadata indices; effectively, the very first page serves as an
- * extended guard page, but otherwise has no special purpose.
- */
-#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
+/* The last page serves as an extended guard page. */
+#define KFENCE_POOL_SIZE	((CONFIG_KFENCE_NUM_OBJECTS * 2 + 1) * PAGE_SIZE)
 extern char *__kfence_pool;
 
 DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 41befcb3b069..f205b860f460 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -240,24 +240,7 @@ static inline void kfence_unprotect(unsigned long addr)
 
 static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
 {
-	unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
-	unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
-
-	/* The checks do not affect performance; only called from slow-paths. */
-
-	/* Only call with a pointer into kfence_metadata. */
-	if (KFENCE_WARN_ON(meta < kfence_metadata ||
-			   meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
-		return 0;
-
-	/*
-	 * This metadata object only ever maps to 1 page; verify that the stored
-	 * address is in the expected range.
-	 */
-	if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
-		return 0;
-
-	return pageaddr;
+	return ALIGN_DOWN(meta->addr, PAGE_SIZE);
 }
 
 /*
@@ -535,34 +518,27 @@ static void kfence_init_pool(void)
 	unsigned long addr = (unsigned long)__kfence_pool;
 	int i;
 
-	/*
-	 * Protect the first 2 pages. The first page is mostly unnecessary, and
-	 * merely serves as an extended guard page. However, adding one
-	 * additional page in the beginning gives us an even number of pages,
-	 * which simplifies the mapping of address to metadata index.
-	 */
-	for (i = 0; i < 2; i++, addr += PAGE_SIZE)
-		kfence_protect(addr);
-
 	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++, addr += 2 * PAGE_SIZE) {
 		struct kfence_metadata *meta = &kfence_metadata[i];
-		struct slab *slab = page_slab(virt_to_page(addr));
+		struct slab *slab = page_slab(virt_to_page(addr + PAGE_SIZE));
 
 		/* Initialize metadata. */
 		INIT_LIST_HEAD(&meta->list);
 		raw_spin_lock_init(&meta->lock);
 		meta->state = KFENCE_OBJECT_UNUSED;
-		meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
+		meta->addr = addr + PAGE_SIZE;
 		list_add_tail(&meta->list, &kfence_freelist);
 
-		/* Protect the right redzone. */
-		kfence_protect(addr + PAGE_SIZE);
+		/* Protect the left redzone. */
+		kfence_protect(addr);
 
 		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
 		slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
 #endif
 	}
+
+	kfence_protect(addr);
 }
 
 static bool __init kfence_init_pool_early(void)
@@ -1043,7 +1019,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 
 	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
 
-	if (page_index % 2) {
+	if (page_index % 2 == 0) {
 		/* This is a redzone, report a buffer overflow. */
 		struct kfence_metadata *meta;
 		int distance = 0;
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 600f2e2431d6..249d420100a7 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -110,7 +110,7 @@ static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
 	 * __kfence_pool, in which case we would report an "invalid access"
 	 * error.
 	 */
-	index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
+	index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2);
 	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
 		return NULL;
 
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index b5d66a69200d..d479f9c8afb1 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -637,19 +637,6 @@ static void test_gfpzero(struct kunit *test)
 	KUNIT_EXPECT_FALSE(test, report_available());
 }
 
-static void test_invalid_access(struct kunit *test)
-{
-	const struct expect_report expect = {
-		.type = KFENCE_ERROR_INVALID,
-		.fn = test_invalid_access,
-		.addr = &__kfence_pool[10],
-		.is_write = false,
-	};
-
-	READ_ONCE(__kfence_pool[10]);
-	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
-}
-
 /* Test SLAB_TYPESAFE_BY_RCU works. */
 static void test_memcache_typesafe_by_rcu(struct kunit *test)
 {
@@ -787,7 +774,6 @@ static struct kunit_case kfence_test_cases[] = {
 	KUNIT_CASE(test_kmalloc_aligned_oob_write),
 	KUNIT_CASE(test_shrink_memcache),
 	KUNIT_CASE(test_memcache_ctor),
-	KUNIT_CASE(test_invalid_access),
 	KUNIT_CASE(test_gfpzero),
 	KUNIT_CASE(test_memcache_typesafe_by_rcu),
 	KUNIT_CASE(test_krealloc),
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328095807.7014-6-songmuchun%40bytedance.com.
