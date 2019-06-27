Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLNA2LUAKGQE4XMM7KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BD6557F84
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 11:45:19 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id q14sf1250000pff.8
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 02:45:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561628718; cv=pass;
        d=google.com; s=arc-20160816;
        b=yZIig2mwqEMTX4BHIC4wCRzm6aXO1M1KTpMc5bm7cNWpJZbcMDBdy/RRnLBvCF226d
         7fvbGHMAGi+Yd7QUM3fbrJ0IwbL/Q3eFgvuVFgm5/xs/w5Rj0dkbZrTBvHu9aZvA+rdj
         gOHVVhTHNPgvwb+xbjNY+kkWhMfIitTDMCJcmze4L63JjQwHIB1CgFvEXplCjDjmNGhV
         FiaKzvnSc0UxgVp1rVTlYHShc6yq0AyQno8LwcknqPn8onH5g5Lgxzcc3DxhmPllYjmI
         YIm1PYlUdaY2IOCMFa46aJeSA9JezZi0VFOtUTCqnuZU0vG3q0yfni9WqMJyH9OCB4EJ
         vUNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4gDvT0y6b6hzMgybGKnZMRP10bnB6swgSA4Ezhi35mE=;
        b=GNDCvVCiTm+g0e9l36L1873UbaNvyrVGf53nlsfytwAReS0mJ+VcLiMk88kxKuzKMr
         2AtGAsYcu1S9REI3i83PD/A9NdT2kS+pGZU2u5/9Q3Ecg7yK7emv0NuwBnZIxHJ5f9Lg
         kZOreQY+fzdwrZQIgRv2ULtA6cvxFR8maSYrVt24v7y2GgRF86tZU1n7knMHIYy8oGpS
         gL2+BaSSCskSKnqPilO6q32hdCqPV1PjPfnfI1JGf0CGg5T2dSgDQCeVv8ZSLqYcPLRW
         B4x9VzeXwJBlPty53MNc2G+25LrGzHv3NrBlQnNbcTydUdHzlNEth4Fx2qUOOk/Xmi0f
         YlJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CDW3O1rc;
       spf=pass (google.com: domain of 3ljauxqukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3LJAUXQUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4gDvT0y6b6hzMgybGKnZMRP10bnB6swgSA4Ezhi35mE=;
        b=Pw7lALvHv1GG4imnjYRWcA4ZhpWn88pNRj9gHdPC6s8be/kERj4KDEpcAVwjsW96cN
         kRio4BtV1cpRbuUa9GvkMZxFYPS3xAkx3wBpheDH4eLph1680IaYphrdWkNhe2tHhMVI
         ES9E04x0ieJA1jgZ6nwAubzh/mkNPxdY4H/gr/CRZfo2inP/YmyuDXbqqw1d671l6kgf
         lTr84T5erNAqmlf0hnQ+fb9PaQmgRGwiy5/HksItQNkMm3IXiSbB0lR5sC3lW4bhs+ja
         26o737ATcmAse2LgjN+p7RRfOUlb1tvSBmaP4AxNFlOxPGU1acDp2SBz1gJc5pWVCbD/
         7Sng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4gDvT0y6b6hzMgybGKnZMRP10bnB6swgSA4Ezhi35mE=;
        b=XJhs/QDndcStKdoIk6ujYd7rN/07bn0fAgMJzDDiz0cNcz/JEbyxcHbcr/4luf7BW4
         kFfkXSGwmtx7+pqVNGsiAaRSnkdSWqn2KqybhsBc4k9iHuiyiNsz61aa4xGr0nOIjvAp
         XNFKHzmBqohncveXNo0FnaPxommi3MVKSMqRRpNyVKfP+Z6iD+IU0QE6d7E1DomERQjl
         8zQH1epGOGXqAkYZKnMi2nWJ1hpyyQ+ZWWPzVKp51VPwx1Zm48LJ510chAkYKnbq5kP0
         ANsTnJ4DTEKHgl8C1TLmsSlhQUC6MGN3kxcMNv/sG25x/uQtaNZ/T1oMrpo15Ol4fOkU
         YVUw==
X-Gm-Message-State: APjAAAWjzUyFkJpjz2Fl0oe2G/eraVcJqQFGR6FqArbC5eAOTjWypb9F
	yU5efV6hojxga76t4oEir1g=
X-Google-Smtp-Source: APXvYqzlBhWLlH51z9fA3LXAmVlCQXOZKn39ZxzqJw/h7r8/nkJDrU5wboI/0TI0e16W6uNbckBJAg==
X-Received: by 2002:a17:90a:a09:: with SMTP id o9mr4918053pjo.95.1561628717986;
        Thu, 27 Jun 2019 02:45:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:322e:: with SMTP id k43ls136632pjb.1.experimental-gmail;
 Thu, 27 Jun 2019 02:45:17 -0700 (PDT)
X-Received: by 2002:a17:90a:7787:: with SMTP id v7mr4898884pjk.143.1561628717374;
        Thu, 27 Jun 2019 02:45:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561628717; cv=none;
        d=google.com; s=arc-20160816;
        b=WHteJuRTUugqGX6qnrPMWErHo7+nNz8sAcFEC2g4oPvIngN8Zxfttd0X8+1KBl4tSh
         SGBzIL+ccPmgtgWTVvY7NWdlT8jSA4zPwBkuEG6HJ4KVvvauTcyXunFo3fkuu8ThGbd6
         bFp2q4mJzo4Zt8ItXEqqi+GYzp+D9kb8/dnwaPIG5Y3FF4CXoPRu91i5NjRTU+twz/qK
         zAmSirvrU3XxJW8NVa4itd2mYr8V3C6nlWVhZ63F5zbGJohlYH5tJqN3hmc1RHusDQVE
         tcBE+3uY/hoChCtbIPunHU1VyyhjCqiMNpvlAP2sH+3p2xZ1zkbKXz+krTbucBQtC6DI
         tEsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3eGEWBsY8dqF2V6DSZ5u38cqY6eLJM9O9Aa4+MoaYxw=;
        b=K5w+unD7T0pVrenV0LNGvkucdLY95LFv4UdZ3tsN9Gog5ObO4OKObmsFZmRfQXXcY0
         ohoYaE1B5kZnX4rsS74Jfk38T8vJeQW+qhs5/r08EvbJMk5O9wU+g2te7fwYaUXK8dDn
         c2/pVg5/0gSTygfVF1IGm/9n9RT8yfJ+s/7nZsX+1AAIZ89NxdpV+PbK9c2nyp7uXd0e
         aguNmOZvbZpu7c6+veXs1pl2FmgJY4p7e/xaYKc9hqB4rT0q/qJ+iUMFRZ9x7tMjevzV
         cyirgYb3JVET0oI/HJSWad4jtzNoDCwYyGOb4/oi8cq6KvMbeeb1BdL9oB9yxg+cfG4R
         Lyqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CDW3O1rc;
       spf=pass (google.com: domain of 3ljauxqukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3LJAUXQUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa49.google.com (mail-vk1-xa49.google.com. [2607:f8b0:4864:20::a49])
        by gmr-mx.google.com with ESMTPS id 7si60910pgb.2.2019.06.27.02.45.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 02:45:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ljauxqukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) client-ip=2607:f8b0:4864:20::a49;
Received: by mail-vk1-xa49.google.com with SMTP id s145so512120vke.18
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 02:45:17 -0700 (PDT)
X-Received: by 2002:ab0:184e:: with SMTP id j14mr1746917uag.91.1561628716321;
 Thu, 27 Jun 2019 02:45:16 -0700 (PDT)
Date: Thu, 27 Jun 2019 11:44:44 +0200
In-Reply-To: <20190627094445.216365-1-elver@google.com>
Message-Id: <20190627094445.216365-5-elver@google.com>
Mime-Version: 1.0
References: <20190627094445.216365-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v4 4/5] mm/slab: Refactor common ksize KASAN logic into slab_common.c
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CDW3O1rc;       spf=pass
 (google.com: domain of 3ljauxqukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3LJAUXQUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This refactors common code of ksize() between the various allocators
into slab_common.c: __ksize() is the allocator-specific implementation
without instrumentation, whereas ksize() includes the required KASAN
logic.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 include/linux/slab.h |  1 +
 mm/slab.c            | 28 ++++++----------------------
 mm/slab_common.c     | 26 ++++++++++++++++++++++++++
 mm/slob.c            |  4 ++--
 mm/slub.c            | 14 ++------------
 5 files changed, 37 insertions(+), 36 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 9449b19c5f10..98c3d12b7275 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -184,6 +184,7 @@ void * __must_check __krealloc(const void *, size_t, gfp_t);
 void * __must_check krealloc(const void *, size_t, gfp_t);
 void kfree(const void *);
 void kzfree(const void *);
+size_t __ksize(const void *);
 size_t ksize(const void *);
 
 #ifdef CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR
diff --git a/mm/slab.c b/mm/slab.c
index f7117ad9b3a3..394e7c7a285e 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -4204,33 +4204,17 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 #endif /* CONFIG_HARDENED_USERCOPY */
 
 /**
- * ksize - get the actual amount of memory allocated for a given object
- * @objp: Pointer to the object
+ * __ksize -- Uninstrumented ksize.
  *
- * kmalloc may internally round up allocations and return more memory
- * than requested. ksize() can be used to determine the actual amount of
- * memory allocated. The caller may use this additional memory, even though
- * a smaller amount of memory was initially specified with the kmalloc call.
- * The caller must guarantee that objp points to a valid object previously
- * allocated with either kmalloc() or kmem_cache_alloc(). The object
- * must not be freed during the duration of the call.
- *
- * Return: size of the actual memory used by @objp in bytes
+ * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
+ * safety checks as ksize() with KASAN instrumentation enabled.
  */
-size_t ksize(const void *objp)
+size_t __ksize(const void *objp)
 {
-	size_t size;
-
 	BUG_ON(!objp);
 	if (unlikely(objp == ZERO_SIZE_PTR))
 		return 0;
 
-	size = virt_to_cache(objp)->object_size;
-	/* We assume that ksize callers could use the whole allocated area,
-	 * so we need to unpoison this area.
-	 */
-	kasan_unpoison_shadow(objp, size);
-
-	return size;
+	return virt_to_cache(objp)->object_size;
 }
-EXPORT_SYMBOL(ksize);
+EXPORT_SYMBOL(__ksize);
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 58251ba63e4a..b7c6a40e436a 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1597,6 +1597,32 @@ void kzfree(const void *p)
 }
 EXPORT_SYMBOL(kzfree);
 
+/**
+ * ksize - get the actual amount of memory allocated for a given object
+ * @objp: Pointer to the object
+ *
+ * kmalloc may internally round up allocations and return more memory
+ * than requested. ksize() can be used to determine the actual amount of
+ * memory allocated. The caller may use this additional memory, even though
+ * a smaller amount of memory was initially specified with the kmalloc call.
+ * The caller must guarantee that objp points to a valid object previously
+ * allocated with either kmalloc() or kmem_cache_alloc(). The object
+ * must not be freed during the duration of the call.
+ *
+ * Return: size of the actual memory used by @objp in bytes
+ */
+size_t ksize(const void *objp)
+{
+	size_t size = __ksize(objp);
+	/*
+	 * We assume that ksize callers could use whole allocated area,
+	 * so we need to unpoison this area.
+	 */
+	kasan_unpoison_shadow(objp, size);
+	return size;
+}
+EXPORT_SYMBOL(ksize);
+
 /* Tracepoints definitions. */
 EXPORT_TRACEPOINT_SYMBOL(kmalloc);
 EXPORT_TRACEPOINT_SYMBOL(kmem_cache_alloc);
diff --git a/mm/slob.c b/mm/slob.c
index 84aefd9b91ee..7f421d0ca9ab 100644
--- a/mm/slob.c
+++ b/mm/slob.c
@@ -527,7 +527,7 @@ void kfree(const void *block)
 EXPORT_SYMBOL(kfree);
 
 /* can't use ksize for kmem_cache_alloc memory, only kmalloc */
-size_t ksize(const void *block)
+size_t __ksize(const void *block)
 {
 	struct page *sp;
 	int align;
@@ -545,7 +545,7 @@ size_t ksize(const void *block)
 	m = (unsigned int *)(block - align);
 	return SLOB_UNITS(*m) * SLOB_UNIT;
 }
-EXPORT_SYMBOL(ksize);
+EXPORT_SYMBOL(__ksize);
 
 int __kmem_cache_create(struct kmem_cache *c, slab_flags_t flags)
 {
diff --git a/mm/slub.c b/mm/slub.c
index cd04dbd2b5d0..05a8d17dd9b2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3901,7 +3901,7 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 }
 #endif /* CONFIG_HARDENED_USERCOPY */
 
-static size_t __ksize(const void *object)
+size_t __ksize(const void *object)
 {
 	struct page *page;
 
@@ -3917,17 +3917,7 @@ static size_t __ksize(const void *object)
 
 	return slab_ksize(page->slab_cache);
 }
-
-size_t ksize(const void *object)
-{
-	size_t size = __ksize(object);
-	/* We assume that ksize callers could use whole allocated area,
-	 * so we need to unpoison this area.
-	 */
-	kasan_unpoison_shadow(object, size);
-	return size;
-}
-EXPORT_SYMBOL(ksize);
+EXPORT_SYMBOL(__ksize);
 
 void kfree(const void *x)
 {
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190627094445.216365-5-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
