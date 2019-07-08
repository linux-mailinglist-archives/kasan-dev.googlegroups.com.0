Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNHRRXUQKGQEC3QRRKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B4690626D9
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 19:09:09 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id w6sf10217414ybe.23
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 10:09:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562605748; cv=pass;
        d=google.com; s=arc-20160816;
        b=OpoiyY1q1QeUwacMyY3rzTZb1G1f7/49vyeCmW3C8e4O9RD1UiVj27Eo5QzuqE4yMT
         gPbW/hj3O/oZOPzPgq6UdzDZ/Z8jeQDORM5BcJd0B+Vr0GnIsOk/mpAkcKhO/8VZ0gr3
         YVHAOtLX1yKWN2FknZAn4i7HUeN6Xd80t9VN4E5S3afoGG23UO8RwsbhsXVYkaQZ5V8f
         ZKCxnpDQjpuUwWVTt2lI78mF01kLBAWorh21j+6xVMymexifAcPQPsJmD0OgJxfpCQJy
         k1XwOb1MOq3t12AmdpksKgWKO2AHK+IxGquGOpLOUo3k3WRzcZ/tX53qwVqiPpHSSNzB
         +/Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=9v/o8D/N1nhp6DPL5/eCc3PywywfHFJGPifd6CJxud0=;
        b=V7mhU3INFjib9XbIB+da9R6QkFGbfWZFR23CHMfwnsptj/6qYmcMktj2VV6Cv41Elp
         WUq7wv5v7NQS6GaGjVvHE94ybVwb+vQIGQbAwuT5YCnhGnt6KKKspy4OcmQgctHN8o7H
         5c9G3tBTusGKS/u26q7YqoE9i/ldByeK8KbhSVRjUTDc65tYD71VGivwv4GeRCHFATe1
         BUZ5ElpJH5p70l63TCYxgk9B0V2Lr22Y6maFlmUFVMfGO/1zBba5yMfMsqMgREfB+G+O
         GA4T32cLKJqQVPgZFJQWYUTON+imNT6gxYfxzxoZImGBm7P3e2dNx6z/FFTVTRWKe78O
         DWOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=keIyX3CN;
       spf=pass (google.com: domain of 3s3gjxqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3s3gjXQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9v/o8D/N1nhp6DPL5/eCc3PywywfHFJGPifd6CJxud0=;
        b=Vitk+2Jnhc7lE2E17ovBL78kuRERCJnIkALly4R0+EywTtbcl9NR1p+CdlKV1bRk9r
         DLEb3DfDevf3KzRsJJkyDPVCN9r5m7jxDgdqgVJf1t2ehnuS05KDKvzl3RaVmneQmIIA
         5+4dCSRAJD408wF3GqZnjeaah3FumQdo5reQOO7shCRHVpit/NsWO5NUizo6lpBSwxOk
         Y1eiO0aF5e5R5b5Zg1eAxJGfFY6qqRPHsk+KoOqZTPPG5XdyUbrL3Io1Pe2G7DUB/uOn
         fQTriNCpg//FQwYOOeYzUsQEsKn5bQnTYjW5NrSmX4tPPq7iwI8vIOmzGGiMt+dw6dHA
         R88Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9v/o8D/N1nhp6DPL5/eCc3PywywfHFJGPifd6CJxud0=;
        b=ccmQWplyqmrQ54MNTb7b3Gfz5ZXNQr19aQfeQJxgZTQR9Hn9wDBgcNqrJpjwDUP3a/
         E4VZQxaxZ88XIX+3c/hhAF/nqyTwlx5JAP7bUT9RJDIA6gIZedZultbHcT2nJ9BnlCVj
         DtlbFS5+JQM3bsY/sqjf7N0LOQ7+qjvECG2nXrjEDXgpZONZ1wj/uqX/Y+wS6Y/TFmNb
         2kKH633pdJ4TdRFR/IdG66romVOSqs/NELbqnd0px/j76R6tmi/xVSfGqi2dNZj9Pg1V
         7n1Bg9l8RnTtlJQTg6Au/TErK7esBNqcLbvtObhV+MQaFes18XT62dtU1WaeiiLZBHS3
         DRag==
X-Gm-Message-State: APjAAAVs18uxE2sZeOm0U0HgMFUwvS+N155XSeIbbdkqzmPtwe6AIq2A
	PMSREl31BSHRS7EikCZwL2Y=
X-Google-Smtp-Source: APXvYqy8yOrcF+1vUHbCqBper58WHN89pFNAwcbuizqakJgrVmJyar/jIQwlYnEGoil4b5Qnh/Z0zw==
X-Received: by 2002:a25:d4f:: with SMTP id 76mr11355137ybn.353.1562605748757;
        Mon, 08 Jul 2019 10:09:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bbce:: with SMTP id c14ls2133473ybk.2.gmail; Mon, 08 Jul
 2019 10:09:08 -0700 (PDT)
X-Received: by 2002:a25:86cf:: with SMTP id y15mr4343464ybm.15.1562605748426;
        Mon, 08 Jul 2019 10:09:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562605748; cv=none;
        d=google.com; s=arc-20160816;
        b=koOQLYfH0x36DvsaAxNFMzrjByL9Vczl7+dZ8Aj9wC6ZHckwr2IzXbIUZ8A5IBvNwp
         cbbG38f3VMBxABhGc0iY9WUYUbD8L8nz21SMbbBa/WqQvxYssx9VgOEgyuY0rssygfad
         amNFEj1oKPjr1C0S3VHSr9BJ8Z4Vf8Kd9aIGuv8x8YEg0P3u4dqEOEev7e20l5tGos9h
         6CuvJH3h/r2xODI22U0mna7/tiO8mh76fbOxxZR7eJIgLc/y6iWz5Ofw+OBsErYD9lBF
         Zi4LWJ8Y6831Psoo0OqAHG9CGWjRjueLfJxfw67/pDmzFdaaT8wWlc2Pf9gp4K2B+S8m
         hc/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3eGEWBsY8dqF2V6DSZ5u38cqY6eLJM9O9Aa4+MoaYxw=;
        b=daOPUqYgvqPGu/6uP1EszIRnvfV04M0FeIpYiVUWRrYEWELyHJXxBEDC03NxzTAknV
         x8XQn/KDOImeAm4gWqSmBNp0Whh5ltVSwGer7hFJoGY8+KKukj8MKI5A03p4pg/dPXrN
         pbcvtKYPdMBDXizH0oJX72a+ZDDv9JyGmrHvvbbvX5t2ZZpQcggIH4Fd2pjLLt2lS7g4
         FcK+g1Gosi6HPzgMCZHqb31cvAN0kq1nUeiMTXHrpzdCe6EdPVj9dDrY2MqZzF3qpgIz
         mw3JNgUsanJCLgTd90UtBxNnqqsULSVo98xzYMT0pni0tYMwUIsjFTIXXgPURhSri4jR
         Jobw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=keIyX3CN;
       spf=pass (google.com: domain of 3s3gjxqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3s3gjXQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r1si889306ywg.4.2019.07.08.10.09.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 10:09:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3s3gjxqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id u21so10696265pfn.15
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 10:09:08 -0700 (PDT)
X-Received: by 2002:a63:2a8d:: with SMTP id q135mr25079867pgq.46.1562605747189;
 Mon, 08 Jul 2019 10:09:07 -0700 (PDT)
Date: Mon,  8 Jul 2019 19:07:06 +0200
In-Reply-To: <20190708170706.174189-1-elver@google.com>
Message-Id: <20190708170706.174189-5-elver@google.com>
Mime-Version: 1.0
References: <20190708170706.174189-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v5 4/5] mm/slab: Refactor common ksize KASAN logic into slab_common.c
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
 header.i=@google.com header.s=20161025 header.b=keIyX3CN;       spf=pass
 (google.com: domain of 3s3gjxqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3s3gjXQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190708170706.174189-5-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
