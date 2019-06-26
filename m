Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOWHZXUAKGQE3ZFPOBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE79B568A1
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 14:23:23 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id t14sf5330686ybt.5
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 05:23:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561551802; cv=pass;
        d=google.com; s=arc-20160816;
        b=m9rgMvSCfvtJEdlYRcQHU5S37+wwz5/Z9bbE3VjnxDIxlXiLauV3pJf4HhYXrqxkK7
         YvEY8wuJRyNV7EFbotFCqPz8OST5EuaNup/tLGCuPLjYB2g+ECVDLDsa6KlUFnDngwrN
         WiFBpKGIWO2sHL3kd3JIiZcVU7J8rxiCsdWfMcp4rhEFvN0gCsglf1UT4CJ5mbwYC07s
         iTmH9+avRLfDe/TsvNQ5bVkKAdjULObHi/ttfMhb+6LIF1xoyD3aBObzPK/q0cq3aBzT
         KZoVVZdjdF9f+VL9teCklcEc5uSyl3pBmcN6fTw8S8ZGsQIynEzvZ0PttED/Ghc32I2l
         8/6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=dR87/D1PVb3+rd96+KPlxFHc25Y1ccbZNgLa2d0dFzc=;
        b=tfW5D8QqapDswTu23bPsU8tszOv6sTu5WF/wy7l4xcDF9+7HSSSIPIKJx1N962JA4v
         /9jyH3a5eb3dWZYjdKbOBL8+qp9GMIUylZy79+Gby+vF2OVd1IEejjPVOwHADjUmMKac
         WYO0mJkPiNpo18Ogr2r1VCBZjVspEHeluU2KPNnChZqEyXAProzpJGcjOLI7QXtsUgXE
         CSDbhkNYV69TBmdtJ6A9cWqruUp6WzQPefGLlco+T3EAcIFXl9YcC9ByHUqsvUkRHsEN
         ex29aSCWk0xg3cFPJq+zBTvSlkRnaP7UpDTpV1fIyAjtfGe7QdOaUZTD3UorTpJxAalM
         I4gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WjjQYoJW;
       spf=pass (google.com: domain of 3uwmtxqukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=3uWMTXQUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dR87/D1PVb3+rd96+KPlxFHc25Y1ccbZNgLa2d0dFzc=;
        b=FlUmc+JPZORnl+6V0s8NIJ6w/7e4UZE1jLoCK0vN8iW8hFv4SaOWURnHs3Ipc1zBaQ
         4WTZJf61MWZVAhNyTONqGUM9Z7G1IfIwfDXqADBpJhdSIRR9+ii6UMFl4WpQJ+Uy02GW
         kmrJhSKhiGXjzwqIvpIYPosD9ojezy+u1w7/991b0xDvkP8/TsEJcuN/4LUs+9mv/4HG
         cLwCwhvsG4Ud9znAkq2LJbKBJ5/IUbfMm9Xfxnnd6EZ0KEt8jXbkpgn0rBgMCANqiqUS
         hn6pK7xcdAbcHJQ0BOpTqFMv6dBP41uma8s7+zIZP61Xos3agRWprRRvwA8pVGJAa/ey
         iIXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dR87/D1PVb3+rd96+KPlxFHc25Y1ccbZNgLa2d0dFzc=;
        b=GmabXiMEEFsS/aWPCiOuhduaGC8YA1H4DyWxDcAyunReILmllgL1Bwtk3Dr9jc0/v2
         jX9C4idsgYCwE47H6jfvB4sOBe5JMVhHADe28UafgU6Iqf8OFHCW0c/oR3HoNSMRmDrh
         XGu2ExSZ9M8KKfBOMmeS0gSr7Pemk+h4TK2xN2O/2bSfjf5zqpGtvB98QOlql76h1Kio
         1llzCYCPPwX6d59flg0s0pV2LsRjLJUGNX1Tmkgrb7lt51PfO45MzTMIrkz2xOkLienO
         s6krnN/sZgqPebIQOXXBjY3PrcWlrZ/82akDbUDXs7s+zLtWcmTzrJGuf5wNXQ1x55k2
         CEFw==
X-Gm-Message-State: APjAAAVsdmvXknf9SLFSlLvF7Bpv9gUozQ54S3GQAhtA80OdpRcarI0h
	OQokUFiVIhxo8fve8HtWY+8=
X-Google-Smtp-Source: APXvYqwX/SxH5eM0lzuBzPwT3LWSiIbVtkOZ2JEZ6Q4sA22FXpic/U6tE8uzlb8AAEr5k4iWvRtJ6w==
X-Received: by 2002:a0d:cc47:: with SMTP id o68mr2612032ywd.62.1561551802520;
        Wed, 26 Jun 2019 05:23:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5f10:: with SMTP id t16ls265360ybb.8.gmail; Wed, 26 Jun
 2019 05:23:22 -0700 (PDT)
X-Received: by 2002:a25:da42:: with SMTP id n63mr2694935ybf.16.1561551802207;
        Wed, 26 Jun 2019 05:23:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561551802; cv=none;
        d=google.com; s=arc-20160816;
        b=rf5K74klL0wWVv7TmXRJy6X8TPPIM5cYiryySqHR1E58ScjkY8LF6jopsmcXB22hW4
         hpYQ6BncFPL3tSvSKHwbwOX0Tlr/MoRVIZFbwY2lZHLQs+kWgst8+o/kmLbNT4TBnWtD
         fOcwQYGIv1mgP9JVmvt+ru3Io0lnrpOdzSwjzQAQleR5SMAoRADUW1gdR5ndSWugLk+N
         5j6MbeqIdj0/LfL8eEtQjgvjyeALPYsJCH9z6M5Ru+Y7c8+HdzLc9f+RUXPsT/kLkAhz
         dTVx1P8EkSp69Y7oqI32Fa9fcVRNlr15Cs7iZ8NnBrCxJYWUvT2oFLq54cD5gT9G1gu9
         wGaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=kb82UguIVlhbKp5QqiDOlo6WFZGIh55p/2yvAOGPdkY=;
        b=av9W3zNmTu7Y96Qk2KyoyP0FQLLZJhpur3/P0OP8HMblmAKgbIbUh4a0LpZ4SSAFIE
         0W3vVvUUJ4LAgeCoQkcZAITErka6Iar4ixUlutXc5z96s+yhHYzKwPNqwNVifCKmLaOX
         bYgadyhlbn3GQ+o6s1/SaYVOxPk1lbiWUJl5ubXiLPxGwouYLn2td7S39bCKtyuJq0r+
         XKDwCQS4VQspcQS9AiIQXHlpgOF9Y55jOJMlxU4j+Hw400hNOzkvrTzoM1yaam24iufk
         2CsMHgK4mWu+e/eR04IdU5VXP0r9mhXiMlrzb0s9WEYUMvlah5kuaLrXB4qqrzyNNQC6
         DaOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WjjQYoJW;
       spf=pass (google.com: domain of 3uwmtxqukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=3uWMTXQUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe49.google.com (mail-vs1-xe49.google.com. [2607:f8b0:4864:20::e49])
        by gmr-mx.google.com with ESMTPS id d16si1070272ywg.5.2019.06.26.05.23.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 05:23:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uwmtxqukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) client-ip=2607:f8b0:4864:20::e49;
Received: by mail-vs1-xe49.google.com with SMTP id i6so410204vsp.15
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 05:23:22 -0700 (PDT)
X-Received: by 2002:a67:f2d3:: with SMTP id a19mr2676462vsn.240.1561551801607;
 Wed, 26 Jun 2019 05:23:21 -0700 (PDT)
Date: Wed, 26 Jun 2019 14:20:18 +0200
In-Reply-To: <20190626122018.171606-1-elver@google.com>
Message-Id: <20190626122018.171606-4-elver@google.com>
Mime-Version: 1.0
References: <20190626122018.171606-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v2 3/4] mm/slab: Refactor common ksize KASAN logic into slab_common.c
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com
Cc: linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WjjQYoJW;       spf=pass
 (google.com: domain of 3uwmtxqukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=3uWMTXQUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626122018.171606-4-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
