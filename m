Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5UBZ3UAKGQEYL45H5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A21156BDC
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 16:28:07 +0200 (CEST)
Received: by mail-yw1-xc38.google.com with SMTP id y205sf5244571ywy.19
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 07:28:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561559286; cv=pass;
        d=google.com; s=arc-20160816;
        b=pwQcN4wjcrT/FWA4S01dsmvMutiS3cvoL5IJ2JNWVVf1its8V3zCMFg4kR/enYv2WT
         dvnDlpgB/RA9K1OsXdeToKm+fisLekCm2azDzisWH0wSluHLhbte0nCIodCsmLppoLJU
         ZaMEJYLSK6yTlTQnY3YQzg+VPYMik0uAS3UoVJ/HWn/POSXX4O8hklqbj/cBPAhRukbF
         CEToOBaWv1TvORpI3NhM4/F0O1S3o/PxmYboYQ3rZagW3dkZ+n1oKnHfomAE1b/ojH1H
         2Ngm0B8ulIA0WDUTGCHZiIFMIAoSTjnwT3NvA5BdYpDG+iXPf4KYKtYsWPuDt6yhg+5Y
         bE+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=mEXSgkv7OS47aEzMG4ZfHs2ybTdz6NDQG4/9GsW3aMs=;
        b=wzZ40wuaqg2cvg1YcZOH4Pxl14X7DWBouwSfmh+K7JaTNs+7Rtyjx6RHHMjUa3Pq6K
         n6gwe/u8iluV86hCUTM7nHRckL0r3GYH+BQxMnuv/UIQZnWBkkAC9rm3+iFWEpzqeKPw
         uhnTPlCsmtHhhYaXdBwUjG2qLtdLuex0qpG9G4rUSwYUUM4gypB7FGyAbLnuQ/kopILW
         GhP+X2MeqTdRulBa9iK4GuZ2nPN0F4LwHcSGh0f3fRXlqG5QbKyTChlhda86jwEes5YM
         3b3qcdQhUuKD/7Bq8V8MsOj25NZmHkVd6faXU0IaoyABd4Nl61ZNvFYPUptsoFfERCAd
         itpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="u/9U+nio";
       spf=pass (google.com: domain of 39yatxqukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=39YATXQUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mEXSgkv7OS47aEzMG4ZfHs2ybTdz6NDQG4/9GsW3aMs=;
        b=taXMSpZuKhRqVHzislsQg8o7c5dGjLDLjknQVg3DS3vkHDj8+rKmEbe6a8o8N9lemY
         yrInSYg9tDJcZto5c717P1ew1sismWyelN4u68AXyM0nQdzJmGR9Bp+YG/k5xkMStD4U
         JopVZDD3k1PRvnUNgjzAJSVyrfHM7oAgVT36WNvf//KiA+UuzWjd8AsZUL5V5PRWqtVH
         ABZr2SxScEUfXgkKdxfo4CI2a9/v2TY43957UWE0MkByArJufuJRlW/nFrfNs/c2D8q4
         Q1NilaJxSxmRLgg+AUQQMjZQum9tEfnYXhUUBW5dvjsNPWw/2njuTf9pAd0Tnw4SVp0I
         JMIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mEXSgkv7OS47aEzMG4ZfHs2ybTdz6NDQG4/9GsW3aMs=;
        b=Ck/Y7TI5aIzuJ8aF41QRAhyNc2b/029/grhWDquAwZE56VK0OeZSgmgCR8c9ng4s4X
         AzT2FuaOYLRAtokLEnAhBPQGMpB9V7/LGMf8Prg+QnLu0N8SkPA4u3gBIeySv0QWyOQa
         Aol4BrIbKoG2yAteprvmFEKS0prK68z91Ltu8StWb8ivYGYysSdqja+/Wx+DrbyGyAjm
         S5OgCKsdEb17rSfcWFy//iRIWPBWWcKAjpiI1tlzcdDhIMgP3IsNPD0R6KvoOEmlnhhq
         WBRo+RhJB9Mgc1TmdyAcvdHI4ffxxOYWLu4qDqRJWCwqfascTQ6UyksusqKKyUQhVNbC
         /vNA==
X-Gm-Message-State: APjAAAWZYtS4WKKR6uXdA+4yILLp05IzE+GS2Q947ek99PUMqsTkNYjV
	p98BDRTM1QxAzgflh6g7NHQ=
X-Google-Smtp-Source: APXvYqyBuo76o2U5SLHodb7B7my9OsHHdD+TZIDMjvkQRb0akIhVIMP2l/wJ6tGmnVY533UuXpVEvg==
X-Received: by 2002:a25:d3c8:: with SMTP id e191mr2981731ybf.66.1561559286695;
        Wed, 26 Jun 2019 07:28:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:6904:: with SMTP id e4ls283696ywc.14.gmail; Wed, 26 Jun
 2019 07:28:06 -0700 (PDT)
X-Received: by 2002:a81:3bd4:: with SMTP id i203mr3039154ywa.116.1561559286360;
        Wed, 26 Jun 2019 07:28:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561559286; cv=none;
        d=google.com; s=arc-20160816;
        b=CpkNfJOZ1lh1z9g5JaOWwu4tD8eTJ1Vz4RAkYsq8550yQWLKhBy9ofMNh+473GmVlR
         GhItS5zx/+muGw+83Vj39298nVFSFMox3rF2tGze8sBAP4RxiVml06o8ZPyL+MK6adAk
         /nNUyMMFGoaqQPQl+VJaaOkjQfAt0w9sD2S47ut1nvGMH2b5+yeRoKFNMZE6s/2jINVx
         MXZM/GgLR5W5lecEwxyl/LBYLh+ff5Nb4XYb6tf9+NQUUyB4bHWSwY6VUUWqiDzWdAwt
         NlGCUJRJA2Bo4ORxcC6pObhURIpHP1wkni2gIkkSp9W2JNLvWotFf2Gyuiv21uZULMwv
         meNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3eGEWBsY8dqF2V6DSZ5u38cqY6eLJM9O9Aa4+MoaYxw=;
        b=i5KayI0oOCYIVUwCecfR1hdU9iRYjEJeVSn93QgB3b1ubNRurqCMngzjhU/nDEJdSh
         aeen/BImIdRqVcAz0pFgBU5qwYd9zDYXYx2zfMGP1Dmnt5qBqr1Ede0i82LJ7vanbsgQ
         r2XrpIu/hGMVYwh2E12QRiTRIU7i4MLIAzNhyxwkRvLhblrD2hw+ZsD5Av9WL1HrJMrX
         v/f7rvlKi1OUy0NCf/NZH5xEjy0UoPyaJvEFfPPV1kFidBeYLrkHLQSf5SLCbn23ejiO
         MYo4IIG+/M+4QZgfowiWxCA9VrdwcSoF+XxGOycN4cW/yOzKKdlBegivR06Y+pASFvy/
         SSsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="u/9U+nio";
       spf=pass (google.com: domain of 39yatxqukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=39YATXQUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id d16si1092699ywg.5.2019.06.26.07.28.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 07:28:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39yatxqukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id v9so527616vsq.7
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 07:28:06 -0700 (PDT)
X-Received: by 2002:a1f:14c1:: with SMTP id 184mr1327869vku.69.1561559285813;
 Wed, 26 Jun 2019 07:28:05 -0700 (PDT)
Date: Wed, 26 Jun 2019 16:20:13 +0200
In-Reply-To: <20190626142014.141844-1-elver@google.com>
Message-Id: <20190626142014.141844-5-elver@google.com>
Mime-Version: 1.0
References: <20190626142014.141844-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v3 4/5] mm/slab: Refactor common ksize KASAN logic into slab_common.c
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
 header.i=@google.com header.s=20161025 header.b="u/9U+nio";       spf=pass
 (google.com: domain of 39yatxqukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=39YATXQUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626142014.141844-5-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
