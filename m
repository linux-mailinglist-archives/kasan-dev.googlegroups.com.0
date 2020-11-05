Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNECRX6QKGQECJ6IXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 143962A7379
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:01 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id n207sf136302lfa.23
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534580; cv=pass;
        d=google.com; s=arc-20160816;
        b=kkW8ox3DmHx0GWibmWSh8IUwMQvzBLO5EQdX+1+vuhHjSVuAbifftZmgA5zLjg9Pph
         YsYzSAuJTb72tvUGmTUnKvDtJOu5l9FeVCHRE0WLJRknZ7iV0B4hxryBaQ6vl0ZIu7XI
         wBk3siUpe3oMzb8kiOdJRVPGVlyldX44uPviS6Yktzau7DHatrQ7a69kQg4YQIp/LPT5
         k+CnDt+I1WZVUYxhGq4mN7Q3NiRotCGgbXoG3pT7DWbRg33Tgatx+7aSqaGhGqO2SQ14
         vreNLzKoTHfVMu9x1YPiqgEkPjtal7Yl46wtoGFkGIPNgLS3Re+HHrM5HCRSQSvZVXJD
         b99A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=GbNLH0w94EzHdSfkF2sM9Aptiqoekjc+2UYk+5JcKOs=;
        b=umPLbi3p7wnf9mrzVBBQ3aFJLfTReiIQwvzj/SUeHuYETRCu0zLBxSo0Uj3DUVrNhE
         upRi8TNeotxZmnC8bom/hFycVciEjed5s1rFH0HSCMUpRk06bvJ2cT3BMioEx8mIwpHu
         qQjJd5/EMo9cQ7viXF6j/IGJclQljbHdxgHR5jWuViHscYqR9TqsGUwitRauwissJIxB
         uVchnFKjA9j7g9Kg1sqsoqcxdv7yjum0ModLNlKQ3imJG4l8vk9VSm/AR339/15V92lC
         rDfsJFYLMwgvzE2zMOge1pSZzEt4MR86HnmXn4tkwUaGgn+RtiHEMSrZAQBgMxiJzHqY
         AegQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iH4SUzBB;
       spf=pass (google.com: domain of 3m0gjxwokcuyivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3M0GjXwoKCUYivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GbNLH0w94EzHdSfkF2sM9Aptiqoekjc+2UYk+5JcKOs=;
        b=WaAjrqzASAa0179zwtRcLR9ToJKG75HsoGS9pbJro4gXPKJIu4KvFMOpB0tp0NXYrb
         0I/4QGajJbiAi0a3G9nC9ZHBU1WrMws2Fiw2JJyAxcKplqK0mIBsZkKjhbLvQ/vuM64r
         zn1gtnFEf7JBR5zoiKom/97+OU42CYfpWBAR2Dxz9qbGsZq8tjRK7d4+bW+dIUsI2hup
         qglC5ZP1d5nKSzy1YwL/sNgft2qZCLNuwHz5LZJnxBaJ9EzxkpgzaXCE74pq3MXWaTBo
         mDMfw6ccIISycqFfDW+L3H98UAjLvmecdakE4eHrXVO12pP7Uzf/nrp6tpyDDiA0hkXR
         uejw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GbNLH0w94EzHdSfkF2sM9Aptiqoekjc+2UYk+5JcKOs=;
        b=OL45pZK9+Zsuf/xOYo7opLgfBH7VFFnUvoxfOrwdks9bzwyi4oG7kvSLij18RNuhdS
         NlnBEUt9nYkxl6RbT1x0jNE8SgyFoim53U+9RmwAymBAzixT7LKovDR/ZCeTPHwAmAY0
         jBhen6zXeUMtunql+EAp/tbD43QGH05ZXW6FQwpXIiBY7XBSSJKMzhWZQrJPSzSvVVuN
         r8CiY+7C5yEIjLrb8vW9XyszKUix3ziXF38n8wtU8sH+UgcwtDGvCyW4mWzDzd/13zKS
         KRvJElt2qzw9lxgVfQ3g3GpuyDpuAz0PA/LlmnnIh1MsqvEah34LO1bMYKytntffYa0I
         K11A==
X-Gm-Message-State: AOAM530L40wteAulpY/kbBPBW7WipCNGzGGh+dCwxR+bE+xZlZdnXfLu
	LCE+pDiDjxnWc+Vz7Yn7gXM=
X-Google-Smtp-Source: ABdhPJxnVWHl8JT/aF2CYehlsVPlei6e4SP6Eq0EffhK1NwVF51kyvk6EIx6KhAgQHK8h+vbAlQVbw==
X-Received: by 2002:a05:6512:3708:: with SMTP id z8mr84452lfr.376.1604534580654;
        Wed, 04 Nov 2020 16:03:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls2304493lfd.3.gmail; Wed, 04
 Nov 2020 16:02:59 -0800 (PST)
X-Received: by 2002:a19:7f48:: with SMTP id a69mr70314lfd.379.1604534579625;
        Wed, 04 Nov 2020 16:02:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534579; cv=none;
        d=google.com; s=arc-20160816;
        b=AIM4FWdUnxWgUJNY4r+8qdVrKiTsSyGxDgdcc8MsuWHXz/eyoxrzbbt0ql0iK16TuJ
         lSNcsRHtpDHiuhs9FAATeAVWDPjDDl+hzt4V/2u75PrdOduMVIctn841hGTcRGIX5Ico
         QqS7DhjF4t4z5UMEag51/Vj4yOXVCeFWAzzpzeea0I0QqkobbokVNqOUfpipAau8clw3
         RoWSCD1qlGQNxKDW0JYlLjHyBqxxIJTniqg622JTcA/giwdQ84HfCa0p5f7RqXbglxN1
         veHkW2O95M2+GAeys0EMtb1pvprEeEDKK046+jYeNs2w7sQ0QoOaEE7Foj7Beub79uOL
         9TCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IR+L7pzOJ3S8sSm3PMiXuYbX9hdb+iZBoVgJRWY7cXM=;
        b=ZkF7JomPC4W+wrkzKQckT7rZZkdn89UEkvmvx3RHgiZCU5iotah2eXbUro0G/WF481
         AI2cg4hMvHWBqdWvo6M0oIyRVT52XdaoB7x4o70bnPFUUTTxxezBKwWfkZfzb6Z7kCm1
         XTuaJAOftJYOX8hpuCtzsQ6a4LXdsCKrEUS3ttmIm0VsJeGDQTaKw8EVwlfxSBafiPBm
         YwAHAkTQmxlIBdB03MA1yxhOaLenOL3LcfuTNJPHY60CVCXJUHxJdUFqprrBp0JSrQmd
         UCsvPjvP3XnNkfRJEVCJ2JJwjyLFLn+86fg3fuzBa0CE6R1vsuqTjbTvzEowaoLpkzKz
         UfmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iH4SUzBB;
       spf=pass (google.com: domain of 3m0gjxwokcuyivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3M0GjXwoKCUYivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id h4si83392ljl.1.2020.11.04.16.02.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3m0gjxwokcuyivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id l16so1440wmh.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:bc08:: with SMTP id
 m8mr185656wmf.137.1604534579112; Wed, 04 Nov 2020 16:02:59 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:20 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <82219b5988592173ba4fbf07abcb7009e3d7265a.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 10/20] kasan: inline and rename kasan_unpoison_memory
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iH4SUzBB;       spf=pass
 (google.com: domain of 3m0gjxwokcuyivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3M0GjXwoKCUYivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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

Currently kasan_unpoison_memory() is used as both an external annotation
and as an internal memory poisoning helper. Rename external annotation to
kasan_unpoison_data() and inline the internal helper for hardware
tag-based mode to avoid undeeded function calls.

There's the external annotation kasan_unpoison_slab() that is currently
defined as static inline and uses kasan_unpoison_memory(). With this
change it's turned into a function call. Overall, this results in the
same number of calls for hardware tag-based mode as
kasan_unpoison_memory() is now inlined.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia7c8b659f79209935cbaab3913bf7f082cc43a0e
---
 include/linux/kasan.h | 16 ++++++----------
 kernel/fork.c         |  2 +-
 mm/kasan/common.c     | 10 ++++++++++
 mm/kasan/hw_tags.c    |  6 ------
 mm/kasan/kasan.h      |  7 +++++++
 mm/slab_common.c      |  2 +-
 6 files changed, 25 insertions(+), 18 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 0211a4ec5d87..34236f134472 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -72,14 +72,15 @@ static inline void kasan_disable_current(void) {}
 
 #ifdef CONFIG_KASAN
 
-void kasan_unpoison_memory(const void *address, size_t size);
-
 void kasan_alloc_pages(struct page *page, unsigned int order);
 void kasan_free_pages(struct page *page, unsigned int order);
 
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			slab_flags_t *flags);
 
+void kasan_unpoison_data(const void *address, size_t size);
+void kasan_unpoison_slab(const void *ptr);
+
 void kasan_poison_slab(struct page *page);
 void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
 void kasan_poison_object_data(struct kmem_cache *cache, void *object);
@@ -104,11 +105,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-size_t __ksize(const void *);
-static inline void kasan_unpoison_slab(const void *ptr)
-{
-	kasan_unpoison_memory(ptr, __ksize(ptr));
-}
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
 bool kasan_save_enable_multi_shot(void);
@@ -116,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
-static inline void kasan_unpoison_memory(const void *address, size_t size) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
@@ -125,6 +119,9 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
 
+static inline void kasan_unpoison_data(const void *address, size_t size) { }
+static inline void kasan_unpoison_slab(const void *ptr) { }
+
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -164,7 +161,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #endif /* CONFIG_KASAN */
diff --git a/kernel/fork.c b/kernel/fork.c
index 463ef51f2b05..d6ff6b5650aa 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -226,7 +226,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 			continue;
 
 		/* Mark stack accessible for KASAN. */
-		kasan_unpoison_memory(s->addr, THREAD_SIZE);
+		kasan_unpoison_data(s->addr, THREAD_SIZE);
 
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a266b90636a1..4598c1364f19 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -184,6 +184,16 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
+void kasan_unpoison_data(const void *address, size_t size)
+{
+	kasan_unpoison_memory(address, size);
+}
+
+void kasan_unpoison_slab(const void *ptr)
+{
+	kasan_unpoison_memory(ptr, __ksize(ptr));
+}
+
 void kasan_poison_slab(struct page *page)
 {
 	unsigned long i;
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9d7b1f1a2553..bd8bf05c8034 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -26,12 +26,6 @@ void kasan_init_hw_tags(void)
 		pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void kasan_unpoison_memory(const void *address, size_t size)
-{
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
-}
-
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 73364acf6ec8..ba850285a360 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -279,6 +279,12 @@ static inline void kasan_poison_memory(const void *address, size_t size, u8 valu
 			round_up(size, KASAN_GRANULE_SIZE), value);
 }
 
+static inline void kasan_unpoison_memory(const void *address, size_t size)
+{
+	hw_set_mem_tag_range(kasan_reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+}
+
 static inline bool check_invalid_free(void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
@@ -291,6 +297,7 @@ static inline bool check_invalid_free(void *addr)
 #else /* CONFIG_KASAN_HW_TAGS */
 
 void kasan_poison_memory(const void *address, size_t size, u8 value);
+void kasan_unpoison_memory(const void *address, size_t size);
 bool check_invalid_free(void *addr);
 
 #endif /* CONFIG_KASAN_HW_TAGS */
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 53d0f8bb57ea..f1b0c4a22f08 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1176,7 +1176,7 @@ size_t ksize(const void *objp)
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
 	 */
-	kasan_unpoison_memory(objp, size);
+	kasan_unpoison_data(objp, size);
 	return size;
 }
 EXPORT_SYMBOL(ksize);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82219b5988592173ba4fbf07abcb7009e3d7265a.1604534322.git.andreyknvl%40google.com.
