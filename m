Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO4LXT6QKGQES7B3DQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 764282B27FD
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:28 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id h5sf2762894ljb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305788; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZ88fcAbomJd7g1xMS2a7RuYLAUdeXLf1y5gZp6Uxlk6jJI54CCewYSHif4Pq7tpzx
         l5aqKx2TalHdPcfox1Q3hf/1XztKHiQyZCSRzskREpZp1b6eEzfyrnvkWMiwFUBR0JML
         c5DI3IKIbeIFLSLSHHuwav5sKQPTky5lNlapCw8w91WkKVu+W1ERrwLxIcukxhfYPkhg
         B9ZU8uTGpXwimVC04Wd/NjgDTVMy7SWPZPh41GG33mzHZm8O9tdoBJy1iAI5GS/6fNaK
         y6TxMfRwstsrTf8FxEUbR1qA2Z+Kxhqge338OxXdEcIYsv4Mh0BArG6Rwrbj/JQOW8Q5
         KvSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hYfEMhKrb0IY8SIWurOFO9S42RocnRgU2oiCiUCMIkw=;
        b=PzG1prb8AhYulYjvBQC2QdGYZsenh3imjy8TgpspF1bQoWH/mOaz5BHE6dQBat+4IK
         j3ytZHdnEodkgDBeVNXvcHdXYjnK5E68g1D/fco0YflyTcZxoaF/K4qpZVDHTkDLV+gn
         1WFspvNKJq2/pJUhFoENR9PQV+dLfAouveRcNYUFhvCSxxQZk8pBsgPywpVawUFJYF3n
         WOzarHfwkOVqxoHGMm9aPRXBbDz3JuXc8oU6FF0tE8/Al42oAxQoAm0DYdW6amLLKYjX
         jckxbHUAPeb0NL1dxhG8fU7d8pF57G5aM7zE4mC7o7WnLkTEj3UCXzhP6uOQ9mHTEDEI
         QhLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G4tltqsl;
       spf=pass (google.com: domain of 3ugwvxwokcyujwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ugWvXwoKCYUjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hYfEMhKrb0IY8SIWurOFO9S42RocnRgU2oiCiUCMIkw=;
        b=opGjSZ21s0M0HcciGBv/wbpPqefvR63wiG2OvQXcAmLvNzO8GoQEcUpvcGUCmTwMB7
         7kyWCFxifTSLMn+C/PWavCsuiA3APkhtMOB/38ZE+hn8kLFvh6Zf8AFNMpR/nmNoSoLP
         s/QWKXJbBBnY4mSME09WKa1XMFTmSSXcvleF2SgO3ZfQiVzcqLfxDcYTmkgQNP7jqPIU
         K+aq2PqmzA80C2HhJYPANloCVx3aX0OEP9DGKFc+OeFfBrqmKTNMTRHg9MKaHNAenwAR
         m6szCMCy2Khx/yedMB1izTTDkScCU1IeRMWo4wcsznqnNrHUW4b1GZRNheaRQqQ9rPyy
         uvFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hYfEMhKrb0IY8SIWurOFO9S42RocnRgU2oiCiUCMIkw=;
        b=VVOvpsS9HiMRJARsaI0oeaJ3AXzfXTVQZRQjg/NBHG1ES7GR35QD0rieQSwKffXxlL
         17Aut07FX51G1mWdiVnTKxhud7ucXyAwaqrIiEhT2AjTl7xHlcwczKR4l6el7ukR9Bkd
         XuSJv7oySvoFU78zEjhqt0Mmk4WL/wengEnp9vq83OGuMVGDdRYnN4X3qlACUO8Kl4da
         edhWA+9NQaeh5Lakl2ilEP65cEIv6v15zK7kFXQQyUpwFAAAvcL1rkRSWsMjEmtZ68wn
         /JSx/rmL1Fktzgp8z96OV2CcvJxxKUj2Iv+XgnmCPVSsoB/Uogg+61pr3FpJQcdat6lK
         0qBw==
X-Gm-Message-State: AOAM532xxQEjeh64VXcElnmPyqpxamS49gb34T+Mw5DBWKYy05CYtT/e
	XhGUg96lB4IW6PP92rVEXc8=
X-Google-Smtp-Source: ABdhPJxBtOdg9+s8eDiPPXP9q6Jb3bi5+xCvo4NxUgldxlyNg/inVowMbH2C5cRS+wE0CO8hhvS0tw==
X-Received: by 2002:a2e:98c1:: with SMTP id s1mr2076025ljj.30.1605305787859;
        Fri, 13 Nov 2020 14:16:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:90b:: with SMTP id 11ls1496578ljj.0.gmail; Fri, 13 Nov
 2020 14:16:26 -0800 (PST)
X-Received: by 2002:a2e:8013:: with SMTP id j19mr2017894ljg.114.1605305786822;
        Fri, 13 Nov 2020 14:16:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305786; cv=none;
        d=google.com; s=arc-20160816;
        b=uJKvHk5Ss7V5chQcedmJWmrH9FIt4AuVWyqm3UZxtFeIcioEgYkjOJmJY1zhk0QmEa
         m+UkQBHj6kho5uwz2j4M64kxrN8EfMTIGP1Py1SROZG+KGvh60c70Cafr/zkFWRRUOSj
         F45TFO/NuUv56369nImusORa1ojwnt/q1qW6Zb3ea+05wQNjOzcn0YPnmhF9ILvZJqPF
         /XeZ+wv4x9GKdQ3OT1vlUy2Zd83bIJikdnmdaDV0Z8upG0aO4WIapycYj6gc/yFH/CPn
         9865a0+oIxhvYOUqXfL4EZdRb12RouJ5YbgP7p2TC+kEl5L8QBg+uXIKvQwL1UM3QH4Z
         Jx4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hWpluxJmhfxrMPaqnk38lH69NZqzlkEZzsvdwyJIM8M=;
        b=YKQ2T3hTiv8MFOVQlw51K8Z0+InZTfMdunRuoEMUdUuu/zixae9ql5zQcioB0HckSE
         6kCMf6IdRyw6fYXkIC7Tx9K+jjpf7/Il8+5dACw163zBhkY4ccRtp+6SI3HQYszm1csV
         7lo7Sgz817uEbdfhaNQlI6ZXakWnjFLofSg60WG+DeDhZbWFmkrdDnj2yn5QW7G+/ESQ
         Y393xXM14Ke66pyTE5Pe587Mdf6g4jkRHyZB7b78c0zEG6DNYNsZ+jVm+pmkhA//bOIY
         HJS/pWo9bqrl5dvvM8ViPLZ3YgSoZXRXyYxSGrMnx1c/f9TGw1ZdJeoFqS478o5MmNUs
         astA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G4tltqsl;
       spf=pass (google.com: domain of 3ugwvxwokcyujwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ugWvXwoKCYUjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f5si137674ljc.0.2020.11.13.14.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ugwvxwokcyujwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id w5so2409736wrm.22
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:26 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f005:: with SMTP id
 j5mr6007813wro.417.1605305786198; Fri, 13 Nov 2020 14:16:26 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:33 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <c305a433db6fe8ef194cddf8615db0ef7a3b0355.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 05/42] kasan: rename (un)poison_shadow to (un)poison_range
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=G4tltqsl;       spf=pass
 (google.com: domain of 3ugwvxwokcyujwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ugWvXwoKCYUjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

The new mode won't be using shadow memory. Rename external annotation
kasan_unpoison_shadow() to kasan_unpoison_range(), and introduce internal
functions (un)poison_range() (without kasan_ prefix).

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: Ia359f32815242c4704e49a5f1639ca2d2f8cba69
---
 include/linux/kasan.h |  6 +++---
 kernel/fork.c         |  4 ++--
 mm/kasan/common.c     | 49 ++++++++++++++++++++++++-------------------
 mm/kasan/generic.c    | 23 ++++++++++----------
 mm/kasan/kasan.h      |  3 ++-
 mm/kasan/tags.c       |  2 +-
 mm/slab_common.c      |  2 +-
 7 files changed, 47 insertions(+), 42 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 26f2ab92e7ca..d237051dca58 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -71,7 +71,7 @@ extern void kasan_enable_current(void);
 /* Disable reporting bugs for current task */
 extern void kasan_disable_current(void);
 
-void kasan_unpoison_shadow(const void *address, size_t size);
+void kasan_unpoison_range(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
 
@@ -108,7 +108,7 @@ struct kasan_cache {
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
-	kasan_unpoison_shadow(ptr, __ksize(ptr));
+	kasan_unpoison_range(ptr, __ksize(ptr));
 }
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
@@ -117,7 +117,7 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
-static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
+static inline void kasan_unpoison_range(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
diff --git a/kernel/fork.c b/kernel/fork.c
index 15f189bb8ec4..bee52236f09b 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -225,8 +225,8 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 		if (!s)
 			continue;
 
-		/* Clear the KASAN shadow of the stack. */
-		kasan_unpoison_shadow(s->addr, THREAD_SIZE);
+		/* Mark stack accessible for KASAN. */
+		kasan_unpoison_range(s->addr, THREAD_SIZE);
 
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f5739be60edc..6adbf5891aff 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -109,7 +109,7 @@ void *memcpy(void *dest, const void *src, size_t len)
  * Poisons the shadow memory for 'size' bytes starting from 'addr'.
  * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
  */
-void kasan_poison_shadow(const void *address, size_t size, u8 value)
+void poison_range(const void *address, size_t size, u8 value)
 {
 	void *shadow_start, *shadow_end;
 
@@ -130,7 +130,7 @@ void kasan_poison_shadow(const void *address, size_t size, u8 value)
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
 
-void kasan_unpoison_shadow(const void *address, size_t size)
+void unpoison_range(const void *address, size_t size)
 {
 	u8 tag = get_tag(address);
 
@@ -149,7 +149,7 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	if (is_kfence_address(address))
 		return;
 
-	kasan_poison_shadow(address, size, tag);
+	poison_range(address, size, tag);
 
 	if (size & KASAN_SHADOW_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
@@ -161,12 +161,17 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	}
 }
 
+void kasan_unpoison_range(const void *address, size_t size)
+{
+	unpoison_range(address, size);
+}
+
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
 	void *base = task_stack_page(task);
 	size_t size = sp - base;
 
-	kasan_unpoison_shadow(base, size);
+	unpoison_range(base, size);
 }
 
 /* Unpoison the entire stack for a task. */
@@ -185,7 +190,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 	 */
 	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
 
-	kasan_unpoison_shadow(base, watermark - base);
+	unpoison_range(base, watermark - base);
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order)
@@ -199,13 +204,13 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
 	tag = random_tag();
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison_shadow(page_address(page), PAGE_SIZE << order);
+	unpoison_range(page_address(page), PAGE_SIZE << order);
 }
 
 void kasan_free_pages(struct page *page, unsigned int order)
 {
 	if (likely(!PageHighMem(page)))
-		kasan_poison_shadow(page_address(page),
+		poison_range(page_address(page),
 				PAGE_SIZE << order,
 				KASAN_FREE_PAGE);
 }
@@ -297,18 +302,18 @@ void kasan_poison_slab(struct page *page)
 
 	for (i = 0; i < compound_nr(page); i++)
 		page_kasan_tag_reset(page + i);
-	kasan_poison_shadow(page_address(page), page_size(page),
-			KASAN_KMALLOC_REDZONE);
+	poison_range(page_address(page), page_size(page),
+		     KASAN_KMALLOC_REDZONE);
 }
 
 void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_unpoison_shadow(object, cache->object_size);
+	unpoison_range(object, cache->object_size);
 }
 
 void kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_poison_shadow(object,
+	poison_range(object,
 			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
 			KASAN_KMALLOC_REDZONE);
 }
@@ -424,7 +429,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	}
 
 	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
-	kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
 			unlikely(!(cache->flags & SLAB_KASAN)))
@@ -467,9 +472,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		tag = assign_tag(cache, object, false, keep_tag);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
-	kasan_unpoison_shadow(set_tag(object, tag), size);
-	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
-		KASAN_KMALLOC_REDZONE);
+	unpoison_range(set_tag(object, tag), size);
+	poison_range((void *)redzone_start, redzone_end - redzone_start,
+		     KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
 		kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
@@ -508,9 +513,9 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(page);
 
-	kasan_unpoison_shadow(ptr, size);
-	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
-		KASAN_PAGE_REDZONE);
+	unpoison_range(ptr, size);
+	poison_range((void *)redzone_start, redzone_end - redzone_start,
+		     KASAN_PAGE_REDZONE);
 
 	return (void *)ptr;
 }
@@ -542,7 +547,7 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
 			kasan_report_invalid_free(ptr, ip);
 			return;
 		}
-		kasan_poison_shadow(ptr, page_size(page), KASAN_FREE_PAGE);
+		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
 	} else {
 		__kasan_slab_free(page->slab_cache, ptr, ip, false);
 	}
@@ -728,7 +733,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	 * // vmalloc() allocates memory
 	 * // let a = area->addr
 	 * // we reach kasan_populate_vmalloc
-	 * // and call kasan_unpoison_shadow:
+	 * // and call unpoison_range:
 	 * STORE shadow(a), unpoison_val
 	 * ...
 	 * STORE shadow(a+99), unpoison_val	x = LOAD p
@@ -763,7 +768,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
 		return;
 
 	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
-	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
+	poison_range(start, size, KASAN_VMALLOC_INVALID);
 }
 
 void kasan_unpoison_vmalloc(const void *start, unsigned long size)
@@ -771,7 +776,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-	kasan_unpoison_shadow(start, size);
+	unpoison_range(start, size);
 }
 
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d6a386255007..cdc2d8112f3e 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -203,11 +203,11 @@ static void register_global(struct kasan_global *global)
 {
 	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
 
-	kasan_unpoison_shadow(global->beg, global->size);
+	unpoison_range(global->beg, global->size);
 
-	kasan_poison_shadow(global->beg + aligned_size,
-		global->size_with_redzone - aligned_size,
-		KASAN_GLOBAL_REDZONE);
+	poison_range(global->beg + aligned_size,
+		     global->size_with_redzone - aligned_size,
+		     KASAN_GLOBAL_REDZONE);
 }
 
 void __asan_register_globals(struct kasan_global *globals, size_t size)
@@ -286,13 +286,12 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
 
 	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
 
-	kasan_unpoison_shadow((const void *)(addr + rounded_down_size),
-			      size - rounded_down_size);
-	kasan_poison_shadow(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
-			KASAN_ALLOCA_LEFT);
-	kasan_poison_shadow(right_redzone,
-			padding_size + KASAN_ALLOCA_REDZONE_SIZE,
-			KASAN_ALLOCA_RIGHT);
+	unpoison_range((const void *)(addr + rounded_down_size),
+		       size - rounded_down_size);
+	poison_range(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
+		     KASAN_ALLOCA_LEFT);
+	poison_range(right_redzone, padding_size + KASAN_ALLOCA_REDZONE_SIZE,
+		     KASAN_ALLOCA_RIGHT);
 }
 EXPORT_SYMBOL(__asan_alloca_poison);
 
@@ -302,7 +301,7 @@ void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
 	if (unlikely(!stack_top || stack_top > stack_bottom))
 		return;
 
-	kasan_unpoison_shadow(stack_top, stack_bottom - stack_top);
+	unpoison_range(stack_top, stack_bottom - stack_top);
 }
 EXPORT_SYMBOL(__asan_allocas_unpoison);
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ac499456740f..42ab02c61331 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -150,7 +150,8 @@ static inline bool addr_has_shadow(const void *addr)
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
 
-void kasan_poison_shadow(const void *address, size_t size, u8 value);
+void poison_range(const void *address, size_t size, u8 value);
+void unpoison_range(const void *address, size_t size);
 
 /**
  * check_memory_region - Check memory region, and report if invalid access.
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 5c8b08a25715..c0b3f327812b 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -153,7 +153,7 @@ EXPORT_SYMBOL(__hwasan_storeN_noabort);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 {
-	kasan_poison_shadow((void *)addr, size, tag);
+	poison_range((void *)addr, size, tag);
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 479d17b90155..0b5ae1819a8b 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1179,7 +1179,7 @@ size_t ksize(const void *objp)
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
 	 */
-	kasan_unpoison_shadow(objp, size);
+	kasan_unpoison_range(objp, size);
 	return size;
 }
 EXPORT_SYMBOL(ksize);
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c305a433db6fe8ef194cddf8615db0ef7a3b0355.1605305705.git.andreyknvl%40google.com.
