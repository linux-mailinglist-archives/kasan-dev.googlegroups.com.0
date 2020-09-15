Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLG6QT5QKGQET225UMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3851726AF4C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:29 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id b7sf1711330wrn.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204589; cv=pass;
        d=google.com; s=arc-20160816;
        b=c48Rz0w77tswcQ8dEdkm8I+qLLUV+3SWbfd0BDpgWTnzLNh8TKiBRbHfAc4ylo0NT8
         LewQp46OvuBUjB82GyyNuMgESPATSjfMO4r9kw3niPTGN1bIYysZ0PPlcxfu2lHuxJe9
         UUu4kaFRTF17j+84pWOgfgM++W5fgfasS302xDnBmSY8/f91FtkAdQroid9MQZVzDPea
         EKllvjDFXxn2A7TcFlkpQ0dwQ4llXoybei9Yy6XjfD8TkGcfy/x5xR9D8T1eIGoe3QVI
         iwHn4Cyqi1RSshPvGso6zB5g7fDIGqWjZEiER6UsTGlX+IIeimfNP67v+kToReFQ448P
         lETg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=kreD4oIuUKXTIpF4T/sX4zhZhggOqRMbwhIGdckSaJU=;
        b=LDTUtM5eD1ItQrpR1wLZKjDc4gP7U/0TPIsfNyq063IcQiXVnSuQLD026AN1NiUPfn
         suaFxLs8jq39AaH31bYYcZ7Q2SE413yr8qiAZQvYwaBYXzd/xOAy361V2DTaEhWAbbli
         Sxj76hBLmG6ivGxe7mscXl+AwUjbvIoSxRgsoBiPNThhrYmSPuQ5wW8JYTFmplNTiYqz
         zZZ3eibPqJUBb+aR8SbJZBpah6rkpJEMuPhZ0oc7l6TvNHN9qRMixyEOifLGJZI8EqMM
         2lW8W6McFOGcTzFUQ5Ygp/8NFK/ax6DyfGhBBauQnk2Li5zZWGvQb1dKzbpSizR4X6Ow
         i8JA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PNOD7wmZ;
       spf=pass (google.com: domain of 3ky9hxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Ky9hXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kreD4oIuUKXTIpF4T/sX4zhZhggOqRMbwhIGdckSaJU=;
        b=celJsZ76fMIxX5ZK+jC/Cv7ukgSsfEE7a+Ip2v2CrTr+UMohVsTXO8rbNQX+Exene4
         I2htbmWUJdo9QD0S3YD/i8n0RqjC4GBzbq7fwNzqV71xl8riUJ5k3n9cj+fDzjulZmWA
         mmwj5qCZwRjIYEfyoNxem0mMsfsTCMUcIn8eklRpbX2IOvFLfWzvdM8m1mYCCphwo5el
         ChExWIq0bKMKVFLgJjtm9R0s8KKZ5kMoihh9Gble1XQe1nOSGDn7tEDhzFYf6sNAMXo8
         KbqdsmprvycoHxOpm7W3s3raUk+QgW50wh6BgjZMqhbEng9CO1KBW4roiDqEtiffc2Wk
         jSeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kreD4oIuUKXTIpF4T/sX4zhZhggOqRMbwhIGdckSaJU=;
        b=ZwKnEqHEU8PzLf0urhjVIQwX8jF8OniERGJIHFPobjpU7hprkq5Du9Lk6xFbhF+8Yk
         EGpYpv6suWP/MCm0CiZboIhuowywIOx4iKst6t2uwoVEHbs8Rnb2PJ9NKGhOJACb2NAv
         ygyK04usqDAEudpUHpqw2J2P7jva8aCg+o1YfMbBoBuxCNrprIdUS9QDQYdhMZeOVtxN
         KQ+uKfsNVHa9IL7K05fl16PjKwP+j0MXfR1d2qDqllv6FC9hm+0AOLuHvlYk3M6GQGLa
         wBeJftVWC06zkqfOeS0T3dQTvuo+fhWUd9MKiRcT5lV5rZOnKY0qGsKzAc1ol7B8z81N
         Z7ng==
X-Gm-Message-State: AOAM530ZA55ipTN0/Vee5wRMQg9+PBgcECeGXkwYgO9/ZjoKMbVfMwhb
	d1dImvgPX74f3N/yGM81SDY=
X-Google-Smtp-Source: ABdhPJzj4zWOvh4Rpejaot3NLYg+Efl1nsxZnl0sRYPhVzG7pEUgQkYSgEMQiY6/EMu9SWLqJNx34g==
X-Received: by 2002:adf:e6c2:: with SMTP id y2mr24803655wrm.117.1600204588987;
        Tue, 15 Sep 2020 14:16:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:81d4:: with SMTP id c203ls101514wmd.1.gmail; Tue, 15 Sep
 2020 14:16:28 -0700 (PDT)
X-Received: by 2002:a05:600c:2252:: with SMTP id a18mr1326417wmm.154.1600204588090;
        Tue, 15 Sep 2020 14:16:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204588; cv=none;
        d=google.com; s=arc-20160816;
        b=hrlDex7z7z7t9Z9eA21AThcVdofxooSJt6bw0b8eYdO+M7euO5LE0YB6MwB8J+zOQz
         sKQ6nTuHpArQpG2vBgI8FF3vqoXB2VykehdpOdEAWTb16MZ7NDvCbOV22MJW1i/NP6fO
         glHL7J/mLO24OjemANLkeZZvBrxE5WXwdRO3y8xTq0P61qRMiHkJyr0PfeNkkmE40uMT
         aHqHoXxNFFOXB0JqzcmwBPP6seCSBCDE6fGmKLIbVG3YWavhhfdb5WOQJXcc/mOm0Swq
         mkDqHWqkNM2JlpHUqpcBzyg5wOxml9PyzCZU01iQp2L8PBxc00bazAEoZUQHKFiFpdzy
         ZXUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=4h8AUAED/J4coJrwCCrtoX8os6dI9SXh1HX4PoZIciE=;
        b=YJgqgigw7qDFp6Mg3DrCgrqf/5ELRmF1CoTZhLH9GqUtiHOryjNV4FO0AfU2VdE5S8
         X/3BdITxMCNJHNqcWdI76+etgMdJNYP0H7aw1bU1K8NW6Oorq3tmIftyEAXxpeyOSFPc
         LztPHYLO9emanuXUxiBGTbVeoYtSMUVrieC7GehHeEbSPRPDQfngDiNiiZlbQgcjJeKK
         TYEtF7xyHqFWEmnvLjhNOyXLBpxxGPijpzomTNkeWVM5EBDYM1VLmrpWoiE97W+5vQQb
         y5RX5PcieOuOobsUHyK1YFZhqbnc8fb7ziVc4GDX5RyB7WPkLtZwQfxFBStympcpPhWX
         kPGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PNOD7wmZ;
       spf=pass (google.com: domain of 3ky9hxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Ky9hXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id n1si13858wmn.1.2020.09.15.14.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ky9hxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id q205so392467wme.0
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:28 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cc84:: with SMTP id
 p4mr1290068wma.58.1600204587590; Tue, 15 Sep 2020 14:16:27 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:44 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <34bc63b581b206b914919c7371cf021bcf26294e.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 02/37] kasan: group vmalloc code
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PNOD7wmZ;       spf=pass
 (google.com: domain of 3ky9hxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Ky9hXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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

Group all vmalloc-related function declarations in include/linux/kasan.h,
and their implementations in mm/kasan/common.c.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: Ie20b6c689203cd6de4fd7f2c465ec081c00c5f15
---
 include/linux/kasan.h | 41 +++++++++++++----------
 mm/kasan/common.c     | 78 ++++++++++++++++++++++---------------------
 2 files changed, 63 insertions(+), 56 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 087fba34b209..bd5b4965a269 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -69,19 +69,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-/*
- * These functions provide a special case to support backing module
- * allocations with real shadow memory. With KASAN vmalloc, the special
- * case is unnecessary, as the work is handled in the generic case.
- */
-#ifndef CONFIG_KASAN_VMALLOC
-int kasan_module_alloc(void *addr, size_t size);
-void kasan_free_shadow(const struct vm_struct *vm);
-#else
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
-#endif
-
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
@@ -150,9 +137,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
-
 static inline int kasan_add_zero_shadow(void *start, unsigned long size)
 {
 	return 0;
@@ -205,13 +189,16 @@ static inline void *kasan_reset_tag(const void *addr)
 #endif /* CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_KASAN_VMALLOC
+
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
 void kasan_poison_vmalloc(const void *start, unsigned long size);
 void kasan_unpoison_vmalloc(const void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
-#else
+
+#else /* CONFIG_KASAN_VMALLOC */
+
 static inline int kasan_populate_vmalloc(unsigned long start,
 					unsigned long size)
 {
@@ -226,7 +213,25 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
 					 unsigned long free_region_end) {}
-#endif
+
+#endif /* CONFIG_KASAN_VMALLOC */
+
+#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
+
+/*
+ * These functions provide a special case to support backing module
+ * allocations with real shadow memory. With KASAN vmalloc, the special
+ * case is unnecessary, as the work is handled in the generic case.
+ */
+int kasan_module_alloc(void *addr, size_t size);
+void kasan_free_shadow(const struct vm_struct *vm);
+
+#else /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
+
+static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
+static inline void kasan_free_shadow(const struct vm_struct *vm) {}
+
+#endif /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
 
 #ifdef CONFIG_KASAN_INLINE
 void kasan_non_canonical_hook(unsigned long addr);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..d1c987f324cd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -541,44 +541,6 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
 	/* The object will be poisoned by page_alloc. */
 }
 
-#ifndef CONFIG_KASAN_VMALLOC
-int kasan_module_alloc(void *addr, size_t size)
-{
-	void *ret;
-	size_t scaled_size;
-	size_t shadow_size;
-	unsigned long shadow_start;
-
-	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
-	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
-	shadow_size = round_up(scaled_size, PAGE_SIZE);
-
-	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
-		return -EINVAL;
-
-	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
-			shadow_start + shadow_size,
-			GFP_KERNEL,
-			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
-			__builtin_return_address(0));
-
-	if (ret) {
-		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
-		find_vm_area(addr)->flags |= VM_KASAN;
-		kmemleak_ignore(ret);
-		return 0;
-	}
-
-	return -ENOMEM;
-}
-
-void kasan_free_shadow(const struct vm_struct *vm)
-{
-	if (vm->flags & VM_KASAN)
-		vfree(kasan_mem_to_shadow(vm->addr));
-}
-#endif
-
 #ifdef CONFIG_MEMORY_HOTPLUG
 static bool shadow_mapped(unsigned long addr)
 {
@@ -690,6 +652,7 @@ core_initcall(kasan_memhotplug_init);
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
@@ -928,4 +891,43 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 				       (unsigned long)shadow_end);
 	}
 }
+
+#else /* CONFIG_KASAN_VMALLOC */
+
+int kasan_module_alloc(void *addr, size_t size)
+{
+	void *ret;
+	size_t scaled_size;
+	size_t shadow_size;
+	unsigned long shadow_start;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
+	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
+	shadow_size = round_up(scaled_size, PAGE_SIZE);
+
+	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
+		return -EINVAL;
+
+	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
+			shadow_start + shadow_size,
+			GFP_KERNEL,
+			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
+			__builtin_return_address(0));
+
+	if (ret) {
+		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
+		find_vm_area(addr)->flags |= VM_KASAN;
+		kmemleak_ignore(ret);
+		return 0;
+	}
+
+	return -ENOMEM;
+}
+
+void kasan_free_shadow(const struct vm_struct *vm)
+{
+	if (vm->flags & VM_KASAN)
+		vfree(kasan_mem_to_shadow(vm->addr));
+}
+
 #endif
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/34bc63b581b206b914919c7371cf021bcf26294e.1600204505.git.andreyknvl%40google.com.
