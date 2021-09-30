Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLVT26FAMGQEUXMDSUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id AD0FF41DDAB
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 17:37:18 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id e12-20020a056000178c00b001606927de88sf1808220wrg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 08:37:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633016238; cv=pass;
        d=google.com; s=arc-20160816;
        b=TO07x3wxZad8xqWims/AupNM+poUGEZrRE5o/Xc4KSKV5aDBdmT94+4+aN/1TYEVzZ
         DFKRRjF1dy8YS6WiG1J3BvAADwlcYHipbScO1LtdjMCdhFPZg0MzJ4KkOGMuF3fWSkPr
         0/sI4OLB6WKtgBnZktad7Y7jsfvvQPv0A7xPf6uom9nrlF/E9niSvd7UOoumOAe7faY8
         PYRjbc6fbecvgAEp6LXzTBhHYM/hchf3eMY0FS65TFjcROsyNL8jFOy7PNVfM8hGAem9
         oRXSedcfgSmw+R/xfLkHPBOtKxYZxJxEvhrLBf3BjsEcsIZTuQwhetv1t106Z5Z3Jg8R
         NvYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=b3xHEUeiObb1imWjvstFRNaczmUnxDBIENtLZRer9QA=;
        b=J5OHmoIuJfkcNRGy0GzaJyQkUVTxN8Ov7EZZm/nUoWxQTmONxxJ7DhvWsSEiiOvncX
         QvJUOucaIuZk8fLS0+rlf6hvx5DRTbTE9BffcbqGUdNhpbhix9TFeCtMSonIIe9laqq5
         9ATR4Ghi4sXp/FhrCjoSQLM1rEujy1PUHTbhppEroOR1qYQ/RHX8i2owQPVamKyJoVJ2
         2wm/+Uy56/q1FP701gady+2BQPFkRVFVx6Xo0eEVN2/EFY3QCHm68ZYU7TpdkQbBp6+t
         93W2j7ewItki7hnUCNS+rG/qjnoAvT9rZN4QaNgmx5ybhQI8dn7AGzFu89W6KYybGHjN
         czGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=agJQ6Par;
       spf=pass (google.com: domain of 3rdlvyqukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rdlVYQUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=b3xHEUeiObb1imWjvstFRNaczmUnxDBIENtLZRer9QA=;
        b=t1/KobbLP3pC/xwnxOazN+eVsEFdQSGAu/JtfCm+SjNOQfSW2OitYmW0CVXh1xY4y3
         NgIqNZtieKALBPa/qQuEuqHT/KAKixAw6xPTwIJ08I34ul7TNb1YXn1diWRARH8tndnv
         GhroNtL3PfttvXgwcUeWeT6VIL2n5Mv/VmQgNSl8Kq9VpWiCaGuqOQooQAtJ5ctk/Ixm
         bV1H4t0mXp//2n9FOPbQmISuLHt7kaWU0Ie30dlccp0rgOuFtZpLfmk0G8bIT7fpl/jf
         jgNBIETUSBx5blmPtRCj6JqZHH/VLaCGaDMlfLkA8Xq6oZj4NVyWuuTE3WZb1KYW44q+
         y2kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b3xHEUeiObb1imWjvstFRNaczmUnxDBIENtLZRer9QA=;
        b=ID0LeVEuwxiqCZ+SK1g57g0ko1yTev5ICjsn2dLy/HOyJO1VqfAzLP5yUrVQ4Pbj8s
         ItCVRJOGLIoyDQUy5HEGkXAq1KkgAFG4s1DBo8AdIkXm9DuhtjKqKhV9s8rGT6II5SNs
         0GottPzjRLbj3KbPua8+pwIoROkfLkZes1oynEyH72AV5RK8HXQZ65WG86R3g/yIB9BP
         MlEN5yjKa6MkytHli9PAGZ7u7Xgp6ph2il57aC07IyThnF6daaxK7MKKTM5WHT7i+GvU
         RrbqEX3QMfqsvC9+nfkAQgtpXyfO3IUHYZ4CbgiiakDFA7y86IUTYjbzzn7vxgtWdldi
         gP1w==
X-Gm-Message-State: AOAM531V3bUJGtMYciGrzAdzCt4UYcNvTW9eW6nIn+8+vyirza80vx2z
	STGBp8IOSLPVObCj39U9d9I=
X-Google-Smtp-Source: ABdhPJxj1pUh19zz7gyXrvcqB/sqtVmzE9Ts4C3py1e9I7aCVVJOMEaT41ih5K/l8CZZVSZw11431A==
X-Received: by 2002:a05:600c:a4b:: with SMTP id c11mr5915785wmq.97.1633016238437;
        Thu, 30 Sep 2021 08:37:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c3c8:: with SMTP id t8ls3406201wmj.3.gmail; Thu, 30 Sep
 2021 08:37:17 -0700 (PDT)
X-Received: by 2002:a05:600c:d6:: with SMTP id u22mr6009612wmm.133.1633016237391;
        Thu, 30 Sep 2021 08:37:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633016237; cv=none;
        d=google.com; s=arc-20160816;
        b=NCruTiizfcd+fJvuq4AV/fKABxqiEEKQ1Z6W8gzCvAxiBEVSi0E+VN7BzR6e4OyRQi
         ZjxArmG2PUaR1/TNMm77LUNqu4emgvAc4NkChX8PpLcwd03ryszfnwjGqt6e9oqmjtR+
         k2LPbE5Rrg6zBX8ATfG/HPRxELkm3nErOheb+CoGLPdKDuDh/sYAiz2F3lSuglm4AjCL
         JvxloypoyelOAsU9DQIP1vUZ0cLzuKpNegcIHqzJj+fd9dHQk00KWqd3KDcM7i3QKPaA
         o3SZyygnZ9vOxYs1sq8YQ6Xeen61sz4pwtVO+dL2R4TVd625RqsqaSHysd8WEzQJL9nf
         BbuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=yWAvf4aQlVR2F4yVcHUaOtHEh1BNX6MVAiZjUIr82Uk=;
        b=l8EZ3JDCRMIpbYykBep/4u3xnXAF3aJYNsdx3L2LDkeHtTMWGFzb+G+kWE+NVcjhlh
         6imdDD5f4xQN85FHOVCde1Gpnt2w4cAIaaorOb6xS707nPuA9Qn7hX/toSbc6H1mBD7F
         OFiY+U1Fan3uSx0VVnw6S2dZ/1XId8pCcbRQKU1mOe5pMcGU5Fn0m4OAJC3gJN6I3a7t
         FX2BDwCvxd+r0nxrqioVAry/0QxASE5/yDQrXZu+L8+o2mUMF9iLHhvdQT3Rjm5KoDf6
         am+z1iKW51yH3lSO4/8gvpkrvHZGU5LyOxbspk134x6xL1ldkwcjf1LiIGAAcFey5QLU
         nMZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=agJQ6Par;
       spf=pass (google.com: domain of 3rdlvyqukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rdlVYQUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id s82si110482wme.1.2021.09.30.08.37.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Sep 2021 08:37:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rdlvyqukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id a7-20020a509e87000000b003da71d1b065so6788617edf.4
        for <kasan-dev@googlegroups.com>; Thu, 30 Sep 2021 08:37:17 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4c54:2b8f:fabf:78b0])
 (user=elver job=sendgmr) by 2002:a05:6402:21ef:: with SMTP id
 ce15mr7675136edb.19.1633016237037; Thu, 30 Sep 2021 08:37:17 -0700 (PDT)
Date: Thu, 30 Sep 2021 17:37:06 +0200
Message-Id: <20210930153706.2105471-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.685.g46640cef36-goog
Subject: [PATCH] kfence: shorten critical sections of alloc/free
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=agJQ6Par;       spf=pass
 (google.com: domain of 3rdlvyqukccgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rdlVYQUKCcgsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
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

Initializing memory and setting/checking the canary bytes is relatively
expensive, and doing so in the meta->lock critical sections extends the
duration with preemption and interrupts disabled unnecessarily.

Any reads to meta->addr and meta->size in kfence_guarded_alloc() and
kfence_guarded_free() don't require locking meta->lock as long as the
object is removed from the freelist: only kfence_guarded_alloc() sets
meta->addr and meta->size after removing it from the freelist,  which
requires a preceding kfence_guarded_free() returning it to the list or
the initial state.

Therefore move reads to meta->addr and meta->size, including expensive
memory initialization using them, out of meta->lock critical sections.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 38 +++++++++++++++++++++-----------------
 1 file changed, 21 insertions(+), 17 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index b61ef93d9f98..802905b1c89b 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -309,12 +309,19 @@ static inline bool set_canary_byte(u8 *addr)
 /* Check canary byte at @addr. */
 static inline bool check_canary_byte(u8 *addr)
 {
+	struct kfence_metadata *meta;
+	unsigned long flags;
+
 	if (likely(*addr == KFENCE_CANARY_PATTERN(addr)))
 		return true;
 
 	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
-	kfence_report_error((unsigned long)addr, false, NULL, addr_to_metadata((unsigned long)addr),
-			    KFENCE_ERROR_CORRUPTION);
+
+	meta = addr_to_metadata((unsigned long)addr);
+	raw_spin_lock_irqsave(&meta->lock, flags);
+	kfence_report_error((unsigned long)addr, false, NULL, meta, KFENCE_ERROR_CORRUPTION);
+	raw_spin_unlock_irqrestore(&meta->lock, flags);
+
 	return false;
 }
 
@@ -324,8 +331,6 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr;
 
-	lockdep_assert_held(&meta->lock);
-
 	/*
 	 * We'll iterate over each canary byte per-side until fn() returns
 	 * false. However, we'll still iterate over the canary bytes to the
@@ -414,8 +419,9 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	WRITE_ONCE(meta->cache, cache);
 	meta->size = size;
 	meta->alloc_stack_hash = alloc_stack_hash;
+	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
-	for_each_canary(meta, set_canary_byte);
+	alloc_covered_add(alloc_stack_hash, 1);
 
 	/* Set required struct page fields. */
 	page = virt_to_page(meta->addr);
@@ -425,11 +431,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	if (IS_ENABLED(CONFIG_SLAB))
 		page->s_mem = addr;
 
-	raw_spin_unlock_irqrestore(&meta->lock, flags);
-
-	alloc_covered_add(alloc_stack_hash, 1);
-
 	/* Memory initialization. */
+	for_each_canary(meta, set_canary_byte);
 
 	/*
 	 * We check slab_want_init_on_alloc() ourselves, rather than letting
@@ -454,6 +457,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 {
 	struct kcsan_scoped_access assert_page_exclusive;
 	unsigned long flags;
+	bool init;
 
 	raw_spin_lock_irqsave(&meta->lock, flags);
 
@@ -481,6 +485,13 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 		meta->unprotected_page = 0;
 	}
 
+	/* Mark the object as freed. */
+	metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
+	init = slab_want_init_on_free(meta->cache);
+	raw_spin_unlock_irqrestore(&meta->lock, flags);
+
+	alloc_covered_add(meta->alloc_stack_hash, -1);
+
 	/* Check canary bytes for memory corruption. */
 	for_each_canary(meta, check_canary_byte);
 
@@ -489,16 +500,9 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	 * data is still there, and after a use-after-free is detected, we
 	 * unprotect the page, so the data is still accessible.
 	 */
-	if (!zombie && unlikely(slab_want_init_on_free(meta->cache)))
+	if (!zombie && unlikely(init))
 		memzero_explicit(addr, meta->size);
 
-	/* Mark the object as freed. */
-	metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
-
-	raw_spin_unlock_irqrestore(&meta->lock, flags);
-
-	alloc_covered_add(meta->alloc_stack_hash, -1);
-
 	/* Protect to detect use-after-frees. */
 	kfence_protect((unsigned long)addr);
 
-- 
2.33.0.685.g46640cef36-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210930153706.2105471-1-elver%40google.com.
