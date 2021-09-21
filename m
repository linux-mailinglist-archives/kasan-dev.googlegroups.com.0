Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEO7U2FAMGQEPMDCHYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A40441314A
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:10:25 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id m1-20020a056000180100b0015e1ec30ac3sf8375839wrh.8
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:10:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632219025; cv=pass;
        d=google.com; s=arc-20160816;
        b=kTN79nTe8tYaPi75nO5GTr5QFbBRmepMUcvs66qsvEPSVe2l/s2fidTl8Iki9TgmH/
         ZpST/BIJUpR8estUBiDp9JciU9HLiSrD7as6nGSulr/O3DnaT0PJAI0cSn1VmYlAkCsH
         +jWqbX0hBZ409AvyIyCxhQyo6CyuYCxuBLkWrkAmAkcxeHbxgOjSNHT7aZP1knqeLb0h
         MBHhJz9biCAK/fkR0WNwRKNEqA552SrjTXdm0tiIXuycwnw6DbkZl0s9PpPvqrRd6Yj0
         LQlmOZu1ezZ4fyoGfTr5SOCVPMQ2wzeGwkwJwLJLIkKJWG1iNgZgr4pAgs7Ri5/fQSMt
         21wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=O36f25bpnVnezkyumCg1vTvewow5r9lj9RcGvdoJeME=;
        b=e38t4LJ1iABYfRye0aIG2hw7RdN92x+wPtLqlQOHvXpiOn1cWwI2pAD0exQecgXo4w
         1IBodnGK66EPdJYy9CUDQyZA6CtTOqQc7Xx/uNa9bBKf5I5Netj1GMlV21EMY3sCvZUX
         md0IhzZ0tiCtD51g2bot/c/EgmWfzscGP0AcwBQxzRa1B9lotljvqctRUWdTLdCfBaiI
         Vg1uRtyf9W9qT3VRusz+X/BrJbh/Kvbrz9KkOOeMV9d6/+2dNRsZQSQ/JYe1FECpJlbX
         ZZbV0PTjE2JklJ8jE+07VGn8sFBBClIh5TWBMkGAjpd0pd1HgPNzhyszmq4FLyWeYjO4
         ci1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qs17jDbt;
       spf=pass (google.com: domain of 3j69jyqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3j69JYQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O36f25bpnVnezkyumCg1vTvewow5r9lj9RcGvdoJeME=;
        b=L2eTZVuf9tQ2UhZBg8I6y3yG+R+JB/7q0Yjx/5AIe4Jail/17bgaxRqXQaPOfta5fx
         HrSEv6qdvCQiYGsmV2MnXfyUsBJ5yjwzDIbxbSfsPq/afbIOzFStnFOwIndkilLBxk/Q
         ObikcycZxrqNB+3OvPi4X3HrZGiyjUPHdeewX+bwvlqvWkJ+RMd/P4WtPui1XLU61Zvm
         WlEXe71z4vTcg8rkb172N87T4NuIvK3vUaSw9dM/RO74I5ciV1wG3kAWC3+VxeDAFGxM
         g+vpVB8cd+2bAOEa6xlD8lyRn3xshjiu+frim1yeQUFDZ4wZzXoIZHHxAhFizItLxe+I
         Yh9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O36f25bpnVnezkyumCg1vTvewow5r9lj9RcGvdoJeME=;
        b=X/fBeiVmauUJZWCGWPc5Fa22JDW6HtnQFvtIOjwDzfhZxHEbDyeMUfwGK60htnDXlv
         CGTYVxn2/iCk7VV3nJcyNJfiRbx/sMy/ayo2JbJxrCQxiog9C4cbxSDtJtdrQhFKee99
         SMJW5c6nUM5XoWU/9I4lQipMaO78ptBlADTDLi1DG3WJ8SGek9iIXEfc5AOgGnktD3K4
         PnmBfxduiPNbCx6Qgn6BJOkkz77ChzV56JCjld3nqcbPnKiXSuIYsJry6k7Ei56QKgah
         rQLQxJ+euw/SRmyZtAyGJ5Ept4jvVJQ9btC5fezHEHq2yX7oUTib1HVho0wN1PjflUWm
         VpFw==
X-Gm-Message-State: AOAM532DsfRMv6yoGj9Iy7EDTufTY+RbL12ySW44e9QHXBi3ckITwBYq
	w/75KjTMYj1zfYrm/qWfOB0=
X-Google-Smtp-Source: ABdhPJzP53laA+2j8zM8t5sdlj/yVzQWaSLAMTDfLWF75QF706NyglNwMfRYa9iWVjrZ7SBBc/DrNA==
X-Received: by 2002:a05:6000:550:: with SMTP id b16mr4391971wrf.297.1632219025433;
        Tue, 21 Sep 2021 03:10:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aacd:: with SMTP id i13ls2209021wrc.3.gmail; Tue, 21 Sep
 2021 03:10:24 -0700 (PDT)
X-Received: by 2002:a05:6000:1090:: with SMTP id y16mr21117844wrw.208.1632219024450;
        Tue, 21 Sep 2021 03:10:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632219024; cv=none;
        d=google.com; s=arc-20160816;
        b=CMOsMZBUBWsR/VBe9zKrIBCXk53xtgR+u2ep+0kJ+0BiymbyypYZFAD1/KTm44jGnp
         t6841CLkMwG2YXlP1V3Sv87wtWGkclCijCczCWH5HvNKX4VviafMI9hDAPnkTN01ar1R
         JkXCbp9xTQ5/2rF/6mw1o/mkaZI5zgHzoLvjHT48P/FOD39cMhg+AAJN9tTWvap+dW8x
         9wxombaCOEnhF+yn+NqDqY+lgLvfZ+YtT6hw9OO7cESUFeZ6M4bxG/6CPeLCCMN2frro
         bNHUPKaQA3zbeK/aO3l9AFXtVRHgWdawT1vg0q2x48B8/QHCdJJME6GBHzy3nKyGeIXs
         dU1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=xqqCxuPrLaI1bLHMtAoGnOmrTQGbiQ0pjESMOvziO8U=;
        b=B0WGOzBgbvaL3x9eI4vJ3Rauv1wmYH0WxQTMr2mVvQHOztmza6rlLkqq7Kv4SqmNgM
         yJ0Df8tcp0BVINHa8pKh1iLpMpbp+hHGsoc7xsk3UKgzZG/wwTXYO9pdFjTtARAgAqSp
         6yaW4qh4biY8e9i7haAy5IwewqsUciGKhkvcvsTMXbDWIErZEHIwbsa/EqTDC5VQw5sM
         xif/gb1Jv0e8Nw21HCjorkrvLdprD+QFKfkgMe81tKzfefubVELUquVsfEcfQ9FZ7Ejc
         DUy1WL01hT3zo/fqKKeVLQyUeQZhxzs3IHB0c5EF+enummR9awHaubHztEcWfWRADx1o
         KJUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qs17jDbt;
       spf=pass (google.com: domain of 3j69jyqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3j69JYQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id q195si172849wme.1.2021.09.21.03.10.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:10:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j69jyqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id r9-20020a5d4989000000b0015d0fbb8823so8365204wrq.18
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:10:24 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dd03:c280:4625:60db])
 (user=elver job=sendgmr) by 2002:a1c:a713:: with SMTP id q19mr3631781wme.42.1632219023932;
 Tue, 21 Sep 2021 03:10:23 -0700 (PDT)
Date: Tue, 21 Sep 2021 12:10:11 +0200
In-Reply-To: <20210921101014.1938382-1-elver@google.com>
Message-Id: <20210921101014.1938382-2-elver@google.com>
Mime-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v2 2/5] kfence: count unexpectedly skipped allocations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qs17jDbt;       spf=pass
 (google.com: domain of 3j69jyqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3j69JYQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

Maintain a counter to count allocations that are skipped due to being
incompatible (oversized, incompatible gfp flags) or no capacity.

This is to compute the fraction of allocations that could not be
serviced by KFENCE, which we expect to be rare.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Do not count deadlock-avoidance skips.
---
 mm/kfence/core.c | 16 +++++++++++++---
 1 file changed, 13 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 7a97db8bc8e7..249d75b7e5ee 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -112,6 +112,8 @@ enum kfence_counter_id {
 	KFENCE_COUNTER_FREES,
 	KFENCE_COUNTER_ZOMBIES,
 	KFENCE_COUNTER_BUGS,
+	KFENCE_COUNTER_SKIP_INCOMPAT,
+	KFENCE_COUNTER_SKIP_CAPACITY,
 	KFENCE_COUNTER_COUNT,
 };
 static atomic_long_t counters[KFENCE_COUNTER_COUNT];
@@ -121,6 +123,8 @@ static const char *const counter_names[] = {
 	[KFENCE_COUNTER_FREES]		= "total frees",
 	[KFENCE_COUNTER_ZOMBIES]	= "zombie allocations",
 	[KFENCE_COUNTER_BUGS]		= "total bugs",
+	[KFENCE_COUNTER_SKIP_INCOMPAT]	= "skipped allocations (incompatible)",
+	[KFENCE_COUNTER_SKIP_CAPACITY]	= "skipped allocations (capacity)",
 };
 static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
 
@@ -271,8 +275,10 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 		list_del_init(&meta->list);
 	}
 	raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
-	if (!meta)
+	if (!meta) {
+		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_CAPACITY]);
 		return NULL;
+	}
 
 	if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
 		/*
@@ -740,8 +746,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	 * Perform size check before switching kfence_allocation_gate, so that
 	 * we don't disable KFENCE without making an allocation.
 	 */
-	if (size > PAGE_SIZE)
+	if (size > PAGE_SIZE) {
+		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
 		return NULL;
+	}
 
 	/*
 	 * Skip allocations from non-default zones, including DMA. We cannot
@@ -749,8 +757,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	 * properties (e.g. reside in DMAable memory).
 	 */
 	if ((flags & GFP_ZONEMASK) ||
-	    (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32)))
+	    (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32))) {
+		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
 		return NULL;
+	}
 
 	/*
 	 * allocation_gate only needs to become non-zero, so it doesn't make
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210921101014.1938382-2-elver%40google.com.
