Return-Path: <kasan-dev+bncBC7OBJGL2MHBB35WWGFAMGQEGW5E6UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id F3CFA415C34
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 12:48:15 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id s14-20020adff80e000000b001601b124f50sf4789221wrp.5
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 03:48:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632394095; cv=pass;
        d=google.com; s=arc-20160816;
        b=yGXvsKmTdKwZFLkYsFlrGS253Cqv+o0SwYci7mxVzAhP90VwFyVD3/3e9Y4z23sQzY
         ZssDdLGK8kJ7juYePuZe/sMsnXO6l3wYXkKhmLu+ijr1p5c00tpLMgDTPz4j9TUO+eNX
         dT+Ml3vnOmFdThLv+RSUIFW9+UmD8ssbTTu01HqpdKqobXAG7SjgetfKsFtgnIwhjH5I
         ntgcPegTbBNJ55Uy1/4YhIieAFATikjE0+Spf1nAA36PJB97+HvPi/zUs/w/gWvlgEns
         hkfFSEWUtJmwd5OlVyuC56TX1cuYtXWLeT/vbJLy8ENjlMK1eI0tV9ss3ftJVWRGua4o
         Qkaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Vz7KGcIfebmHiexOaHU5WW4GC/sh76FAdhz/VasJJIs=;
        b=odievDbaUp1ovmWlZyqvme855pnLGfhXEbsKo2chGcHDcl7TPiV8byIKO6xi+QSMhZ
         xyJz0dxj0HF1m8dS6XiDfFp5OhbIrNuFJJzPmK799yG+TBC8hJM0b8kiivrk/1xD1lkz
         yPmpIDRdGPUSQmKjWqOQJFEYLVIvH1ue401+euB5GCJsf/qaQxi9Ulu6npMXLVOciuUo
         5atOFvJaSkCbLP2tShBX+R4fH/HCxz0L2vNn/JGK0FHc3EPjWb+yC0cpbW//rKMIz6L5
         A8u6xK3YGUwWnrAtWuwp0Rv+0Dbaw3C1AkBoSIhi8/m2XqM8Bvi8t5k4FDTxXhRW1rXg
         1rrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YK7pY2T3;
       spf=pass (google.com: domain of 3bltmyqukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bltMYQUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vz7KGcIfebmHiexOaHU5WW4GC/sh76FAdhz/VasJJIs=;
        b=T499y3hzv6elrw4RiA8PWjC2sPezRTLxtuPE4ywvGwLtoQsgwDuEORH7SK+DB0DPgB
         fRGMV1G66oQCV2wrmH2OfjN6jJtRt32m5Bxl9pz5YJcNVosmbrpwEA6SkYrwb7dtcz/U
         zL6cgbHn6EuJHjS/18LPRqwjMXdeD1AAFZI9hUwu2YN0m0nQ7fn+KNxBonN4G+A8fGho
         DUaqJybsU7McabLEspqNKbVVj5jDCCO7JTakgMO6X/bmT9xmGnl32TQ12Nyl4Wkw+Od9
         QkBtRuIJwHjeXmXc9FzJTQXGJ3Tx17sHcUVAs+EoiDoPbAPIWGNY1xCmr4sQTj+rq2pq
         rsLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vz7KGcIfebmHiexOaHU5WW4GC/sh76FAdhz/VasJJIs=;
        b=fqw7Upeurvt6LhaGICKdKd6OcCY5NE31s0lZ/aT/vg1YhHEX8Me4g+u+Ba21hyDK1d
         Zp6bm1H3UjCWpJfxBZDOF6eXvST2+qt7FkS2FIwU7kyh7nxXHjEsdif+1Hs7uRA2VvzD
         WgX2xydDyChbQ85VQhBUQQ0NeghaJ8lPrZcmKfVsQ3Ven+D8MKGTjvyN+tZwOD7zQaPS
         KY0Bmhl1JRlqXEJwa+avU7YiuZaBeMB0e2WMmlZiojBE8Il8bh00sr5X7cp0yos1pQw9
         YpXnDjfFstKPRWX/8Hx++cA7NsC+ciIzh/qIQKA6SsaxPX+azZpZ4C7A0qfjXyGjmPZm
         5n3A==
X-Gm-Message-State: AOAM531PI/vlHNJcZYDX+aCOJ7DHONU19Kz6oPBGtOMotPNtTy5Ga6Kv
	nplAMHoW8fsYx7Qhqx/Ps2o=
X-Google-Smtp-Source: ABdhPJyl0jXECp0/BAZrpb4JXYBb7S77Y3vnhpkivbJDfIOQlGwYB2kRItxV27Ex/OS55EHbRRkq8Q==
X-Received: by 2002:a05:6000:186a:: with SMTP id d10mr4332873wri.113.1632394095724;
        Thu, 23 Sep 2021 03:48:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9bd7:: with SMTP id e23ls674134wrc.2.gmail; Thu, 23 Sep
 2021 03:48:14 -0700 (PDT)
X-Received: by 2002:a5d:6c6e:: with SMTP id r14mr4125644wrz.319.1632394094739;
        Thu, 23 Sep 2021 03:48:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632394094; cv=none;
        d=google.com; s=arc-20160816;
        b=k0XYX2RYph5iccYg9kZ/z3l95BFGZTF/Nb8+pLJye+9Sze5ef9BKRxAyNzXyVW0BGx
         Htp35QV/E+PbrLH10IGVcpo/3oxr5rrddhtAuzuF0lOd1Wgx58ajOzhuMs0YNLgE+WN/
         Uv4E8xGylRN18gDlQxmRhCJayFk7tZweLJ0+NuVWRP2amrTShAAzcDmN4yvr+ZW5ZrtY
         lJR0MBhuSjT6oGgqre5O2x7mD3vfD95KxWS9JAkHeeDis3goANCYz73bcQKGUszXC6Kc
         Wi1x177RxyUy1EJaF+gzI5A59gjy0WjgoXHi38waO28VZ9cAp8faY7SbXUjPIyrhMEbX
         vViA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=fWJbOvO/9IQd66CKXhWeX2UUgjmgk+7Ytnnk5fprUlg=;
        b=kb0c35+Oq9ufzH9Ttsro3ASh6uhgoPx/qoUXxc6QZmhr/qGtELrRj3RRw5ElgQWqnh
         /Jeg6HSl/NKP0dqVmWqrQH9e77Y7Y+HxYlXt4zCTHM9fIhRtKYjVBuA8C93lWOqyA+8H
         KABOOaqTlBUgS/pbvdr1vWcXcEBi/LZbx4iVU8E5x6L7Q5WJwlSQTT/iozbfek5wSWQ6
         XjWbfIS2BwVmm8D7IwoqzlYj7iELv5TWcHNo2Ki9WynP7iE4iUAtCpdhjfbSW5fjUSoV
         fMRal31L87e7kwRQdH5LG/Wm3Tiw+UjbdXWAMPjj/dmOY05ALRJ19ysEzBMBrTqghfh2
         Utxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YK7pY2T3;
       spf=pass (google.com: domain of 3bltmyqukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bltMYQUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id r19si244507wrc.1.2021.09.23.03.48.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 03:48:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bltmyqukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s14-20020adff80e000000b001601b124f50so4789140wrp.5
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 03:48:14 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:bd72:fd35:a085:c2e3])
 (user=elver job=sendgmr) by 2002:a05:600c:4154:: with SMTP id
 h20mr15186317wmm.172.1632394094273; Thu, 23 Sep 2021 03:48:14 -0700 (PDT)
Date: Thu, 23 Sep 2021 12:48:00 +0200
In-Reply-To: <20210923104803.2620285-1-elver@google.com>
Message-Id: <20210923104803.2620285-2-elver@google.com>
Mime-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v3 2/5] kfence: count unexpectedly skipped allocations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YK7pY2T3;       spf=pass
 (google.com: domain of 3bltmyqukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3bltMYQUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923104803.2620285-2-elver%40google.com.
