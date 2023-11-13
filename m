Return-Path: <kasan-dev+bncBDXYDPH3S4OBBB7LZGVAMGQE7SJXD7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 41C2A7EA36A
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:16 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40a3efec9a7sf29511085e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902856; cv=pass;
        d=google.com; s=arc-20160816;
        b=XzUuId/XCzVZ5dOqR3xeLM3smBK25kZw18UViXCK1dYwOrCfkxAu8v4uBWUAAph7iy
         pMNZ8XFQIcfxb2ZmLAew1TT0wDgBzAXmCWAByv7XbLxuWUvonflI+XCWB/0GCDvFV/ui
         qWuPaGJ+Ndw57jzV6GeYTa7E4W8aXS+01n+3Tg2Aes7FemmgHfb69TwjJPXSduS8yb5t
         tYitbGiYyimZSnf5o8QR5VV4Kfl9zcXyJ1Q6/WiV1Eueh5ClvmGNd9MKJZvwcfr+wgvh
         eIOdEkOW+MqieDbwjZcHQRWBjk0atdEX/h+g2cnOYg21/dLmE64S0kKm2P+UB05dJWFe
         N3ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WQOnFtx39+6Wa/MNxLXfcL4vAuB2jBN3xtbEJf9FKy8=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=oYA+c+7uQoGM8MrB2+dFuPXVEO7iZEkF2O9YE0jxJkEzOs4W4iG/bwFXxa6K//2FiM
         pgl6SANHdjQjSH9wdpRAX60bjWTWYoLwqfCGut1nb5bnIFgSXNEfxs9bE3H8n2Y6M80K
         dWMoMtNhwUbrCt1EiXXNlVrDOk0cgWIKuo9MxYIjvQvfbXn95mcotE3mWdmmxOB48v1H
         0YaO9UgKHItd+mRGax/bw1EPBx7copLV8g+5CoxQ75v4Mcgjahkzf4x2quexFOsj/GKE
         7WVbdVEsrTwdEeqC2Fkucy8IZiYuNAnOIallac9KOUClTI+Ptrq8nX9CUiDdo1qgWnro
         dakg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=x6gwpjWZ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902856; x=1700507656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WQOnFtx39+6Wa/MNxLXfcL4vAuB2jBN3xtbEJf9FKy8=;
        b=CYWKOlLPD65YwYOEVVaUBoyL/IuesvJQr4frXW2N8DR2oWq3JcYrxjwrh6ren8BNT1
         vsHZ8WCyIfu2T71yJRP0IY1TM7gG/vbYmV9xrAcIJFWUZ52CXPgwPEFuksblNZGXB6k7
         2oBNWZScHbsZ0Dxc26x8zR9gIIL1AEelGKRydVQCBrx4JojD+Z9ZyLyWlo6H4dsP23IN
         nZh/Ft370vBkn+OmhQT76xKeEH3mDQFG9Xk/cbn9wl32yt1MsN5lDObDH+lyPKOUwteK
         foDIGDVIzfIcbOZ9rmi0B9B7DnhTwSOURAlET/U9Dd+VvED9DzoPHKj5nqVg2Lx3VFvW
         yTOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902856; x=1700507656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WQOnFtx39+6Wa/MNxLXfcL4vAuB2jBN3xtbEJf9FKy8=;
        b=dPa/uIkeg6JC5mLHtO7URzySEsR8TdQbJ/79mVNCR0dNjfzF2i4AqF6jBHMGVgzJgu
         RmAoq/gbnuXxjEEO/Oij6P+h5spVSpNqhqFQSLBynbFPm+RIXdW4wHGA3JBRCvLcTz0I
         DhRoU/0LIfHxlj3zjtKjKjUdmv1bwhGcB//qC1GWqNZUj4jVA8JEB9TqBjj2qWHEwFYU
         9pdBK/OAC9ugA+HhcYGdb+EMHd7tj06/LWHiQHG2az8YjskJgfC+x1Na6RFR6eTLWQLl
         F2bxLROvJ0GPPG/2z6nKNuO8qe5rSLausisaxDiQjx7VtfKH54+N1cLsUbmFSims/rsn
         v/Dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzuLOiCQJ2aUteDMopY5w8sQhHPlY3zT4JYSPd+pigtPIyv3w20
	yR8f4wqpGIBfZtYP3i3undo=
X-Google-Smtp-Source: AGHT+IFELLUuzuJWTrZx/Ox4Ebjpu6pG4vwkNssC+ckgFt/5eDYaSEJRjvsg63PKqxBY1ASTcNH9Hg==
X-Received: by 2002:a5d:44cc:0:b0:32f:8442:8f34 with SMTP id z12-20020a5d44cc000000b0032f84428f34mr4579888wrr.25.1699902855610;
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1192:b0:32f:833b:55a7 with SMTP id
 g18-20020a056000119200b0032f833b55a7ls577184wrx.0.-pod-prod-06-eu; Mon, 13
 Nov 2023 11:14:14 -0800 (PST)
X-Received: by 2002:a05:6000:184e:b0:32d:9395:dec6 with SMTP id c14-20020a056000184e00b0032d9395dec6mr4432443wri.67.1699902853833;
        Mon, 13 Nov 2023 11:14:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902853; cv=none;
        d=google.com; s=arc-20160816;
        b=sxAG3N0PKBeGYCJsjo8jpDzDxMy4RjXhzmeU426jLDXrLdwA173iGdfM6K2Q5SYGBX
         snG6MZb0yP3wJlj8iBavZnWIIXu9uqOrLAVoYKtrytr37O2l0BQXfHEPDgqLYAazSg0C
         a+fdObtuTT/22R93ut7qOi0pbF/Ws+YcmZ6Iser2fBs846adfBVBzIgd0bHD5/oOJYYD
         i8plDSTo6apWbAyS/ck1tCtB1fC3Xm6/ZBtI5cNaV12Htnas2PNM2Yv9P2aXQAn4kZcM
         AO+YosA6TGcZTD9Rgitxw7kB+R3KkM4RITRk+EKkjWXaZvLP/e9IklLen2A/j5HGzpQk
         UT9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=BJGzWBWfS91Bn2q4x5GTRkmtz77nGJm/AYtGcjP8oqQ=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=ReSQwPc0+8rqzNAxbxMiI00f7IZnCLjvM0bhxkei0De12m/dTv8LTWjXn1i5f9kfPN
         U48gTEFYIujckyK0okV+ZVBiUm5K+tZYUBbCHhpUPgefHni0oVaHaToj9NdT3bQgV7X1
         ox81HqN1W7YjHUBxJ3npg0CeGhvUJybulOMV3OGOMR17MJj8eHbjzYPciv7eyYq2TlZD
         ScRoKpAxpV1ddqc+KdcCa9ktlj7f1KPVcj8Yif/UIt6/xc1feedKwPP0BUBgro0DqOC4
         5oebYZ9JTYhHzq1cMRczHltftjlvOuWrIWKX4LMhdQu88RiPpS7ojOn+cQNusGzBBGm8
         Gv2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=x6gwpjWZ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id cc4-20020a5d5c04000000b0032626963dfbsi267058wrb.5.2023.11.13.11.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:13 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8AC962190C;
	Mon, 13 Nov 2023 19:14:13 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3AAE713398;
	Mon, 13 Nov 2023 19:14:13 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ALK4DYV1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:13 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 12/20] mm/slab: move pre/post-alloc hooks from slab.h to slub.c
Date: Mon, 13 Nov 2023 20:13:53 +0100
Message-ID: <20231113191340.17482-34-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=x6gwpjWZ;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

We don't share the hooks between two slab implementations anymore so
they can be moved away from the header. As part of the move, also move
should_failslab() from slab_common.c as the pre_alloc hook uses it.
This means slab.h can stop including fault-inject.h and kmemleak.h.
Fix up some files that were depending on the includes transitively.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/kasan/report.c |  1 +
 mm/memcontrol.c   |  1 +
 mm/slab.h         | 72 -----------------------------------------
 mm/slab_common.c  |  8 +----
 mm/slub.c         | 81 +++++++++++++++++++++++++++++++++++++++++++++++
 5 files changed, 84 insertions(+), 79 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e77facb62900..011f727bfaff 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -23,6 +23,7 @@
 #include <linux/stacktrace.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/vmalloc.h>
 #include <linux/kasan.h>
 #include <linux/module.h>
 #include <linux/sched/task_stack.h>
diff --git a/mm/memcontrol.c b/mm/memcontrol.c
index 947fb50eba31..8a0603517065 100644
--- a/mm/memcontrol.c
+++ b/mm/memcontrol.c
@@ -64,6 +64,7 @@
 #include <linux/psi.h>
 #include <linux/seq_buf.h>
 #include <linux/sched/isolation.h>
+#include <linux/kmemleak.h>
 #include "internal.h"
 #include <net/sock.h>
 #include <net/ip.h>
diff --git a/mm/slab.h b/mm/slab.h
index c278f8b15251..aad18992269f 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -9,8 +9,6 @@
 #include <linux/kobject.h>
 #include <linux/sched/mm.h>
 #include <linux/memcontrol.h>
-#include <linux/fault-inject.h>
-#include <linux/kmemleak.h>
 #include <linux/kfence.h>
 #include <linux/kasan.h>
 
@@ -795,76 +793,6 @@ static inline size_t slab_ksize(const struct kmem_cache *s)
 	return s->size;
 }
 
-static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
-						     struct list_lru *lru,
-						     struct obj_cgroup **objcgp,
-						     size_t size, gfp_t flags)
-{
-	flags &= gfp_allowed_mask;
-
-	might_alloc(flags);
-
-	if (should_failslab(s, flags))
-		return NULL;
-
-	if (!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags))
-		return NULL;
-
-	return s;
-}
-
-static inline void slab_post_alloc_hook(struct kmem_cache *s,
-					struct obj_cgroup *objcg, gfp_t flags,
-					size_t size, void **p, bool init,
-					unsigned int orig_size)
-{
-	unsigned int zero_size = s->object_size;
-	bool kasan_init = init;
-	size_t i;
-
-	flags &= gfp_allowed_mask;
-
-	/*
-	 * For kmalloc object, the allocated memory size(object_size) is likely
-	 * larger than the requested size(orig_size). If redzone check is
-	 * enabled for the extra space, don't zero it, as it will be redzoned
-	 * soon. The redzone operation for this extra space could be seen as a
-	 * replacement of current poisoning under certain debug option, and
-	 * won't break other sanity checks.
-	 */
-	if (kmem_cache_debug_flags(s, SLAB_STORE_USER | SLAB_RED_ZONE) &&
-	    (s->flags & SLAB_KMALLOC))
-		zero_size = orig_size;
-
-	/*
-	 * When slub_debug is enabled, avoid memory initialization integrated
-	 * into KASAN and instead zero out the memory via the memset below with
-	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
-	 * cause false-positive reports. This does not lead to a performance
-	 * penalty on production builds, as slub_debug is not intended to be
-	 * enabled there.
-	 */
-	if (__slub_debug_enabled())
-		kasan_init = false;
-
-	/*
-	 * As memory initialization might be integrated into KASAN,
-	 * kasan_slab_alloc and initialization memset must be
-	 * kept together to avoid discrepancies in behavior.
-	 *
-	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
-	 */
-	for (i = 0; i < size; i++) {
-		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
-		if (p[i] && init && (!kasan_init || !kasan_has_integrated_init()))
-			memset(p[i], 0, zero_size);
-		kmemleak_alloc_recursive(p[i], s->object_size, 1,
-					 s->flags, flags);
-		kmsan_slab_alloc(s, p[i], flags);
-	}
-
-	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
-}
 
 /*
  * The slab lists for all objects.
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 63b8411db7ce..bbc2e3f061f1 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -21,6 +21,7 @@
 #include <linux/swiotlb.h>
 #include <linux/proc_fs.h>
 #include <linux/debugfs.h>
+#include <linux/kmemleak.h>
 #include <linux/kasan.h>
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
@@ -1470,10 +1471,3 @@ EXPORT_TRACEPOINT_SYMBOL(kmem_cache_alloc);
 EXPORT_TRACEPOINT_SYMBOL(kfree);
 EXPORT_TRACEPOINT_SYMBOL(kmem_cache_free);
 
-int should_failslab(struct kmem_cache *s, gfp_t gfpflags)
-{
-	if (__should_failslab(s, gfpflags))
-		return -ENOMEM;
-	return 0;
-}
-ALLOW_ERROR_INJECTION(should_failslab, ERRNO);
diff --git a/mm/slub.c b/mm/slub.c
index 64170a1ccbba..e15912d1f6ed 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -34,6 +34,7 @@
 #include <linux/memory.h>
 #include <linux/math64.h>
 #include <linux/fault-inject.h>
+#include <linux/kmemleak.h>
 #include <linux/stacktrace.h>
 #include <linux/prefetch.h>
 #include <linux/memcontrol.h>
@@ -3494,6 +3495,86 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
 			0, sizeof(void *));
 }
 
+noinline int should_failslab(struct kmem_cache *s, gfp_t gfpflags)
+{
+	if (__should_failslab(s, gfpflags))
+		return -ENOMEM;
+	return 0;
+}
+ALLOW_ERROR_INJECTION(should_failslab, ERRNO);
+
+static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
+						     struct list_lru *lru,
+						     struct obj_cgroup **objcgp,
+						     size_t size, gfp_t flags)
+{
+	flags &= gfp_allowed_mask;
+
+	might_alloc(flags);
+
+	if (should_failslab(s, flags))
+		return NULL;
+
+	if (!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags))
+		return NULL;
+
+	return s;
+}
+
+static inline void slab_post_alloc_hook(struct kmem_cache *s,
+					struct obj_cgroup *objcg, gfp_t flags,
+					size_t size, void **p, bool init,
+					unsigned int orig_size)
+{
+	unsigned int zero_size = s->object_size;
+	bool kasan_init = init;
+	size_t i;
+
+	flags &= gfp_allowed_mask;
+
+	/*
+	 * For kmalloc object, the allocated memory size(object_size) is likely
+	 * larger than the requested size(orig_size). If redzone check is
+	 * enabled for the extra space, don't zero it, as it will be redzoned
+	 * soon. The redzone operation for this extra space could be seen as a
+	 * replacement of current poisoning under certain debug option, and
+	 * won't break other sanity checks.
+	 */
+	if (kmem_cache_debug_flags(s, SLAB_STORE_USER | SLAB_RED_ZONE) &&
+	    (s->flags & SLAB_KMALLOC))
+		zero_size = orig_size;
+
+	/*
+	 * When slub_debug is enabled, avoid memory initialization integrated
+	 * into KASAN and instead zero out the memory via the memset below with
+	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
+	 * cause false-positive reports. This does not lead to a performance
+	 * penalty on production builds, as slub_debug is not intended to be
+	 * enabled there.
+	 */
+	if (__slub_debug_enabled())
+		kasan_init = false;
+
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_slab_alloc and initialization memset must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
+	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
+	 */
+	for (i = 0; i < size; i++) {
+		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
+		if (p[i] && init && (!kasan_init ||
+				     !kasan_has_integrated_init()))
+			memset(p[i], 0, zero_size);
+		kmemleak_alloc_recursive(p[i], s->object_size, 1,
+					 s->flags, flags);
+		kmsan_slab_alloc(s, p[i], flags);
+	}
+
+	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
+}
+
 /*
  * Inlined fastpath so that allocation functions (kmalloc, kmem_cache_alloc)
  * have the fastpath folded into their functions. So no function call
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-34-vbabka%40suse.cz.
