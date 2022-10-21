Return-Path: <kasan-dev+bncBDN7L7O25EIBBYFBZCNAMGQEQIIOV5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FEE9606E46
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 05:24:17 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id u2-20020ac25182000000b004a24f3189fesf480709lfi.15
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 20:24:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666322657; cv=pass;
        d=google.com; s=arc-20160816;
        b=bjhLkiBKZ2dCjWNHqkPQ+fufF+LwjAq1nb9FSSu4x8UmeTxiYEpPfJIhyqmzHUYHr5
         O9QAoL1jYdPLskXuhRpNSN3SSIkbvf3HwuL7men+qamw3kb0lpZOztFgw6fuAaFYiiZS
         TdcbHuHAt52VIgjI1M7SMgB9KWAQqohtej0ZyL8DDzYkGzQMYF2dRMsKySih6nxSDyJR
         PzubSX7PaN783wUprDjP/7V6fw0eyaDf3/C3YOo8ggXSeqfH2wBmlomLy0JxsVRmviUR
         INjG3KcyPQQr4VZv10VG7pZVSBNGLwO4MJ25Oj8XDUxmf0SJLfiJ+zmlOD9jA4X9k3dP
         VkRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5WyBdHE3kfbNpfqvvvG5sN1xckwodzH0I6PoElIRF7k=;
        b=g4bSuUd/rbhbZqcE3/JXyGYhjqVFo00/DGcsrF/wcx/JF8Qt07Pmozlj3RulMq95ma
         H3bBApWJILzjt/vXAet589JfqQ6vW0RpESc4xpSlKNEiAft6nF8tI01oCmqAmqc1ugj6
         3ViignP97hO4t9CwJE6gTTgjFpBcCWxUhLT2lf29aL/ZoQ7e1E74vaKz9oYy6MYYi/w+
         7OITUXLQ4uhYi2b19iG4wpa6G2NuKqeav3LiGrM+IEuMAtTQFmjFg4nZ2FXiJzr7rzzB
         q2d/4k/9zOu1lowT4eyvmNUBoTfxozGSMgBT8eU9RUhUTMN8WR6OagCs/nPu4nBxl7Zz
         MLFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W1XowHlk;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5WyBdHE3kfbNpfqvvvG5sN1xckwodzH0I6PoElIRF7k=;
        b=n8j5KQD7QUE4IK3t1vFTJ705CfMc8f5PWU8BCf7BGgKEoLYV2evih0WVdeKJammWKC
         M031WxdMOlvojKLWIbWfl9SwAY3SYOtfu4inJITpDTBWgYT92sJOgfmpoAjjk4/n2Dhy
         1m353yIdsZ7uJfmPaaqR4Eb86OJ82nBI6ZDRIkuVoj17qC3SavQ8ozEHFxyEBZfTTVz1
         fIeY5TGknbpXyenK6tTQ7LON7mQ55au/qpEiHeSGuYpQaBRL7KJHQgXFBzprVC5UTKle
         skliEUfMqA9k0FlACY8Jf0LPUmSbGldAZCLNqeQ0pjTuSl5Rls5VnuKq7ToEAEWTl9Ay
         LmJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5WyBdHE3kfbNpfqvvvG5sN1xckwodzH0I6PoElIRF7k=;
        b=fcpOFEgOZo1tKSJswvLs0wwMrMg15xfx5I2e1J8ONe6Q7lPTZfn53GmS+Wy9CpU6f/
         W8rxwGEVbvwUT4QnACOob6EDtdllRVsUgIi/yE6KvLXUYIwFOxgtMRFGer6TOL4MNmtU
         NsYkGRW/ZsBEdws+k1mn4ZGxe/A7WDXqIbSd2jWtQZ+Z8gEb+NPkeQ4Cz5l1gUw03D5O
         IlHA6ulYR3h1WxHFEEQ8UJnkc7AzCwZPmbCzsXB7bSwwBBfBMUa8Vq3SiJ6CguI82AjX
         TnNbPYYYXT7i+HsqwqA6b9a3FNSd/4NXnCPJbTH7Ta+xrmWQ/6kpdJvpQVakwFoI/IGN
         4y7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1/5V6jPIKAalFRikgqzSLiiqT9RCBza+Dj5j68kaUgLlDDe56x
	9jBJ0ingOMJeacx5bCyZhd4=
X-Google-Smtp-Source: AMsMyM4qAyUh1ZIwORUJxWc3c1xSzGWzx/t4+zCYm3OvFQAvz+UaJ2FBmiL8S8lKiKoRMi35m8yuBQ==
X-Received: by 2002:a05:651c:54f:b0:26f:eb91:4e3c with SMTP id q15-20020a05651c054f00b0026feb914e3cmr6311275ljp.376.1666322656732;
        Thu, 20 Oct 2022 20:24:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:10a1:b0:26f:b018:381 with SMTP id
 k1-20020a05651c10a100b0026fb0180381ls278133ljn.10.-pod-prod-gmail; Thu, 20
 Oct 2022 20:24:15 -0700 (PDT)
X-Received: by 2002:a05:651c:158f:b0:26b:dd9c:dca5 with SMTP id h15-20020a05651c158f00b0026bdd9cdca5mr5907820ljq.400.1666322655618;
        Thu, 20 Oct 2022 20:24:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666322655; cv=none;
        d=google.com; s=arc-20160816;
        b=rYZ2iFWqwg4gwIjQvfSsbywnZL9OSQyN/YpsrHe4/vARQiJZLeWNLyStD1F5JCmcTk
         4NnBkyWcKhrUdSk7SyAQQz6Ndu6kjK1uOQxYrk+/aksOBVEz007nxm8pzztwSvxOD97M
         SILE4Nqzlz5vS9R4HXZe6Ivy4xvhiz3Ildota7F0whfAFEnOzBAN21DZOz7CeGG1Qu5N
         mL+lUY8iun62da06w0zhmdK5HHOI38+vHRBitS42MOhhUvjue+oQ6tKFWwvL20U24/WE
         B48PhFKdibZtPsesoHuTTKw/HxIGTImQjMMVtybgSypiEdWEf66+q8U0YcWL3QtCEqTg
         ZjVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3YDxtwYk13Eg8oX62TDkjnLYaWguBEGcZS5fYx2UnH0=;
        b=jI3JS5Z2mh4U3QWRkCRfOqoKIgermvMthyLrat/3nB98rPmhtarE7r1o3EEPCVY2IA
         0AUG+673w5cZC83Dm31zbgspkNKAWxP5Tkf1/gM5FOftyEyalGzewHiMgCMoHmacKEvT
         S+5qMlOYL9GuuvvxnwbA+PyXQjE6kgKZUbNbKqEdWVu2oqOaVmz+DxDPPbMF+FKY+ODX
         eg9G0wSZSo3QdLFNJcsJ5CDkcgLqS92WRyS1bbMWqCbCc6LYZVsnzSM8A3m/2EXL4Sa+
         ic9TxR6SOHDasSa8LwUvBGLSQtoALylhBJDi1qeZThygq7364usFkJiJdmCmn1kolnQE
         RRYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W1XowHlk;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id k20-20020a2eb754000000b0026fb09d81bbsi595748ljo.1.2022.10.20.20.24.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Oct 2022 20:24:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10506"; a="371114055"
X-IronPort-AV: E=Sophos;i="5.95,200,1661842800"; 
   d="scan'208";a="371114055"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Oct 2022 20:24:14 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10506"; a="719459559"
X-IronPort-AV: E=Sophos;i="5.95,200,1661842800"; 
   d="scan'208";a="719459559"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by FMSMGA003.fm.intel.com with ESMTP; 20 Oct 2022 20:24:11 -0700
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Kees Cook <keescook@chromium.org>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v7 1/3] mm/slub: only zero requested size of buffer for kzalloc when debug enabled
Date: Fri, 21 Oct 2022 11:24:03 +0800
Message-Id: <20221021032405.1825078-2-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221021032405.1825078-1-feng.tang@intel.com>
References: <20221021032405.1825078-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=W1XowHlk;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

kzalloc/kmalloc will round up the request size to a fixed size
(mostly power of 2), so the allocated memory could be more than
requested. Currently kzalloc family APIs will zero all the
allocated memory.

To detect out-of-bound usage of the extra allocated memory, only
zero the requested part, so that redzone sanity check could be
added to the extra space later.

For kzalloc users who will call ksize() later and utilize this
extra space, please be aware that the space is not zeroed any
more when debug is enabled. (Thanks to Kees Cook's effort to
sanitize all ksize() user cases [1], this won't be a big issue).

[1]. https://lore.kernel.org/all/20220922031013.2150682-1-keescook@chromium.org/#r
Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slab.c |  7 ++++---
 mm/slab.h | 18 ++++++++++++++++--
 mm/slub.c | 10 +++++++---
 3 files changed, 27 insertions(+), 8 deletions(-)

diff --git a/mm/slab.c b/mm/slab.c
index a5486ff8362a..4594de0e3d6b 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3253,7 +3253,8 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
 	init = slab_want_init_on_alloc(flags, cachep);
 
 out:
-	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
+	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
+				cachep->object_size);
 	return objp;
 }
 
@@ -3506,13 +3507,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 * Done outside of the IRQ disabled section.
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
-				slab_want_init_on_alloc(flags, s));
+			slab_want_init_on_alloc(flags, s), s->object_size);
 	/* FIXME: Trace call missing. Christoph would like a bulk variant */
 	return size;
 error:
 	local_irq_enable();
 	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
diff --git a/mm/slab.h b/mm/slab.h
index 0202a8c2f0d2..8b4ee02fc14a 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -720,12 +720,26 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
 
 static inline void slab_post_alloc_hook(struct kmem_cache *s,
 					struct obj_cgroup *objcg, gfp_t flags,
-					size_t size, void **p, bool init)
+					size_t size, void **p, bool init,
+					unsigned int orig_size)
 {
+	unsigned int zero_size = s->object_size;
 	size_t i;
 
 	flags &= gfp_allowed_mask;
 
+	/*
+	 * For kmalloc object, the allocated memory size(object_size) is likely
+	 * larger than the requested size(orig_size). If redzone check is
+	 * enabled for the extra space, don't zero it, as it will be redzoned
+	 * soon. The redzone operation for this extra space could be seen as a
+	 * replacement of current poisoning under certain debug option, and
+	 * won't break other sanity checks.
+	 */
+	if (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
+	    (s->flags & SLAB_KMALLOC))
+		zero_size = orig_size;
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_alloc and initialization memset must be
@@ -736,7 +750,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 	for (i = 0; i < size; i++) {
 		p[i] = kasan_slab_alloc(s, p[i], flags, init);
 		if (p[i] && init && !kasan_has_integrated_init())
-			memset(p[i], 0, s->object_size);
+			memset(p[i], 0, zero_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
 		kmsan_slab_alloc(s, p[i], flags);
diff --git a/mm/slub.c b/mm/slub.c
index 12354fb8d6e4..17292c2d3eee 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3395,7 +3395,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
 	init = slab_want_init_on_alloc(gfpflags, s);
 
 out:
-	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
+	/*
+	 * When init equals 'true', like for kzalloc() family, only
+	 * @orig_size bytes will be zeroed instead of s->object_size
+	 */
+	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
 
 	return object;
 }
@@ -3852,11 +3856,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 * Done outside of the IRQ disabled fastpath loop.
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
-				slab_want_init_on_alloc(flags, s));
+			slab_want_init_on_alloc(flags, s), s->object_size);
 	return i;
 error:
 	slub_put_cpu_ptr(s->cpu_slab);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221021032405.1825078-2-feng.tang%40intel.com.
