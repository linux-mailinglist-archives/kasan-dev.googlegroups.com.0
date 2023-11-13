Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBXLZGVAMGQE5P7265A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F8597EA367
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:15 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4084a9e637esf31813255e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902855; cv=pass;
        d=google.com; s=arc-20160816;
        b=CclAY5h2ezkdDRciURn2dfux+oNcMtXQypZOcD010nAeUE+OxT7kSybvvnMb6NR5z3
         pnH16/ytB4T99zjbL/Ry6Ctr2zhHSg0hnI+PY5PIa1VvyKimpCTfrnd4HWmtMD5nJNIT
         E78aW2/2muiD3wfx2pQqkCLWmY5Ljb9blG6MtIrbM/yWh64T9hIGmOgWCnhwLnwV9wGy
         j1ixDBs9vaOCz3zdsyvkJv3CYM4pO3H72qeXio8QhZx5TuMzdLgYbu9FGJzZFrkb9TUj
         u+zYDbGeyUoFLPTaIxqQxDXHCfW8kbga5kOM/voZDSoYcSL/tFAgm0rIA51wMElnoDQk
         I1eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5NnVnIZ/6wPrA7Hew/tZ0H1UTZK5cAEMq7HyuCQhquI=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=AK9wGkSiHPhYVF6gtI3CumX458pzQNhJuAE3lU0F+8u9dVoZESFmYGIREZGut0rPjE
         +MQ1+FduAfKoqdEgf9GwRGDzcUzN5+H7zosB7C4LFnuk3H2MiTDL9kL92ESJ09VsOfXD
         aDn4aXfzN2zCBZP9UZhqodbtMhIW9A8raqZnMJLISbnV0J3SjjIY4mrVI6H1yIeIlMJ3
         VhcAio1DWBhKSWXBbGKy0rqzC95z9fLbVmbHcKoWtmF9n9LT/ixReAL08z1Mke7VdK2c
         Yplh46fdFAEV9YdrgtmU3ZkUZrFpIfDpzs/6AhAa2FRsi8wkzt7wogcle/X1uMvLO1Me
         vUMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=vks2zsCM;
       dkim=neutral (no key) header.i=@suse.cz header.b=NVLU6T7U;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902855; x=1700507655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5NnVnIZ/6wPrA7Hew/tZ0H1UTZK5cAEMq7HyuCQhquI=;
        b=CrtmBzfVw93t30k2RnB5D+w1CmwOxUZwT1dgSsjiACDHay1MnVcWXeudu/WVyDs4Tt
         dfV9q2R1cKzxBNXGUDGdLWfSeWZJnFcnrA8JAHmGlEr0Spaw51AlCpjKB9AtxXSAcWpk
         j1QGTPrqTpFDwUE2LmxBL2m9DWp0tlzESRlIwNqdLPbEa2ZWaY2kgh4QmPCCwB4+mAe4
         lESaauk6TKJ2fC4QCgUSVZvJp0BlJzqphnLDLlHGCMILejU5mn4rQa4LivH7xehtw6hJ
         8G3ZoWkyrREorJiw5+GRN4qu+eLSi/lERcOVyl9uJpKxhnmabvHoPSUG2LyETTQNGRPP
         l1Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902855; x=1700507655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5NnVnIZ/6wPrA7Hew/tZ0H1UTZK5cAEMq7HyuCQhquI=;
        b=Ch1znXImGvdjAIFPdNRv3V5BGJ4hO09M6d9RKvuRXIB2dtUhtWuRh0We7SlfUgTKiZ
         uDmInn8le+XSOFnYNHLcP09WgI9gI9DBF9AJAFvPsrpl6SGG5KiLqnMl/y6KQyfsH552
         dKuEcNopCOaVRKMtr5LVIyjy7Scb7sC2UqY34u31OwNYLauPrsWvqOfmlAJ2TSz6NI3k
         eaokIWPpQxmM457Twj+j9iyjSd4OXw7n8Gge7B2hraBdYxVtWtwCn3S1zDax4X+zYCG6
         Tb58T6POODgYvHxAYOdd7cfKQ4jpv4hZQwRXegRnkqkYan+XlN1J1f4T5qhKlkaU584B
         8Yqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxPme7Ukx1WPvwCn3U/FVX3gOhRB8FD/3E5HNNsXARQzVYrjQPA
	xNYVUzUUcifl96WbxZ+OmGU=
X-Google-Smtp-Source: AGHT+IHeMmS3nk5Uuc/2v21N4jye7eTwwszyIczJ9MXDOKj4POgMFl70kOkotVi61YPOe/b1Q28pDg==
X-Received: by 2002:a05:600c:1d93:b0:406:3977:eccd with SMTP id p19-20020a05600c1d9300b004063977eccdmr5750222wms.33.1699902854479;
        Mon, 13 Nov 2023 11:14:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c1e:b0:407:7e47:8258 with SMTP id
 j30-20020a05600c1c1e00b004077e478258ls2385797wms.2.-pod-prod-03-eu; Mon, 13
 Nov 2023 11:14:13 -0800 (PST)
X-Received: by 2002:a05:600c:350a:b0:406:c6de:2bea with SMTP id h10-20020a05600c350a00b00406c6de2beamr6080927wmq.17.1699902852805;
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902852; cv=none;
        d=google.com; s=arc-20160816;
        b=PBCTXLy/oUUVYmofIzDsdjDduLsTd/CDwdeCqtGThxmIP7hmifmXClLMQ6WVRwysWb
         JcbP6tZp0Hk5pt3Uekj7JP/4TOgmCNCPH0SoQGJeTJ7J8t1xYgBkSoce4pHXz2guVtVb
         6ihRS7Ho+THQmIZx0/yRGyslyZLVVX1pwImKKqO3Gm5nvXpWlfsjNb0M3yW8TKsJJKyP
         r87TaMJJ4VQjpRM0fDG5iPmFoWJq2By9M2mHQsXw/hkNBjPPYsLIhYMRsV97Q5C1zDkL
         u+Z7mBz6dkWE12sbkrDfWXnsTjXn11Q62OdaNt7UQz96jeppKObtYE+XX6vjzPkh6GEa
         UnsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=s3nv+0Sqzbudyo8axulOBmhTAGTu9yIEYPQrJtiVg8g=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=zFEHiTHlJYwPpjOAtKF9beXPgmdvbOCmcxOYh374/oh4ttDhUDmv/V++6Dv/mcakFt
         MPGd+NJSSRd9QpiSy711lSExykdxBmQAZMhnqwBHX5UL3FYy+SkwKKyh8ZR7gR0tEjtV
         luER1mSrRraR6RBFtMHBLZks32yfSjpDaJacLBtl7N+MncI9VhfdHxjqOOgjl3sqfgym
         D3xek8k8SKpmChc/fNyskynIhtUSorVkyiZ//WUiAgcSTo240SJhUsJjMZ6dWukWEZuh
         igdLDZnUv+DU+enWzQOV+skqPZ7nftkeD1r/DvOAJWX3AlMB9CA0xWP1N3/pSYMHuC2K
         ROew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=vks2zsCM;
       dkim=neutral (no key) header.i=@suse.cz header.b=NVLU6T7U;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id n30-20020a05600c501e00b004047722bcc7si226740wmr.1.2023.11.13.11.14.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7F8F31F88B;
	Mon, 13 Nov 2023 19:14:12 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 350B613907;
	Mon, 13 Nov 2023 19:14:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 6KdtDIR1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:12 +0000
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
Subject: [PATCH 09/20] mm/slab: move struct kmem_cache_cpu declaration to slub.c
Date: Mon, 13 Nov 2023 20:13:50 +0100
Message-ID: <20231113191340.17482-31-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=vks2zsCM;       dkim=neutral
 (no key) header.i=@suse.cz header.b=NVLU6T7U;       spf=softfail (google.com:
 domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Nothing outside SLUB itself accesses the struct kmem_cache_cpu fields so
it does not need to be declared in slub_def.h. This allows also to move
enum stat_item.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/slub_def.h | 54 ----------------------------------------
 mm/slub.c                | 54 ++++++++++++++++++++++++++++++++++++++++
 2 files changed, 54 insertions(+), 54 deletions(-)

diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index deb90cf4bffb..a0229ea42977 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -12,60 +12,6 @@
 #include <linux/reciprocal_div.h>
 #include <linux/local_lock.h>
 
-enum stat_item {
-	ALLOC_FASTPATH,		/* Allocation from cpu slab */
-	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
-	FREE_FASTPATH,		/* Free to cpu slab */
-	FREE_SLOWPATH,		/* Freeing not to cpu slab */
-	FREE_FROZEN,		/* Freeing to frozen slab */
-	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
-	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
-	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
-	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
-	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
-	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
-	FREE_SLAB,		/* Slab freed to the page allocator */
-	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
-	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
-	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
-	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
-	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
-	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
-	DEACTIVATE_BYPASS,	/* Implicit deactivation */
-	ORDER_FALLBACK,		/* Number of times fallback was necessary */
-	CMPXCHG_DOUBLE_CPU_FAIL,/* Failure of this_cpu_cmpxchg_double */
-	CMPXCHG_DOUBLE_FAIL,	/* Number of times that cmpxchg double did not match */
-	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
-	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
-	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
-	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
-	NR_SLUB_STAT_ITEMS
-};
-
-#ifndef CONFIG_SLUB_TINY
-/*
- * When changing the layout, make sure freelist and tid are still compatible
- * with this_cpu_cmpxchg_double() alignment requirements.
- */
-struct kmem_cache_cpu {
-	union {
-		struct {
-			void **freelist;	/* Pointer to next available object */
-			unsigned long tid;	/* Globally unique transaction id */
-		};
-		freelist_aba_t freelist_tid;
-	};
-	struct slab *slab;	/* The slab from which we are allocating */
-#ifdef CONFIG_SLUB_CPU_PARTIAL
-	struct slab *partial;	/* Partially allocated frozen slabs */
-#endif
-	local_lock_t lock;	/* Protects the fields above */
-#ifdef CONFIG_SLUB_STATS
-	unsigned stat[NR_SLUB_STAT_ITEMS];
-#endif
-};
-#endif /* CONFIG_SLUB_TINY */
-
 #ifdef CONFIG_SLUB_CPU_PARTIAL
 #define slub_percpu_partial(c)		((c)->partial)
 
diff --git a/mm/slub.c b/mm/slub.c
index 63d281dfacdb..64170a1ccbba 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -330,6 +330,60 @@ static void debugfs_slab_add(struct kmem_cache *);
 static inline void debugfs_slab_add(struct kmem_cache *s) { }
 #endif
 
+enum stat_item {
+	ALLOC_FASTPATH,		/* Allocation from cpu slab */
+	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
+	FREE_FASTPATH,		/* Free to cpu slab */
+	FREE_SLOWPATH,		/* Freeing not to cpu slab */
+	FREE_FROZEN,		/* Freeing to frozen slab */
+	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
+	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
+	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
+	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
+	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
+	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
+	FREE_SLAB,		/* Slab freed to the page allocator */
+	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
+	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
+	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
+	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
+	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
+	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
+	DEACTIVATE_BYPASS,	/* Implicit deactivation */
+	ORDER_FALLBACK,		/* Number of times fallback was necessary */
+	CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
+	CMPXCHG_DOUBLE_FAIL,	/* Failures of slab freelist update */
+	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
+	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
+	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
+	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
+	NR_SLUB_STAT_ITEMS
+};
+
+#ifndef CONFIG_SLUB_TINY
+/*
+ * When changing the layout, make sure freelist and tid are still compatible
+ * with this_cpu_cmpxchg_double() alignment requirements.
+ */
+struct kmem_cache_cpu {
+	union {
+		struct {
+			void **freelist;	/* Pointer to next available object */
+			unsigned long tid;	/* Globally unique transaction id */
+		};
+		freelist_aba_t freelist_tid;
+	};
+	struct slab *slab;	/* The slab from which we are allocating */
+#ifdef CONFIG_SLUB_CPU_PARTIAL
+	struct slab *partial;	/* Partially allocated frozen slabs */
+#endif
+	local_lock_t lock;	/* Protects the fields above */
+#ifdef CONFIG_SLUB_STATS
+	unsigned int stat[NR_SLUB_STAT_ITEMS];
+#endif
+};
+#endif /* CONFIG_SLUB_TINY */
+
 static inline void stat(const struct kmem_cache *s, enum stat_item si)
 {
 #ifdef CONFIG_SLUB_STATS
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-31-vbabka%40suse.cz.
