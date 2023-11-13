Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCXLZGVAMGQEJOWBTVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id DCD3B7EA374
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:19 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c73f8300c9sf45560711fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902859; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhJeLmlDWFcwMqICgQbKART0uRP/lOcv1/K4B/BuGCY9T+omLeFyiN0XndtI5VXqEd
         xIKJmtqtfq++vWbcTnvdTlGFldiMX9vgvkJag9Mhfrrx/Hwe6QRe/FM5bn1wg3+iHxfL
         umTvHMuszOxzUX8uDxdH61eKCp0b01+0u/BaMXCNlo358FBWT1r2ZWXLLgQRUch111Mg
         n3NtEBfKkjbh08blgG1LPdYuoHQA+ELYtYPDyOmf7fpqGIP5EiQiXn97etgQoSB2IcgX
         f3F1cGPpSiO+rCFmIZDNzsVahN3hJv/2AQIr+XppzVmL/BFFpNh8/3u2LCqVTeJmH7vp
         MT0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=04fefnkkmzecL0bDcvaV0YI8jHvxZ+ZLiJo+oUU50aY=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=jvg+FwZedCFJAfeZZn67DAUQESCM3H/xKae/G5MaF+TCZyZDNQ4+Rl9PBr2rFqMw/F
         vg4PEjyMDvQzyfvULxPqGPpkaxju3fwy2lWC5+ElXqQ2SrxPEZU3vpjDJUgrk1dGPzgx
         S1/GsAlld7Xof1aWoGvAJtuTG6+JwV1l2FFiPQ2uKhBX3jz6zmSTUvPM9BE5JG6iQ8IM
         pALgVekgKwDoeXZSmPvasmoGRPKRsn+L1bG/78TfL3c7pWktuXRrtSNG8Jxv7M3X9GqY
         nMFOsYDsbt9PIx1yPIM0NLfhblF4YuS2VTiOSC+KZlTDsS1XDx7ZQofJYgDjZZIBJup0
         Kqpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LiNsUX0q;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=5iBlhYbr;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902859; x=1700507659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=04fefnkkmzecL0bDcvaV0YI8jHvxZ+ZLiJo+oUU50aY=;
        b=sEBjnPOIUrDSGDf1SYuFHceLGoRz9lChk9f+1UIq1eNWm65KgMQ/PiuBRRZTx3tQKt
         4+NUOJrnoG+MwV3VriiYsEvLA2qT5TVWT9X7SN+Fph27tlti/3hV21F2WxBjxnCt7jRs
         8ua2Gl2Pt5Z0ZDOe/KociCRSRPh8dkd8u6bELczWKozCtVXNa0hqqYhf96kDiiH1cMoR
         0+owAAIfhfw1dVaM84KpAm+XrxKuqss74GWOPMf0vAeDvRaP2ei9E9UitJ7U9frny3IX
         sTxDx9nfXf7CUx8OnNGEjpyR3ns+I2PZq39up704tJvMv343Kb2xY3rNQjK88tZvHgVn
         LfdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902859; x=1700507659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=04fefnkkmzecL0bDcvaV0YI8jHvxZ+ZLiJo+oUU50aY=;
        b=HCdAARdhLxw3+F464qzn+FoLP9CSFJJt/ab2oDJC60eTwrrTxOVICtRo8/30BIlVBZ
         3uZ57wvZGoc7xSLmuu/e/F0Pobcc2oww+Ycs4VsHynpeqwfVNx6n9X79RbEihBC5fpXT
         g7epmLunp/S2N9dFXrwT7EvgttshQmZzz4PZr80jfO2rE6lI5sM8I7Qt6ulwNjgurQ1P
         QSxIyu6fXOCD6hxxkok7RsTAmqft2xxnXzMEZuGITfnzpGj4MElwuC9DaXRsjagiiSft
         EKSB0BPUh0oXH7eCVJnS+6nIW9Y9y0ASacFjFmsZMvWPQNzXXtBH/rzctQ/FyV4WjQIv
         xyag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzAMhEQUDflH/FQiGFf+DM8T+4GPtbiWDzE1SktghRoPr6xDd4P
	PIpdtACGvff23QrtGmm2btY=
X-Google-Smtp-Source: AGHT+IHb5yLJkxbHuxh1kG7UJmeBTzUQUEmDNXqGyPJRn6E3lXirPK6XktbAyPVPvhwRmcr99ACH5A==
X-Received: by 2002:a19:5f5a:0:b0:509:445b:dcde with SMTP id a26-20020a195f5a000000b00509445bdcdemr4289245lfj.22.1699902858412;
        Mon, 13 Nov 2023 11:14:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:159c:b0:507:9702:8b88 with SMTP id
 bp28-20020a056512159c00b0050797028b88ls312563lfb.1.-pod-prod-03-eu; Mon, 13
 Nov 2023 11:14:16 -0800 (PST)
X-Received: by 2002:ac2:4907:0:b0:509:8e1b:c932 with SMTP id n7-20020ac24907000000b005098e1bc932mr5040650lfi.50.1699902856394;
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902856; cv=none;
        d=google.com; s=arc-20160816;
        b=kNn28qmfIVLDq5lD07RJvCpm6C1qBW/OABudcF/NG1onCRECM3Nx+uxz5M3jq0O0O7
         h/0QaZNAs+r3qOf66I3z3rk8NBLFTzFqRHDy7u4eMMc7fNXOOAxHhC8mjXmq4l6R1+da
         je6EE62VYuXvZggp++qo+ri00UyN8EA0I3zBq+n5Q4m5Me8DnW8Xndz+h8hndLgChdfb
         mvN3M6osgR2rSlQBk/Ag+q7+j6X4x2i1i/mzoRhFY+UePlJXbZo02sDye0RSGuKPttmI
         Wp699P8YFFrRrPbj3BhvakGQgKoquD0dQ5PDJtCi6ZMmQKYJAhWhI8yRvGRNpSFMoObm
         NKkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=Lj2Ybkc9bEyxzgjbB/gyBkYp7HC/f0D1F7NR5xIwYLA=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=vwRP6Utl2hxKCp3iyV5xqvOgjdNWf3EOgnvqfXCrrRSnlcow6udPxTyPqeuLhy6Yo/
         U/Uqs+0LvCwl9OYuVj4oPyWlBthOc3QLgnpM+LjYgLN5DheM1nW0wnNEct7r1qkGYUKV
         Jka44Cs6sJ1ifxQtHBn4uJPP75a4kCfjIQYE4x0nOeyVR9bWxlBPCEjPAiucuJ31LVVx
         4WJXot38ddEwgxTSTCQmWLuwPxrUP2hZD7G28cXjgE62xiRB5/VgHZ4pFXhlHMIY7iWx
         JWo4ucLoRAhtlx3A2fkghmE6FKmJS1aHOL5XwNbeigNHZWoITbWvuUf1YYbHT6w7uzwi
         BApA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LiNsUX0q;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=5iBlhYbr;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id v18-20020a056512097200b005068bf0b332si243577lft.1.2023.11.13.11.14.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C8C7221940;
	Mon, 13 Nov 2023 19:14:15 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 8757A13907;
	Mon, 13 Nov 2023 19:14:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id +CJlIId1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:15 +0000
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
Subject: [PATCH 19/20] mm/slub: optimize alloc fastpath code layout
Date: Mon, 13 Nov 2023 20:14:00 +0100
Message-ID: <20231113191340.17482-41-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=LiNsUX0q;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=5iBlhYbr;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

With allocation fastpaths no longer divided between two .c files, we
have better inlining, however checking the disassembly of
kmem_cache_alloc() reveals we can do better to make the fastpaths
smaller and move the less common situations out of line or to separate
functions, to reduce instruction cache pressure.

- split memcg pre/post alloc hooks to inlined checks that use likely()
  to assume there will be no objcg handling necessary, and non-inline
  functions doing the actual handling

- add some more likely/unlikely() to pre/post alloc hooks to indicate
  which scenarios should be out of line

- change gfp_allowed_mask handling in slab_post_alloc_hook() so the
  code can be optimized away when kasan/kmsan/kmemleak is configured out

bloat-o-meter shows:
add/remove: 4/2 grow/shrink: 1/8 up/down: 521/-2924 (-2403)
Function                                     old     new   delta
__memcg_slab_post_alloc_hook                   -     461    +461
kmem_cache_alloc_bulk                        775     791     +16
__pfx_should_failslab.constprop                -      16     +16
__pfx___memcg_slab_post_alloc_hook             -      16     +16
should_failslab.constprop                      -      12     +12
__pfx_memcg_slab_post_alloc_hook              16       -     -16
kmem_cache_alloc_lru                        1295    1023    -272
kmem_cache_alloc_node                       1118     817    -301
kmem_cache_alloc                            1076     772    -304
kmalloc_node_trace                          1149     838    -311
kmalloc_trace                               1102     789    -313
__kmalloc_node_track_caller                 1393    1080    -313
__kmalloc_node                              1397    1082    -315
__kmalloc                                   1374    1059    -315
memcg_slab_post_alloc_hook                   464       -    -464

Note that gcc still decided to inline __memcg_pre_alloc_hook(), but the
code is out of line. Forcing noinline did not improve the results. As a
result the fastpaths are shorter and overal code size is reduced.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 89 +++++++++++++++++++++++++++++++++----------------------
 1 file changed, 54 insertions(+), 35 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d2363b91d55c..7a40132b717a 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1866,25 +1866,17 @@ static inline size_t obj_full_size(struct kmem_cache *s)
 /*
  * Returns false if the allocation should fail.
  */
-static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
-					     struct list_lru *lru,
-					     struct obj_cgroup **objcgp,
-					     size_t objects, gfp_t flags)
+static bool __memcg_slab_pre_alloc_hook(struct kmem_cache *s,
+					struct list_lru *lru,
+					struct obj_cgroup **objcgp,
+					size_t objects, gfp_t flags)
 {
-	struct obj_cgroup *objcg;
-
-	if (!memcg_kmem_online())
-		return true;
-
-	if (!(flags & __GFP_ACCOUNT) && !(s->flags & SLAB_ACCOUNT))
-		return true;
-
 	/*
 	 * The obtained objcg pointer is safe to use within the current scope,
 	 * defined by current task or set_active_memcg() pair.
 	 * obj_cgroup_get() is used to get a permanent reference.
 	 */
-	objcg = current_obj_cgroup();
+	struct obj_cgroup *objcg = current_obj_cgroup();
 	if (!objcg)
 		return true;
 
@@ -1907,17 +1899,34 @@ static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
 	return true;
 }
 
-static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
-					      struct obj_cgroup *objcg,
-					      gfp_t flags, size_t size,
-					      void **p)
+/*
+ * Returns false if the allocation should fail.
+ */
+static __fastpath_inline
+bool memcg_slab_pre_alloc_hook(struct kmem_cache *s, struct list_lru *lru,
+			       struct obj_cgroup **objcgp, size_t objects,
+			       gfp_t flags)
+{
+	if (!memcg_kmem_online())
+		return true;
+
+	if (likely(!(flags & __GFP_ACCOUNT) && !(s->flags & SLAB_ACCOUNT)))
+		return true;
+
+	return likely(__memcg_slab_pre_alloc_hook(s, lru, objcgp, objects,
+						  flags));
+}
+
+static void __memcg_slab_post_alloc_hook(struct kmem_cache *s,
+					 struct obj_cgroup *objcg,
+					 gfp_t flags, size_t size,
+					 void **p)
 {
 	struct slab *slab;
 	unsigned long off;
 	size_t i;
 
-	if (!memcg_kmem_online() || !objcg)
-		return;
+	flags &= gfp_allowed_mask;
 
 	for (i = 0; i < size; i++) {
 		if (likely(p[i])) {
@@ -1940,6 +1949,16 @@ static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
 	}
 }
 
+static __fastpath_inline
+void memcg_slab_post_alloc_hook(struct kmem_cache *s, struct obj_cgroup *objcg,
+				gfp_t flags, size_t size, void **p)
+{
+	if (likely(!memcg_kmem_online() || !objcg))
+		return;
+
+	return __memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
+}
+
 static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 					void **p, int objects)
 {
@@ -3709,34 +3728,34 @@ noinline int should_failslab(struct kmem_cache *s, gfp_t gfpflags)
 }
 ALLOW_ERROR_INJECTION(should_failslab, ERRNO);
 
-static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
-						     struct list_lru *lru,
-						     struct obj_cgroup **objcgp,
-						     size_t size, gfp_t flags)
+static __fastpath_inline
+struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
+				       struct list_lru *lru,
+				       struct obj_cgroup **objcgp,
+				       size_t size, gfp_t flags)
 {
 	flags &= gfp_allowed_mask;
 
 	might_alloc(flags);
 
-	if (should_failslab(s, flags))
+	if (unlikely(should_failslab(s, flags)))
 		return NULL;
 
-	if (!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags))
+	if (unlikely(!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags)))
 		return NULL;
 
 	return s;
 }
 
-static inline void slab_post_alloc_hook(struct kmem_cache *s,
-					struct obj_cgroup *objcg, gfp_t flags,
-					size_t size, void **p, bool init,
-					unsigned int orig_size)
+static __fastpath_inline
+void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
+			  gfp_t flags, size_t size, void **p, bool init,
+			  unsigned int orig_size)
 {
 	unsigned int zero_size = s->object_size;
 	bool kasan_init = init;
 	size_t i;
-
-	flags &= gfp_allowed_mask;
+	gfp_t init_flags = flags & gfp_allowed_mask;
 
 	/*
 	 * For kmalloc object, the allocated memory size(object_size) is likely
@@ -3769,13 +3788,13 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
 	 */
 	for (i = 0; i < size; i++) {
-		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
+		p[i] = kasan_slab_alloc(s, p[i], init_flags, kasan_init);
 		if (p[i] && init && (!kasan_init ||
 				     !kasan_has_integrated_init()))
 			memset(p[i], 0, zero_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
-					 s->flags, flags);
-		kmsan_slab_alloc(s, p[i], flags);
+					 s->flags, init_flags);
+		kmsan_slab_alloc(s, p[i], init_flags);
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
@@ -3799,7 +3818,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
 	bool init = false;
 
 	s = slab_pre_alloc_hook(s, lru, &objcg, 1, gfpflags);
-	if (!s)
+	if (unlikely(!s))
 		return NULL;
 
 	object = kfence_alloc(s, orig_size, gfpflags);
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-41-vbabka%40suse.cz.
