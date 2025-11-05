Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZFGVTEAMGQEJQEQNZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D94EC34AD9
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 10:05:42 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-640bb21b512sf3647977a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 01:05:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762333542; cv=pass;
        d=google.com; s=arc-20240605;
        b=AjKbZz0Pk2GOUFs6bmJzBrzQj/PtyBTd7pFFnEeojwwLZMgOE4hPiuwL1bUOxnik13
         d8G3CNkf3Bu2ohnilOv3AefUvUBvl8qMjaPRZsF+FQPL0WCGKfw3c9BU6GiD1rIFQZzo
         loUFeFqDsmNEf8kCHbkIdd1vMIyZYAOv4e+VIJP3rZlLGzFfXs4+XBYcAytg9RTdQxJg
         WhITSE7Cc9UVWsuDSswt6rb3Vy6TWV8bG/BVQdru1l3k0mptjSXMeEugU1/6p/jSugUd
         0O0pDQTFq5UY6zj8Sl7mG0Vkp98hdKyZdWa/ZJaUOzknrCyZHLxO8beSav82+Vza+X7/
         1ETA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=95pD7eMuRt5ZvJ+MCgxZFS6W6kY58sO3eA5InVag3bQ=;
        fh=v1TaUjBqW9m8Ucn0wzkVK6w0RQ0QltTHX6mNFFFtMoI=;
        b=QwplOZkp1pgyNSr5PSnMEVnZtHRWGAPQjUiNaZoCJSjjZ1lxRQSn2jj8pwz1ae3gtg
         lvT+Uap3PzV6XgnAjGOAtw5kt22SDkhS9JpkBCclDGe0svDqdYlvyqlyIOp4uHeVgm4q
         yq1O9y59OFVvZviPjo5fZNmWM1qEyZpkYaOtX71mDeBygBEv6hj3ANfQZoCBBdF54mrK
         7zvA7N4MNO1EXO4/UvBSBRZTAdC0e+sX8b62aDgJcqcF35B/niOku0LG7ul51SQ1ti1U
         C2AeAkUvrEz+znkNQKmwnls6QeLmvKFoH9mjZKGLdVtkTRwiWoxkO/iL/kS01zfA+fKd
         7Sig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fX1xBGgc;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fX1xBGgc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762333542; x=1762938342; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:in-reply-to:references:message-id:mime-version
         :subject:date:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=95pD7eMuRt5ZvJ+MCgxZFS6W6kY58sO3eA5InVag3bQ=;
        b=pzXJygogAnL9oU4Q/g9InkwRasGxbX9Fa/eB4AMcXuXSu8RP+gjv/nk45413GnYDO4
         GOE9bSvKU257LYIFdVBdHwUIzokK4lu3di1KTj2SjW40ER4BUECC/j/kInN2WVlNCyVT
         pGVV8lTDE9+de2B3gCkBR2DTa80zjHFkA0ANhTLDtYg+tJVba2XJNC2HI4562ofrzilT
         JR1xotwSfJPuIqj8eT2Ig1DZylYTOblzAgkMpAegMeCEeXKI8Djf5fFS+q7IsXsA8zKm
         r0IP1zNX45PRugzjzIrNhysyyQQszikNaY5Ht2msoVNRuYFyLqWskmeHxBPq0SpujsCS
         rD4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762333542; x=1762938342;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=95pD7eMuRt5ZvJ+MCgxZFS6W6kY58sO3eA5InVag3bQ=;
        b=aMgbg0SFmU6gu61RJRnpObwCsA2A+dXHdZEEyJZQQZa5yc3HVjZ8CkiUA+zWe4c0pq
         bQdzZlmxAX7lrj2S/V+J9u6dRX3QqAZz1Mg+rAc0sk0EEhvXNq8ATZsHzFLTNhHI3zZy
         fQHE+yIeHkLI5Is2bgZR2Kq5J0t5eERCfqQ0M8FWNRWQCiaiBeNNnaWmW+CocWBHXUQm
         GNSZ84SO2HjmsuE2cfjkNG7LNF9TQ/4Q0UxhGOAOCMjHdHEKLVx5qDcFpu5z2rW5a6O0
         +R4dZgEdUxDt2m8Bt0KcrZDQTlCHKojthzmql4k8qd9t1Aas2eYDrjsQSruTR0EBg19I
         C9bg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCUu3CM4LN0C8PyOb0xjI9yYxr6YL3ji9o2ahvwEPSPnYpB9TXxxoQ0waFitwTnwMAVHYB5w==@lfdr.de
X-Gm-Message-State: AOJu0Yzf4ASS8seuI76BZNTyqPUH4P99MzWIo/oDFqZZ9R77D1tzLTYY
	xH5JeTSXlxMmTBhM62T5zmoJ3+cte8yiD4+U9lLNrd2ONDhBPfzyWkiR
X-Google-Smtp-Source: AGHT+IHSxdDik7Sssaaa6iyfkkqTTAcDndxMRGzqb4lV1XLZk97g/f/o1DXSuQqhWcUCMoOw6HBSiA==
X-Received: by 2002:a05:6402:3486:b0:63c:334c:fbc7 with SMTP id 4fb4d7f45d1cf-64105a44263mr1723999a12.19.1762333541279;
        Wed, 05 Nov 2025 01:05:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aEG7XmIZ9y4XFs66UQvXDce6kZ0bWqgqNALotNQWwDrw=="
Received: by 2002:a05:6402:5355:20b0:640:cdaf:421e with SMTP id
 4fb4d7f45d1cf-640cdaf49ebls248147a12.1.-pod-prod-03-eu; Wed, 05 Nov 2025
 01:05:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUqtzFmF9ABnUoanWFXicka9Od/4kJaHvUM2VJalcoWgkkSqHc20Q3iqLVPJMOIUd9uUGiG7sHH8HI=@googlegroups.com
X-Received: by 2002:a17:907:d649:b0:b6d:2b14:4aa4 with SMTP id a640c23a62f3a-b7265643189mr216838566b.63.1762333538095;
        Wed, 05 Nov 2025 01:05:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762333538; cv=none;
        d=google.com; s=arc-20240605;
        b=Pg19HSJMfptRw2KDrs5ITZISfCjVvQ7fKisgNemF6GndBPG9Vn03RNWWnFVW2lErLy
         1yMsvZn8NZdHRpBAj0PJCZQzmam41YaYc/6GUA8ZsnoBiJ74WAIh5px67oCcudVdEyqd
         Qpl5//9hG9PlX/7dbE70TimNBsUDMNZrqK1DsiwOE+i7JP041+7uRFrnL+inRtp4F7e3
         8PRqIdghobmFNf3sP/YrifGrMhQiq7cKbVP8QmhcDgHkKvdX7Pb7VhBRuIP2r1Qvd8mL
         8i8zIutyJdNdNym9J9CrLD9AyE5Tddb7rRccrduALU2j7T/8e1EyKTTz6khjLE2eh45w
         NOjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=U6xgVA63NMfAYlm/Ncmyru9bsRe/qhoJxymi9ppBFWA=;
        fh=dklpSMYSEC41gVZaXcntr2MBCAntdHiJG8gGN2y0lZI=;
        b=RG9fppxH/I7tI6P0VpDTtC6BcJ+ZK6Syx9OCDwxfEdNEvDHm+ZouFiAQaoIIBZGFMF
         5IZVTdJfBfQ/luDxICPKMY/1P//LYgqIgSJVy8yocidAjBiwYb2H3k3E7Dn9SirD4weW
         T+e3SuID0t4kMS+1ZVK9Ynpbyqeq6dFf9hqSrr6SAmHwEQRYPxIczQLp1mR7/geG2ou2
         Ot6GL6nsIvogz4tPMwNeBtBoCNbCtAyISFG9XhuQMJ0jPgc2kggR2GI7jPAXV83Pf0B0
         Rwz+MMIKQsCws1HVkihNaRakP+lxXLvUIqeEtPo1M17pjhBUoehM1ISVwvSHTE7MPVji
         cI1g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fX1xBGgc;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=fX1xBGgc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b724130ff62si15954566b.3.2025.11.05.01.05.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 01:05:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E1B7B1F44F;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C7B6313C01;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ABZ9MFoTC2lSBAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 05 Nov 2025 09:05:30 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 05 Nov 2025 10:05:32 +0100
Subject: [PATCH 4/5] slub: remove CONFIG_SLUB_TINY specific code paths
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251105-sheaves-cleanups-v1-4-b8218e1ac7ef@suse.cz>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
In-Reply-To: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, bpf@vger.kernel.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.996];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[13];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid,suse.cz:email]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=fX1xBGgc;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=fX1xBGgc;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

CONFIG_SLUB_TINY minimizes the SLUB's memory overhead in multiple ways,
mainly by avoiding percpu caching of slabs and objects. It also reduces
code size by replacing some code paths with simplified ones through
ifdefs, but the benefits of that are smaller and would complicate the
upcoming changes.

Thus remove these code paths and associated ifdefs and simplify the code
base.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   2 --
 mm/slub.c | 107 +++-----------------------------------------------------------
 2 files changed, 4 insertions(+), 105 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 078daecc7cf5..f7b8df56727d 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -236,10 +236,8 @@ struct kmem_cache_order_objects {
  * Slab cache management.
  */
 struct kmem_cache {
-#ifndef CONFIG_SLUB_TINY
 	struct kmem_cache_cpu __percpu *cpu_slab;
 	struct lock_class_key lock_key;
-#endif
 	struct slub_percpu_sheaves __percpu *cpu_sheaves;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
diff --git a/mm/slub.c b/mm/slub.c
index bb744e8044f0..a7c6d79154f8 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -410,7 +410,6 @@ enum stat_item {
 	NR_SLUB_STAT_ITEMS
 };
 
-#ifndef CONFIG_SLUB_TINY
 /*
  * When changing the layout, make sure freelist and tid are still compatible
  * with this_cpu_cmpxchg_double() alignment requirements.
@@ -432,7 +431,6 @@ struct kmem_cache_cpu {
 	unsigned int stat[NR_SLUB_STAT_ITEMS];
 #endif
 };
-#endif /* CONFIG_SLUB_TINY */
 
 static inline void stat(const struct kmem_cache *s, enum stat_item si)
 {
@@ -597,12 +595,10 @@ static inline void *get_freepointer(struct kmem_cache *s, void *object)
 	return freelist_ptr_decode(s, p, ptr_addr);
 }
 
-#ifndef CONFIG_SLUB_TINY
 static void prefetch_freepointer(const struct kmem_cache *s, void *object)
 {
 	prefetchw(object + s->offset);
 }
-#endif
 
 /*
  * When running under KMSAN, get_freepointer_safe() may return an uninitialized
@@ -714,10 +710,12 @@ static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
 	return s->cpu_partial_slabs;
 }
 #else
+#ifdef SLAB_SUPPORTS_SYSFS
 static inline void
 slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
 {
 }
+#endif
 
 static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
 {
@@ -2026,13 +2024,11 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
 static inline void dec_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
-#ifndef CONFIG_SLUB_TINY
 static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
 			       void **freelist, void *nextfree)
 {
 	return false;
 }
-#endif
 #endif /* CONFIG_SLUB_DEBUG */
 
 #ifdef CONFIG_SLAB_OBJ_EXT
@@ -3623,8 +3619,6 @@ static struct slab *get_partial(struct kmem_cache *s, int node,
 	return get_any_partial(s, pc);
 }
 
-#ifndef CONFIG_SLUB_TINY
-
 #ifdef CONFIG_PREEMPTION
 /*
  * Calculate the next globally unique transaction for disambiguation
@@ -4024,12 +4018,6 @@ static bool has_cpu_slab(int cpu, struct kmem_cache *s)
 	return c->slab || slub_percpu_partial(c);
 }
 
-#else /* CONFIG_SLUB_TINY */
-static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu) { }
-static inline bool has_cpu_slab(int cpu, struct kmem_cache *s) { return false; }
-static inline void flush_this_cpu_slab(struct kmem_cache *s) { }
-#endif /* CONFIG_SLUB_TINY */
-
 static bool has_pcs_used(int cpu, struct kmem_cache *s)
 {
 	struct slub_percpu_sheaves *pcs;
@@ -4370,7 +4358,6 @@ static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags)
 	return true;
 }
 
-#ifndef CONFIG_SLUB_TINY
 static inline bool
 __update_cpu_freelist_fast(struct kmem_cache *s,
 			   void *freelist_old, void *freelist_new,
@@ -4634,7 +4621,7 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	pc.orig_size = orig_size;
 	slab = get_partial(s, node, &pc);
 	if (slab) {
-		if (kmem_cache_debug(s)) {
+		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 			freelist = pc.object;
 			/*
 			 * For debug caches here we had to go through
@@ -4672,7 +4659,7 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 
 	stat(s, ALLOC_SLAB);
 
-	if (kmem_cache_debug(s)) {
+	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 		freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
 
 		if (unlikely(!freelist)) {
@@ -4884,32 +4871,6 @@ static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 
 	return object;
 }
-#else /* CONFIG_SLUB_TINY */
-static void *__slab_alloc_node(struct kmem_cache *s,
-		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
-{
-	struct partial_context pc;
-	struct slab *slab;
-	void *object;
-
-	pc.flags = gfpflags;
-	pc.orig_size = orig_size;
-	slab = get_partial(s, node, &pc);
-
-	if (slab)
-		return pc.object;
-
-	slab = new_slab(s, gfpflags, node);
-	if (unlikely(!slab)) {
-		slab_out_of_memory(s, gfpflags, node);
-		return NULL;
-	}
-
-	object = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
-
-	return object;
-}
-#endif /* CONFIG_SLUB_TINY */
 
 /*
  * If the object has been wiped upon free, make sure it's fully initialized by
@@ -5760,9 +5721,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	 * it did local_lock_irqsave(&s->cpu_slab->lock, flags).
 	 * In this case fast path with __update_cpu_freelist_fast() is not safe.
 	 */
-#ifndef CONFIG_SLUB_TINY
 	if (!in_nmi() || !local_lock_is_locked(&s->cpu_slab->lock))
-#endif
 		ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
 
 	if (PTR_ERR(ret) == -EBUSY) {
@@ -6553,14 +6512,10 @@ static void free_deferred_objects(struct irq_work *work)
 	llist_for_each_safe(pos, t, llnode) {
 		struct slab *slab = container_of(pos, struct slab, llnode);
 
-#ifdef CONFIG_SLUB_TINY
-		free_slab(slab->slab_cache, slab);
-#else
 		if (slab->frozen)
 			deactivate_slab(slab->slab_cache, slab, slab->flush_freelist);
 		else
 			free_slab(slab->slab_cache, slab);
-#endif
 	}
 }
 
@@ -6596,7 +6551,6 @@ void defer_free_barrier(void)
 		irq_work_sync(&per_cpu_ptr(&defer_free_objects, cpu)->work);
 }
 
-#ifndef CONFIG_SLUB_TINY
 /*
  * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
  * can perform fastpath freeing without additional function calls.
@@ -6689,14 +6643,6 @@ static __always_inline void do_slab_free(struct kmem_cache *s,
 	}
 	stat_add(s, FREE_FASTPATH, cnt);
 }
-#else /* CONFIG_SLUB_TINY */
-static void do_slab_free(struct kmem_cache *s,
-				struct slab *slab, void *head, void *tail,
-				int cnt, unsigned long addr)
-{
-	__slab_free(s, slab, head, tail, cnt, addr);
-}
-#endif /* CONFIG_SLUB_TINY */
 
 static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
@@ -6974,11 +6920,7 @@ void kfree_nolock(const void *object)
 	 * since kasan quarantine takes locks and not supported from NMI.
 	 */
 	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
-#ifndef CONFIG_SLUB_TINY
 	do_slab_free(s, slab, x, x, 0, _RET_IP_);
-#else
-	defer_free(s, x);
-#endif
 }
 EXPORT_SYMBOL_GPL(kfree_nolock);
 
@@ -7428,7 +7370,6 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 }
 EXPORT_SYMBOL(kmem_cache_free_bulk);
 
-#ifndef CONFIG_SLUB_TINY
 static inline
 int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			    void **p)
@@ -7493,35 +7434,6 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	return 0;
 
 }
-#else /* CONFIG_SLUB_TINY */
-static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-				   size_t size, void **p)
-{
-	int i;
-
-	for (i = 0; i < size; i++) {
-		void *object = kfence_alloc(s, s->object_size, flags);
-
-		if (unlikely(object)) {
-			p[i] = object;
-			continue;
-		}
-
-		p[i] = __slab_alloc_node(s, flags, NUMA_NO_NODE,
-					 _RET_IP_, s->object_size);
-		if (unlikely(!p[i]))
-			goto error;
-
-		maybe_wipe_obj_freeptr(s, p[i]);
-	}
-
-	return i;
-
-error:
-	__kmem_cache_free_bulk(s, i, p);
-	return 0;
-}
-#endif /* CONFIG_SLUB_TINY */
 
 /* Note that interrupts must be enabled when calling this function. */
 int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
@@ -7740,7 +7652,6 @@ init_kmem_cache_node(struct kmem_cache_node *n, struct node_barn *barn)
 		barn_init(barn);
 }
 
-#ifndef CONFIG_SLUB_TINY
 static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
 {
 	BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
@@ -7761,12 +7672,6 @@ static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
 
 	return 1;
 }
-#else
-static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
-{
-	return 1;
-}
-#endif /* CONFIG_SLUB_TINY */
 
 static int init_percpu_sheaves(struct kmem_cache *s)
 {
@@ -7856,13 +7761,11 @@ void __kmem_cache_release(struct kmem_cache *s)
 	cache_random_seq_destroy(s);
 	if (s->cpu_sheaves)
 		pcs_destroy(s);
-#ifndef CONFIG_SLUB_TINY
 #ifdef CONFIG_PREEMPT_RT
 	if (s->cpu_slab)
 		lockdep_unregister_key(&s->lock_key);
 #endif
 	free_percpu(s->cpu_slab);
-#endif
 	free_kmem_cache_nodes(s);
 }
 
@@ -8605,10 +8508,8 @@ void __init kmem_cache_init(void)
 
 void __init kmem_cache_init_late(void)
 {
-#ifndef CONFIG_SLUB_TINY
 	flushwq = alloc_workqueue("slub_flushwq", WQ_MEM_RECLAIM, 0);
 	WARN_ON(!flushwq);
-#endif
 }
 
 struct kmem_cache *

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251105-sheaves-cleanups-v1-4-b8218e1ac7ef%40suse.cz.
