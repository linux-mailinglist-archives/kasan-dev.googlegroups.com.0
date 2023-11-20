Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRON52VAMGQEYH5G65Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 653827F1C85
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:46 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40855a91314sf13378265e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505286; cv=pass;
        d=google.com; s=arc-20160816;
        b=hTRk8Ko2q7SPo4N9Sl+6YFdRAS+GquT6XQbTOJXDZWyDba62WbvGvbC/s2QaFfFOhS
         zJiiFUPXT3Q0NKL28WYiUAIswbxXJm1z2ssSVdrz787D9emVS6a1ghVRIPxyOMpT85WD
         Yg7pu2R/zr+Kv3B9ZL9qX4Llb3P8Ytzrxr3eEZuv7ja4YYV8wkyKx2FJq5Z121OzSRrC
         FxlzD6H1ZiVz06KQNEAnJG1GJuMJN40uM5Ap24DIKDNanHuRGOBak3laCXmjp+xU/sAq
         X2IBWYp5cnQlf9ZqZd2KseP+AWyQOJrqEb5WlNA9CydqipicK+zuoJFMk7n8lhlhsPa4
         r4gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=+UCBP6SHnigXa0NIqNc+36XQvO/s+VtAV697siBsanE=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=FtgiUYIc1jRwntOv18i+cA+rtQiMTYp5e01BSxODhooxPz5/7vRBNkrzoM5a//gpoz
         kbf3yDHeXs95qPdQa/AZ/zsGWCwevurOF5nebigsXybqrOYijDatXHz0uDmyWJUjKrPR
         xAWIgSbVA1mPqSA6+RuOsQus3COvxdS+D60poH3lZrm2CCqknAN03sUb1MCRyhpQphl8
         wBtJxgRIo6JYgQXHpFWfCnLol5JRICDPxJ+0FlsEXGJIObVmHMD3ATX42T0mKe+yRA/i
         yjHVBPTWoe6DuzIqa/H8TMhkocOqBJ3eTVE8ExXHIDJXi+rf3n4DVvQMtf0LdbPYTtLg
         MXtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LCzJgngk;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505286; x=1701110086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+UCBP6SHnigXa0NIqNc+36XQvO/s+VtAV697siBsanE=;
        b=nu2X1jixOxw3ziGYPU4zGNGBxXblX2mBvnCeSONku12Ew1hEmgDuetwiD25LLjmKIF
         grjSzU6N6fuiqPozuLBRolSqp8FP6WjEnUlD+VLs93pA8Lw3c9J0i8gQPrRkkNdBm37+
         srm5klSQNBTmgMZKWiEq4ZlBI3XgQ5Cpm8oSeg6vzvcWndVVL1VwBIwju8oCRb3om05g
         ox8d8vkwynnRqQklQtbXqYBoIKvPc67BCsfsPq+nqMhzrRj2nymA4MVxm/iTOLyJPzYo
         06O7/4RoK8WumuxPEfIjjNRCyIgJ0elMUqr33i3EJ8Sctixm3tazIOzvZLHSvX8q06S+
         Qy+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505286; x=1701110086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+UCBP6SHnigXa0NIqNc+36XQvO/s+VtAV697siBsanE=;
        b=sxgK6FAhJjvzfRzxvLCHYoYWNm9A+z9j4Onn+5gPVM4GYYdj9pZzkXY8IvfT5SGZHM
         XMkh8Sz9pgPBkQpyicrwjXh6Hvaw8JEvHUiAb8hwubRORXQALPJbV2lIOmPWfOs9k/Y1
         a5d1yTgvN4R7y1dVjDD92hratCWuh8+UkzFFdfdgQaMTMztT18rxmrTMKPK6/FPLPBSS
         bbIUmauSoeB5l8+t6Z9W/cuglxlvru4OoEYmilGuqbdqYUT9NrTYT4/9tAbtDRrqVGQi
         kOvWL/pQoxFT2fVU4KANQbtEj7FSuLDa+CafVIGQRZNT8IR34/vyCOpQ6hzhmbpwM3ec
         t2fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyvmlGFwXKXaKySWpcGKMYTqJGrtp3r7SxxCQPdLd6NWAVmEuqu
	8t1cvXT9crf8okCCAuhhsDY=
X-Google-Smtp-Source: AGHT+IEc23eiROgpwTnlyGNR4yizl2Pqk0L4eVZALA+DzWb8mX4/ptawOdpW+J00U61akeNeNF8yUw==
X-Received: by 2002:a05:600c:354d:b0:405:358c:ba74 with SMTP id i13-20020a05600c354d00b00405358cba74mr346688wmq.0.1700505285814;
        Mon, 20 Nov 2023 10:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b9e:b0:409:5426:9d6a with SMTP id
 n30-20020a05600c3b9e00b0040954269d6als139971wms.1.-pod-prod-00-eu; Mon, 20
 Nov 2023 10:34:44 -0800 (PST)
X-Received: by 2002:a05:600c:4f53:b0:40a:3ff8:e8eb with SMTP id m19-20020a05600c4f5300b0040a3ff8e8ebmr291085wmq.15.1700505284144;
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505284; cv=none;
        d=google.com; s=arc-20160816;
        b=CUuuJTdJoxN4eruUWcmTgwOzh5y+CazdfxDsixVFoVCsfciuoPn84bbxMnPKdqwaEL
         VChWxsRelXPSmEgoeE4le8//qdJ37ka0SVNiz21IHL6JPz2TLpbtUtU8jXy57S/COz/9
         9eS/vJmzXC9e5o7rQiAGX+6UaDDeqGAqt1stSW9wmmzZq+/SGasWw+oncRGMRb3F/VFN
         GLuXYApJ4NMF21yi6gfXRzmwdginoSwLdNW0w+F60bOqrcVfz9MKDaDDzxoSW0gLzI53
         lZXto9yzMtbNUDRkbvFiU1RT6VxrWYZcaMDwZ+u+CNZqQZjDiXnRgKnHpWkbmHnbzSws
         5HNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=l41Jb+BHNYtQ2OIFgOGmX9WMKyvcGjadAJ7/ZFyre/E=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=mFWOqAOXYtWKDUNQUYMRq1Bh+S2i+LvuHrT/40q8+z1yiMVWqdNhJojSYaI1GXZfFO
         LMk7aKYmuX36P/Ppmp3MK9tN8wvtujonIkzeUIC7MmpW5LBTP7x/zAKPlMru7khHZpfT
         ll0/l/oCEsLRNNlXyFYYsiymxzM23wG+oKFXSvojh4AWD1gPdd0Zb3qbCG87muXuG+1F
         W/LqsR67EA2CmrPBmX4MgyUERoyjwb5xNN/N8rGBwhr0kfbKIi2GcCGoD0dm3BqDjelW
         yqQauOLJfQpstp4uKFQO3iVD3sieXavGKndbb94THHIYB07HnCbffxOgaFjXb18m6IJs
         /rfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=LCzJgngk;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id bi24-20020a05600c3d9800b00405c7dd428csi438576wmb.2.2023.11.20.10.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C354A1F8B2;
	Mon, 20 Nov 2023 18:34:43 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 8455213499;
	Mon, 20 Nov 2023 18:34:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id OCGvH8OmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:43 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:29 +0100
Subject: [PATCH v2 18/21] mm/slab: move kmalloc() functions from
 slab_common.c to slub.c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-18-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: *
X-Spam-Score: 1.30
X-Spamd-Result: default: False [1.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 BAYES_SPAM(5.10)[100.00%];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=LCzJgngk;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

This will eliminate a call between compilation units through
__kmem_cache_alloc_node() and allow better inlining of the allocation
fast path.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h        |   3 --
 mm/slab_common.c | 119 ----------------------------------------------------
 mm/slub.c        | 126 +++++++++++++++++++++++++++++++++++++++++++++++++++----
 3 files changed, 118 insertions(+), 130 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 7d7cc7af614e..54deeb0428c6 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -416,9 +416,6 @@ kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
 	return kmalloc_caches[kmalloc_type(flags, caller)][index];
 }
 
-void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
-			      int node, size_t orig_size,
-			      unsigned long caller);
 gfp_t kmalloc_fix_flags(gfp_t flags);
 
 /* Functions provided by the slab allocators */
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 31ade17a7ad9..238293b1dbe1 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -936,50 +936,6 @@ void __init create_kmalloc_caches(slab_flags_t flags)
 	slab_state = UP;
 }
 
-static void *__kmalloc_large_node(size_t size, gfp_t flags, int node);
-static __always_inline
-void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller)
-{
-	struct kmem_cache *s;
-	void *ret;
-
-	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
-		ret = __kmalloc_large_node(size, flags, node);
-		trace_kmalloc(caller, ret, size,
-			      PAGE_SIZE << get_order(size), flags, node);
-		return ret;
-	}
-
-	if (unlikely(!size))
-		return ZERO_SIZE_PTR;
-
-	s = kmalloc_slab(size, flags, caller);
-
-	ret = __kmem_cache_alloc_node(s, flags, node, size, caller);
-	ret = kasan_kmalloc(s, ret, size, flags);
-	trace_kmalloc(caller, ret, size, s->size, flags, node);
-	return ret;
-}
-
-void *__kmalloc_node(size_t size, gfp_t flags, int node)
-{
-	return __do_kmalloc_node(size, flags, node, _RET_IP_);
-}
-EXPORT_SYMBOL(__kmalloc_node);
-
-void *__kmalloc(size_t size, gfp_t flags)
-{
-	return __do_kmalloc_node(size, flags, NUMA_NO_NODE, _RET_IP_);
-}
-EXPORT_SYMBOL(__kmalloc);
-
-void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
-				  int node, unsigned long caller)
-{
-	return __do_kmalloc_node(size, flags, node, caller);
-}
-EXPORT_SYMBOL(__kmalloc_node_track_caller);
-
 /**
  * __ksize -- Report full size of underlying allocation
  * @object: pointer to the object
@@ -1016,30 +972,6 @@ size_t __ksize(const void *object)
 	return slab_ksize(folio_slab(folio)->slab_cache);
 }
 
-void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
-{
-	void *ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
-					    size, _RET_IP_);
-
-	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
-
-	ret = kasan_kmalloc(s, ret, size, gfpflags);
-	return ret;
-}
-EXPORT_SYMBOL(kmalloc_trace);
-
-void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
-			 int node, size_t size)
-{
-	void *ret = __kmem_cache_alloc_node(s, gfpflags, node, size, _RET_IP_);
-
-	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, node);
-
-	ret = kasan_kmalloc(s, ret, size, gfpflags);
-	return ret;
-}
-EXPORT_SYMBOL(kmalloc_node_trace);
-
 gfp_t kmalloc_fix_flags(gfp_t flags)
 {
 	gfp_t invalid_mask = flags & GFP_SLAB_BUG_MASK;
@@ -1052,57 +984,6 @@ gfp_t kmalloc_fix_flags(gfp_t flags)
 	return flags;
 }
 
-/*
- * To avoid unnecessary overhead, we pass through large allocation requests
- * directly to the page allocator. We use __GFP_COMP, because we will need to
- * know the allocation order to free the pages properly in kfree.
- */
-
-static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
-{
-	struct page *page;
-	void *ptr = NULL;
-	unsigned int order = get_order(size);
-
-	if (unlikely(flags & GFP_SLAB_BUG_MASK))
-		flags = kmalloc_fix_flags(flags);
-
-	flags |= __GFP_COMP;
-	page = alloc_pages_node(node, flags, order);
-	if (page) {
-		ptr = page_address(page);
-		mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
-				      PAGE_SIZE << order);
-	}
-
-	ptr = kasan_kmalloc_large(ptr, size, flags);
-	/* As ptr might get tagged, call kmemleak hook after KASAN. */
-	kmemleak_alloc(ptr, size, 1, flags);
-	kmsan_kmalloc_large(ptr, size, flags);
-
-	return ptr;
-}
-
-void *kmalloc_large(size_t size, gfp_t flags)
-{
-	void *ret = __kmalloc_large_node(size, flags, NUMA_NO_NODE);
-
-	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
-		      flags, NUMA_NO_NODE);
-	return ret;
-}
-EXPORT_SYMBOL(kmalloc_large);
-
-void *kmalloc_large_node(size_t size, gfp_t flags, int node)
-{
-	void *ret = __kmalloc_large_node(size, flags, node);
-
-	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
-		      flags, node);
-	return ret;
-}
-EXPORT_SYMBOL(kmalloc_large_node);
-
 #ifdef CONFIG_SLAB_FREELIST_RANDOM
 /* Randomize a generic freelist */
 static void freelist_randomize(unsigned int *list,
diff --git a/mm/slub.c b/mm/slub.c
index 2baa9e94d9df..d6bc15929d22 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3851,14 +3851,6 @@ void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 }
 EXPORT_SYMBOL(kmem_cache_alloc_lru);
 
-void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
-			      int node, size_t orig_size,
-			      unsigned long caller)
-{
-	return slab_alloc_node(s, NULL, gfpflags, node,
-			       caller, orig_size);
-}
-
 /**
  * kmem_cache_alloc_node - Allocate an object on the specified node
  * @s: The cache to allocate from.
@@ -3882,6 +3874,124 @@ void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 }
 EXPORT_SYMBOL(kmem_cache_alloc_node);
 
+/*
+ * To avoid unnecessary overhead, we pass through large allocation requests
+ * directly to the page allocator. We use __GFP_COMP, because we will need to
+ * know the allocation order to free the pages properly in kfree.
+ */
+static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
+{
+	struct page *page;
+	void *ptr = NULL;
+	unsigned int order = get_order(size);
+
+	if (unlikely(flags & GFP_SLAB_BUG_MASK))
+		flags = kmalloc_fix_flags(flags);
+
+	flags |= __GFP_COMP;
+	page = alloc_pages_node(node, flags, order);
+	if (page) {
+		ptr = page_address(page);
+		mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
+				      PAGE_SIZE << order);
+	}
+
+	ptr = kasan_kmalloc_large(ptr, size, flags);
+	/* As ptr might get tagged, call kmemleak hook after KASAN. */
+	kmemleak_alloc(ptr, size, 1, flags);
+	kmsan_kmalloc_large(ptr, size, flags);
+
+	return ptr;
+}
+
+void *kmalloc_large(size_t size, gfp_t flags)
+{
+	void *ret = __kmalloc_large_node(size, flags, NUMA_NO_NODE);
+
+	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
+		      flags, NUMA_NO_NODE);
+	return ret;
+}
+EXPORT_SYMBOL(kmalloc_large);
+
+void *kmalloc_large_node(size_t size, gfp_t flags, int node)
+{
+	void *ret = __kmalloc_large_node(size, flags, node);
+
+	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
+		      flags, node);
+	return ret;
+}
+EXPORT_SYMBOL(kmalloc_large_node);
+
+static __always_inline
+void *__do_kmalloc_node(size_t size, gfp_t flags, int node,
+			unsigned long caller)
+{
+	struct kmem_cache *s;
+	void *ret;
+
+	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
+		ret = __kmalloc_large_node(size, flags, node);
+		trace_kmalloc(caller, ret, size,
+			      PAGE_SIZE << get_order(size), flags, node);
+		return ret;
+	}
+
+	if (unlikely(!size))
+		return ZERO_SIZE_PTR;
+
+	s = kmalloc_slab(size, flags, caller);
+
+	ret = slab_alloc_node(s, NULL, flags, node, caller, size);
+	ret = kasan_kmalloc(s, ret, size, flags);
+	trace_kmalloc(caller, ret, size, s->size, flags, node);
+	return ret;
+}
+
+void *__kmalloc_node(size_t size, gfp_t flags, int node)
+{
+	return __do_kmalloc_node(size, flags, node, _RET_IP_);
+}
+EXPORT_SYMBOL(__kmalloc_node);
+
+void *__kmalloc(size_t size, gfp_t flags)
+{
+	return __do_kmalloc_node(size, flags, NUMA_NO_NODE, _RET_IP_);
+}
+EXPORT_SYMBOL(__kmalloc);
+
+void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
+				  int node, unsigned long caller)
+{
+	return __do_kmalloc_node(size, flags, node, caller);
+}
+EXPORT_SYMBOL(__kmalloc_node_track_caller);
+
+void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
+{
+	void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE,
+					    _RET_IP_, size);
+
+	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
+
+	ret = kasan_kmalloc(s, ret, size, gfpflags);
+	return ret;
+}
+EXPORT_SYMBOL(kmalloc_trace);
+
+void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
+			 int node, size_t size)
+{
+	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, size);
+
+	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, node);
+
+	ret = kasan_kmalloc(s, ret, size, gfpflags);
+	return ret;
+}
+EXPORT_SYMBOL(kmalloc_node_trace);
+
 static noinline void free_to_partial_list(
 	struct kmem_cache *s, struct slab *slab,
 	void *head, void *tail, int bulk_cnt,

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-18-9c9c70177183%40suse.cz.
