Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRWN52VAMGQEZMRTXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CFE4D7F1C8A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:47 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50aa822cb33sf1789406e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505287; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rzyvr3RDsqqyLfzmpy6D/uCg8Ky5weEtQP1f5WvQZcNHHgJiF0NaRRQg/XmM7QcCP/
         ZrIe1gGK02Y7N+NEheOKPhnczX0zw86pe62sZNrQDxcA5rFKzdWO0lD8fmtgzv+LeNgl
         kkd7wMum8RklCZdufouz4Z/Rnx4BR/e3kE0QfQEB7RySSE5Rn4xPgnublwH8kELiS+yb
         icR/4r+wRbjXoua7wJtokYm8jHPvLKQMED+JN6+/D8q/c1pcP0tJ0yUrtYkNy1jUgUqV
         QXA3izV2H8Vo1HIKDqhwgJLIeT09T+sKjb8dZunTyYQwf0XjqEZE4e41259W4nlBABbJ
         C/Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=8RL0MQnMwVi0m28VnJOHLWh3yq33R+hPNoInZB9fg00=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=h1u4vN/fe5Stm/J/qCcQI/zHcQetjK+Ih7vjuj4J75hu8ANd7IyOOJEw9/h1ZfDtmL
         mHxQ1KmI0SvIjv+SPkqlx7O9oCB5+F72EIxrcyI05FLdcLegEefnbQsZT83CekzCyP2f
         Oa1z6qfED6QZr/IVABT84XFGaaHkchVaYL5Bfkk1CG5qPE8is3+9FHmnYzkqjXfmrcn+
         H1EmHXEZzcMeWtBDfrCpUNKGZmQbe77GWl8iXqvrKLgHOIoWAJ4bwY/V2olkBBSeqU6m
         CYQN2zWOb5szCKw5yVRvMW/WwxS7eGmewSJqXV4vihOvf+uE+tZJytHFNqkeJ8vsPHfo
         Zg6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dA1DtXnN;
       dkim=neutral (no key) header.i=@suse.cz header.b=hPvTmXax;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505287; x=1701110087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8RL0MQnMwVi0m28VnJOHLWh3yq33R+hPNoInZB9fg00=;
        b=ryaVWxCDnczzDQ5CrJ2zfdsV+iz/YvrIwre6rfseDRBCSj1d1Zrqct7Oggqtk+kSww
         VVp9m/9eWBgiQZx2dNKqN0KITIxqi8P6AjBsUUWHIDUERrRoo4LXKyhKevxKR0K4MruG
         mXeQilUL0IaDHPWXaggaGayFyydHMYF8vdG9ZIefJMNopX60SgOKJwhXIFcbWlKhzdJL
         1ELJB86Us0TmGUSYFSHM8y/PGKoLtzchFPHhQEeusyStoyIwi9oCYjeFxVBxzfiLO4tH
         +guGQdtiPx//5O5C/EJptiWHTVRq7GI2cAISuz9pK2HXY2eAK7REieL7zzpPMtv61DgP
         z2fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505287; x=1701110087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8RL0MQnMwVi0m28VnJOHLWh3yq33R+hPNoInZB9fg00=;
        b=epK0WTB+XRP+gXDjriggnXjDtbz8bs01BVuSLxUlvgcEMBuyF4SU38sGXmly16hMFI
         iz58AXbFmpznhYnrk0Q3zvrYfbxR8uNiSqvSY4yUpPE7PIFYPzuseybX87CHdp1tLVeM
         WEERUWFymCeBM3lXJ42UeEfNRGAtshOwI24J6aLasZpSHrCmshqs+hNI4tUliX6neNMO
         acB91dHTwTKMioU0tiz4Hhay952dBy8bNeKbn6r7wUdCaCky8Bxj8LEtlev/ouL2Fla0
         gOnLE/MxXrsj69odr4uYENuUq9Zjf/m8vkI5CLGicPFvTaRZDN1lJppWt6GuhoqbIfRJ
         5qWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwHk688Jjq4s6vQxXA7F9MSfcf/hSjS+WeTonNTiz3LgEbjQu6j
	I8bDvimbhH6jZ4/L9Au06gkM4w==
X-Google-Smtp-Source: AGHT+IHUlhWsnTU/7hbM8SNuS/LwAKv/DLxWKS8JiUHkQbXQF14xnLLWcRW70af+lXIKeaYJ1PNiYg==
X-Received: by 2002:a05:6512:244:b0:509:48ad:930d with SMTP id b4-20020a056512024400b0050948ad930dmr6373276lfo.25.1700505287055;
        Mon, 20 Nov 2023 10:34:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:a92:b0:50a:aac1:d1bf with SMTP id
 m18-20020a0565120a9200b0050aaac1d1bfls69887lfu.1.-pod-prod-01-eu; Mon, 20 Nov
 2023 10:34:45 -0800 (PST)
X-Received: by 2002:a2e:8716:0:b0:2c7:18bb:9987 with SMTP id m22-20020a2e8716000000b002c718bb9987mr5911062lji.8.1700505284987;
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505284; cv=none;
        d=google.com; s=arc-20160816;
        b=GuJ8+FSdzlQpVWbqkV9TNLvAPoA/AbxW6+CqGzjGk9oEjmHmv00jUfV937igawTdB+
         UfTeLe8AIJ211vbkhCgULUhquuqpRI8tq0htSJrlux8p5xG0BBcXXDe1O+JcGJBlJDCJ
         i9pjQGcINJL0LTfO+sF25lo+V6F2pxPfTDxjxmFP3CRiNof2C6s29Z2VYmQG2QrtT3Vr
         BSgueVmfuW6sM54+pgpo4PmIFdLdeJ0SxzYc2YggqJSyQ3xuHsj2D1P+AAvcsB4nkNuv
         8Wk362MD0/tYwLudL2CyZe8gnNbDc/iWZ2nkop4Sssd/19LIt8LC3Mww8D2PgT+wypDw
         MjzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=CxVtau361btrxEZ1p8oQK+uCjxmURZ9Wrr8QyUc+PdA=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=ELFV3J4yBjUhWZzMrEPR4gMhSAEKJVYPcQ8SjqXl4UeOL0mRYKtP2jMjgxRKQ5/2G7
         aZ0WrRUzNMH/fTTKxS37n6wiAXO0rzdXY4sLOWDx5dKMDaq/OfW/GEoEcLmi+pysB60X
         rrsbXQjFDv+Eit21GF+lJGlAoEkCidSzpbX2l8gWDj6TuvkVH/kKdkeHE6EQnaX+9mnz
         0zV5EqNL6oR4WzAggU9QTM9XJ+l6p9rVgFDVpZpT9QS0GYlVY/sUt9SyA8nj46gzLg9Y
         Nrwg0fDq0Z8HxjniX6lOM5Fz7zMfWxXA741N76n1Q+WnqPnaYlC3dbmFMO4D8reoceZn
         W9Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dA1DtXnN;
       dkim=neutral (no key) header.i=@suse.cz header.b=hPvTmXax;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id h22-20020a170906585600b009e2c2a65c8asi377598ejs.0.2023.11.20.10.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A69CC1F8B4;
	Mon, 20 Nov 2023 18:34:44 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 67EF913912;
	Mon, 20 Nov 2023 18:34:44 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id UHi1GMSmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:44 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:32 +0100
Subject: [PATCH v2 21/21] mm/slub: optimize free fast path code layout
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-21-9c9c70177183@suse.cz>
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
X-Spam-Level: 
X-Spam-Score: -6.80
X-Spamd-Result: default: False [-6.80 / 50.00];
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
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 BAYES_HAM(-3.00)[100.00%];
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
 header.i=@suse.cz header.s=susede2_rsa header.b=dA1DtXnN;       dkim=neutral
 (no key) header.i=@suse.cz header.b=hPvTmXax;       spf=softfail (google.com:
 domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Inspection of kmem_cache_free() disassembly showed we could make the
fast path smaller by providing few more hints to the compiler, and
splitting the memcg_slab_free_hook() into an inline part that only
checks if there's work to do, and an out of line part doing the actual
uncharge.

bloat-o-meter results:
add/remove: 2/0 grow/shrink: 0/3 up/down: 286/-554 (-268)
Function                                     old     new   delta
__memcg_slab_free_hook                         -     270    +270
__pfx___memcg_slab_free_hook                   -      16     +16
kfree                                        828     665    -163
kmem_cache_free                             1116     948    -168
kmem_cache_free_bulk.part                   1701    1478    -223

Checking kmem_cache_free() disassembly now shows the non-fastpath
cases are handled out of line, which should reduce instruction cache
usage.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 40 ++++++++++++++++++++++++----------------
 1 file changed, 24 insertions(+), 16 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 77d259f3d592..3f8b95757106 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1959,20 +1959,11 @@ void memcg_slab_post_alloc_hook(struct kmem_cache *s, struct obj_cgroup *objcg,
 	return __memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
 }
 
-static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
-					void **p, int objects)
+static void __memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+				   void **p, int objects,
+				   struct obj_cgroup **objcgs)
 {
-	struct obj_cgroup **objcgs;
-	int i;
-
-	if (!memcg_kmem_online())
-		return;
-
-	objcgs = slab_objcgs(slab);
-	if (!objcgs)
-		return;
-
-	for (i = 0; i < objects; i++) {
+	for (int i = 0; i < objects; i++) {
 		struct obj_cgroup *objcg;
 		unsigned int off;
 
@@ -1988,6 +1979,22 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
 		obj_cgroup_put(objcg);
 	}
 }
+
+static __fastpath_inline
+void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
+			  int objects)
+{
+	struct obj_cgroup **objcgs;
+
+	if (!memcg_kmem_online())
+		return;
+
+	objcgs = slab_objcgs(slab);
+	if (likely(!objcgs))
+		return;
+
+	__memcg_slab_free_hook(s, slab, p, objects, objcgs);
+}
 #else /* CONFIG_MEMCG_KMEM */
 static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
 {
@@ -2047,7 +2054,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
 	 * The initialization memset's clear the object and the metadata,
 	 * but don't touch the SLAB redzone.
 	 */
-	if (init) {
+	if (unlikely(init)) {
 		int rsize;
 
 		if (!kasan_has_integrated_init())
@@ -2083,7 +2090,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
+		if (likely(!slab_free_hook(s, object,
+					   slab_want_init_on_free(s)))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -4282,7 +4290,7 @@ static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
 	 */
-	if (slab_free_freelist_hook(s, &head, &tail, &cnt))
+	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
 		do_slab_free(s, slab, head, tail, cnt, addr);
 }
 

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-21-9c9c70177183%40suse.cz.
