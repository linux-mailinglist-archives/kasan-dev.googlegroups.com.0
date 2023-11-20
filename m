Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRWN52VAMGQEZMRTXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id ECCAD7F1C8B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:47 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-507bd5f4b2dsf4735731e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505287; cv=pass;
        d=google.com; s=arc-20160816;
        b=wOW8xC6TnxyzjSPlKeBeit8SB8A+QCsA7AfB1hweEpdFGte6qOS1p+OhF7AN2Pw81M
         zQLCqnwr8Larx25H4mqecNdF3tm1m20Wj/EExmZ3dS1HYbQ6uDfFzNwVSblLuW1sq/Mo
         F46mfefxcrqfSGCn0w0/QxqAJYchEb09dwekLBDKn1mnQaEWKTZckiox5BXTSFg8fEuj
         uJkbmDISGBnDlQ//z/NRQ4gSHQkmfifUaa1YV1L6EqwkHC2I3CkzKC5xEiPT0Bsw71aw
         9nU8mENu+R1vDTkxahY/1JP1wWBcWNCkKS6eRq1G3ocAstcjcNCois6Eb/QneSFi/YOa
         H0eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=jAQZ2l69EG7HHDo2mkdggjfAPs8ijpo2u/cLB1Ob09U=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=VEBXHDFgQuqDHdNRO2F00qUuFS6VB+LAtWbGLHNOX5rovccjCX+OmI18ws9wj9nYUR
         2zg18oKJw6hECjQyC7+zJ47pdgW1qu1tOjUVSNDkQTQNYqgRgwTQuYjOYOM5L0ehUpAP
         I4RgHwKtCAgSyrqnXqlinazV/ELB29qm4CQgfTYiaqVbUvtBxW0mOd+X0xHKXB/B6tNw
         w/clXywRvZU22SK6QdUsc1+6mI4NjUt6WNQLIL198i81cjZw+Wqqf8H/YgxJRYYDdcWs
         a6JwBCeTTXL4AEBUX6VO7zZqppJz113PVHqkkjrFszauzfLjANucGVRpij9mUOTF7QM2
         YpIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=hwuFRol6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505287; x=1701110087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jAQZ2l69EG7HHDo2mkdggjfAPs8ijpo2u/cLB1Ob09U=;
        b=WK6Wgex+ltKUmx5FENyzmq4rsJh0uXxGPyM56DPDmwz1TULKVo3JGToU0eHY5ZJ6U1
         nvZE0p4Bqw2pZdNy4tlzbYDR1gXFMBBJyTUecrK/ZTzXisTGXcllcYdo9ABGV5qlvCw6
         Fcu1xqeWWe+AyqMaZibP/tNh3+OOwWuSoiBnkNCLhh2fe1uMxG0VCvT2JJkxEnXvxmQc
         ksaXBHnWnEnBbpEhH0Uoi2PZIpIEQYQIXSbEXQXbylQNb01kZ/dGobstU6GZUNpVPbRa
         4eXlE/CQ2Xc3513buB5x5gIvEvcjzXUzgfXMmIly7tlmMhAEm0MQ+I/POoqYjk6OZE+G
         G5DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505287; x=1701110087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jAQZ2l69EG7HHDo2mkdggjfAPs8ijpo2u/cLB1Ob09U=;
        b=eTVLCEv6bWcCkF+KrQ/W7LBirq13Ol8axBcPkVt4ib6DJqzw1DZxcFPLgPUu3glV6v
         mXWfQlZz7+DhbeR/1XgIo4qROb2v0FcNjb9R/aQ8V0YkP08xggNhU+vN62yK/fmTXyci
         1YHh3+L2+IjSQNA1wxTBbVXLTchTGmA39s/AkyRjDV8xJeA07BAkUNEbnK96owhae9eV
         L0C5q3mKzdHCCf+SK56Xs601/Jd9waurJ1dvYyw/WZ1pSj8LPPlTSfqOfsw0sPNqjmw0
         nn5I9WMD5GaJocEH3ksDg0Aeqju1Z00FXEIhrS8y5o8MJRL2KjtyPEMW8Ipys6R/Kt45
         WSQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxq+s+cOBOP8VkzJStTmc5pe+Lu4Z3ry40VleOi81uLcvLzFsKi
	WWFeeZe4sa9SWaHEkZi7zL4=
X-Google-Smtp-Source: AGHT+IEnpXFv/gs7PoINUlDolRFx1IBv7sJaV37TAIaDrm3HqknY0T5T/gRzJjk7vAVhudn3RgKDGA==
X-Received: by 2002:ac2:5b1c:0:b0:509:44d5:18e5 with SMTP id v28-20020ac25b1c000000b0050944d518e5mr4807119lfn.63.1700505286859;
        Mon, 20 Nov 2023 10:34:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e9e:b0:50a:a999:f190 with SMTP id
 bi30-20020a0565120e9e00b0050aa999f190ls109505lfb.1.-pod-prod-06-eu; Mon, 20
 Nov 2023 10:34:45 -0800 (PST)
X-Received: by 2002:a19:7010:0:b0:503:343a:829f with SMTP id h16-20020a197010000000b00503343a829fmr5841849lfc.23.1700505285010;
        Mon, 20 Nov 2023 10:34:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505284; cv=none;
        d=google.com; s=arc-20160816;
        b=lo0T4sdCwWu0Ty9+FPYA2zZMc0H4kVlcKllwRGOcBZo48FR1w834y/7hH0hVbjq2mP
         Hvkf5upBMH5MeCQnSS9Cft8G02CYFif1tUVdKoe+uOiJYWB6OJrJkx+kSmWy9RvHueZU
         pHbvXODpIRuI46PofFFgh1DKMq9Jqf7Sifp7OVv5f1MfjG1DbBJJuN71Q4OlPLPQh3uM
         4Nlm7WYJHT5q+fwnhzP8zGswSX7pQwoyjNjun550/JckkzK/UG0mHw5rEfbU+Sk0Wsji
         JuJ9Pq4G8V7O5nfqNbibiuAVXa/10i7g9/nRvOS1khXIbNJl+9Yc5Gv7otjx+9RY0kRm
         EL9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=mirY2Hk97uPg9xiXuUhtPBwRnD0yXek2uhM+MkvFe9M=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=hniOl3sOeqFDPUsjIw1f1nOlgD7oDkMqwzxVApCrPDb+E6VXf/BIh8NEzWczS/mHXH
         ptMDugfGjVXQVD9+YdYhcNsCqVXxHFIHD17fwFR89yg+B4DwhUUCScLxbgrmGTm9Wg+P
         dRjauFUTFYojtd4q9HghPI/dWDJ0OhopcL3GuzaGypux/UkXCa+ZU7X4anWhWVhTdBni
         svmK9B9ymOnmD3FHqiOgyfLVu3VTUCwzryVmOGkDmD8ZiB1xaYbLUId0Uk9P86N4pycb
         szW29wsfgLSombWvrBY0RBrslGOXQHrnGei7DBPTRmjLm1OixC7olszSxay6Ra+JqvHo
         3AOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=hwuFRol6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id i20-20020a0565123e1400b005098ece8aa9si354608lfv.12.2023.11.20.10.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 62AEA1F8B3;
	Mon, 20 Nov 2023 18:34:44 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1AE0B13499;
	Mon, 20 Nov 2023 18:34:44 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 6JftBcSmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:44 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:31 +0100
Subject: [PATCH v2 20/21] mm/slub: optimize alloc fastpath code layout
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-20-9c9c70177183@suse.cz>
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
 header.i=@suse.cz header.s=susede2_rsa header.b=hwuFRol6;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
 mm/slub.c | 89 ++++++++++++++++++++++++++++++++++++++-------------------------
 1 file changed, 54 insertions(+), 35 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 5683f1d02e4f..77d259f3d592 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-20-9c9c70177183%40suse.cz.
