Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRGN52VAMGQEUDVA3WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 657047F1C81
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:45 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-542d5dd0c8esf7398103a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505285; cv=pass;
        d=google.com; s=arc-20160816;
        b=OCKLkUhEW0/wlkExObfquph35yu0GVdWa32eCx72ls9nXhOkUw/OGC0EHzIWuZwAqv
         QfOonCZNVJa8P5yzZ1BsElxmoLYQCnYgI8wDDTd44mfFa32FpU0W47j3uTJUXgVrtpKT
         XOyXqjYbOYJn4uV5NbmWxhN22VhHgAHmFGOZCe+qyF2Bz1K5RZ4A7OIzqqoEAFCn6L55
         yWZXtU1wpGh4UC3z5P3eKiV+eMWPXHmmGzq13ssSzmrqvhhBnSyGkCZNSB8CXKDhkHu3
         MUjp+GisBSBnZbuzIv6Y/vPrufbjhFbfDLRbcKIM8MsmgaTl9dMceK8qJ+drB4pWxeP7
         cX3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=v7Ix4BvDyr7Y1O/+zGFSiVhlsLuPFAF7PmfBsJikHv4=;
        fh=dfD2X5Mb6QAP79KDvnu8aL/16Lml7JbeXAz+yHwdS1Q=;
        b=iXd9hyeuduY+eh1Yd2Rn20cQJtC54Fzk+MIa2055/D7YR/w/avVdt1HLyu6WpGg4YH
         8UaP0MllR6p3sh6PSNuI668Q3ql5UOdt2LpwwE5x9LScb0J75PDkDEZMfeM2UzUpCEON
         uy07EvQTtgpj2l9lQSMAbj+Z5Dp9V43tR6qvvjOXqt62pHLaY70YY7tbUujAdotGGQ36
         wBhbyODP4fYQfOpAHYxVESA5sazVTWO9QMLMObGpTYFixTY37ZvDQfgrKAzJ6dGMJwOW
         e8bV6Wqy+YXtIEi7kOXpUSt1AxVbscCkJvWLzfCVe5bNNc5wA8YX5eextG6AqOLslBG/
         VBRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0iQJa2PO;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505285; x=1701110085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v7Ix4BvDyr7Y1O/+zGFSiVhlsLuPFAF7PmfBsJikHv4=;
        b=fFwNDFQbgW8Q4nMpRslctZvxxUoMnYy3MpjxxV057tkeiGDg3KT496CwbC8+OZx1gt
         UzMKeuOZCrAz42A9nWsFmM48Thd60/q5JxERmbQ9PkkpSDpdUDdYkqYGJC7a5SQ7rrwi
         I+6jNrPkvo9Hsk7FpkGbeVcjfCgS4+q+hSI2rV2aqVD1m2EUC3qiNDp7UcBGVswMlAuc
         lsWbvXDHcKJphCVRDyIoeJ+GWTZwCCgiSWP/q4icLr9YntZugKMcfbpKVumsIeCIaopR
         yiACdDmwwZAnjQXgxCQcaiodt1ivQ270R8tn6Vknnb9juC2hVlbDFHYL9rCK1/MmrRDo
         /D6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505285; x=1701110085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v7Ix4BvDyr7Y1O/+zGFSiVhlsLuPFAF7PmfBsJikHv4=;
        b=O8kBDO6pxMdPCzYIpOrKq7WxoWCgkVDJKkH0lP/ywn7isRKH8IYyZnRa29VFtMmhQs
         9JFuZHkWjrj+IyIMwJphcAg8D8EFYgrFLu++4LFdI7/ZsQzPyjMgkU+zy8ZoOLWz1Xpa
         glbJWcCHlPIUq9BwVeDeQubXPCAG4ttVbi87zXFaSm7+qDFj/NjHwX9mVh1LlsFqeHbH
         7aFYtcQUC5D1Y9R7SEHNKeVjp9wJfhh3LKzI0zkGgiv79N3iEMXzdJzsYQAyA3qgaAMX
         n1e1tTYt3kXD6Z5YlitLbU6use6rODqKxdsNFFUMXnwrFGoj4Ibnqj5JucaejoTHkkxG
         oioA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy1Dn3LJQK8GuMMsKKBOfZiiF+dhvsQHKZSRn/n7ECCpl+HbPs1
	oaNfDo4+DjM1VlwSMIOiRW0=
X-Google-Smtp-Source: AGHT+IHDK5zCsVQWNAKBXmdJKOtbveZ2XQ3sNj7V4nDPakIMSWkjgZPXnJAWNN6hFoQ+l7fPMTBEOQ==
X-Received: by 2002:a05:6402:1b08:b0:542:f0af:21e6 with SMTP id by8-20020a0564021b0800b00542f0af21e6mr186414edb.14.1700505284914;
        Mon, 20 Nov 2023 10:34:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:17c3:b0:548:47f7:ad97 with SMTP id
 s3-20020a05640217c300b0054847f7ad97ls122159edy.0.-pod-prod-00-eu; Mon, 20 Nov
 2023 10:34:43 -0800 (PST)
X-Received: by 2002:a17:906:5acd:b0:a00:1263:8c4c with SMTP id x13-20020a1709065acd00b00a0012638c4cmr363325ejs.18.1700505283039;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505283; cv=none;
        d=google.com; s=arc-20160816;
        b=WPo10aJItNEuFwPEqGupk/tgReystfflXJu96uUKfMaaSuOcBixmCuQ7yerYwXlU05
         S1kBuSOFKY2OLV3/UiGssZjcLMecSiEWLASWrjxsnapPy51pK5ZmnB2jUnx4eEY0XOLv
         bauASiucsnlhahtVfrPassKs8mJuAk7IWMMnV2tQ1JKKDxY1HHRqY+arFlHWvfdQTZsu
         QQeay0EQtcEkFS/W6cg3K60wUAKpYt+V/X6Y5vOZvVviFmY//BxW6XfMmLfbojqozSHW
         qD/UDNX8WnsgCGcVGVhJJ8ADU1GnoOx/F6zKoFcZ7l0qAdz5vnaDJg3g3cN1SZOEJLog
         M2SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=o4aibseo8uvIfZF2g6BXwYSpSGkKoIdwIMMXWbU0crw=;
        fh=dfD2X5Mb6QAP79KDvnu8aL/16Lml7JbeXAz+yHwdS1Q=;
        b=z20V23iQ+SuQ5lflcS5GXv50FQ6C7Ga4QoaTJ5BqiMacUmIFRUKkiDOQ3//HPeU8+o
         4w7+hBBJSR8QOhIedfaYkjxozz2T/8BdPh25JrCJ62CM8JPYS/wPzbI9omM5EH+W/yhu
         9Yi+5YOhfPQaQYJhUzJFJRo+m/BYaG+Lu0m/agSELzlbu8Lc34tH3hoQjZKhHWXkUWx9
         32T3KRfrtYmzzb7fE+HZclAPImnW+4jfXFzUZSQloHp/gsekGDPHIpeA0XaBvF/lSQ7h
         DBOwnkf8s+AUFuuklybzpKm6ZJ3lfk3py62mml45S1j0badBXXrQn6ZIedzDEi8tLF0G
         k3mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0iQJa2PO;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id st1-20020a170907c08100b009f0ec8d7ff6si467396ejc.1.2023.11.20.10.34.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C512221940;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 8048613499;
	Mon, 20 Nov 2023 18:34:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 6HPaHsKmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:42 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:25 +0100
Subject: [PATCH v2 14/21] mm/slab: move memcg related functions from slab.h
 to slub.c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-14-9c9c70177183@suse.cz>
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
 linux-hardening@vger.kernel.org, Michal Hocko <mhocko@suse.com>, 
 Vlastimil Babka <vbabka@suse.cz>
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
	 RCPT_COUNT_TWELVE(0.00)[25];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0iQJa2PO;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

We don't share those between SLAB and SLUB anymore, so most memcg
related functions can be moved to slub.c proper.

Reviewed-by: Kees Cook <keescook@chromium.org>
Acked-by: Michal Hocko <mhocko@suse.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h | 206 --------------------------------------------------------------
 mm/slub.c | 205 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 205 insertions(+), 206 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 65ebf86b3fe9..a81ef7c9282d 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -486,12 +486,6 @@ void slabinfo_show_stats(struct seq_file *m, struct kmem_cache *s);
 ssize_t slabinfo_write(struct file *file, const char __user *buffer,
 		       size_t count, loff_t *ppos);
 
-static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
-{
-	return (s->flags & SLAB_RECLAIM_ACCOUNT) ?
-		NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
-}
-
 #ifdef CONFIG_SLUB_DEBUG
 #ifdef CONFIG_SLUB_DEBUG_ON
 DECLARE_STATIC_KEY_TRUE(slub_debug_enabled);
@@ -551,220 +545,20 @@ int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
 				 gfp_t gfp, bool new_slab);
 void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
 		     enum node_stat_item idx, int nr);
-
-static inline void memcg_free_slab_cgroups(struct slab *slab)
-{
-	kfree(slab_objcgs(slab));
-	slab->memcg_data = 0;
-}
-
-static inline size_t obj_full_size(struct kmem_cache *s)
-{
-	/*
-	 * For each accounted object there is an extra space which is used
-	 * to store obj_cgroup membership. Charge it too.
-	 */
-	return s->size + sizeof(struct obj_cgroup *);
-}
-
-/*
- * Returns false if the allocation should fail.
- */
-static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
-					     struct list_lru *lru,
-					     struct obj_cgroup **objcgp,
-					     size_t objects, gfp_t flags)
-{
-	struct obj_cgroup *objcg;
-
-	if (!memcg_kmem_online())
-		return true;
-
-	if (!(flags & __GFP_ACCOUNT) && !(s->flags & SLAB_ACCOUNT))
-		return true;
-
-	/*
-	 * The obtained objcg pointer is safe to use within the current scope,
-	 * defined by current task or set_active_memcg() pair.
-	 * obj_cgroup_get() is used to get a permanent reference.
-	 */
-	objcg = current_obj_cgroup();
-	if (!objcg)
-		return true;
-
-	if (lru) {
-		int ret;
-		struct mem_cgroup *memcg;
-
-		memcg = get_mem_cgroup_from_objcg(objcg);
-		ret = memcg_list_lru_alloc(memcg, lru, flags);
-		css_put(&memcg->css);
-
-		if (ret)
-			return false;
-	}
-
-	if (obj_cgroup_charge(objcg, flags, objects * obj_full_size(s)))
-		return false;
-
-	*objcgp = objcg;
-	return true;
-}
-
-static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
-					      struct obj_cgroup *objcg,
-					      gfp_t flags, size_t size,
-					      void **p)
-{
-	struct slab *slab;
-	unsigned long off;
-	size_t i;
-
-	if (!memcg_kmem_online() || !objcg)
-		return;
-
-	for (i = 0; i < size; i++) {
-		if (likely(p[i])) {
-			slab = virt_to_slab(p[i]);
-
-			if (!slab_objcgs(slab) &&
-			    memcg_alloc_slab_cgroups(slab, s, flags,
-							 false)) {
-				obj_cgroup_uncharge(objcg, obj_full_size(s));
-				continue;
-			}
-
-			off = obj_to_index(s, slab, p[i]);
-			obj_cgroup_get(objcg);
-			slab_objcgs(slab)[off] = objcg;
-			mod_objcg_state(objcg, slab_pgdat(slab),
-					cache_vmstat_idx(s), obj_full_size(s));
-		} else {
-			obj_cgroup_uncharge(objcg, obj_full_size(s));
-		}
-	}
-}
-
-static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
-					void **p, int objects)
-{
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
-		struct obj_cgroup *objcg;
-		unsigned int off;
-
-		off = obj_to_index(s, slab, p[i]);
-		objcg = objcgs[off];
-		if (!objcg)
-			continue;
-
-		objcgs[off] = NULL;
-		obj_cgroup_uncharge(objcg, obj_full_size(s));
-		mod_objcg_state(objcg, slab_pgdat(slab), cache_vmstat_idx(s),
-				-obj_full_size(s));
-		obj_cgroup_put(objcg);
-	}
-}
-
 #else /* CONFIG_MEMCG_KMEM */
 static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
 {
 	return NULL;
 }
 
-static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
-{
-	return NULL;
-}
-
 static inline int memcg_alloc_slab_cgroups(struct slab *slab,
 					       struct kmem_cache *s, gfp_t gfp,
 					       bool new_slab)
 {
 	return 0;
 }
-
-static inline void memcg_free_slab_cgroups(struct slab *slab)
-{
-}
-
-static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
-					     struct list_lru *lru,
-					     struct obj_cgroup **objcgp,
-					     size_t objects, gfp_t flags)
-{
-	return true;
-}
-
-static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
-					      struct obj_cgroup *objcg,
-					      gfp_t flags, size_t size,
-					      void **p)
-{
-}
-
-static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
-					void **p, int objects)
-{
-}
 #endif /* CONFIG_MEMCG_KMEM */
 
-static inline struct kmem_cache *virt_to_cache(const void *obj)
-{
-	struct slab *slab;
-
-	slab = virt_to_slab(obj);
-	if (WARN_ONCE(!slab, "%s: Object is not a Slab page!\n",
-					__func__))
-		return NULL;
-	return slab->slab_cache;
-}
-
-static __always_inline void account_slab(struct slab *slab, int order,
-					 struct kmem_cache *s, gfp_t gfp)
-{
-	if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
-		memcg_alloc_slab_cgroups(slab, s, gfp, true);
-
-	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
-			    PAGE_SIZE << order);
-}
-
-static __always_inline void unaccount_slab(struct slab *slab, int order,
-					   struct kmem_cache *s)
-{
-	if (memcg_kmem_online())
-		memcg_free_slab_cgroups(slab);
-
-	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
-			    -(PAGE_SIZE << order));
-}
-
-static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
-{
-	struct kmem_cache *cachep;
-
-	if (!IS_ENABLED(CONFIG_SLAB_FREELIST_HARDENED) &&
-	    !kmem_cache_debug_flags(s, SLAB_CONSISTENCY_CHECKS))
-		return s;
-
-	cachep = virt_to_cache(x);
-	if (WARN(cachep && cachep != s,
-		  "%s: Wrong slab cache. %s but object is from %s\n",
-		  __func__, s->name, cachep->name))
-		print_tracking(cachep, x);
-	return cachep;
-}
-
 void free_large_kmalloc(struct folio *folio, void *object);
 
 size_t __ksize(const void *objp);
diff --git a/mm/slub.c b/mm/slub.c
index 9eb6508152c2..844e0beb84ee 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1814,6 +1814,165 @@ static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
 #endif
 #endif /* CONFIG_SLUB_DEBUG */
 
+static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
+{
+	return (s->flags & SLAB_RECLAIM_ACCOUNT) ?
+		NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
+}
+
+#ifdef CONFIG_MEMCG_KMEM
+static inline void memcg_free_slab_cgroups(struct slab *slab)
+{
+	kfree(slab_objcgs(slab));
+	slab->memcg_data = 0;
+}
+
+static inline size_t obj_full_size(struct kmem_cache *s)
+{
+	/*
+	 * For each accounted object there is an extra space which is used
+	 * to store obj_cgroup membership. Charge it too.
+	 */
+	return s->size + sizeof(struct obj_cgroup *);
+}
+
+/*
+ * Returns false if the allocation should fail.
+ */
+static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
+					     struct list_lru *lru,
+					     struct obj_cgroup **objcgp,
+					     size_t objects, gfp_t flags)
+{
+	struct obj_cgroup *objcg;
+
+	if (!memcg_kmem_online())
+		return true;
+
+	if (!(flags & __GFP_ACCOUNT) && !(s->flags & SLAB_ACCOUNT))
+		return true;
+
+	/*
+	 * The obtained objcg pointer is safe to use within the current scope,
+	 * defined by current task or set_active_memcg() pair.
+	 * obj_cgroup_get() is used to get a permanent reference.
+	 */
+	objcg = current_obj_cgroup();
+	if (!objcg)
+		return true;
+
+	if (lru) {
+		int ret;
+		struct mem_cgroup *memcg;
+
+		memcg = get_mem_cgroup_from_objcg(objcg);
+		ret = memcg_list_lru_alloc(memcg, lru, flags);
+		css_put(&memcg->css);
+
+		if (ret)
+			return false;
+	}
+
+	if (obj_cgroup_charge(objcg, flags, objects * obj_full_size(s)))
+		return false;
+
+	*objcgp = objcg;
+	return true;
+}
+
+static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
+					      struct obj_cgroup *objcg,
+					      gfp_t flags, size_t size,
+					      void **p)
+{
+	struct slab *slab;
+	unsigned long off;
+	size_t i;
+
+	if (!memcg_kmem_online() || !objcg)
+		return;
+
+	for (i = 0; i < size; i++) {
+		if (likely(p[i])) {
+			slab = virt_to_slab(p[i]);
+
+			if (!slab_objcgs(slab) &&
+			    memcg_alloc_slab_cgroups(slab, s, flags, false)) {
+				obj_cgroup_uncharge(objcg, obj_full_size(s));
+				continue;
+			}
+
+			off = obj_to_index(s, slab, p[i]);
+			obj_cgroup_get(objcg);
+			slab_objcgs(slab)[off] = objcg;
+			mod_objcg_state(objcg, slab_pgdat(slab),
+					cache_vmstat_idx(s), obj_full_size(s));
+		} else {
+			obj_cgroup_uncharge(objcg, obj_full_size(s));
+		}
+	}
+}
+
+static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+					void **p, int objects)
+{
+	struct obj_cgroup **objcgs;
+	int i;
+
+	if (!memcg_kmem_online())
+		return;
+
+	objcgs = slab_objcgs(slab);
+	if (!objcgs)
+		return;
+
+	for (i = 0; i < objects; i++) {
+		struct obj_cgroup *objcg;
+		unsigned int off;
+
+		off = obj_to_index(s, slab, p[i]);
+		objcg = objcgs[off];
+		if (!objcg)
+			continue;
+
+		objcgs[off] = NULL;
+		obj_cgroup_uncharge(objcg, obj_full_size(s));
+		mod_objcg_state(objcg, slab_pgdat(slab), cache_vmstat_idx(s),
+				-obj_full_size(s));
+		obj_cgroup_put(objcg);
+	}
+}
+#else /* CONFIG_MEMCG_KMEM */
+static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
+{
+	return NULL;
+}
+
+static inline void memcg_free_slab_cgroups(struct slab *slab)
+{
+}
+
+static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
+					     struct list_lru *lru,
+					     struct obj_cgroup **objcgp,
+					     size_t objects, gfp_t flags)
+{
+	return true;
+}
+
+static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
+					      struct obj_cgroup *objcg,
+					      gfp_t flags, size_t size,
+					      void **p)
+{
+}
+
+static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
+					void **p, int objects)
+{
+}
+#endif /* CONFIG_MEMCG_KMEM */
+
 /*
  * Hooks for other subsystems that check memory allocations. In a typical
  * production configuration these hooks all should produce no code at all.
@@ -2048,6 +2207,26 @@ static inline bool shuffle_freelist(struct kmem_cache *s, struct slab *slab)
 }
 #endif /* CONFIG_SLAB_FREELIST_RANDOM */
 
+static __always_inline void account_slab(struct slab *slab, int order,
+					 struct kmem_cache *s, gfp_t gfp)
+{
+	if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
+		memcg_alloc_slab_cgroups(slab, s, gfp, true);
+
+	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
+			    PAGE_SIZE << order);
+}
+
+static __always_inline void unaccount_slab(struct slab *slab, int order,
+					   struct kmem_cache *s)
+{
+	if (memcg_kmem_online())
+		memcg_free_slab_cgroups(slab);
+
+	mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
+			    -(PAGE_SIZE << order));
+}
+
 static struct slab *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
 {
 	struct slab *slab;
@@ -3965,6 +4144,32 @@ void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 }
 #endif
 
+static inline struct kmem_cache *virt_to_cache(const void *obj)
+{
+	struct slab *slab;
+
+	slab = virt_to_slab(obj);
+	if (WARN_ONCE(!slab, "%s: Object is not a Slab page!\n", __func__))
+		return NULL;
+	return slab->slab_cache;
+}
+
+static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
+{
+	struct kmem_cache *cachep;
+
+	if (!IS_ENABLED(CONFIG_SLAB_FREELIST_HARDENED) &&
+	    !kmem_cache_debug_flags(s, SLAB_CONSISTENCY_CHECKS))
+		return s;
+
+	cachep = virt_to_cache(x);
+	if (WARN(cachep && cachep != s,
+		 "%s: Wrong slab cache. %s but object is from %s\n",
+		 __func__, s->name, cachep->name))
+		print_tracking(cachep, x);
+	return cachep;
+}
+
 void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller)
 {
 	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, caller);

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-14-9c9c70177183%40suse.cz.
