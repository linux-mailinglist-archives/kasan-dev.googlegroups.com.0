Return-Path: <kasan-dev+bncBDXYDPH3S4OBBB7LZGVAMGQE7SJXD7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 078207EA370
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:18 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5079630993dsf4536957e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902857; cv=pass;
        d=google.com; s=arc-20160816;
        b=fN61jPHNWLsEdwie6c5cX1QZWm62IqgGoUaMxB7rIPQmX2/Pgbfw1yUNQQQ6GD2oXx
         nxPPKqTbHUJEpmWZQqBhO2cVQ98Y5eMOsI5YGgRmQrCAvTbi5oIoJxt2Fx7RbXAXkaJj
         Oh5Juy8wCOR4agkZjtyQEwDrFLzckrtEnj4v7J+f3yv+riZ2YgyJdTQYaZsxFcWnWWca
         KKza84J+9pfS9xPW/jRS4mutWuI0+Jb3HvvgLO/8bre1DOSN9Shv8JT88QKwXSGt5bT5
         lYjnTQsIQACySgvuydzRJMXFHwkgfWkhX3i1KI0xo6d02pv3waiPcxp0UKmbIxtblScE
         SR/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VCjeX92TMtNHwQeF/Tb7A/1/VB6Bv+5QMvzmMqBgxpQ=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=ZKrCxqNpHfVr7OzIE21MB6zpKk2GfbrXMMcnOKNjcLIGd6t3RFbZxDyeDdjEQGBLP5
         E9ET5iroB8JK4MdVRDGMBCyMK76O/XelhzwQO9V+QDTuO8f1beFvApcJz1v3OCrdiKKK
         UwFhhFoWxhD5ZNoC03KNqrE4iErqNdNjcDV+lfc5rFaMzfMcPTLRMWAkx4Se4HMLqAOc
         GppHcsDy0KlmCN/33QH90ocCmG3qtQRRnxlAAAZ+zueniJwUNZ2gLqeYdW5YGvThDVkH
         vH+j4SVL8H5AJUmzdO+78XZqG4hzhvCngxomtniUFdaHzernEMKSXdOPtpfJzzAvoj/5
         tkmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gMfnvmxh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=IzoyBqQa;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902857; x=1700507657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VCjeX92TMtNHwQeF/Tb7A/1/VB6Bv+5QMvzmMqBgxpQ=;
        b=LiBiJyzTeeiyiOVM/U0VY/x8vWorY5+IEnBXuYZPn/ZpNvCyVGNXhtbNJNKIDyq/7w
         +L0aYvbLCpcG/Vp+LfsY3Q/QnVC4jJFo5vx3U4W4XQdVNxbzrFcTD+vP5AmIhu8bhKnX
         dUUZkHpVhIudbeee5nALQmM69+INLREE7X7LpFzRSfWfqC/5tnLU+jaxSqj3GAqfzbyt
         AXYYZGXbD5poAieTCMXF+7jzmjOLMexF2SLJ1LqPYxwU5QaXt1TTtQUb3K9bRajKgF12
         Nz8a3XSOCWgfW03gd4YaS5ZzGvIuVCY+dOKipcv4MEg25+TdUl+D5x38R2dPiNk4JB8n
         NWCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902857; x=1700507657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VCjeX92TMtNHwQeF/Tb7A/1/VB6Bv+5QMvzmMqBgxpQ=;
        b=lgtp/ZzdeNOrgD4LzbGngBp3gImSnYV4+oh3PIybhLX/NcKfSE4iaZ1CfM310jlgKH
         Lq0yaySw1rlc+nufDzNVRwexAAPVDjgL2ydO/5SALcagKj0ynMCNDpuRIXSNwkPm8drP
         tiqZIM+dpCeF2z+X0bn2UQUPKeQ96KpsVQPPcKa+ZRu0sDVsrVCumCQGYhVEWSE8Zf84
         /CFi1694AO/hmasmWgQGDsJyXXckrrdmC8HU5/A2jnucoI1tMus9w8XYmG0CK2PMzXhK
         ujlTyaNN8+fGVigrIvZjvzVdFmz3Q/leb0mfrSomn1O094TUQAvASYpn3gP2OglroMEy
         73Pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxXSxVqA8h1iTM4I7fkFeQe5lBLkFPRFOJaNx+OmJfD+CtVSDTp
	AQXgUi6EhCZPXxaCc79P6oo=
X-Google-Smtp-Source: AGHT+IH11ruH7j8SahApIS2ySP5rM72tFn5QJfceXtn7fh75946Rp9K2o0E2sUIZnPVLnGU2W9rNtA==
X-Received: by 2002:a05:6512:2214:b0:507:a12c:558c with SMTP id h20-20020a056512221400b00507a12c558cmr5691167lfu.46.1699902856202;
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:281b:b0:509:105e:64f2 with SMTP id
 cf27-20020a056512281b00b00509105e64f2ls295745lfb.0.-pod-prod-04-eu; Mon, 13
 Nov 2023 11:14:14 -0800 (PST)
X-Received: by 2002:ac2:4186:0:b0:509:4523:4039 with SMTP id z6-20020ac24186000000b0050945234039mr4972552lfh.64.1699902854422;
        Mon, 13 Nov 2023 11:14:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902854; cv=none;
        d=google.com; s=arc-20160816;
        b=E9irnGELcFWeCVwCqnsW1GjNwM6buj+qdnscWUlEvHkzwTuUfkEAsObLgqbedkmfNZ
         ZdQeLY0GkgIztSLDahG//2L3Sj4rkLlhek9DwDq9z72KW4gcx5gBG8lqsw4o9MTKJWon
         IPSeBAi/gmXyKMajsFRvv4NYuRp5wLNwzsq2GYQOgZgdFaBOPWbIlfL9wPTGuoKbQRr6
         NYDQkzjWNcntikU+H//VCwRutN/+Odh4sPkPBIaoOG5aLM+BGh9UyiBnEonkLHRqjdYm
         T7Ou87JMcTS0zB2xgRhY3YRk+SRgcETjzf5acy9FXL1hCHxusmVN2cWC5QlRR+zjBd4h
         23KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=bBHYobYuCSx6ydYwBPVMXk5g8Fw3SvV+K+uyrFaLYqs=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=jL+D3h/lj7HEKAoWDV1U5SCe7CgKqxbwrMgc0fov0X/xtOA24U76p60M8kzmZMiFUt
         Dzdhu0SQy3wXD6Pk99hi2d+vzPmOA2oxm/fgttx6cV/IAdm+m+l8y4QwUzo+Las+zEd3
         3IcqQ7LxSV1Giv5z2mDtPFVIkaCZ6beHypnNXfsnuz0yzYJxtF+1aVBGsc8m4DUDvz6W
         nFyeEwKuXCn8f05DZ6h65LXZgtKrJ9Rv3a4uWlweECnyKrlMJ8Mpk4n9vxu9ttL3N6xQ
         vq8G0Ij+7HHc/6DbFkqNNBqXD+AXkjyRNgkCczAkf0SSWMRhkugOL/cjeQ9YM1kdvTTS
         NwmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gMfnvmxh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=IzoyBqQa;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id c18-20020a056512239200b0050a72e696casi192098lfv.6.2023.11.13.11.14.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:14 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E37402191E;
	Mon, 13 Nov 2023 19:14:13 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 8AFB313907;
	Mon, 13 Nov 2023 19:14:13 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id aPo/IYV1UmVFOgAAMHmgww
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
Subject: [PATCH 13/20] mm/slab: move memcg related functions from slab.h to slub.c
Date: Mon, 13 Nov 2023 20:13:54 +0100
Message-ID: <20231113191340.17482-35-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=gMfnvmxh;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=IzoyBqQa;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

We don't share those between SLAB and SLUB anymore, so most memcg
related functions can be moved to slub.c proper.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h | 206 ------------------------------------------------------
 mm/slub.c | 205 +++++++++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 205 insertions(+), 206 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index aad18992269f..8de9780d345a 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -485,12 +485,6 @@ void slabinfo_show_stats(struct seq_file *m, struct kmem_cache *s);
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
@@ -550,220 +544,20 @@ int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
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
index e15912d1f6ed..25ff9d2d44a8 100644
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
@@ -3952,6 +4131,32 @@ void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-35-vbabka%40suse.cz.
