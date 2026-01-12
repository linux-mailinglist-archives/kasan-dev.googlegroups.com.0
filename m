Return-Path: <kasan-dev+bncBDXYDPH3S4OBBANBSTFQMGQETS5OHZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 547B0D138FE
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:22 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-47d3ba3a49csf60709705e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231042; cv=pass;
        d=google.com; s=arc-20240605;
        b=djsuQfBJnySpi6RbPUYOcJu3duuUIjqbAjRoBq7JVQDKo4R9RTZqiTAHYlIPtYhZkT
         /Srvb3/DRwbmFwnT3ZSwdU/Kak3A5h2kcl9eBY2EzCRFH11FIuk5FM4D98iBkUyWYSAR
         Hq65iSUnvec+sk5Su1SFMtcrmxWehyS1A4UbhYFGWWLhINw5Tmo9HNagh/TaS6giViGZ
         IbK6YflNRLA9eUvEvfSdYJDiyF2E80OZjcy96LpQEWY9l18YKGrLoXMEBsoc7qe9av3R
         HCLNGe0uaPjhuw+GvXG6MJo3f3G0yCrWLxMUU7voA+XsgN5+GOucdJqPlcC0hp6YsXWv
         rDQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=yp0RS/oXsUvBQ1KO8Ukt0iAOCzquRwmc0n8Mj/y5Wfg=;
        fh=7YpllrOB5TRrtqJQR61uhXDFbetvUeOAb+2fnP9ws98=;
        b=ZK6AP/sNfDkEar8NP0Lw3pD3sl+rct4M11h9LGbVDLd6S/x0xAzn7qthuAAOJDWZOX
         fm2fJB2lCu6Es3I0qvgiZLF1GP0vCFGL+VG6in8ruGMzER6bz4VI3D1x3g1thB9DXXGi
         osm3t1i3/ty+Uh/evlZa44c0/zEUub97k87wOKDhQGnCiv9qxEmI45Ose+hYeoHEcOWr
         /GsVUszfoZRtIS6TvnKGaGL0S7B6lyby9/ofjl6irokOP0M74ifFReCfKmwayaFk5qG2
         om7W1dJ9lvZgfnjNCpso2NFOSbGasS0+sRzm51C3SV5R3tYyyTUmoTbewkYDu90qpGsg
         2K8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231042; x=1768835842; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yp0RS/oXsUvBQ1KO8Ukt0iAOCzquRwmc0n8Mj/y5Wfg=;
        b=ufGKtRgpTq1OnPRUL/3i+Mt74p7+zUJV7A7IBgRl1Eys3PONMNG6tMCoHpiyObLqFm
         LJkeGBgZVRFQWtXHbsqpmaCGEjh0yL6wU70fXrhqu4EheHMprIsi8KFCek7ric1aA1oI
         +ByyiDZvnxX0sHr9THYX9dt+PahdMsKi/tRhXVhc5w09AAttFmlhZ7p8Lo7mCBdNFJd6
         Trl9l7/eDIPfzOFhoSmxJ0PgbNDd1WM0A0UsNpER28C1Kus69NC01wmfep6uzUXIdp04
         vyfLC7TAvNHwf+mTsjzW2WtoPfALGWU3Bn1Fgll8QFg43TwH5TtJW3SdS9NrtqNblxT4
         v8NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231042; x=1768835842;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yp0RS/oXsUvBQ1KO8Ukt0iAOCzquRwmc0n8Mj/y5Wfg=;
        b=YQIYOaW6GuZ8z0wDBRygL2GeJqYmU1TCy7oAQkYCgCVH3EhxKTiRkBGaJfN/xYGK2u
         7kipZV1Fae9Heiw8W914svp4WAsehfwJ44L+YWUCTsHlsat6tbQHka2GTAXq2usxKffG
         7jelFTeqqVG+JjHeMhNor/L2RWcVEqUr1fM4UI94/qDQM9r5L0gUCu+psexEn5bXzjTj
         RAJUnoPRVpKcqZNesHQR6m2tlg7HAPXqLRECDzcLPAVp0/BgjJ9UWu118p6ibzHIumfW
         tbr7zyfsPK+2ECqFg/9+X2BsKY/AB9OXaWxZgWfvAnLmpGj9/ZrbsYlCHFZet/X8JfT2
         xMSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXGvV3xLIfsDQDCqTVwSMhuuLrWJFLJs1eO/Ta7eQSg84GnxJd6TzF420ZcTjM7HrslPyrtGQ==@lfdr.de
X-Gm-Message-State: AOJu0YzLwvzuyvyRzbdtUgWc6jis4x3T+hmYYCYYJDo4dsR/A5yUKdoF
	OEHcMwoEZa11DEUGImnRhfaSkrrMp6ZzhLzwgclibn0l9+z2Y1SMJpCO
X-Google-Smtp-Source: AGHT+IG1FEhjKE9yWwU1QBbXqCA34rtpSlAS+pKHcEh9/7djhXJhMsW9TUE+xKJ7bPfshaFCvLRpBw==
X-Received: by 2002:a05:600c:4fd0:b0:47b:da85:b9f3 with SMTP id 5b1f17b1804b1-47d84b34a73mr213795655e9.23.1768231041512;
        Mon, 12 Jan 2026 07:17:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Glrt560FBkAYRtZ4XXRXXVHD5m6rLtjBKX0o9VQ6S1Xw=="
Received: by 2002:a5d:5f43:0:b0:432:84f4:e9d6 with SMTP id ffacd0b85a97d-432bc9216f2ls3643594f8f.1.-pod-prod-05-eu;
 Mon, 12 Jan 2026 07:17:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUT+MALm66mT3tVGl9G9835hVKtYotZeusl3JoEntSXwMHoC3ThmRBGAVFwdShuYFW6uljFEt0k5s0=@googlegroups.com
X-Received: by 2002:a05:6000:2511:b0:430:f41f:bd5a with SMTP id ffacd0b85a97d-432c37a2fe5mr23158615f8f.57.1768231039312;
        Mon, 12 Jan 2026 07:17:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231039; cv=none;
        d=google.com; s=arc-20240605;
        b=JGrJFNXLgBQah/8FUTZasJxMheIC9U47JDxVru0iYb64gkv3lL4tudKc8BSPOYqnSc
         TWPMySYWzS1JjDhRAszwbc7gJWNLAQbO+sVBsO6UsZHD04SkNkmYjaPDPsrbzvEbMwNw
         WwAUuAs/A3zSu+0gUYBlKPnbLPFiLF1p/o4DwPL+el62EeHgZGFuDFK2qx2id9rMtIFq
         4G3o/cZ5Yi1NTdY0Ln16UY2nt2Ci5TeOTsjIGYNgNvgWWGxgt5rDnKTi7+rTpU8Fbkee
         7ytggzxkwBAOOBxKpSkwvbDI8pqudRmYlZY3i8DM7k8Ssbt2VzldTlkMhPGjkZozfgZu
         aqCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=j2JQu2pafvIycdznp2G0O4mrDR9UXeav0J7qRhN6tDg=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=YD4TRatfH11TplO4ogTsZh3QtaJV7rqDBx2lUqW5Gvda8grXdZtJFpUvFNmXLDmwKY
         6ft2DzLibGkLbg/5OKqFjykjLqwBHJrG1oDCIlVQ6/cOvK6TfbqaRuZbmMUQLtqtIQ89
         7gKlYsJicPGUvqb7ST0MoXSTVwekSUdiHUnT2o8icpcwtWD6HS6n5FEBrh6XSuN8HeD6
         6gRsJRSbWNwSVVFQUjPTWpsGUQbJZJmhIXSNXnz9B9EmZfZAebBJr5agCLd6mFq7Bii+
         1SuyJ6+fMGZ92d33chp3/TD3qDPfv/YDMcyhiO8GCoZv9MJqpnzXtDUVuijllug5GAZL
         LP6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432c1a1bca1si267596f8f.5.2026.01.12.07.17.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:19 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 075C33369A;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DF6E73EA65;
	Mon, 12 Jan 2026 15:16:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id WKlFNmoQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:58 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:08 +0100
Subject: [PATCH RFC v2 14/20] slab: remove struct kmem_cache_cpu
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-14-98225cfb50cf@suse.cz>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 075C33369A
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
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

The cpu slab is not used anymore for allocation or freeing, the
remaining code is for flushing, but it's effectively dead.  Remove the
whole struct kmem_cache_cpu, the flushing code and other orphaned
functions.

The remaining used field of kmem_cache_cpu is the stat array with
CONFIG_SLUB_STATS. Put it instead in a new struct kmem_cache_stats.
In struct kmem_cache, the field is cpu_stats and placed near the
end of the struct.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   7 +-
 mm/slub.c | 298 +++++---------------------------------------------------------
 2 files changed, 24 insertions(+), 281 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index e9a0738133ed..87faeb6143f2 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -21,14 +21,12 @@
 # define system_has_freelist_aba()	system_has_cmpxchg128()
 # define try_cmpxchg_freelist		try_cmpxchg128
 # endif
-#define this_cpu_try_cmpxchg_freelist	this_cpu_try_cmpxchg128
 typedef u128 freelist_full_t;
 #else /* CONFIG_64BIT */
 # ifdef system_has_cmpxchg64
 # define system_has_freelist_aba()	system_has_cmpxchg64()
 # define try_cmpxchg_freelist		try_cmpxchg64
 # endif
-#define this_cpu_try_cmpxchg_freelist	this_cpu_try_cmpxchg64
 typedef u64 freelist_full_t;
 #endif /* CONFIG_64BIT */
 
@@ -189,7 +187,6 @@ struct kmem_cache_order_objects {
  * Slab cache management.
  */
 struct kmem_cache {
-	struct kmem_cache_cpu __percpu *cpu_slab;
 	struct slub_percpu_sheaves __percpu *cpu_sheaves;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
@@ -238,6 +235,10 @@ struct kmem_cache {
 	unsigned int usersize;		/* Usercopy region size */
 #endif
 
+#ifdef CONFIG_SLUB_STATS
+	struct kmem_cache_stats __percpu *cpu_stats;
+#endif
+
 	struct kmem_cache_node *node[MAX_NUMNODES];
 };
 
diff --git a/mm/slub.c b/mm/slub.c
index 07d977e12478..882f607fb4ad 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -400,28 +400,11 @@ enum stat_item {
 	NR_SLUB_STAT_ITEMS
 };
 
-struct freelist_tid {
-	union {
-		struct {
-			void *freelist;		/* Pointer to next available object */
-			unsigned long tid;	/* Globally unique transaction id */
-		};
-		freelist_full_t freelist_tid;
-	};
-};
-
-/*
- * When changing the layout, make sure freelist and tid are still compatible
- * with this_cpu_cmpxchg_double() alignment requirements.
- */
-struct kmem_cache_cpu {
-	struct freelist_tid;
-	struct slab *slab;	/* The slab from which we are allocating */
-	local_trylock_t lock;	/* Protects the fields above */
 #ifdef CONFIG_SLUB_STATS
+struct kmem_cache_stats {
 	unsigned int stat[NR_SLUB_STAT_ITEMS];
-#endif
 };
+#endif
 
 static inline void stat(const struct kmem_cache *s, enum stat_item si)
 {
@@ -430,7 +413,7 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
 	 * The rmw is racy on a preemptible kernel but this is acceptable, so
 	 * avoid this_cpu_add()'s irq-disable overhead.
 	 */
-	raw_cpu_inc(s->cpu_slab->stat[si]);
+	raw_cpu_inc(s->cpu_stats->stat[si]);
 #endif
 }
 
@@ -438,7 +421,7 @@ static inline
 void stat_add(const struct kmem_cache *s, enum stat_item si, int v)
 {
 #ifdef CONFIG_SLUB_STATS
-	raw_cpu_add(s->cpu_slab->stat[si], v);
+	raw_cpu_add(s->cpu_stats->stat[si], v);
 #endif
 }
 
@@ -1148,20 +1131,6 @@ static void object_err(struct kmem_cache *s, struct slab *slab,
 	WARN_ON(1);
 }
 
-static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
-			       void **freelist, void *nextfree)
-{
-	if ((s->flags & SLAB_CONSISTENCY_CHECKS) &&
-	    !check_valid_pointer(s, slab, nextfree) && freelist) {
-		object_err(s, slab, *freelist, "Freechain corrupt");
-		*freelist = NULL;
-		slab_fix(s, "Isolate corrupted freechain");
-		return true;
-	}
-
-	return false;
-}
-
 static void __slab_err(struct slab *slab)
 {
 	if (slab_in_kunit_test())
@@ -1943,11 +1912,6 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
 static inline void dec_slabs_node(struct kmem_cache *s, int node,
 							int objects) {}
-static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
-			       void **freelist, void *nextfree)
-{
-	return false;
-}
 #endif /* CONFIG_SLUB_DEBUG */
 
 /*
@@ -3638,191 +3602,6 @@ static void *get_partial(struct kmem_cache *s, int node,
 	return get_any_partial(s, pc);
 }
 
-#ifdef CONFIG_PREEMPTION
-/*
- * Calculate the next globally unique transaction for disambiguation
- * during cmpxchg. The transactions start with the cpu number and are then
- * incremented by CONFIG_NR_CPUS.
- */
-#define TID_STEP  roundup_pow_of_two(CONFIG_NR_CPUS)
-#else
-/*
- * No preemption supported therefore also no need to check for
- * different cpus.
- */
-#define TID_STEP 1
-#endif /* CONFIG_PREEMPTION */
-
-static inline unsigned long next_tid(unsigned long tid)
-{
-	return tid + TID_STEP;
-}
-
-#ifdef SLUB_DEBUG_CMPXCHG
-static inline unsigned int tid_to_cpu(unsigned long tid)
-{
-	return tid % TID_STEP;
-}
-
-static inline unsigned long tid_to_event(unsigned long tid)
-{
-	return tid / TID_STEP;
-}
-#endif
-
-static inline unsigned int init_tid(int cpu)
-{
-	return cpu;
-}
-
-static void init_kmem_cache_cpus(struct kmem_cache *s)
-{
-	int cpu;
-	struct kmem_cache_cpu *c;
-
-	for_each_possible_cpu(cpu) {
-		c = per_cpu_ptr(s->cpu_slab, cpu);
-		local_trylock_init(&c->lock);
-		c->tid = init_tid(cpu);
-	}
-}
-
-/*
- * Finishes removing the cpu slab. Merges cpu's freelist with slab's freelist,
- * unfreezes the slabs and puts it on the proper list.
- * Assumes the slab has been already safely taken away from kmem_cache_cpu
- * by the caller.
- */
-static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
-			    void *freelist)
-{
-	struct kmem_cache_node *n = get_node(s, slab_nid(slab));
-	int free_delta = 0;
-	void *nextfree, *freelist_iter, *freelist_tail;
-	int tail = DEACTIVATE_TO_HEAD;
-	unsigned long flags = 0;
-	struct freelist_counters old, new;
-
-	if (READ_ONCE(slab->freelist)) {
-		stat(s, DEACTIVATE_REMOTE_FREES);
-		tail = DEACTIVATE_TO_TAIL;
-	}
-
-	/*
-	 * Stage one: Count the objects on cpu's freelist as free_delta and
-	 * remember the last object in freelist_tail for later splicing.
-	 */
-	freelist_tail = NULL;
-	freelist_iter = freelist;
-	while (freelist_iter) {
-		nextfree = get_freepointer(s, freelist_iter);
-
-		/*
-		 * If 'nextfree' is invalid, it is possible that the object at
-		 * 'freelist_iter' is already corrupted.  So isolate all objects
-		 * starting at 'freelist_iter' by skipping them.
-		 */
-		if (freelist_corrupted(s, slab, &freelist_iter, nextfree))
-			break;
-
-		freelist_tail = freelist_iter;
-		free_delta++;
-
-		freelist_iter = nextfree;
-	}
-
-	/*
-	 * Stage two: Unfreeze the slab while splicing the per-cpu
-	 * freelist to the head of slab's freelist.
-	 */
-	do {
-		old.freelist = READ_ONCE(slab->freelist);
-		old.counters = READ_ONCE(slab->counters);
-		VM_BUG_ON(!old.frozen);
-
-		/* Determine target state of the slab */
-		new.counters = old.counters;
-		new.frozen = 0;
-		if (freelist_tail) {
-			new.inuse -= free_delta;
-			set_freepointer(s, freelist_tail, old.freelist);
-			new.freelist = freelist;
-		} else {
-			new.freelist = old.freelist;
-		}
-	} while (!slab_update_freelist(s, slab, &old, &new, "unfreezing slab"));
-
-	/*
-	 * Stage three: Manipulate the slab list based on the updated state.
-	 */
-	if (!new.inuse && n->nr_partial >= s->min_partial) {
-		stat(s, DEACTIVATE_EMPTY);
-		discard_slab(s, slab);
-		stat(s, FREE_SLAB);
-	} else if (new.freelist) {
-		spin_lock_irqsave(&n->list_lock, flags);
-		add_partial(n, slab, tail);
-		spin_unlock_irqrestore(&n->list_lock, flags);
-		stat(s, tail);
-	} else {
-		stat(s, DEACTIVATE_FULL);
-	}
-}
-
-static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
-{
-	unsigned long flags;
-	struct slab *slab;
-	void *freelist;
-
-	local_lock_irqsave(&s->cpu_slab->lock, flags);
-
-	slab = c->slab;
-	freelist = c->freelist;
-
-	c->slab = NULL;
-	c->freelist = NULL;
-	c->tid = next_tid(c->tid);
-
-	local_unlock_irqrestore(&s->cpu_slab->lock, flags);
-
-	if (slab) {
-		deactivate_slab(s, slab, freelist);
-		stat(s, CPUSLAB_FLUSH);
-	}
-}
-
-static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
-{
-	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
-	void *freelist = c->freelist;
-	struct slab *slab = c->slab;
-
-	c->slab = NULL;
-	c->freelist = NULL;
-	c->tid = next_tid(c->tid);
-
-	if (slab) {
-		deactivate_slab(s, slab, freelist);
-		stat(s, CPUSLAB_FLUSH);
-	}
-}
-
-static inline void flush_this_cpu_slab(struct kmem_cache *s)
-{
-	struct kmem_cache_cpu *c = this_cpu_ptr(s->cpu_slab);
-
-	if (c->slab)
-		flush_slab(s, c);
-}
-
-static bool has_cpu_slab(int cpu, struct kmem_cache *s)
-{
-	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
-
-	return c->slab;
-}
-
 static bool has_pcs_used(int cpu, struct kmem_cache *s)
 {
 	struct slub_percpu_sheaves *pcs;
@@ -3836,7 +3615,7 @@ static bool has_pcs_used(int cpu, struct kmem_cache *s)
 }
 
 /*
- * Flush cpu slab.
+ * Flush percpu sheaves
  *
  * Called from CPU work handler with migration disabled.
  */
@@ -3851,8 +3630,6 @@ static void flush_cpu_slab(struct work_struct *w)
 
 	if (s->sheaf_capacity)
 		pcs_flush_all(s);
-
-	flush_this_cpu_slab(s);
 }
 
 static void flush_all_cpus_locked(struct kmem_cache *s)
@@ -3865,7 +3642,7 @@ static void flush_all_cpus_locked(struct kmem_cache *s)
 
 	for_each_online_cpu(cpu) {
 		sfw = &per_cpu(slub_flush, cpu);
-		if (!has_cpu_slab(cpu, s) && !has_pcs_used(cpu, s)) {
+		if (!has_pcs_used(cpu, s)) {
 			sfw->skip = true;
 			continue;
 		}
@@ -3975,7 +3752,6 @@ static int slub_cpu_dead(unsigned int cpu)
 
 	mutex_lock(&slab_mutex);
 	list_for_each_entry(s, &slab_caches, list) {
-		__flush_cpu_slab(s, cpu);
 		if (s->sheaf_capacity)
 			__pcs_flush_all_cpu(s, cpu);
 	}
@@ -7115,26 +6891,21 @@ init_kmem_cache_node(struct kmem_cache_node *n, struct node_barn *barn)
 		barn_init(barn);
 }
 
-static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
+#ifdef CONFIG_SLUB_STATS
+static inline int alloc_kmem_cache_stats(struct kmem_cache *s)
 {
 	BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
 			NR_KMALLOC_TYPES * KMALLOC_SHIFT_HIGH *
-			sizeof(struct kmem_cache_cpu));
+			sizeof(struct kmem_cache_stats));
 
-	/*
-	 * Must align to double word boundary for the double cmpxchg
-	 * instructions to work; see __pcpu_double_call_return_bool().
-	 */
-	s->cpu_slab = __alloc_percpu(sizeof(struct kmem_cache_cpu),
-				     2 * sizeof(void *));
+	s->cpu_stats = alloc_percpu(struct kmem_cache_stats);
 
-	if (!s->cpu_slab)
+	if (!s->cpu_stats)
 		return 0;
 
-	init_kmem_cache_cpus(s);
-
 	return 1;
 }
+#endif
 
 static int init_percpu_sheaves(struct kmem_cache *s)
 {
@@ -7246,7 +7017,9 @@ void __kmem_cache_release(struct kmem_cache *s)
 	cache_random_seq_destroy(s);
 	if (s->cpu_sheaves)
 		pcs_destroy(s);
-	free_percpu(s->cpu_slab);
+#ifdef CONFIG_SLUB_STATS
+	free_percpu(s->cpu_stats);
+#endif
 	free_kmem_cache_nodes(s);
 }
 
@@ -7938,12 +7711,6 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
 
 	memcpy(s, static_cache, kmem_cache->object_size);
 
-	/*
-	 * This runs very early, and only the boot processor is supposed to be
-	 * up.  Even if it weren't true, IRQs are not up so we couldn't fire
-	 * IPIs around.
-	 */
-	__flush_cpu_slab(s, smp_processor_id());
 	for_each_kmem_cache_node(s, node, n) {
 		struct slab *p;
 
@@ -8158,8 +7925,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 	if (!init_kmem_cache_nodes(s))
 		goto out;
 
-	if (!alloc_kmem_cache_cpus(s))
+#ifdef CONFIG_SLUB_STATS
+	if (!alloc_kmem_cache_stats(s))
 		goto out;
+#endif
 
 	err = init_percpu_sheaves(s);
 	if (err)
@@ -8478,33 +8247,6 @@ static ssize_t show_slab_objects(struct kmem_cache *s,
 	if (!nodes)
 		return -ENOMEM;
 
-	if (flags & SO_CPU) {
-		int cpu;
-
-		for_each_possible_cpu(cpu) {
-			struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab,
-							       cpu);
-			int node;
-			struct slab *slab;
-
-			slab = READ_ONCE(c->slab);
-			if (!slab)
-				continue;
-
-			node = slab_nid(slab);
-			if (flags & SO_TOTAL)
-				x = slab->objects;
-			else if (flags & SO_OBJECTS)
-				x = slab->inuse;
-			else
-				x = 1;
-
-			total += x;
-			nodes[node] += x;
-
-		}
-	}
-
 	/*
 	 * It is impossible to take "mem_hotplug_lock" here with "kernfs_mutex"
 	 * already held which will conflict with an existing lock order:
@@ -8875,7 +8617,7 @@ static int show_stat(struct kmem_cache *s, char *buf, enum stat_item si)
 		return -ENOMEM;
 
 	for_each_online_cpu(cpu) {
-		unsigned x = per_cpu_ptr(s->cpu_slab, cpu)->stat[si];
+		unsigned x = per_cpu_ptr(s->cpu_stats, cpu)->stat[si];
 
 		data[cpu] = x;
 		sum += x;
@@ -8901,7 +8643,7 @@ static void clear_stat(struct kmem_cache *s, enum stat_item si)
 	int cpu;
 
 	for_each_online_cpu(cpu)
-		per_cpu_ptr(s->cpu_slab, cpu)->stat[si] = 0;
+		per_cpu_ptr(s->cpu_stats, cpu)->stat[si] = 0;
 }
 
 #define STAT_ATTR(si, text) 					\

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-14-98225cfb50cf%40suse.cz.
