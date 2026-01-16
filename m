Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3M3VHFQMGQE7NF5Z4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB57FD32C52
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:46 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id a640c23a62f3a-b7cea4b3f15sf254311266b.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574446; cv=pass;
        d=google.com; s=arc-20240605;
        b=LLV9wrkBt4/b963Pou2eNptMEYHBUO48xodfHcUUH9vXF/yNlCD6ZuZfL15Svctr2x
         eBtVOWEw0KqsffvcKLECAriyVY6/ku8Y7epGgKtcWfUhHcQxbPoxw4/flzONDLg/CuUJ
         aYqJGZHFaqyI1OAGpbCfw6GxBeikD7IC0sL2/y5VEtEjxV4WVbCyaJWuJjHc0wNMz3Cm
         0zZa9y+PcU248D+xef/OxIh9A4s0u6dlohD0orUSwBD2owY9QT8RinMiLdH2YLWWiKg2
         ZjQWt5YSzL/KOrr+L78BCcdxUxYCLCiukuQuRTJigwBoGNv4KLMr38X7rsXC2Vzc/aGJ
         WQew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=ZpKADpA3fJUsDfXo8yxMRtpLOUYffjerOtFtDKi6bak=;
        fh=wYQdnflnIBrIE/1vV0ND373q1JlQHeD9utn4Xs+YFJs=;
        b=J4uQoWcxC+czTiFF+iUrsibN0qDbRkSv5+ShrxPd1dbraSpkLIPYSwNSy/2FuSLowx
         eu90wvlDvhBBpvsUDA5u4zF6P/sqVGXmdjEitEZa7x3LNb+JSCh6kkJj3AcVEtkSUEdm
         09mtcSd74ljEQR7Byi4JXldowl4lbPR+Ajr4XJUOJfvEWBYeSFFKWdHwZDmblqfZXrkN
         Zq/e3Nh4NdzmHaIiIIoV28FeZtjbkeHUTvEvrd/OA/Pj7Zs4ZzhF4nai8lG9YRisNr/V
         EbTNGfvBFd9LI7pMxQLnWIld4pfRcYdL6AOKSOq2DUn1FGFipz9swwCv4KXE9uRjlmhp
         30Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eZQyPLN9;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eZQyPLN9;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574446; x=1769179246; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZpKADpA3fJUsDfXo8yxMRtpLOUYffjerOtFtDKi6bak=;
        b=E2IVMGIiFSf4R6cZsGI/XIZ6oWXviish8u6J7w5DaYXPMQ55HsWhcNgRAOzFzZhbl8
         c2+/Kw/KIurW/+GUohlCZbw34zNAcp9rKtayTQeeN2MD11siGInrB8Q5zMcATrAjzXvf
         JnSIZQRAibnbO50B7ep0IpA80w2qvZJrNDK89aFttAymFD4O7rVJ8KTy9sqyt63c/UIK
         sXtqPaujzuduDQPbrgcC0T2NVnBRC6zdt0jAfCXrOP4t83EFfLhcoZUtr3IezwtCAGki
         YBIVec8x6I9UzE2Pp9Z/6H5CQHWrCv/LVXeDnZHD9lAIdbm2icJ/Tvbb1fbyQh0Pve7A
         yROw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574446; x=1769179246;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZpKADpA3fJUsDfXo8yxMRtpLOUYffjerOtFtDKi6bak=;
        b=jrB0m2fGL25DvlFlATJDP+1E1+EBu1AEKP3U56TAGUBB4C2SXoTK+J/xqB4acfZSQO
         a1C/voNyvN8dlWHENsloqYv1bCXSOYK6MLdgWzvi0azviJWGpFh7VZ7xq4buaQDFpsH8
         GmbeylwKYE2bl8Az3+opbaT/tNYcjkN0Hb41CdSQNVkTtL5R8LHW/yg5s4Jo04XStoWt
         WCD2yzAdYM4E11404WLq7cuYbsYG4QG/zkZ2N5cCxTP2lUwBPUOnxZQ3MBkEJKy9/gzk
         6+9hOC+Jt3eQRrRqZvJ0BlSkzMRxdMRMqc4jh8g3LN2jC/uWnfH2bqMhdzGhVbeXTfLZ
         NeOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXxNUYtR+Igu8pRV/VS3lz+gQxBfXW9p8lfoPxrSR6hWDnWdv8tuvPeqjPDOZoVWcWNmK0KYg==@lfdr.de
X-Gm-Message-State: AOJu0Yw5cVIobI3zuVCesLe0/K1WrkWyTfNqyZouIabmnzfhcXkdo7YF
	fHGOqff/tNzB49hrkLEgX4OsYG75iwyGW8+l4TkUHUDxjCNv7Uif9hF4
X-Received: by 2002:a05:6402:1ec9:b0:64b:60e4:f898 with SMTP id 4fb4d7f45d1cf-654526cc2c5mr2655708a12.15.1768574445712;
        Fri, 16 Jan 2026 06:40:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GGi1oDr4Ln5JIqlJgNVsVflK5C1TOiugH/UVxm4FAADw=="
Received: by 2002:a05:6402:3256:20b0:641:6610:6028 with SMTP id
 4fb4d7f45d1cf-6541c6e9c85ls2467830a12.2.-pod-prod-03-eu; Fri, 16 Jan 2026
 06:40:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUCcKBAIxt/iNVRF7ahjMyaakVzN1VwXao0Sl8u+4cs9eSpfTk+KJdJtI8MyBJygye7UKMoJlJBpx4=@googlegroups.com
X-Received: by 2002:a17:907:930e:b0:b83:73ee:9dc0 with SMTP id a640c23a62f3a-b8793028f11mr256874966b.65.1768574443363;
        Fri, 16 Jan 2026 06:40:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574443; cv=none;
        d=google.com; s=arc-20240605;
        b=KzaWX/Vjj7vrLa7dysSts13r6buTkc7MOoVMVLVODKDIdZMDcbiMz1cXkf4gmuL8j3
         lmA4BcrHArqCJp3NJoOrcmE6UxcL4ibrFoYp0I+wP0Jv4W0BKN4xDuyRUUQFmfz6yzQE
         Qs732I0otySORV/SL+fpJ3xaXYkwDX8BAjA/o6IADh6/jeO53cCdjYqpEak1eyGtK8Gr
         WgDwzWVMe2gQ5sarRrIDrshobEglQ7DIfEmu90fH3yx0KvOKrepzISLPBKGMz/keTRZ/
         Yh1g7RTusuC2k3qSlvYpVYohwogZrZ1fmqF8xhEbDuwIM6plDWG/tJYFLFlt6L8f2cVi
         Ob6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=/upRfJ3PHSpDAJJ/Lor3pwgQGBiD4JB0EJmftl/mO6A=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=H8R0dxYwvswWcGZWaTdp4EAqYN/MBYdmQBXRDGP2rSs9EBlz9+K6f1RDhHrCFG5Ka8
         SBzObvi2Z9DpQnLhK6hvKm0QicPwf7NzvywQfdqVcoRh8ALjxnL60nv1eER4mlpo6Qmy
         zwvGhmgK0M0jWIUpdCi23iWLF5fa0AKIZFNK7czR3/kMgIrynjVLO64Vf5b2YOAff811
         FfJdoLN5AlLLzg8PlGoTsiWTVJrCLmQ0cAeliVZOc+avBcwdbBXHiqv5F28y46RzqTGP
         2FnS6BbhmttBMU57lkbl23kkP1exkTSfzETWy9+szRWIvpR+kDjJ1KnK6NTWtVxyoVRX
         EF/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eZQyPLN9;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eZQyPLN9;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654530dc8c4si46604a12.3.2026.01.16.06.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 460AA5BE85;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 27AF03EA66;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id cDlrCeVNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:26 +0100
Subject: [PATCH v3 06/21] slab: introduce percpu sheaves bootstrap
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
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
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: 460AA5BE85
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=eZQyPLN9;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=eZQyPLN9;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
sheaves enabled. Since we want to enable them for almost all caches,
it's suboptimal to test the pointer in the fast paths, so instead
allocate it for all caches in do_kmem_cache_create(). Instead of testing
the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
kmem_cache->sheaf_capacity for being 0, where needed, using a new
cache_has_sheaves() helper.

However, for the fast paths sake we also assume that the main sheaf
always exists (pcs->main is !NULL), and during bootstrap we cannot
allocate sheaves yet.

Solve this by introducing a single static bootstrap_sheaf that's
assigned as pcs->main during bootstrap. It has a size of 0, so during
allocations, the fast path will find it's empty. Since the size of 0
matches sheaf_capacity of 0, the freeing fast paths will find it's
"full". In the slow path handlers, we use cache_has_sheaves() to
recognize that the cache doesn't (yet) have real sheaves, and fall back.
Thus sharing the single bootstrap sheaf like this for multiple caches
and cpus is safe.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 119 ++++++++++++++++++++++++++++++++++++++++++--------------------
 1 file changed, 81 insertions(+), 38 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index edf341c87e20..706cb6398f05 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -501,6 +501,18 @@ struct kmem_cache_node {
 	struct node_barn *barn;
 };
 
+/*
+ * Every cache has !NULL s->cpu_sheaves but they may point to the
+ * bootstrap_sheaf temporarily during init, or permanently for the boot caches
+ * and caches with debugging enabled, or all caches with CONFIG_SLUB_TINY. This
+ * helper distinguishes whether cache has real non-bootstrap sheaves.
+ */
+static inline bool cache_has_sheaves(struct kmem_cache *s)
+{
+	/* Test CONFIG_SLUB_TINY for code elimination purposes */
+	return !IS_ENABLED(CONFIG_SLUB_TINY) && s->sheaf_capacity;
+}
+
 static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
 {
 	return s->node[node];
@@ -2855,6 +2867,10 @@ static void pcs_destroy(struct kmem_cache *s)
 		if (!pcs->main)
 			continue;
 
+		/* bootstrap or debug caches, it's the bootstrap_sheaf */
+		if (!pcs->main->cache)
+			continue;
+
 		/*
 		 * We have already passed __kmem_cache_shutdown() so everything
 		 * was flushed and there should be no objects allocated from
@@ -4030,7 +4046,7 @@ static bool has_pcs_used(int cpu, struct kmem_cache *s)
 {
 	struct slub_percpu_sheaves *pcs;
 
-	if (!s->cpu_sheaves)
+	if (!cache_has_sheaves(s))
 		return false;
 
 	pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
@@ -4052,7 +4068,7 @@ static void flush_cpu_slab(struct work_struct *w)
 
 	s = sfw->s;
 
-	if (s->cpu_sheaves)
+	if (cache_has_sheaves(s))
 		pcs_flush_all(s);
 
 	flush_this_cpu_slab(s);
@@ -4157,7 +4173,7 @@ void flush_all_rcu_sheaves(void)
 	mutex_lock(&slab_mutex);
 
 	list_for_each_entry(s, &slab_caches, list) {
-		if (!s->cpu_sheaves)
+		if (!cache_has_sheaves(s))
 			continue;
 		flush_rcu_sheaves_on_cache(s);
 	}
@@ -4179,7 +4195,7 @@ static int slub_cpu_dead(unsigned int cpu)
 	mutex_lock(&slab_mutex);
 	list_for_each_entry(s, &slab_caches, list) {
 		__flush_cpu_slab(s, cpu);
-		if (s->cpu_sheaves)
+		if (cache_has_sheaves(s))
 			__pcs_flush_all_cpu(s, cpu);
 	}
 	mutex_unlock(&slab_mutex);
@@ -4979,6 +4995,12 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 
 	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
 
+	/* Bootstrap or debug cache, back off */
+	if (unlikely(!cache_has_sheaves(s))) {
+		local_unlock(&s->cpu_sheaves->lock);
+		return NULL;
+	}
+
 	if (pcs->spare && pcs->spare->size > 0) {
 		swap(pcs->main, pcs->spare);
 		return pcs;
@@ -5165,6 +5187,11 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		struct slab_sheaf *full;
 		struct node_barn *barn;
 
+		if (unlikely(!cache_has_sheaves(s))) {
+			local_unlock(&s->cpu_sheaves->lock);
+			return allocated;
+		}
+
 		if (pcs->spare && pcs->spare->size > 0) {
 			swap(pcs->main, pcs->spare);
 			goto do_alloc;
@@ -5244,8 +5271,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
 	if (unlikely(object))
 		goto out;
 
-	if (s->cpu_sheaves)
-		object = alloc_from_pcs(s, gfpflags, node);
+	object = alloc_from_pcs(s, gfpflags, node);
 
 	if (!object)
 		object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);
@@ -5355,17 +5381,6 @@ kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp_t gfp, unsigned int size)
 
 	if (unlikely(size > s->sheaf_capacity)) {
 
-		/*
-		 * slab_debug disables cpu sheaves intentionally so all
-		 * prefilled sheaves become "oversize" and we give up on
-		 * performance for the debugging. Same with SLUB_TINY.
-		 * Creating a cache without sheaves and then requesting a
-		 * prefilled sheaf is however not expected, so warn.
-		 */
-		WARN_ON_ONCE(s->sheaf_capacity == 0 &&
-			     !IS_ENABLED(CONFIG_SLUB_TINY) &&
-			     !(s->flags & SLAB_DEBUG_FLAGS));
-
 		sheaf = kzalloc(struct_size(sheaf, objects, size), gfp);
 		if (!sheaf)
 			return NULL;
@@ -6082,6 +6097,12 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 restart:
 	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
 
+	/* Bootstrap or debug cache, back off */
+	if (unlikely(!cache_has_sheaves(s))) {
+		local_unlock(&s->cpu_sheaves->lock);
+		return NULL;
+	}
+
 	barn = get_barn(s);
 	if (!barn) {
 		local_unlock(&s->cpu_sheaves->lock);
@@ -6280,6 +6301,12 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
 		struct slab_sheaf *empty;
 		struct node_barn *barn;
 
+		/* Bootstrap or debug cache, fall back */
+		if (unlikely(!cache_has_sheaves(s))) {
+			local_unlock(&s->cpu_sheaves->lock);
+			goto fail;
+		}
+
 		if (pcs->spare && pcs->spare->size == 0) {
 			pcs->rcu_free = pcs->spare;
 			pcs->spare = NULL;
@@ -6674,9 +6701,8 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	if (unlikely(!slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		return;
 
-	if (s->cpu_sheaves && likely(!IS_ENABLED(CONFIG_NUMA) ||
-				     slab_nid(slab) == numa_mem_id())
-			   && likely(!slab_test_pfmemalloc(slab))) {
+	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
+	    && likely(!slab_test_pfmemalloc(slab))) {
 		if (likely(free_to_pcs(s, object)))
 			return;
 	}
@@ -7379,7 +7405,7 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 	 * freeing to sheaves is so incompatible with the detached freelist so
 	 * once we go that way, we have to do everything differently
 	 */
-	if (s && s->cpu_sheaves) {
+	if (s && cache_has_sheaves(s)) {
 		free_to_pcs_bulk(s, size, p);
 		return;
 	}
@@ -7490,8 +7516,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 		size--;
 	}
 
-	if (s->cpu_sheaves)
-		i = alloc_from_pcs_bulk(s, size, p);
+	i = alloc_from_pcs_bulk(s, size, p);
 
 	if (i < size) {
 		/*
@@ -7702,6 +7727,7 @@ static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
 
 static int init_percpu_sheaves(struct kmem_cache *s)
 {
+	static struct slab_sheaf bootstrap_sheaf = {};
 	int cpu;
 
 	for_each_possible_cpu(cpu) {
@@ -7711,7 +7737,28 @@ static int init_percpu_sheaves(struct kmem_cache *s)
 
 		local_trylock_init(&pcs->lock);
 
-		pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
+		/*
+		 * Bootstrap sheaf has zero size so fast-path allocation fails.
+		 * It has also size == s->sheaf_capacity, so fast-path free
+		 * fails. In the slow paths we recognize the situation by
+		 * checking s->sheaf_capacity. This allows fast paths to assume
+		 * s->cpu_sheaves and pcs->main always exists and is valid.
+		 * It's also safe to share the single static bootstrap_sheaf
+		 * with zero-sized objects array as it's never modified.
+		 *
+		 * bootstrap_sheaf also has NULL pointer to kmem_cache so we
+		 * recognize it and not attempt to free it when destroying the
+		 * cache
+		 *
+		 * We keep bootstrap_sheaf for kmem_cache and kmem_cache_node,
+		 * caches with debug enabled, and all caches with SLUB_TINY.
+		 * For kmalloc caches it's used temporarily during the initial
+		 * bootstrap.
+		 */
+		if (!s->sheaf_capacity)
+			pcs->main = &bootstrap_sheaf;
+		else
+			pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
 
 		if (!pcs->main)
 			return -ENOMEM;
@@ -7809,7 +7856,7 @@ static int init_kmem_cache_nodes(struct kmem_cache *s)
 			continue;
 		}
 
-		if (s->cpu_sheaves) {
+		if (cache_has_sheaves(s)) {
 			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
 
 			if (!barn)
@@ -8127,7 +8174,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
 	flush_all_cpus_locked(s);
 
 	/* we might have rcu sheaves in flight */
-	if (s->cpu_sheaves)
+	if (cache_has_sheaves(s))
 		rcu_barrier();
 
 	/* Attempt to free all objects */
@@ -8439,7 +8486,7 @@ static int slab_mem_going_online_callback(int nid)
 		if (get_node(s, nid))
 			continue;
 
-		if (s->cpu_sheaves) {
+		if (cache_has_sheaves(s)) {
 			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, nid);
 
 			if (!barn) {
@@ -8647,12 +8694,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 
 	set_cpu_partial(s);
 
-	if (s->sheaf_capacity) {
-		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
-		if (!s->cpu_sheaves) {
-			err = -ENOMEM;
-			goto out;
-		}
+	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
+	if (!s->cpu_sheaves) {
+		err = -ENOMEM;
+		goto out;
 	}
 
 #ifdef CONFIG_NUMA
@@ -8671,11 +8716,9 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 	if (!alloc_kmem_cache_cpus(s))
 		goto out;
 
-	if (s->cpu_sheaves) {
-		err = init_percpu_sheaves(s);
-		if (err)
-			goto out;
-	}
+	err = init_percpu_sheaves(s);
+	if (err)
+		goto out;
 
 	err = 0;
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-6-5595cb000772%40suse.cz.
