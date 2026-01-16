Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBM4VHFQMGQEQP2DNVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B879D32C87
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:41:10 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-47ee3dd7fc8sf17938075e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:41:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574469; cv=pass;
        d=google.com; s=arc-20240605;
        b=MOHMcTfcxwKnUJ2r9dpuX6bGrrHGhTrD5dJEB93HemQmzznQuNelWTaVpPSrx3XJCS
         v1VIY8mJwvZ7CkXZGhTCt9HWqvzb5Wsfuq3KHPz0BDL8uEZdFUI/ir4hFD/KwwUE0sZH
         e0OxF+/EF76EmcrSPGLZh8yu0j/9L7pyH0BCvp15fQyIsTCqQQ38l8iGhfsScdnFs4KF
         Sv4/Wm5xqp+Vv6JUDaLA0HMxBIJA3Ez3D6vAuWFvPoRiydSXryUkyZyjjtUmZ3MH/xcE
         WfjxLooEBswpIMuRxHXbCfYvitdqIajn+h189qRHkXTbZ7AX8ufm5D2BEXrY9fCz5Pwy
         4hLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=3E8GbGVG80CyNUTZQzNF6qzdFsfZGbAmHZGr3e2+sxQ=;
        fh=hfZBl3pjyKBVbwWdSzRrm1dem1QR5slscoG/IvM9dGc=;
        b=doaq6mRxxJ3I9USwK17OUwASj9azyEGeIealLCKPhdn5JpKkiycf7sEdGOqJiv/9Ia
         NxJUJmqAkpJ5YT7KDaortxpgExikofteq7AGaoDmN75nE1Ho3jQWRju02MeTgqbLifef
         gz8A781PWQ+EcVUchexpIM1mTVyQ/zQiMgqBO27oRRmL/qvR8PRvutRLdBtoGmhpvTer
         gIRUNmVYyIlR3LdNH/pIOwGhQ7f+u5NVcri4NghdIEMiX66NR2+8AfTqMbNshwCdTV6m
         f1I2Jgd7WPn5Rircsj3DfsdzOLkWgi6WRSzK1UMDkG3bt28hIJYHpkWeXHNOD5LU4qQY
         cYyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Umj/qy2M";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Umj/qy2M";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574469; x=1769179269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3E8GbGVG80CyNUTZQzNF6qzdFsfZGbAmHZGr3e2+sxQ=;
        b=nd1gma1GHTWXiHXZ+mVLwNH5BriiOZ6fAb6g3QaDQUww1/dRDdM/g2egLln52dJzeU
         UD0pVm1PGx8oqC7TzTrArYb2pMPfHlaZS9rgC9ZU7Ahho/c0Vq8g4gYgfKIO19B11wSl
         4BRo7QEfWfxCKpDjrE+sZ6UpfYSZx3gAmzXm0sULvt2NlhSjINsOr14YYhL7uyfJ2JZu
         S+24P6yWu7/3lEQZjzajfsLcQa6fxrr9j2xSdTZ48NcIyLIQEtnyTymTWLgatNNiXE+g
         6mG/ezrW+egQJLFxcD3bnjrWdavhGZRQt9cVE1hYqO7noA7HNKuqRdIgq7Bz2Yg9ADa4
         Wc2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574469; x=1769179269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3E8GbGVG80CyNUTZQzNF6qzdFsfZGbAmHZGr3e2+sxQ=;
        b=VxPO5zc0rcw++wOslKw2biRXqkOPdIP7GZbZSoHXxcYNT5+uPQqiW317qBoX6n1alJ
         nLFa/kZxVwaJefxpdQSklBI1RAcA4VY2jZDUWUA17sQ9feStkPcN6icj0veVH5a7TUDG
         e8b87j94qQuZESGoHC2+1HkwOOWM5ar/WPe8N9K64vlP0morHw4DwrDDeitRO4vFZAMt
         2LYTt3NILYSdbdyqcaRkR7u7xfGMfmLMDq0FF+7Au5nIPGRGIjYevukz9IB7Vb6k48vV
         B4KyPAA/U0rlYYPVXPJt8+KGhGnNoMPsUxsmn92wVOQTh2m+r6sx/kzoRl664aMGh9PZ
         wvuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsB0y2OxRccocIujrpG/3oO9BBUiMP8f9WRWXhGelZSUbc5A/O0it7hah2nr5V5DkgQ1I9sA==@lfdr.de
X-Gm-Message-State: AOJu0YwyiDXvWcyC6Ks06GJqXCfHvA15uIC3QpVJgY2jlWVoEXP68VoR
	MXuFTyfl0ihlQe+kOXAxoW7PQY5HyC9YQmPKM6obmmFhgr+R1h0f0YiF
X-Received: by 2002:a05:600c:37c8:b0:46e:1a5e:211 with SMTP id 5b1f17b1804b1-4801eb09213mr33056965e9.21.1768574469504;
        Fri, 16 Jan 2026 06:41:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gb/vlEDQ0Hp2j5GCTId6yTc+dmG/9vXLHg55uWftLmCg=="
Received: by 2002:a05:600c:1c1a:b0:471:e4b:ff10 with SMTP id
 5b1f17b1804b1-47f3b7aa88bls14059095e9.2.-pod-prod-06-eu; Fri, 16 Jan 2026
 06:41:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVAXFGtRmMDZFEYKhL85DsWWC1jmk5jT6Yl0PPhOkPaZALS/PH+fCarZ1OGOYY1aBE+CfyN4FvGNSU=@googlegroups.com
X-Received: by 2002:a05:600c:37c8:b0:477:a978:3a7b with SMTP id 5b1f17b1804b1-4801eb0922cmr32203975e9.22.1768574467266;
        Fri, 16 Jan 2026 06:41:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574467; cv=none;
        d=google.com; s=arc-20240605;
        b=R/eS3TLrLnyoFKL2/sdHHFJszSlDQ2eATIkum4swC1tTIjGOxZata00HV30KnuS7gu
         tf14y9tcas7nSoyJQYj7c51OsIGysKLRU2lYlVj4nkJ37gwa5JS9eAUqv/TOxzU3X5MO
         ZBMr5W73QiadoPezOP+6dXYiEIrwgFUvko4Ukg3Bu7k0TJE0QVmftyDFjeQDRvz/R7Cn
         BhmapG9spggJ5V82MnHkpZwoZHi1fbRPUbMk1YNkuTpwCgVo/Z/Nt119y7pnBWQY1bkT
         24/fX5flUIKGIXNV1xT5cKIUz409rQZVKsYDac8XTF3k08DJuqALcHxHJLJxYuxqsVnn
         F38Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=QYPFN/yW/JKvudjCCeDF8Mzn+JOB4FaaxcACY1SSQAU=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=b7YjeEMiwnsNhNiooAR7S0jao12/j7oTFuzP9qfs0EY9vg7hR6+RSBfhqZtrCi9Lg5
         tZQY5lW8xl5tskbvocWoFgj8ZNROZBhb6yL/qqbjCW4X6AH1+NUH1t0uOY6Y+lI8mFRP
         AaytqrtspxTGVJWhA30lJqUGUEy7FKAbTgLLQGvgo38EfrcA6YiIkItb1PYPTgcW2xEb
         hcB0ZsR+3+HY0OaCC4OFvKpcVPamOmbRPdlrUTEORszyOO4TOQzVzAL8LVj27tPUj1Se
         50/1N4UVzJ8ELBVYT2lb5vLt+CeVcK1+PMYdPZJ247GE600pcShfZSBX0t/OAoNGu+wO
         8rqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Umj/qy2M";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Umj/qy2M";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356996ed8asi51241f8f.7.2026.01.16.06.41.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:41:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 822D6337D7;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 66D243EA65;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id WHXYGOZNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:37 +0100
Subject: [PATCH v3 17/21] slab: refill sheaves from all nodes
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
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
X-Spam-Score: -4.51
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
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
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
	R_RATELIMIT(0.00)[to(RL941jgdop1fyjkq8h4),to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 822D6337D7
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Umj/qy2M";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Umj/qy2M";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

__refill_objects() currently only attempts to get partial slabs from the
local node and then allocates new slab(s). Expand it to trying also
other nodes while observing the remote node defrag ratio, similarly to
get_any_partial().

This will prevent allocating new slabs on a node while other nodes have
many free slabs. It does mean sheaves will contain non-local objects in
that case. Allocations that care about specific node will still be
served appropriately, but might get a slowpath allocation.

Like get_any_partial() we do observe cpuset_zone_allowed(), although we
might be refilling a sheaf that will be then used from a different
allocation context.

We can also use the resulting refill_objects() in
__kmem_cache_alloc_bulk() for non-debug caches. This means
kmem_cache_alloc_bulk() will get better performance when sheaves are
exhausted. kmem_cache_alloc_bulk() cannot indicate a preferred node so
it's compatible with sheaves refill in preferring the local node.
Its users also have gfp flags that allow spinning, so document that
as a requirement.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 137 ++++++++++++++++++++++++++++++++++++++++++++++++--------------
 1 file changed, 106 insertions(+), 31 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d52de6e3c2d5..2c522d2bf547 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2518,8 +2518,8 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
 }
 
 static unsigned int
-__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
-		 unsigned int max);
+refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+	       unsigned int max);
 
 static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 			 gfp_t gfp)
@@ -2530,8 +2530,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 	if (!to_fill)
 		return 0;
 
-	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
-			to_fill, to_fill);
+	filled = refill_objects(s, &sheaf->objects[sheaf->size], gfp, to_fill,
+				to_fill);
 
 	sheaf->size += filled;
 
@@ -6522,29 +6522,22 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 EXPORT_SYMBOL(kmem_cache_free_bulk);
 
 static unsigned int
-__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
-		 unsigned int max)
+__refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		      unsigned int max, struct kmem_cache_node *n)
 {
 	struct slab *slab, *slab2;
 	struct partial_context pc;
 	unsigned int refilled = 0;
 	unsigned long flags;
 	void *object;
-	int node;
 
 	pc.flags = gfp;
 	pc.min_objects = min;
 	pc.max_objects = max;
 
-	node = numa_mem_id();
-
-	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
+	if (!get_partial_node_bulk(s, n, &pc))
 		return 0;
 
-	/* TODO: consider also other nodes? */
-	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
-		goto new_slab;
-
 	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
 
 		list_del(&slab->slab_list);
@@ -6582,8 +6575,6 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 	}
 
 	if (unlikely(!list_empty(&pc.slabs))) {
-		struct kmem_cache_node *n = get_node(s, node);
-
 		spin_lock_irqsave(&n->list_lock, flags);
 
 		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
@@ -6605,13 +6596,92 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 		}
 	}
 
+	return refilled;
+}
 
-	if (likely(refilled >= min))
-		goto out;
+#ifdef CONFIG_NUMA
+static unsigned int
+__refill_objects_any(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		     unsigned int max, int local_node)
+{
+	struct zonelist *zonelist;
+	struct zoneref *z;
+	struct zone *zone;
+	enum zone_type highest_zoneidx = gfp_zone(gfp);
+	unsigned int cpuset_mems_cookie;
+	unsigned int refilled = 0;
+
+	/* see get_any_partial() for the defrag ratio description */
+	if (!s->remote_node_defrag_ratio ||
+			get_cycles() % 1024 > s->remote_node_defrag_ratio)
+		return 0;
+
+	do {
+		cpuset_mems_cookie = read_mems_allowed_begin();
+		zonelist = node_zonelist(mempolicy_slab_node(), gfp);
+		for_each_zone_zonelist(zone, z, zonelist, highest_zoneidx) {
+			struct kmem_cache_node *n;
+			unsigned int r;
+
+			n = get_node(s, zone_to_nid(zone));
+
+			if (!n || !cpuset_zone_allowed(zone, gfp) ||
+					n->nr_partial <= s->min_partial)
+				continue;
+
+			r = __refill_objects_node(s, p, gfp, min, max, n);
+			refilled += r;
+
+			if (r >= min) {
+				/*
+				 * Don't check read_mems_allowed_retry() here -
+				 * if mems_allowed was updated in parallel, that
+				 * was a harmless race between allocation and
+				 * the cpuset update
+				 */
+				return refilled;
+			}
+			p += r;
+			min -= r;
+			max -= r;
+		}
+	} while (read_mems_allowed_retry(cpuset_mems_cookie));
+
+	return refilled;
+}
+#else
+static inline unsigned int
+__refill_objects_any(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		     unsigned int max, int local_node)
+{
+	return 0;
+}
+#endif
+
+static unsigned int
+refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+	       unsigned int max)
+{
+	int local_node = numa_mem_id();
+	unsigned int refilled;
+	struct slab *slab;
+
+	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
+		return 0;
+
+	refilled = __refill_objects_node(s, p, gfp, min, max,
+					 get_node(s, local_node));
+	if (refilled >= min)
+		return refilled;
+
+	refilled += __refill_objects_any(s, p + refilled, gfp, min - refilled,
+					 max - refilled, local_node);
+	if (refilled >= min)
+		return refilled;
 
 new_slab:
 
-	slab = new_slab(s, pc.flags, node);
+	slab = new_slab(s, gfp, local_node);
 	if (!slab)
 		goto out;
 
@@ -6626,8 +6696,8 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 
 	if (refilled < min)
 		goto new_slab;
-out:
 
+out:
 	return refilled;
 }
 
@@ -6637,18 +6707,20 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 {
 	int i;
 
-	/*
-	 * TODO: this might be more efficient (if necessary) by reusing
-	 * __refill_objects()
-	 */
-	for (i = 0; i < size; i++) {
+	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
+		for (i = 0; i < size; i++) {
 
-		p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
-				     s->object_size);
-		if (unlikely(!p[i]))
-			goto error;
+			p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
+					     s->object_size);
+			if (unlikely(!p[i]))
+				goto error;
 
-		maybe_wipe_obj_freeptr(s, p[i]);
+			maybe_wipe_obj_freeptr(s, p[i]);
+		}
+	} else {
+		i = refill_objects(s, p, flags, size, size);
+		if (i < size)
+			goto error;
 	}
 
 	return i;
@@ -6659,7 +6731,10 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
 }
 
-/* Note that interrupts must be enabled when calling this function. */
+/*
+ * Note that interrupts must be enabled when calling this function and gfp
+ * flags must allow spinning.
+ */
 int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 				 void **p)
 {

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-17-5595cb000772%40suse.cz.
