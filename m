Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWPG5DDQMGQEYLZFL6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id BB11BC01903
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:30 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-471125c8bc1sf11911865e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227610; cv=pass;
        d=google.com; s=arc-20240605;
        b=SUsImyNAv+I/jYQWcuWwxcKBPwr5/+CrZWaLZZw79FpTclgkgSGSpdGEISKPUb3Hfe
         oI/kIjBPUSFvSrnibbtao1F+kzpcc5lDc0W0Q1JB5c79PC3mEFvIIk/MC9NZ8o4/9BLl
         gmJrvZLUVWtJc9OaJVoP85Noeaxsl/O3VUhN0NfPInfa+MPmuLGwUWKVxDylWhagEvRd
         cKfUhyJt9FTgTJYEqzexNFmOKqcm/6I++ACZVL4uS7e/JofdH0K4702zPGwf673/ZJHI
         Zu0/97pnNjNVmmOSycWuopi7rRBPTnrR4hG56e5ytsKcijW1uEAeq9ve3wdJSVwkeKdC
         GiVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=fX7cDmP1GaEvYcUYNtOF+CW/rKIkg9sOhz6sIV7l6K8=;
        fh=dRz2DTPEOSEcWUC+thW39356s3H4YB4rCKVU6Kb8eCQ=;
        b=C/GP6y6rW1jPmPa2d6Nh2+hGqnJ+u5crvF9k5mNNjehbJxDCV6RK84zE3FVMq5VDdC
         aMbpb8Qmv5DwxQc2liv/tZUxOTSvdsh2A8mN9lhCVIL344Gw4FVvTS1eKsi/nR1eos4t
         fsdSQ257tDDM0K2S+LK9j1mw2N/1GQO8IFnLgc3l0lkreAEIryiP8oqfXK0t3B7+64NI
         PddwQWYqW9WcK4f/ZEEy7eTJJlyFKS/Xni0BONmrHfvhcP2lLW/XFQUzMvuGaz0w3F2p
         TTO/CG5P9DttotXl1/SiRUa2YbnHkZE6yZooNiL2pBHWt6eVk/7DQ1S5kt98XZeXxx+m
         1paw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WGt9KBeH;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="RnNG/pQ0";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227610; x=1761832410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fX7cDmP1GaEvYcUYNtOF+CW/rKIkg9sOhz6sIV7l6K8=;
        b=rLGjcO8VNhEKV6UEf2MOY29kWenNxmg5ZBE9+Pi0nEtL2vu3E4rcN24qpjZZDRKfqu
         Mb/jTUJG6EZyFkaEXGHQF9Qi23Qoh5wYWu2W4j90LaMbPeSO1NIsOXjAI4+ytJiD/6kg
         Rm/B2SdUSzXlS7IWzStyFO137Piu83TKW0IhJEq0PBZJ9dFIojYNGH3/0j1tWCUYq3wu
         msMr7KtFAUB4iCySsu3b3ogN2vHvgTuaMiDQA2PMlELgSONPX0fVBEAsZycxAMzqw5CB
         DL+l/LBnmv1M77BYJp+ctiLFxtZGutYWw4emnAj9QjNdo5IB9Ap8/UPIATasvs6mTQUR
         PvDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227610; x=1761832410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fX7cDmP1GaEvYcUYNtOF+CW/rKIkg9sOhz6sIV7l6K8=;
        b=evuYkV571TABpG28eQtsYz8lEICo3cKsZ1bHuM2fIlJzhsVPhk+CyQgDMTIwEvSMFB
         dol0xtHOYHyNt7xGxK/6zN0EqaBKSOX+/9mwBKNjdkjhH5rX2NV+eKaRhqDoLAM6y/dF
         qCLY2LTuUykodP9MpmYTF3ylgdE2pLXCHwKLkDcgWp5//jDhKlN9lalkmVokWIUtx0Tl
         XUtBA3NWprUCvkniWXMe6vov+YgCRf5zePLL4er5iylqIBhZ4EboyS0qB/rjw5YkZ0/B
         go++ILlJf2sqtVwgVp+3NpC0Oi4J10jQ9FmEDubgC/aY7F8y2LYyciqdlYJflq8g0eSI
         cR4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHEzkRcrew9C4EwPev1S8SyD8hxQJV3m80nXWp2x0boishcUFgxdN4+lPvLsLWQPHWOH0KHA==@lfdr.de
X-Gm-Message-State: AOJu0YxBlfSwxFdWXt6R3SQzKbhBhM7MAURLOedRxi1OjSq5bR2Z4NKa
	lnrhSwjWGvCugAIjxg2ujgoNI8SxXK0ucIP3rs244AUn5ucR6y/nNrKR
X-Google-Smtp-Source: AGHT+IEOLcsDsdznkNNEvY+Gvg1pWASKfweZRAuEMPukzJDKWo4qP/ihR/ie5ZW7FNWUCUKAVs7bqg==
X-Received: by 2002:a05:600c:450c:b0:46e:38cc:d3e2 with SMTP id 5b1f17b1804b1-47117906a23mr190330165e9.22.1761227609821;
        Thu, 23 Oct 2025 06:53:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4R8IUbxKGt7+tU+NRly68wQNJsMn7ip4/2qh8mEZNl1w=="
Received: by 2002:a05:600c:1c87:b0:471:75:502f with SMTP id
 5b1f17b1804b1-475caa4c946ls4881635e9.2.-pod-prod-07-eu; Thu, 23 Oct 2025
 06:53:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTde42tUsZd/CM3ZMwS9fwV86ayfZW2XSU6KA2bQum3ukvA4bCDciuY6OAobwCXOWsj9NdYqzO/Fo=@googlegroups.com
X-Received: by 2002:a5d:5d81:0:b0:429:58f:400 with SMTP id ffacd0b85a97d-429058f0432mr2274703f8f.50.1761227607327;
        Thu, 23 Oct 2025 06:53:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227607; cv=none;
        d=google.com; s=arc-20240605;
        b=fIqkSrYy2IIazl3KAS8YwPzW4S1sML/eAgfivXNpu6mDsb3LhepbbE7ZPTR4Y6DHb7
         jp44FnLJfaw9aEfOaxeq/5S1DB92ZHE5MpGZFSnabCpk5XJWunf8C6Si15qaR+eILTrv
         CZ4NR1HbH6u84DvEfjaZ12eCtcvjI4GvMY4q+ACt0bci/ZCrp1dWJh6mbVZZ/7puKMcn
         7b/msvTTd3fzxX3PeJ52Z5bVsBga7Xx3H/T5+jrVxxB2yLSvGC723BEpovOxDpvScI4w
         xtnTfC6t3iGhtzwJIOXlRSWkOL/BGQenlbTGfzhZsmUmua9QjHtMC94FKDJnUdSjv0PC
         0OEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=TM6deDozNl3p401cZo7KYCMKkhM0vweS25W/XL8gDI0=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=lpK3YMj7+uHUdravXw8zq87czdVTxvj8H4pF+nJs4/lqo/LdPyJ9IAuXCbjrRNw2h1
         VzfqzyWDneK0IUXCKKufeaojWsMvwEUvlyFmUQV5Oyj3rlj2G+sS5hkLWj02RLM75cIc
         tu7p1OXY/MwYjYzJGR00FqQFDxGai5oJcmvov+Oxn3MY0xhHSTWbYW3gfhVO5BGQ9e9R
         ChtH+I0FxDkFDhWpdwjnHVKsfwaXVrzgkiEGQxf6hHGtlv2NvqL/0dKJpWpaslO3EuIP
         PgwBunZMmqWsbbQ4hikOOYwm/kLwKS9xyowt+XzFibFw+ycFfpJLYwG897kuyDKsKyDx
         XfLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WGt9KBeH;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="RnNG/pQ0";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42989564517si43000f8f.0.2025.10.23.06.53.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 83BEC211A7;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DBA9A13B07;
	Thu, 23 Oct 2025 13:52:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id mHRZNTUz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:53 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:31 +0200
Subject: [PATCH RFC 09/19] slab: add optimized sheaf refill from partial
 list
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-9-6ffa2c9941c0@suse.cz>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spam-Level: 
X-Spamd-Result: default: False [-8.30 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	ARC_NA(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=WGt9KBeH;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b="RnNG/pQ0";       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

At this point we have sheaves enabled for all caches, but their refill
is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
slabs - now a redundant caching layer that we are about to remove.

The refill will thus be done from slabs on the node partial list.
Introduce new functions that can do that in an optimized way as it's
easier than modifying the __kmem_cache_alloc_bulk() call chain.

Extend struct partial_context so it can return a list of slabs from the
partial list with the sum of free objects in them within the requested
min and max.

Introduce get_partial_node_bulk() that removes the slabs from freelist
and returns them in the list.

Introduce get_freelist_nofreeze() which grabs the freelist without
freezing the slab.

Introduce __refill_objects() that uses the functions above to fill an
array of objects. It has to handle the possibility that the slabs will
contain more objects that were requested, due to concurrent freeing of
objects to those slabs. When no more slabs on partial lists are
available, it will allocate new slabs.

Finally, switch refill_sheaf() to use __refill_objects().

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 235 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 230 insertions(+), 5 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index a84027fbca78..e2b052657d11 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -246,6 +246,9 @@ struct partial_context {
 	gfp_t flags;
 	unsigned int orig_size;
 	void *object;
+	unsigned int min_objects;
+	unsigned int max_objects;
+	struct list_head slabs;
 };
 
 static inline bool kmem_cache_debug(struct kmem_cache *s)
@@ -2633,9 +2636,9 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
 	stat(s, SHEAF_FREE);
 }
 
-static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
-				   size_t size, void **p);
-
+static unsigned int
+__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		 unsigned int max);
 
 static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 			 gfp_t gfp)
@@ -2646,8 +2649,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 	if (!to_fill)
 		return 0;
 
-	filled = __kmem_cache_alloc_bulk(s, gfp, to_fill,
-					 &sheaf->objects[sheaf->size]);
+	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
+			to_fill, to_fill);
 
 	sheaf->size += filled;
 
@@ -3508,6 +3511,69 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
 #endif
 static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
 
+static bool get_partial_node_bulk(struct kmem_cache *s,
+				  struct kmem_cache_node *n,
+				  struct partial_context *pc)
+{
+	struct slab *slab, *slab2;
+	unsigned int total_free = 0;
+	unsigned long flags;
+
+	/*
+	 * Racy check. If we mistakenly see no partial slabs then we
+	 * just allocate an empty slab. If we mistakenly try to get a
+	 * partial slab and there is none available then get_partial()
+	 * will return NULL.
+	 */
+	if (!n || !n->nr_partial)
+		return false;
+
+	INIT_LIST_HEAD(&pc->slabs);
+
+	if (gfpflags_allow_spinning(pc->flags))
+		spin_lock_irqsave(&n->list_lock, flags);
+	else if (!spin_trylock_irqsave(&n->list_lock, flags))
+		return false;
+
+	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
+		struct slab slab_counters;
+		unsigned int slab_free;
+
+		if (!pfmemalloc_match(slab, pc->flags))
+			continue;
+
+		/*
+		 * due to atomic updates done by a racing free we should not
+		 * read garbage here, but do a sanity check anyway
+		 *
+		 * slab_free is a lower bound due to subsequent concurrent
+		 * freeing, the caller might get more objects than requested and
+		 * must deal with it
+		 */
+		slab_counters.counters = data_race(READ_ONCE(slab->counters));
+		slab_free = slab_counters.objects - slab_counters.inuse;
+
+		if (unlikely(slab_free > oo_objects(s->oo)))
+			continue;
+
+		/* we have already min and this would get us over the max */
+		if (total_free >= pc->min_objects
+		    && total_free + slab_free > pc->max_objects)
+			continue;
+
+		remove_partial(n, slab);
+
+		list_add(&slab->slab_list, &pc->slabs);
+
+		total_free += slab_free;
+		if (total_free >= pc->max_objects)
+			break;
+	}
+
+	spin_unlock_irqrestore(&n->list_lock, flags);
+	return total_free > 0;
+}
+
 /*
  * Try to allocate a partial slab from a specific node.
  */
@@ -4436,6 +4502,38 @@ static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
 	return freelist;
 }
 
+/*
+ * Get the slab's freelist and do not freeze it.
+ *
+ * Assumes the slab is isolated from node partial list and not frozen.
+ *
+ * Assumes this is performed only for caches without debugging so we
+ * don't need to worry about adding the slab to the full list
+ */
+static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct slab *slab)
+{
+	struct slab new;
+	unsigned long counters;
+	void *freelist;
+
+	do {
+		freelist = slab->freelist;
+		counters = slab->counters;
+
+		new.counters = counters;
+		VM_BUG_ON(new.frozen);
+
+		new.inuse = slab->objects;
+		new.frozen = 0;
+
+	} while (!slab_update_freelist(s, slab,
+		freelist, counters,
+		NULL, new.counters,
+		"get_freelist_nofreeze"));
+
+	return freelist;
+}
+
 /*
  * Freeze the partial slab and return the pointer to the freelist.
  */
@@ -5373,6 +5471,9 @@ static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
 	return ret;
 }
 
+static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
+				   size_t size, void **p);
+
 /*
  * returns a sheaf that has at least the requested size
  * when prefilling is needed, do so with given gfp flags
@@ -7409,6 +7510,130 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 }
 EXPORT_SYMBOL(kmem_cache_free_bulk);
 
+static unsigned int
+__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		 unsigned int max)
+{
+	struct slab *slab, *slab2;
+	struct partial_context pc;
+	unsigned int refilled = 0;
+	unsigned long flags;
+	void *object;
+	int node;
+
+	pc.flags = gfp;
+	pc.min_objects = min;
+	pc.max_objects = max;
+
+	node = numa_mem_id();
+
+	/* TODO: consider also other nodes? */
+	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
+		goto new_slab;
+
+	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
+
+		list_del(&slab->slab_list);
+
+		object = get_freelist_nofreeze(s, slab);
+
+		while (object && refilled < max) {
+			p[refilled] = object;
+			object = get_freepointer(s, object);
+			maybe_wipe_obj_freeptr(s, p[refilled]);
+
+			refilled++;
+		}
+
+		/*
+		 * Freelist had more objects than we can accomodate, we need to
+		 * free them back. We can treat it like a detached freelist, just
+		 * need to find the tail object.
+		 */
+		if (unlikely(object)) {
+			void *head = object;
+			void *tail;
+			int cnt = 0;
+
+			do {
+				tail = object;
+				cnt++;
+				object = get_freepointer(s, object);
+			} while (object);
+			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
+		}
+
+		if (refilled >= max)
+			break;
+	}
+
+	if (unlikely(!list_empty(&pc.slabs))) {
+		struct kmem_cache_node *n = get_node(s, node);
+
+		spin_lock_irqsave(&n->list_lock, flags);
+
+		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
+
+			if (unlikely(!slab->inuse && n->nr_partial >= s->min_partial))
+				continue;
+
+			list_del(&slab->slab_list);
+			add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		}
+
+		spin_unlock_irqrestore(&n->list_lock, flags);
+
+		/* any slabs left are completely free and for discard */
+		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
+
+			list_del(&slab->slab_list);
+			discard_slab(s, slab);
+		}
+	}
+
+
+	if (likely(refilled >= min))
+		goto out;
+
+new_slab:
+
+	slab = new_slab(s, pc.flags, node);
+	if (!slab)
+		goto out;
+
+	stat(s, ALLOC_SLAB);
+	inc_slabs_node(s, slab_nid(slab), slab->objects);
+
+	/*
+	 * TODO: possible optimization - if we know we will consume the whole
+	 * slab we might skip creating the freelist?
+	 */
+	object = slab->freelist;
+	while (object && refilled < max) {
+		p[refilled] = object;
+		object = get_freepointer(s, object);
+		maybe_wipe_obj_freeptr(s, p[refilled]);
+
+		slab->inuse++;
+		refilled++;
+	}
+	slab->freelist = object;
+
+	if (slab->freelist) {
+		struct kmem_cache_node *n = get_node(s, slab_nid(slab));
+
+		spin_lock_irqsave(&n->list_lock, flags);
+		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		spin_unlock_irqrestore(&n->list_lock, flags);
+	}
+
+	if (refilled < min)
+		goto new_slab;
+out:
+
+	return refilled;
+}
+
 static inline
 int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			    void **p)

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-9-6ffa2c9941c0%40suse.cz.
