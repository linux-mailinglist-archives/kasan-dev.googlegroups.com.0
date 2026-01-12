Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBNBSTFQMGQE5XOUNII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 45947D13904
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:26 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4775d8428e8sf53333295e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231045; cv=pass;
        d=google.com; s=arc-20240605;
        b=iRiTchrtAw8UHdLdp2Fxis+EpgaRhFtxMX3QqBmB9DD6sWYgPe8qOshKs7w6ZNzdsW
         2njzaImnUqIWobG1f504AgeBnBl6/7zCd40v0RQ029b8IbdhGTqkbM/dNyUGk3y4X6cj
         TFPxwVj6UUe5vHKPS7uMfcRjO0yi8HoXQcBLSBBfrMz9XBED3s1ghMoO+Q4dK8/4yKSN
         5OpAKpA95cAgER2J7RH7fpzEH2ABriDx2aw0ucbY+KGh5w6nQ73hMi5VAj89/lVSw0Py
         a0aNyFkgSgRAQgsw88GWBTLQTMh+YhnxrQN8tb28TvPqygbDA0oJz0X87kDbB+BcQYat
         /DtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=rdAvFg477TTSzYlCzNIX86cHMOAuTP9GH9JCvm70yDM=;
        fh=TbXNhMmVrFCDAb9eg0F5LnFqs8a5PzhZdg7lhVuNHCc=;
        b=FKC5wXsXVFpQR1ac+txlZVWUyK7RtqzQDW/huthdXeYW7RKV8yWQdfEiLmuBnvejL4
         W1b+D5Wro5j0KadW51XQ3aCm+XW8VIu3GW50X2LeN+3pGuJ4JQpbaWaqrBO1wn2oi4Zc
         jcPrsyDmnoF+gOIHYboPjG/6y5WH8KZBI9jNOO94xg4UngrVga9+UeExQijs3RQBGJDl
         oYO9FMz7VEzwDl/kG9cGi4ebrjZuZzFbZtQxP1dXPnWxQ0odoFcg0H7OxhOU/QURPu/H
         tZtt4/6T+4Xbcq2RxkqmgY3VVH2yom2CjKEpYdYIDipTDa4yYcmrIYMA5VySbKL+MVGN
         gMYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231045; x=1768835845; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rdAvFg477TTSzYlCzNIX86cHMOAuTP9GH9JCvm70yDM=;
        b=RwUpRT69WjbZlquWMmLm6x6y/11Ktv4OLF0SphjUZTemxDfgLk4a94LdgwjM5uZ3nE
         JD7IK9Hbvr7lm59B+BqE7cGmIHtSl6LGkLMC7Ik++jxFiJUr8HlWIfR4Z53xVXhsuNzr
         rVzNkfHNsJJgkX6vwjfimb4Mt01O39+sJ6lI7bhE6oiEyqVKj1mcyBsvly2rPu0hklHP
         FTZKABxlVWANxc/i3vS6JkntXAe/Da1P0sjrKAmpiUNlribdmOWIQqc8juaogkasU5X1
         QkKLNEB4npgJjuvmOqwLlZIrXlDJnXQnMy6vXj95RuWmz9Zo3B/KrLAui5fJWjtDTqs3
         0vaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231045; x=1768835845;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rdAvFg477TTSzYlCzNIX86cHMOAuTP9GH9JCvm70yDM=;
        b=DkS5Ti22l+dMig+FdSuYXboqhJTq6uRl20BKALxpE5rUUfn6bFUVhhGNaEQL+2usw0
         Yk2+kl4X1J/DW5MGkz7h69LtoDnpI9neY98XHs0iuIhc6zLXQd6kzPG3+JOfZSqQJiOI
         tX3e+7DHWysUyEpmfbSe8MbEGocclfXKHk+nFtcNhJtP7plYIx1zQrKXZzPuaRZPfGin
         JsUkOOARV01dT2WCJOyWeeGomLLBVs6d+00uqJT5ySAKSZXra9GkoZmmjO4IzM1dqEZm
         /6t+/LXT5u0sER0wedNVWEbjfs0+/npobxnUGzjw1CLoQLvPbAMDRe1adenDATt88AGd
         2g4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdzADfDOWL2ldGQMJJY5UZtt0Xos96rRaMWWMYhc43odbWOKv5Cnj7b9CgoZCu+KWLd2JiFQ==@lfdr.de
X-Gm-Message-State: AOJu0YyhTkwCLOfnmbHFccyy/q088FatYaCL6fysHU6FIMVzwoGGPsp3
	OxDHSvVy9I2vYsXilGov2tb8Pyg1dZdR5cnQajt+stGdNx3xWTojjhUL
X-Google-Smtp-Source: AGHT+IGKIrZ5SXNk+iliL4U2QDdUNFoEDHbUIu87vMNXx6m9TrOHn4ijfYVk9A/Adk4Lu9F6JJRJnw==
X-Received: by 2002:a05:600c:3556:b0:477:5af7:6fa with SMTP id 5b1f17b1804b1-47d84b3b52dmr216971505e9.32.1768231045516;
        Mon, 12 Jan 2026 07:17:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HU5nXwUZH17cfCwba9o1qXlD1v108LVG3zZaGmqfHVYg=="
Received: by 2002:a05:600c:c84:b0:47a:74d9:db with SMTP id 5b1f17b1804b1-47d7eb13fd7ls40963635e9.1.-pod-prod-02-eu;
 Mon, 12 Jan 2026 07:17:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVprH9Hyf/3/Lax97/Sq+2HyRCnuIHhsZyhRC68RKltQR91hC37nmZs03tXeiYuQdSMUnYHxIhpYak=@googlegroups.com
X-Received: by 2002:a05:600c:1d14:b0:477:7b16:5fb1 with SMTP id 5b1f17b1804b1-47d84b0a96emr210262765e9.7.1768231043132;
        Mon, 12 Jan 2026 07:17:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231043; cv=none;
        d=google.com; s=arc-20240605;
        b=lvzRq5RmbtBDv9zP5zNCIUXe06NarrwK+Rkl0BHVU9Dl5W5WuZAmy0ZBejzd5iGCnD
         2JG0ieyvEVTXQb1agmPrfQ+kjiZDJX6yHfpkB4h0xGfBB4y6WcCKtCEdGxHPppl2lNzV
         j0y+nJ36TSBLbOTbPfY2sktlDYXB9QwBYm5G+pkBC4EWCY3pHvmtljMF8sYQeh3qnlFt
         5QT4cLPgPWD8N4zGROZwD4REuHEgt3YXF8KPMvBOQPKseo4XanxaiiAuGwOkL3GkRYvF
         GeWYU4sq+4vouVYSJhsfvy+MwRhmuX/K82P/3hFHmBlzsBxyvJGMM884yAxLTB07YpS1
         jkJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=wYjYxR/+1reeFjJM9R0TPTSqWA+3lSDKQpt8R5DuILc=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=FHbvvTOnpDSs3OG2P2CkZdogsg7NPZacXc2MLzyniy9HdvQOOzdq1cbZDvBO5OGUcO
         x/cB4cYH3UjWw5MN35ae4FDcADfk3r/bO1nOLlJZ/JfA5McEZHX1psj5mDJ98vtC//jk
         pHOIupdcMvFrG+ujWhPJkROt8otN0vwzK20DBKfDBJAcQLRhsQ/W+FEUSNod34Zc0rLl
         6kXOvJT9BF6hqdtuOr6W8J0IV/7k4sIjJ+Nh/RSjwyQDDvqLnNXXpyIeTApUDR/5fvmD
         aXff1eFA/juXYGtiLg/KZv4YH9E2U3gZzkYTgagiqgI2u2pCUGjNBepzA1+aX7lgBGfk
         M7SA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47d865d356asi1026485e9.1.2026.01.12.07.17.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 3ECEE3369B;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2008E3EA65;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id uEqHB2sQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:59 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:10 +0100
Subject: [PATCH RFC v2 16/20] slab: refill sheaves from all nodes
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-16-98225cfb50cf@suse.cz>
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
X-Rspamd-Queue-Id: 3ECEE3369B
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 137 ++++++++++++++++++++++++++++++++++++++++++++++++--------------
 1 file changed, 106 insertions(+), 31 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 088b4f6f81fa..602674d56ae6 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2506,8 +2506,8 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
 }
 
 static unsigned int
-__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
-		 unsigned int max);
+refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+	       unsigned int max);
 
 static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 			 gfp_t gfp)
@@ -2518,8 +2518,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 	if (!to_fill)
 		return 0;
 
-	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
-			to_fill, to_fill);
+	filled = refill_objects(s, &sheaf->objects[sheaf->size], gfp, to_fill,
+				to_fill);
 
 	sheaf->size += filled;
 
@@ -6515,29 +6515,22 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
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
@@ -6575,8 +6568,6 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 	}
 
 	if (unlikely(!list_empty(&pc.slabs))) {
-		struct kmem_cache_node *n = get_node(s, node);
-
 		spin_lock_irqsave(&n->list_lock, flags);
 
 		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
@@ -6598,13 +6589,92 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
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
 
@@ -6620,8 +6690,8 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 
 	if (refilled < min)
 		goto new_slab;
-out:
 
+out:
 	return refilled;
 }
 
@@ -6631,18 +6701,20 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
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
@@ -6653,7 +6725,10 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-16-98225cfb50cf%40suse.cz.
