Return-Path: <kasan-dev+bncBDXYDPH3S4OBBVHG5DDQMGQEFFQOPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC18CC018F7
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:26 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id a640c23a62f3a-b6d5363df93sf64213766b.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227605; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mp8aE41Vxto44rDs6SH1Zun2aKzlUlgloZGe5bOlpShBYQKhbfqp08ViGfgSHKjd6G
         LXkQqvaWsshjm5Ks5QCC9fFAhTyoy3r43Z+m+sqm4kOXw8kiZK/n609OM6zCfjKPKxlj
         X6SZs31y1Y+WmpXb1kHSaHcPfxxoLg2sh4SAylzRqgqv14umN5qB9pdacBvTNr0vuovm
         aNDh52iaULk6HST22T3wZo9hH5bUc5HsZbxl8+oM30HSTgoKx/l9nVroHZ5VDDB9Oii7
         GALzzlScSU43/4k17WFYNyiDI79J3ygHt5tC5i+fURiYdzOskI0b+H0ViLLvjKUuttfw
         wCsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=4XcRJh9X/IXNiJnYm8IxAUsNRyKe9l0p5vl0hlVfkbQ=;
        fh=/MsBBBqLKiAtAeu/GzgbLTnrkWNMFsr04Gn43STxlKk=;
        b=aGahdDuPQesMxor4RAGbJdbXUQZkPoxT6cmWFd018XFXnB3fBqhx4Vx+9sNot5xBs5
         QT6gy04943l+hCb2+srhlHh7+lPsWMypRCULOREdEKffDtcEiKG7OEDtaCd/oA8vdr4u
         lmCuSGeLK4vRCVx4t2UTxLDDVLw8X8qDchNlXxoGMudTU/MZXzAZsLk7u/8wgIwVgwrX
         4/zIdEJFQcI3lgSXpCDZzRdianS7UrlGaW7zeE0PSSG1pZ2sTYlAouyhJQTLohiu7TLW
         H6UatYBNrY85GdiXeqUF5QhtnN64rDDrSyme4Yn/edDVySUH7pKiEoXbv8ovHA44S5oB
         ceVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227605; x=1761832405; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4XcRJh9X/IXNiJnYm8IxAUsNRyKe9l0p5vl0hlVfkbQ=;
        b=Dl4oCDKCfj2+n0DIEpRt6kOUC9zjODuCxpsBX2eFWtEoYSW1RaGq+RI9gXtXQKypcP
         NRet+Yu0ElX0jy7WLHgdgo9oFnyAspGwSxxqOJmwkTJGNhQce9682JLO8GXdwhxOHWku
         wNuNYNYwbIZEx3fhxKItKkkYLjSdxDmVagOFE7kIhhgsZbXdU5wI42PK8rNgJw/v7YxR
         JuRh3Qce7t0v3MxNP3g6K+e/WlDD+5W7jDgkyoCnBubNA362tRliTvVPet241N6a9fY9
         U2f7SfeX++DAGeT9DwPMqZrcOC3X7qmbIwOzjC7U7wb9d0bvUu/xHyww+Ppf8DteGeiu
         tXvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227605; x=1761832405;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4XcRJh9X/IXNiJnYm8IxAUsNRyKe9l0p5vl0hlVfkbQ=;
        b=DDrG4ebFTIp0zrr6CgUdHQLjaalu2zZzjZ1/Lq+WjmpI+bqMbuk4yHwR2MDtF7i8VB
         ZOuci3E+AHFBpUCJtIJbNk7tePHJPc/u0pTRkqpoiTTYId3nOkg7BrHLg1J/hPbRn5Q0
         Qmo3NuQW8BdHKJLAprXG0RghCUtA7fq8wRiHb4NUCxTNhhpJov7NgE2JxJ3zbmgI2mLf
         BdpAC1+O9ulu+5Palxje1740bA2fcq6I0s/c7R27rUQGDYE++H50jVepRGNUGpSBq+71
         2AJb+1LyvSCc7BfQQemUTxduv897rfW8Q5jvv+mC2/5u7miuNx6Puy8MqhIHGVAqHcwM
         Vfew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmOAKVn7JByaI2HFfb3LCGu75+BLhnTVzUg7Vk67/YQjUblJ4DPi7tpFyjDEC2VR8m1gzj1Q==@lfdr.de
X-Gm-Message-State: AOJu0YymFODf+E/rbxFsBfIPTZfRmmPzzmXwEqvLWeVHUhxsQctBcZxC
	w24X+lUDxzUC/pfgqqhvR3vDz77t6hAF17BMVDP6gqWWrqJpUnziAdcy
X-Google-Smtp-Source: AGHT+IHAGE4XGZvJH7S6Jrujt0G2jP8wxSkJWyXRCGw2D/I7mykjE0kbjLuroHTa6k1zjorth8qgKg==
X-Received: by 2002:a17:907:868c:b0:b6d:53e9:924f with SMTP id a640c23a62f3a-b6d53e99531mr320142966b.28.1761227605405;
        Thu, 23 Oct 2025 06:53:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+avvLVr63DXX/jbqVhWG2+su9cFJRWYifd/qWN8YVEeBA=="
Received: by 2002:a05:6402:52db:20b0:63b:eda4:74d0 with SMTP id
 4fb4d7f45d1cf-63e17e6bcdels993374a12.0.-pod-prod-00-eu-canary; Thu, 23 Oct
 2025 06:53:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUi8KlIclbi45TVZRcANIwGXxu1YxmqL94fptzGBjz9EagcrVsoq/7MNh1IVksQ++h3lb0g/ArSyn4=@googlegroups.com
X-Received: by 2002:a17:906:9f8c:b0:b60:6347:c5bc with SMTP id a640c23a62f3a-b6d38b71496mr614000366b.19.1761227602505;
        Thu, 23 Oct 2025 06:53:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227602; cv=none;
        d=google.com; s=arc-20240605;
        b=hEcgDnaw1uBI1KTwJhjEL0bHT8tAprqxJFeKaxAQEQS80u9MmcuilcE1+6GNBTp6//
         trTYS3ReynTf27D4GN9kVJpvHF4EhQCT+jtSsOpFPGNQricLKOmeTXUwDbOTLRlmim+q
         M0wZj2gzmSd01dGNT6Eb2XY2cWev8g9kxw8pmO2C3D2uslG7b8fZdpAS0XCFiMtSkIYA
         XgB+o+OmeuKl/TayS1b9syAEU2+8rzE7mlVc0WbOklnEtxk28Z0nHPUztPDuctXmC+Kf
         hgpGEZr/s/vCjD0rEpAkG9prItMSk+gkf4fyU9qg1Hw6MNNqG6kWQKmQ3f5QkYGr/IwW
         5P/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=FdsfcgWiQTdjWc+591nyXqsvmY3zD37UPWy6kdzpGKM=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=C5eC4i+Bbv9MuxGG6FxhbZvLl8+QLXz6abBFjdRuG9Eeg8dx+Su81RtBXRmOo0mIVr
         C/0K0ATdUr2iQeg5NO8PBrpUo343K4vRT/3XqucTv6OspOuMq8DiYMbxwNQaLMjmUTX8
         K+fwfZqxt2ecdBdp7zWdeVIwdjaIWjJRyO87UxcelF6BfjNKYVy155IK5+UpjK+37zHO
         3IRYb6PhRo6gKOUl+yZwUbnXvQa1ffAO1qZ6Pv2B8SHwpYrI+5ROJ8Q4MDjivZqMUEx7
         nYbOMMkKo2DoGAwluUHisADvNhUMK5GlNxoubDpEU3697fjQnfOp3kUk/RyRQtZV+EVh
         ZBUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b6d5f23f349si1702566b.1.2025.10.23.06.53.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id AFC0F1F7CE;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id BF88613B0F;
	Thu, 23 Oct 2025 13:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id oPB8LjYz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:54 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:39 +0200
Subject: [PATCH RFC 17/19] slab: refill sheaves from all nodes
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-17-6ffa2c9941c0@suse.cz>
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
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Queue-Id: AFC0F1F7CE
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
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

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 130 ++++++++++++++++++++++++++++++++++++++++++++++++--------------
 1 file changed, 102 insertions(+), 28 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d55afa9b277f..4e003493ba60 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2505,8 +2505,8 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
 }
 
 static unsigned int
-__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
-		 unsigned int max);
+refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+	       unsigned int max);
 
 static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 			 gfp_t gfp)
@@ -2517,8 +2517,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 	if (!to_fill)
 		return 0;
 
-	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
-			to_fill, to_fill);
+	filled = refill_objects(s, &sheaf->objects[sheaf->size], gfp, to_fill,
+				to_fill);
 
 	sheaf->size += filled;
 
@@ -6423,25 +6423,21 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
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
-	/* TODO: consider also other nodes? */
-	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
-		goto new_slab;
+	if (!get_partial_node_bulk(s, n, &pc))
+		return 0;
 
 	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
 
@@ -6480,8 +6476,6 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 	}
 
 	if (unlikely(!list_empty(&pc.slabs))) {
-		struct kmem_cache_node *n = get_node(s, node);
-
 		spin_lock_irqsave(&n->list_lock, flags);
 
 		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
@@ -6503,13 +6497,91 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
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
+	unsigned long flags;
+	struct slab *slab;
+	void *object;
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
 
@@ -6541,8 +6613,8 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 
 	if (refilled < min)
 		goto new_slab;
-out:
 
+out:
 	return refilled;
 }
 
@@ -6552,18 +6624,20 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
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

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-17-6ffa2c9941c0%40suse.cz.
