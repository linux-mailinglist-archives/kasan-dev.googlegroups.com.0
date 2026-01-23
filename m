Return-Path: <kasan-dev+bncBDXYDPH3S4OBB55VZTFQMGQEJJC6XBI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uDUnIvkac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB55VZTFQMGQEJJC6XBI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:45 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BE177135F
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:45 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-42fd46385c0sf1124012f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151224; cv=pass;
        d=google.com; s=arc-20240605;
        b=RNjdp6T0UYENdaUkjY9QU2jE/VPWZ2EEQSD+udm/aXKyBCVc8ZGp+Ih9Xf4zYiuy+p
         vw4tlkYC/PiaT4wM/RkAed2Q53pGM/Uz38szZjqOOf3l6ZmrSbo3ULXm7Mto6EmF2vms
         8vmjJQda7EWRSxBChJANzIwRNu9geHkjapphVLhC4+Skif/l+bAhgMqJKw4aYAoiUmZS
         BNt4qfhXNakkHC58nuIVXmq5g8mNncduxhBvIKOgItP0FjkYTAFpwm/yzXkefoT5EKXG
         4WTqhWYbvaTarfyBxJKhO+ZpX/JI/QNjXpNDMEqfgM6/Bl54mgRShvlwZYDCkloVVZp2
         Jnyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=sBT+s+fmPTUx3mjW8NE+JfqPk5dE59QGIcxiSlaOlJs=;
        fh=gzbN/4IWTTeTcFakYAighdBO7G+bE9saE55eXUUrMs8=;
        b=XXFNYeFjto3ZYmagwyeZsSduxnzW1VxzdRY3ZHZLuT3Z5FCOKey+ffBC0BhksWvulr
         Sv6XavTCxlDx2uqxbrZnsd1Cpfy0+6Fl40zNvYwVQbJY167WknXuuQS4yNPbFvOsKhad
         aRVIFOnuoLuCpBiZjciQwrS2ZV3EnSBY/ETIBzvqzIla1z/Zg0M3t5JV2zPZ+gZJgYXV
         9yiYIUtNmd6iAEw/3w1NA/qWvqgb/3d1Sm2i4LQMqsPKXHQxUe6RsqsGe+7AULiu36Ll
         leIZayeedJyHpAG+QrxXVcSGP52RRaL1vDpK1sYoQwTIa78/cjNUgXVv4W9tLd29jUeR
         VKmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151224; x=1769756024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sBT+s+fmPTUx3mjW8NE+JfqPk5dE59QGIcxiSlaOlJs=;
        b=vT2Ez4CKWot6d4Dd0x9phaTIVfJpcBBOB6D8FmoRc4a8NQ3KA+ePSkeU4x+Y8LB5z6
         fGEHnwXej8ZJA+Ex8JhXdTgMMPL9vUOqcVbn56dRlloybcrHOkVkULxa+Z28cDc5Oxul
         7bsweRm1euAsVhMln7FrCcfYSiD4btJMqGYeNc4k7GuIuH09clvsOxhHBqTKzLBD/rpe
         dUqiU+BUMxJDI6fCaZW9cu6Yul+ON+iWZk/yHkLJJGJziRttC1ZmctqWSe+kl1uwhI2H
         CBVdtSRBSRFEvVzmld71kh80fxF4PwR1QabIzLc9MLPRHQEMiS0Ppx6zItbewgVk3S3E
         Ox9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151224; x=1769756024;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sBT+s+fmPTUx3mjW8NE+JfqPk5dE59QGIcxiSlaOlJs=;
        b=JUIZqNgwBIyxrpIAqL4lFGj38/o0R0wyl6x62LUywrPjOtPFyCuqBvFQ/7XfKPINx1
         fnoWOsxzD4iWJdmdbUgXUrqGVOv4veccDv+kSnD9rNeZfPCCXvc7uZruTENEdciGu3UO
         va9UaAmE7K54UCsk3LTfEDv2ISkELOAiMXA4M7xVqfNr5CRGbH1ebUuxBBDj7zRxsB0+
         PVFF83pEzROBuqB6MVT0bYvM5cc2f3Sg/M5p119J1Ye+SQ68K8KFcTQASrVKpb8Or5VR
         6TMYPooQe+5/mN0DqrU6fj3I+4WRGrHuhrDRkV0QIDu7XyN3g18dnLFBztr8ezgWsCmR
         VIow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGEA5UtZEJ0oV+vuA22AKaUw2cSVO+6FXuZwAMhy6qJmLxwbh0RbAzQ5chtmq0wpmSfVAogw==@lfdr.de
X-Gm-Message-State: AOJu0YxBkKqX+UB6gTGxLKyO/5NtWbOsVU+B9PPwCrlTXq6+xLyHVcqF
	MqQl/BaS/yr5L5ztKIFAwkWCyCQBDSX9cOQ+yqeE1VdO7jLTCqt8xD6l
X-Received: by 2002:a5d:5d07:0:b0:42b:3dfb:644c with SMTP id ffacd0b85a97d-435b92f82a6mr482971f8f.10.1769151224374;
        Thu, 22 Jan 2026 22:53:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F9tPhECDKeQgCqO6DOv/mvvtqhFyROqhiNNuWuXh2UUQ=="
Received: by 2002:a05:6000:1acc:b0:432:dd3f:7f78 with SMTP id
 ffacd0b85a97d-435a640f267ls1081191f8f.0.-pod-prod-01-eu; Thu, 22 Jan 2026
 22:53:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXiAAR+gcETBBi9Y1PsKLrTf47Kg1AWq3OsMC/6LMQvFhJgWv7cUUAjQlsvMctMatIiIRiSXlSBjS0=@googlegroups.com
X-Received: by 2002:a05:6000:2888:b0:432:8537:8592 with SMTP id ffacd0b85a97d-435b92f94afmr499090f8f.4.1769151222194;
        Thu, 22 Jan 2026 22:53:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151222; cv=none;
        d=google.com; s=arc-20240605;
        b=A2OxKXNO4Hz/c9DWHn7jQ9pukJJqb1/X8JSZCa4poOdWbyB9+29ysRpgFrTmPsPTuC
         DHB0X8qODi+2c0XunTcun66Aw7o2s5crjWwa/rJV/oHIzIH6I3n3ZejL1p2Rjq+ZJoG0
         ZRS8LiL9GWEXrF98hNG1qX8URVnJzBs/sSfp8/o7YltXojUnqWEzAdu0A7X2nVfUKo77
         dCLiWsPh6cOh93fTP+wCE6psniT9ap5/YO+RvGt3O4lgbAYFfCtqHjwj2B0JSVR/L0Re
         0KX1t6fEGch5eu1LN/cPoYo5inm3BXy2sUwubxzqt5kycTkXLvwMZcq+R0bfpbWrGQA5
         v+Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=WFAOzWfhPzGkFxwo51JGvuWwzN6El4GjSbI8LiKzML0=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=R5JuY+wiz6K6UrhQ15cuimkoDCK4jgJBk2IgR6++64xWiTPZK3ZYedWlH8u4HSkoYS
         FXV6+V3htsy3AaAYwfuWyJ377R93IfFJ7WIJdzYaL8Y6r6SunaRwazT2hTiJ+/vhHYf1
         MZOxfd6MRppZ52vyvIwrRUHSRozsJc4YttUl5RWowWVb/pj/7p2yJfdUXrKi7fZswEwm
         aRwYNCHr0uJQz4wYqoYasF2FQWbP29yy/wal5AOpMzT1GqCnDSeeqsbhBn75tdpJ7gqc
         JXpOmHww626H4AE87OkFwcZ3WH6nuW01SMa4PIF9FiIz4Kk7O7Bei61g5i9SDHmGjF/r
         lw7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435b1c06e32si34467f8f.3.2026.01.22.22.53.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2C50933779;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 065801395E;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id YJ9FAdcac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:11 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:56 +0100
Subject: [PATCH v4 18/22] slab: refill sheaves from all nodes
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-18-041323d506f7@suse.cz>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
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
X-Spam-Level: 
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB55VZTFQMGQEJJC6XBI];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.973];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,suse.cz:email]
X-Rspamd-Queue-Id: 4BE177135F
X-Rspamd-Action: no action

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
Reviewed-by: Hao Li <hao.li@linux.dev>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 137 ++++++++++++++++++++++++++++++++++++++++++++++++--------------
 1 file changed, 106 insertions(+), 31 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 1d135baf5e9e..540e3c641d1e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2512,8 +2512,8 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
 }
 
 static unsigned int
-__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
-		 unsigned int max);
+refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+	       unsigned int max);
 
 static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 			 gfp_t gfp)
@@ -2524,8 +2524,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 	if (!to_fill)
 		return 0;
 
-	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
-			to_fill, to_fill);
+	filled = refill_objects(s, &sheaf->objects[sheaf->size], gfp, to_fill,
+				to_fill);
 
 	sheaf->size += filled;
 
@@ -6550,29 +6550,22 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 EXPORT_SYMBOL(kmem_cache_free_bulk);
 
 static unsigned int
-__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
-		 unsigned int max)
+__refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		      unsigned int max, struct kmem_cache_node *n)
 {
 	struct partial_bulk_context pc;
 	struct slab *slab, *slab2;
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
@@ -6610,8 +6603,6 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 	}
 
 	if (unlikely(!list_empty(&pc.slabs))) {
-		struct kmem_cache_node *n = get_node(s, node);
-
 		spin_lock_irqsave(&n->list_lock, flags);
 
 		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
@@ -6633,13 +6624,92 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 		}
 	}
 
+	return refilled;
+}
 
-	if (likely(refilled >= min))
-		goto out;
+#ifdef CONFIG_NUMA
+static unsigned int
+__refill_objects_any(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		     unsigned int max)
+{
+	struct zonelist *zonelist;
+	struct zoneref *z;
+	struct zone *zone;
+	enum zone_type highest_zoneidx = gfp_zone(gfp);
+	unsigned int cpuset_mems_cookie;
+	unsigned int refilled = 0;
+
+	/* see get_from_any_partial() for the defrag ratio description */
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
+		     unsigned int max)
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
+					 max - refilled);
+	if (refilled >= min)
+		return refilled;
 
 new_slab:
 
-	slab = new_slab(s, pc.flags, node);
+	slab = new_slab(s, gfp, local_node);
 	if (!slab)
 		goto out;
 
@@ -6654,8 +6724,8 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 
 	if (refilled < min)
 		goto new_slab;
-out:
 
+out:
 	return refilled;
 }
 
@@ -6665,18 +6735,20 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
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
@@ -6687,7 +6759,10 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-18-041323d506f7%40suse.cz.
