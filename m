Return-Path: <kasan-dev+bncBDXYDPH3S4OBBYVVZTFQMGQEPKRDB5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +JnqCuQac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBYVVZTFQMGQEPKRDB5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:24 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 14742712D9
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:24 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-65820bba158sf1607333a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151203; cv=pass;
        d=google.com; s=arc-20240605;
        b=gXBsokbfuePc+2l/FXPzPdY4NKmqIDef34unCB1WRlK7aD8adaJtZCzUEDtxkq6OmS
         Ft3UNsJBhaCYy7O+bbWeCSf8jVkc3PwgbXtoCvxLG7KNVkWgZ2qd7TYKHW738oMpfxX0
         pjhfH4LOYuef1/kbHATyP78PIEP5R2aVKElcjRGDgKW+ZF9AAfYvMwUn5cWBS+JuAe5T
         HaJnEA+Xbe8yRINW9C7J+M81ziDV1Cq5HhzotGR/tiP9erGy08GfkWbhsI2Wq8DJATM5
         ov+uKTPfRPsMZJNDmM9+75qo4fcH7mqFDhHlOwrVkl2KJoRcLMfU2B4uNS7FNSfG/cdp
         j/iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=gQeBm2PrOZAEcF5LPMCKDlp8edKRFtb1562Bum93N6o=;
        fh=yIjzLtSvyylDwYz3aBtdDlkwecBlFeVMbgWZO17cShg=;
        b=cdpAwEQqg+rRNECpsPuD4SGKlBR8Cu+yLWEX4nqCIPkbx/o19XvVTQp9w+QtXrkqRi
         G+S+lm6GDcJYkPfZcU1wxcvDwCy5QRZtI1b2qE7qZJUceZdQfSTe3Tt4TxxKaP24WNmx
         YQx4dpFuDzXd1GXq6a1YIBImS1mjjiCWldgl7pNKGm0MQIic8pavN6u8tqHAi+tdi5Kk
         UqOLI1xUH586vUJ1j6MPa6Qou8/uAW0kjrOQgDHfyEA49z9NAv6mdpACatLleacSTCz6
         J4vC4Gzlk2zmGx66mysJ+VXAbBF1bmSdulG7nmEhhr3IZS0iusk3/L6eqFMvvetg3TQZ
         U3PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151203; x=1769756003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gQeBm2PrOZAEcF5LPMCKDlp8edKRFtb1562Bum93N6o=;
        b=Lj9Ny2DWqFgbE9wBdFSBWITP9erof3niKMYl9To4yZjI4P2qxWuo2hApYPDJEueb8w
         Y/TKEECplFUWteho8sld/eVv2SLrFSGESvJLVy9/VHDWWWrho/tq/LHfuYCFuwIIh1Zk
         tyffpRrPi93Fgpu7zJIo0oC1vdb2eBaOj/sojlm5jln4e9jCOtDijL09FA7UHeTa3/gl
         J8QcWiWZQLxrxMGGlFYDepaA+vrBPPx6RNQgiGSmXA1p9eHPTexgM8aU1RuOt0AWVaMb
         dcsPKuIuQJb2I0tSxRW5rlUE/7fpxjHncPdeA2VfhZyITdeW1REfMrSi0stzMD0JC9oP
         F0dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151203; x=1769756003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gQeBm2PrOZAEcF5LPMCKDlp8edKRFtb1562Bum93N6o=;
        b=KEDlG1umULLCuGV+j9y43cQ3PJMMADs0iK9m/oMpRXa7+yqJMl8Dkgy6GwSdi+GzDg
         XzPybR8pXy9X8OX3+0YIPX0dXOlSmhhG16Ehxj79j8utKUAghtZ5/sf9XxLIT/zOQ/YP
         D9hNjb+gkY7EB6eJeKFQVXdORnQjk5FvdQ2EODf5t+lkziH5xUGgAWwl6nJubgn/ODLX
         UzO7qbMbihoj/0aQ82GAShlBfRcuYxt/8uDB6yz343BCRmp7DeHiKRyTnmwz3MoH7YDk
         1iz+DEkpy0I9N785AybonishJNyrQv4Klm8PMP1503o+AbP1nPm27NlaE8LrBFXGFj8F
         EnhA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWlNJFzJkoKahWiBCy9ByCG7GbqdaGHSYT1SUjWPXdoGMwq/p6R9RXS+a/wf7ixCSPY0jzQwQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMUrgf5l3oFRr1zR8Cey3pi8+/AqFfRkGz2zPd00dSe5GsUvlD
	7Q8KW++KyTmAow3ZwlfXG8+2d+Udcz/T7MRGxAXVmCXoBaZax9CF0bcV
X-Received: by 2002:a05:6402:1476:b0:658:1304:b697 with SMTP id 4fb4d7f45d1cf-6584874e5acmr1380399a12.7.1769151203364;
        Thu, 22 Jan 2026 22:53:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F6NyOpmMIcMZgSMQ+KJ1i2mdAOSYCcicaR3HamGDnznA=="
Received: by 2002:aa7:c387:0:b0:650:855d:592a with SMTP id 4fb4d7f45d1cf-65832d99336ls1376805a12.2.-pod-prod-07-eu;
 Thu, 22 Jan 2026 22:53:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXaR7gtJAahu3WF2+s2ayxwR85+GAsBoL4PKsXXky4Gk4FCOw6f+j/le0/f21mccL0IQoMrGbfe8ug=@googlegroups.com
X-Received: by 2002:a05:6402:3592:b0:658:2f40:1f83 with SMTP id 4fb4d7f45d1cf-6584874bf53mr1418193a12.2.1769151200751;
        Thu, 22 Jan 2026 22:53:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151200; cv=none;
        d=google.com; s=arc-20240605;
        b=bLvPMv9eD0uMgz4A9qsn1SD+w1GZeGol3/uqe0sFs36wJjdbVyxVjOSx6tjqeooCCH
         pf2C0dARGlpQjUsu2TqXjCuWMchC+Dsd505tUo4Ql3BQr12gZ3ovzRM25pUgNuERlvzu
         n9R0NQWW3CZ8DQZTMEK5RTVQQZPzgMkNquSYbxKhwBvOE9k2YvxMWoyjqRNiD/LAjHmM
         2TAwlCsuKv/KJ6JkUJ+Cz0g/oZZ2jAueHV5oFbWb2UJCJcSVXcXKRplS3riSroYk4ZV6
         1XPE62zfdUC4Xfg73n0mgV77Oyf//wJWf92rG2MaMqa+zeY9wyOXCvmsOOlQbFhCUnvk
         GAgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=WgW1lCL3OaN/eVgdYpNk+UjSSxD7uq3EZ952lKhFlrQ=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=VeQcLS8TQV2fEQvMTahvFq6nB1hv//ur2cmfkJj3ysoYLmvS4IBdOqmtt5gmWdhWwD
         F/OaMdSsqYI9beEx+FLMPZSoghS/csLNoCili/PYqQKVB/tnPcjUCc0MvfXz+QMJg8uG
         qtwxt3U+SQEBLpYL0A7elRXXEjEFYZbCZmDru2dQA9JeeZaiewb6MctMfx17wt2BET8P
         LJ7XSZNgLNQ9aIEhY1z2I9FJG61ZC1WGGWm/GWHzSE3QknK+9dELGPwpIhvixqIkecYP
         VZ0O5wmHBveQRb2hZbfWjtMdW8BVxQ0SSfgbud6hGDg9GzfhYUatJrjfYhTSvxAvQOfu
         OEfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6584b540209si35485a12.6.2026.01.22.22.53.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CF2D233773;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2A0A3139F1;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8Hz8CdYac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:48 +0100
Subject: [PATCH v4 10/22] slab: add optimized sheaf refill from partial
 list
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-10-041323d506f7@suse.cz>
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
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBYVVZTFQMGQEPKRDB5I];
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
	NEURAL_HAM(-0.00)[-0.977];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,mail-ed1-x539.google.com:helo,mail-ed1-x539.google.com:rdns]
X-Rspamd-Queue-Id: 14742712D9
X-Rspamd-Action: no action

At this point we have sheaves enabled for all caches, but their refill
is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
slabs - now a redundant caching layer that we are about to remove.

The refill will thus be done from slabs on the node partial list.
Introduce new functions that can do that in an optimized way as it's
easier than modifying the __kmem_cache_alloc_bulk() call chain.

Introduce struct partial_bulk_context, a variant of struct
partial_context that can return a list of slabs from the partial list
with the sum of free objects in them within the requested min and max.

Introduce get_partial_node_bulk() that removes the slabs from freelist
and returns them in the list. There is a racy read of slab->counters
so make sure the non-atomic write in __update_freelist_slow() is not
tearing.

Introduce get_freelist_nofreeze() which grabs the freelist without
freezing the slab.

Introduce alloc_from_new_slab() which can allocate multiple objects from
a newly allocated slab where we don't need to synchronize with freeing.
In some aspects it's similar to alloc_single_from_new_slab() but assumes
the cache is a non-debug one so it can avoid some actions. It supports
the allow_spin parameter, which we always set true here, but the
followup change will reuse the function in a context where it may be
false.

Introduce __refill_objects() that uses the functions above to fill an
array of objects. It has to handle the possibility that the slabs will
contain more objects that were requested, due to concurrent freeing of
objects to those slabs. When no more slabs on partial lists are
available, it will allocate new slabs. It is intended to be only used
in context where spinning is allowed, so add a WARN_ON_ONCE check there.

Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
only refilled from contexts that allow spinning, or even blocking.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 293 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
 1 file changed, 272 insertions(+), 21 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 22acc249f9c0..142a1099bbc1 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -248,6 +248,14 @@ struct partial_context {
 	void *object;
 };
 
+/* Structure holding parameters for get_partial_node_bulk() */
+struct partial_bulk_context {
+	gfp_t flags;
+	unsigned int min_objects;
+	unsigned int max_objects;
+	struct list_head slabs;
+};
+
 static inline bool kmem_cache_debug(struct kmem_cache *s)
 {
 	return kmem_cache_debug_flags(s, SLAB_DEBUG_FLAGS);
@@ -778,7 +786,8 @@ __update_freelist_slow(struct slab *slab, struct freelist_counters *old,
 	slab_lock(slab);
 	if (slab->freelist == old->freelist &&
 	    slab->counters == old->counters) {
-		slab->freelist = new->freelist;
+		/* prevent tearing for the read in get_partial_node_bulk() */
+		WRITE_ONCE(slab->freelist, new->freelist);
 		slab->counters = new->counters;
 		ret = true;
 	}
@@ -2638,9 +2647,9 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
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
@@ -2651,8 +2660,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
 	if (!to_fill)
 		return 0;
 
-	filled = __kmem_cache_alloc_bulk(s, gfp, to_fill,
-					 &sheaf->objects[sheaf->size]);
+	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
+			to_fill, to_fill);
 
 	sheaf->size += filled;
 
@@ -3518,6 +3527,57 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
 #endif
 static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
 
+static bool get_partial_node_bulk(struct kmem_cache *s,
+				  struct kmem_cache_node *n,
+				  struct partial_bulk_context *pc)
+{
+	struct slab *slab, *slab2;
+	unsigned int total_free = 0;
+	unsigned long flags;
+
+	/* Racy check to avoid taking the lock unnecessarily. */
+	if (!n || data_race(!n->nr_partial))
+		return false;
+
+	INIT_LIST_HEAD(&pc->slabs);
+
+	spin_lock_irqsave(&n->list_lock, flags);
+
+	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
+		struct freelist_counters flc;
+		unsigned int slab_free;
+
+		if (!pfmemalloc_match(slab, pc->flags))
+			continue;
+
+		/*
+		 * determine the number of free objects in the slab racily
+		 *
+		 * slab_free is a lower bound due to possible subsequent
+		 * concurrent freeing, so the caller may get more objects than
+		 * requested and must handle that
+		 */
+		flc.counters = data_race(READ_ONCE(slab->counters));
+		slab_free = flc.objects - flc.inuse;
+
+		/* we have already min and this would get us over the max */
+		if (total_free >= pc->min_objects
+		    && total_free + slab_free > pc->max_objects)
+			break;
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
@@ -4444,6 +4504,33 @@ static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
 	return old.freelist;
 }
 
+/*
+ * Get the slab's freelist and do not freeze it.
+ *
+ * Assumes the slab is isolated from node partial list and not frozen.
+ *
+ * Assumes this is performed only for caches without debugging so we
+ * don't need to worry about adding the slab to the full list.
+ */
+static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct slab *slab)
+{
+	struct freelist_counters old, new;
+
+	do {
+		old.freelist = slab->freelist;
+		old.counters = slab->counters;
+
+		new.freelist = NULL;
+		new.counters = old.counters;
+		VM_WARN_ON_ONCE(new.frozen);
+
+		new.inuse = old.objects;
+
+	} while (!slab_update_freelist(s, slab, &old, &new, "get_freelist_nofreeze"));
+
+	return old.freelist;
+}
+
 /*
  * Freeze the partial slab and return the pointer to the freelist.
  */
@@ -4467,6 +4554,72 @@ static inline void *freeze_slab(struct kmem_cache *s, struct slab *slab)
 	return old.freelist;
 }
 
+/*
+ * If the object has been wiped upon free, make sure it's fully initialized by
+ * zeroing out freelist pointer.
+ *
+ * Note that we also wipe custom freelist pointers.
+ */
+static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
+						   void *obj)
+{
+	if (unlikely(slab_want_init_on_free(s)) && obj &&
+	    !freeptr_outside_object(s))
+		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
+			0, sizeof(void *));
+}
+
+static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
+		void **p, unsigned int count, bool allow_spin)
+{
+	unsigned int allocated = 0;
+	struct kmem_cache_node *n;
+	bool needs_add_partial;
+	unsigned long flags;
+	void *object;
+
+	/*
+	 * Are we going to put the slab on the partial list?
+	 * Note slab->inuse is 0 on a new slab.
+	 */
+	needs_add_partial = (slab->objects > count);
+
+	if (!allow_spin && needs_add_partial) {
+
+		n = get_node(s, slab_nid(slab));
+
+		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
+			/* Unlucky, discard newly allocated slab */
+			defer_deactivate_slab(slab, NULL);
+			return 0;
+		}
+	}
+
+	object = slab->freelist;
+	while (object && allocated < count) {
+		p[allocated] = object;
+		object = get_freepointer(s, object);
+		maybe_wipe_obj_freeptr(s, p[allocated]);
+
+		slab->inuse++;
+		allocated++;
+	}
+	slab->freelist = object;
+
+	if (needs_add_partial) {
+
+		if (allow_spin) {
+			n = get_node(s, slab_nid(slab));
+			spin_lock_irqsave(&n->list_lock, flags);
+		}
+		add_partial(n, slab, DEACTIVATE_TO_HEAD);
+		spin_unlock_irqrestore(&n->list_lock, flags);
+	}
+
+	inc_slabs_node(s, slab_nid(slab), slab->objects);
+	return allocated;
+}
+
 /*
  * Slow path. The lockless freelist is empty or we need to perform
  * debugging duties.
@@ -4909,21 +5062,6 @@ static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 	return object;
 }
 
-/*
- * If the object has been wiped upon free, make sure it's fully initialized by
- * zeroing out freelist pointer.
- *
- * Note that we also wipe custom freelist pointers.
- */
-static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
-						   void *obj)
-{
-	if (unlikely(slab_want_init_on_free(s)) && obj &&
-	    !freeptr_outside_object(s))
-		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
-			0, sizeof(void *));
-}
-
 static __fastpath_inline
 struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s, gfp_t flags)
 {
@@ -5384,6 +5522,9 @@ static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
 	return ret;
 }
 
+static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
+				   size_t size, void **p);
+
 /*
  * returns a sheaf that has at least the requested size
  * when prefilling is needed, do so with given gfp flags
@@ -7484,6 +7625,116 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 }
 EXPORT_SYMBOL(kmem_cache_free_bulk);
 
+static unsigned int
+__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
+		 unsigned int max)
+{
+	struct partial_bulk_context pc;
+	struct slab *slab, *slab2;
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
+	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
+		return 0;
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
+		 * Freelist had more objects than we can accommodate, we need to
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
+
+	/*
+	 * TODO: possible optimization - if we know we will consume the whole
+	 * slab we might skip creating the freelist?
+	 */
+	refilled += alloc_from_new_slab(s, slab, p + refilled, max - refilled,
+					/* allow_spin = */ true);
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
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-10-041323d506f7%40suse.cz.
