Return-Path: <kasan-dev+bncBDXYDPH3S4OBB2FVZTFQMGQEBRPXNCQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 8AcHAeoac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB2FVZTFQMGQEBRPXNCQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:30 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B7F7B712F7
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:29 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-658188b600asf1990747a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151209; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uycn7h+R9TOG7B7ZKfLrsXNABL2T5ftE0/5jwB5F8ZC+V3m2q341K+xLg99XvVPrLa
         Rr05E4mZLxWoP1iFMTqWT4Rjpe5fqTE0vIqa2lFbTBJLck5dblByEZrg9lSvEpfdZagm
         ElwwWYEREj40zjofB3R+DSnxAXR59iivsHAhUoTQsX9DIb7nS0tgjnT6J+vJ+sfBNrGU
         dcJkTSt1nAzMgGoIqf43PrKDHy/cmaLSaNu+pEFFKotBwRelxdm3qdN3GtZhjb/9d+Cr
         V78Lx3MrIfqUD4HQkBrOyDPCs9yDUsMmdt/wkscLo0n7UNTrW29Qvzbis2sa+k0oIm7g
         /Y0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=Fi4pjEGFOIUO8fXKXrGOwoHmkRkA7kFxHIPl0jCzuxs=;
        fh=tX9WC8ox5ZBd5n/xcoKysp6mji3ElDz0OTAM/bMXrUE=;
        b=dYBtb5j2kCwIabVtMJQXBbKCCqkWz2aBMWWHgu60WoW45dWL/BKp9eT68fbvuXUc9p
         H7diT4Y3xuuB2pS9weeAVcflPpC6aMP+qyZi1EfEE4iX7zRFAuZnh6mjK15mX12Ngm5e
         ODLiGeAPq5F/pmTvlVPUl0Bt9900s275H9WogY9VNa5WI9SZ8Eb4MFxNXovquZEmv+7g
         1kDh8q28qlisA8xhb4ihvqY7p5D4K5GPMNOBuYhCAW7uXHY8UMJbDUFghqz1tbIhCE/X
         x0ltArt+r6autnwlVfrwLY0Jb+b3o2b46XuHVqauk2dAmcruPAjdIZ2R/uKIBQs95UeE
         TMSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151209; x=1769756009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fi4pjEGFOIUO8fXKXrGOwoHmkRkA7kFxHIPl0jCzuxs=;
        b=m6CB1Tn6i3cRaOFLsnU5acbT780F4FwX3XQKB5bHtiQwj4lTjs/aL/PTHEdZDLZWnM
         vtn1GX43rZfauscG+hfjge4+0ABF813Cj2b60g5NQquwqh1TTJ7jp6s/X1/p2Lbt06fx
         K4NyEHlSgCuyF8qhnOrBZm1O3ufwA6++FYqngto04FCMo6pFnSxwh2MWBm1rUIySmF4e
         +XQ6csIfa2uVr1pDhFlToB/B01TOwSns1hgv0YUKG20s688gvAOjUveE5rPCTlxsx7NW
         t6VL2QjJnnEZh9FqoRBQA+ytNVSApFNz1PLem9ebKwkR9s6wanS9/kWPeiXphrw7P0w6
         avTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151209; x=1769756009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fi4pjEGFOIUO8fXKXrGOwoHmkRkA7kFxHIPl0jCzuxs=;
        b=huWAGHZ4W6Mrr/kyxG3RFD1/MBNyM4UWREe+kETVndnDRX86C4BL5Kan7B95gyudsi
         G50ag1J0q3YKPPJoc/bxFVdiUSsii1Nvy+3c+Y4PSyzjvBD0Mdl66MMBENm0nox773VZ
         7JRDYn+C4EX0JM4ZQLPDTxcuEUeSVWSRz0yyI0iCxXhvWMF+/3WzopydzItXZpUYK2dp
         Xun7bRn7QgUSEgA+swQ3zesHrvjceb/cdI3pppgMPLRLNQJlECZIP8hbvyrOKAuGboFJ
         phNd+Z1nxphgZz+CjMchwCKJMkaPMMxT4GqGHux3TZBjZ0jXgl9xaizKucRKNuLsbSnJ
         GL4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXqID/xsZQN6RkiY4IZxzol95f3qs68fDFUf+uskpuA92k9JxnNKKe9YkAY25ZrMuiSDucMQw==@lfdr.de
X-Gm-Message-State: AOJu0YxDotsqmk4da/FO8iZAB1USggvfkarjQ68RNyiGJnAi4GEjP/da
	rYX4uQ39g/WMg7Vf9qFKwJWTRa3NX6jMMT8DC8KvuITtQxbUSmyCrsY7
X-Received: by 2002:a05:6402:278f:b0:653:eb48:7e4d with SMTP id 4fb4d7f45d1cf-6584876feeemr1376731a12.15.1769151208976;
        Thu, 22 Jan 2026 22:53:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HVCgdW+7MDCKxk5AnzOUi44sMcTl27Eqhe83zwtxzv5Q=="
Received: by 2002:a05:6402:42c2:b0:64d:faf4:f73e with SMTP id
 4fb4d7f45d1cf-658329fa78bls1624542a12.0.-pod-prod-05-eu; Thu, 22 Jan 2026
 22:53:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUoeGgQW3j35LcD38kp0gBlt3U+gYGSYVYfnqgydIr6w2yKSaPMiIbTJakw2FZh1TZJG4xGiY8ylpE=@googlegroups.com
X-Received: by 2002:a05:6402:2713:b0:650:8a2c:43de with SMTP id 4fb4d7f45d1cf-658487cb113mr1207268a12.29.1769151206777;
        Thu, 22 Jan 2026 22:53:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151206; cv=none;
        d=google.com; s=arc-20240605;
        b=YRfKlCv0yXlavvIih9IlprYGKwWtH9c5aB+E0zBCiCH+Y4FMRj0PfcG6qpAkcdNmyg
         RtGG8agn3mF3C0rvyZvi7vb8zY72vjRtcYz3NtvaOq8IEleizd+T4AnO4+7wClAkMMYI
         z7QrxiN8krV5yYUguDoBwebJ/43KUJS0T/zzpt/dx1MSodoXZb74lqNWVhfZ2bc6L5Zf
         jVIM0E7wYsPYnt+PN/T+kTM61Ja0PPZIvhefMSqYYyA49CnBM6IMbRT2s12GzU1qjvBj
         7BsQS4cowMnRMUvKterMGa0O5OS8kI56Pbeeybyy6Fke6NvaeJLPcGUq8xYX6TDUliZP
         rhOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=Iq7UWdW4QXI0XgzbTe6sxpLmaSn9uxzUuTNcFry6wsI=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=NK3ZuTwaHfvB1Cd5OgKE7i9G/VThEuVeGR+3khmvBRMg1Nj7hAQfkbJda68MM0De4M
         wQb1ehMf15vpXlvm6QLOVeyZus3qDGdJTRCBuWOl1I7olRrPsC+dC88nI/V+MegxCZtu
         vzGVis8oHKu1LEdGIROkUiun14GoklMdwiDOLCiyqvclWjrENT4hIpJ29NFn0QWw21Il
         k6ccd4u1+se2REwekM38p7M42WerqxtNNTlqyC85bkoMHgpcFiu39ecqm1TGg1Awi7i6
         utl76YUGtJhM4E4aSFVq5ux0oeIln2W5Uv71WbjcY299+ir0EqeLrPuEPOLjRpvLjA/w
         1ehg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6584b526f12si25717a12.3.2026.01.22.22.53.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:26 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C79315BCD0;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9539D13A01;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id yBQnJNYac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:52 +0100
Subject: [PATCH v4 14/22] slab: remove defer_deactivate_slab()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-14-041323d506f7@suse.cz>
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
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB2FVZTFQMGQEBRPXNCQ];
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
	NEURAL_HAM(-0.00)[-0.975];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,oracle.com:email]
X-Rspamd-Queue-Id: B7F7B712F7
X-Rspamd-Action: no action

There are no more cpu slabs so we don't need their deferred
deactivation. The function is now only used from places where we
allocate a new slab but then can't spin on node list_lock to put it on
the partial list. Instead of the deferred action we can free it directly
via __free_slab(), we just need to tell it to use _nolock() freeing of
the underlying pages and take care of the accounting.

Since free_frozen_pages_nolock() variant does not yet exist for code
outside of the page allocator, create it as a trivial wrapper for
__free_frozen_pages(..., FPI_TRYLOCK).

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Reviewed-by: Hao Li <hao.li@linux.dev>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/internal.h   |  1 +
 mm/page_alloc.c |  5 +++++
 mm/slab.h       |  8 +-------
 mm/slub.c       | 58 +++++++++++++++++++++------------------------------------
 4 files changed, 28 insertions(+), 44 deletions(-)

diff --git a/mm/internal.h b/mm/internal.h
index e430da900430..1f44ccb4badf 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -846,6 +846,7 @@ static inline struct page *alloc_frozen_pages_noprof(gfp_t gfp, unsigned int ord
 struct page *alloc_frozen_pages_nolock_noprof(gfp_t gfp_flags, int nid, unsigned int order);
 #define alloc_frozen_pages_nolock(...) \
 	alloc_hooks(alloc_frozen_pages_nolock_noprof(__VA_ARGS__))
+void free_frozen_pages_nolock(struct page *page, unsigned int order);
 
 extern void zone_pcp_reset(struct zone *zone);
 extern void zone_pcp_disable(struct zone *zone);
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c380f063e8b7..0127e9d661ad 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2981,6 +2981,11 @@ void free_frozen_pages(struct page *page, unsigned int order)
 	__free_frozen_pages(page, order, FPI_NONE);
 }
 
+void free_frozen_pages_nolock(struct page *page, unsigned int order)
+{
+	__free_frozen_pages(page, order, FPI_TRYLOCK);
+}
+
 /*
  * Free a batch of folios
  */
diff --git a/mm/slab.h b/mm/slab.h
index 0fbe13bec864..37090a7dffb6 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -71,13 +71,7 @@ struct slab {
 	struct kmem_cache *slab_cache;
 	union {
 		struct {
-			union {
-				struct list_head slab_list;
-				struct { /* For deferred deactivate_slab() */
-					struct llist_node llnode;
-					void *flush_freelist;
-				};
-			};
+			struct list_head slab_list;
 			/* Double-word boundary */
 			struct freelist_counters;
 		};
diff --git a/mm/slub.c b/mm/slub.c
index a63a0eed2c55..82950c2bc26d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3262,7 +3262,7 @@ static struct slab *new_slab(struct kmem_cache *s, gfp_t flags, int node)
 		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
 }
 
-static void __free_slab(struct kmem_cache *s, struct slab *slab)
+static void __free_slab(struct kmem_cache *s, struct slab *slab, bool allow_spin)
 {
 	struct page *page = slab_page(slab);
 	int order = compound_order(page);
@@ -3273,14 +3273,26 @@ static void __free_slab(struct kmem_cache *s, struct slab *slab)
 	__ClearPageSlab(page);
 	mm_account_reclaimed_pages(pages);
 	unaccount_slab(slab, order, s);
-	free_frozen_pages(page, order);
+	if (allow_spin)
+		free_frozen_pages(page, order);
+	else
+		free_frozen_pages_nolock(page, order);
+}
+
+static void free_new_slab_nolock(struct kmem_cache *s, struct slab *slab)
+{
+	/*
+	 * Since it was just allocated, we can skip the actions in
+	 * discard_slab() and free_slab().
+	 */
+	__free_slab(s, slab, false);
 }
 
 static void rcu_free_slab(struct rcu_head *h)
 {
 	struct slab *slab = container_of(h, struct slab, rcu_head);
 
-	__free_slab(slab->slab_cache, slab);
+	__free_slab(slab->slab_cache, slab, true);
 }
 
 static void free_slab(struct kmem_cache *s, struct slab *slab)
@@ -3296,7 +3308,7 @@ static void free_slab(struct kmem_cache *s, struct slab *slab)
 	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		call_rcu(&slab->rcu_head, rcu_free_slab);
 	else
-		__free_slab(s, slab);
+		__free_slab(s, slab, true);
 }
 
 static void discard_slab(struct kmem_cache *s, struct slab *slab)
@@ -3389,8 +3401,6 @@ static void *alloc_single_from_partial(struct kmem_cache *s,
 	return object;
 }
 
-static void defer_deactivate_slab(struct slab *slab, void *flush_freelist);
-
 /*
  * Called only for kmem_cache_debug() caches to allocate from a freshly
  * allocated slab. Allocate a single object instead of whole freelist
@@ -3406,8 +3416,8 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
 	void *object;
 
 	if (!allow_spin && !spin_trylock_irqsave(&n->list_lock, flags)) {
-		/* Unlucky, discard newly allocated slab */
-		defer_deactivate_slab(slab, NULL);
+		/* Unlucky, discard newly allocated slab. */
+		free_new_slab_nolock(s, slab);
 		return NULL;
 	}
 
@@ -4279,7 +4289,7 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
 
 		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
 			/* Unlucky, discard newly allocated slab */
-			defer_deactivate_slab(slab, NULL);
+			free_new_slab_nolock(s, slab);
 			return 0;
 		}
 	}
@@ -6056,7 +6066,6 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 
 struct defer_free {
 	struct llist_head objects;
-	struct llist_head slabs;
 	struct irq_work work;
 };
 
@@ -6064,23 +6073,21 @@ static void free_deferred_objects(struct irq_work *work);
 
 static DEFINE_PER_CPU(struct defer_free, defer_free_objects) = {
 	.objects = LLIST_HEAD_INIT(objects),
-	.slabs = LLIST_HEAD_INIT(slabs),
 	.work = IRQ_WORK_INIT(free_deferred_objects),
 };
 
 /*
  * In PREEMPT_RT irq_work runs in per-cpu kthread, so it's safe
- * to take sleeping spin_locks from __slab_free() and deactivate_slab().
+ * to take sleeping spin_locks from __slab_free().
  * In !PREEMPT_RT irq_work will run after local_unlock_irqrestore().
  */
 static void free_deferred_objects(struct irq_work *work)
 {
 	struct defer_free *df = container_of(work, struct defer_free, work);
 	struct llist_head *objs = &df->objects;
-	struct llist_head *slabs = &df->slabs;
 	struct llist_node *llnode, *pos, *t;
 
-	if (llist_empty(objs) && llist_empty(slabs))
+	if (llist_empty(objs))
 		return;
 
 	llnode = llist_del_all(objs);
@@ -6104,16 +6111,6 @@ static void free_deferred_objects(struct irq_work *work)
 
 		__slab_free(s, slab, x, x, 1, _THIS_IP_);
 	}
-
-	llnode = llist_del_all(slabs);
-	llist_for_each_safe(pos, t, llnode) {
-		struct slab *slab = container_of(pos, struct slab, llnode);
-
-		if (slab->frozen)
-			deactivate_slab(slab->slab_cache, slab, slab->flush_freelist);
-		else
-			free_slab(slab->slab_cache, slab);
-	}
 }
 
 static void defer_free(struct kmem_cache *s, void *head)
@@ -6129,19 +6126,6 @@ static void defer_free(struct kmem_cache *s, void *head)
 		irq_work_queue(&df->work);
 }
 
-static void defer_deactivate_slab(struct slab *slab, void *flush_freelist)
-{
-	struct defer_free *df;
-
-	slab->flush_freelist = flush_freelist;
-
-	guard(preempt)();
-
-	df = this_cpu_ptr(&defer_free_objects);
-	if (llist_add(&slab->llnode, &df->slabs))
-		irq_work_queue(&df->work);
-}
-
 void defer_free_barrier(void)
 {
 	int cpu;

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-14-041323d506f7%40suse.cz.
