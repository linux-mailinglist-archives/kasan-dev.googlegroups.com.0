Return-Path: <kasan-dev+bncBDXYDPH3S4OBB7E3VHFQMGQEY3JJT4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AA3ED32C78
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:41:02 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b7e9f0af5sf2784872e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:41:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574461; cv=pass;
        d=google.com; s=arc-20240605;
        b=aPLq5UG/KZpM17ZT5ww3f3561zJrs0e++jZ5zHWl5vAex2tVqKbI5G8ce1pJYi5ooD
         2GfsEgHeXNcNf/OOidOFqgLhq24sUzavLXshKRiUt1b6hb/PGv3H2+Dg8ERkdorJSZWn
         aUfKZ8AGqEwYvdsfYdiDO5ucCDYlweJpXQeGlr3Vo/mWzRu3EsRwPQ/cuErFC3C71gBG
         A/+4aw2av07aNSg6eK8MjDxFknN+8jY8HVUA0rSQ29KliS2c1FO47DUA1hdffhy/v53j
         wYdK7+reo+ff0RpcvKuQ3a2l9Gpw/aQq5RNJJvJviGl78O3K1LNWJdS2uMmwNJZgghNT
         iTPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=iSxI5HNcyCYQWTp6HpX69Dp+meIoDFpJ6jOIrm61Jko=;
        fh=62g33ymFZ5fHh5hEgx8jdSADBPaQuo+658yLV+hAoc4=;
        b=XKiafyOKBal5rZPd6fJcUeOh+fnBkcTyK+vX3uRmho7SpxIdx8NKdfhFU/fRW3jMpM
         S2pTkS+tZ/LitZj5cLUP9m4XDhuYundaYXV/fWTSe5zA4j7TDQAfoPiHY9qQb0sidNrv
         VDCw3u2WBtXpikbUYsOkHUealw148QSieDU/aWfTsovrZ+YJPudTLe94m1IyYj2eNEfG
         +oMe1HbwwC/8rme1RakJP7bss0jwf3xogrmreI8sseDrLjlqdiGzoq5y5tq4qnXEJqqT
         9PQvtj+cDSVMz2UoTC9djcNcJ9djECmxEVTza79QykElpABvDnLjbjs1ncUVAlBrnO5A
         u0Nw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JbNQlxsV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JbNQlxsV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574461; x=1769179261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iSxI5HNcyCYQWTp6HpX69Dp+meIoDFpJ6jOIrm61Jko=;
        b=csh3Vp3uTQrH7oQSsDjsYLp4kPdpgH+gklFmFp/WGFsKkvlPDaoy64ACuaBKemYx7/
         02V5cv4d7ZhqPNyTJbE6tprCXg7/ohL86w3nfHXhcfp73viOOF/RwU0Jc5bfBKPc41iS
         51xEuyG+6AhRxkXkLmgbv+/fsv21TcsN6P+sQRT3xHdGr+8A4Pd3K9ABPUANHvFPqegm
         m0q8YPot9IXYD5IOoLjfe1uJMxPtHEuVHAhflg1+aG/uALjLU6At94LiRMhrjjtLe/xk
         6EARNlxEz6xzNih4dU0k1ndaza8vLN+pr9eE2gRVIM5/yorJ9rGw4mI95WplS2vt1p59
         FPDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574461; x=1769179261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iSxI5HNcyCYQWTp6HpX69Dp+meIoDFpJ6jOIrm61Jko=;
        b=iPFqoFo8yL38xCKq5Zp3nDZpuTokez/g79HM5mrXEC/p8CDyCK+UwdSoOgq7UFoQmv
         z8NUrPLbpP6YVSd9+taB4X4PnjU4DFZ9GsGWN/R5vh7wudo/AZfeg9ocq/zD+ZzvdGkg
         hNI8C+NOrOU1kUs+IU3abtIffiSKdMddILTkTpizFgTUw88Pg3Jguew1e9kSrm6+ilUP
         ltsX6Vtda2gVPrED8ROj1CNY2VHC9bWp4bkYRAHd8PfBqr5zgqsAF5mbp2EghWJhoQiW
         G1KgGucD0ZN+qgQociPHgUeEUi98Mj8OGDUx7tfvPYqR4N83YW7HRfgLalaQB/BEI8fC
         qK+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdbuCfC+fSUQp7nvg4HrkLzYHIAKE+Ed7poYezcQmHE0PxmRRxJXQWZkVOJwZaubJNC6bdXA==@lfdr.de
X-Gm-Message-State: AOJu0YzDosWdJSidb8p5N5vRC2xQBR9qxuD+tQTdelk9ENNfZt1i4gpR
	K67Js8uOfs+kwovKVEpMOUSm9w3exe5OewJVTzPru+AonL+SUkk6THBm
X-Received: by 2002:ac2:4f14:0:b0:594:5f00:c0b7 with SMTP id 2adb3069b0e04-59baeeb9fe3mr1207177e87.15.1768574461371;
        Fri, 16 Jan 2026 06:41:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eh15TIgRe2BpbuWtDJcbTEZ9GiT0OGxh4nUgPvfrWlCQ=="
Received: by 2002:a2e:86cf:0:b0:377:735b:7cbf with SMTP id 38308e7fff4ca-3836ecb2a5als6304631fa.0.-pod-prod-08-eu;
 Fri, 16 Jan 2026 06:40:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVsRRBIY3702EK8zjs9HbPcUhweyT+sPDhAWb/5QWGagQMuVdwt+YcemFho9Zbr8i99tfDJzxuUFyA=@googlegroups.com
X-Received: by 2002:a05:651c:b10:b0:383:1dff:8a8c with SMTP id 38308e7fff4ca-38384148b13mr10914971fa.8.1768574458608;
        Fri, 16 Jan 2026 06:40:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574458; cv=none;
        d=google.com; s=arc-20240605;
        b=LQdXUcLRcQB90pJD2dsgcbh1Ez3aMkV4Stx7TQun2kHvtP+gUhWEx9JXhZ0cVrKjLX
         Ny4f/ExAHbjovPax03TdsbPDZWn9aKfkoVGCbbnpzLLOL3Krj5WU4kwW3F5jRiE2MRSJ
         NBQqWpRjisK+/PpjYCtlSSSnhN0c5f+Hml23dFIF7CkS58Szp7/tsytlpijcqUVyVwFl
         FJi8f5GmzwxlPwas7/W1o+h4ZSick52HqacXvQcoKXoraQig7FgMwnGOY6p5A9+OKbo9
         s27OZHk2X4T2BC8Z3laPKHAdFxfW1IUA0PEekoEakKgKKG7SrqIlzSU2csLIw5UEQwBz
         AIbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=x//ubRuVrxiZHDkZo7cacxsgeijKPvlM+1IHTFUCb9Y=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=J50DewY2BLrkbr/qhI6PGe4dju2+fdadk9Vzp7nULaLFEqQgvaEaA+rBSUZ7QoTFO4
         VHSM/uLLsNalS4wGySy3cuc2lhHe8sw/grrnGyZXvb2DujL2c0l71ddrRE6ZHKj8gci5
         /7fuN8DyNkhii5xEmnAEkwu7SuMg2DvdMx71UWMW1lHhVO6Zp/xAkq358V3e8IgndrbT
         Kdf57iDcbXH32R9Wa4W2AiAp7MHz4wtp3OXjovIwzxlL9/OF5jFX2VD8V8nJa2wgDeVw
         J2jjbGecbIdl+PDJQjKKZSJBveBWK1wE8hSUFCOqGFLOhrScEWT9vdwTKfl22fi3bVII
         KJzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JbNQlxsV;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=JbNQlxsV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e78091si504981fa.8.2026.01.16.06.40.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1AB9D3373A;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id EFFE43EA63;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id cEpROuVNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:33 +0100
Subject: [PATCH v3 13/21] slab: remove defer_deactivate_slab()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-13-5595cb000772@suse.cz>
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
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.999];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=JbNQlxsV;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=JbNQlxsV;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

There are no more cpu slabs so we don't need their deferred
deactivation. The function is now only used from places where we
allocate a new slab but then can't spin on node list_lock to put it on
the partial list. Instead of the deferred action we can free it directly
via __free_slab(), we just need to tell it to use _nolock() freeing of
the underlying pages and take care of the accounting.

Since free_frozen_pages_nolock() variant does not yet exist for code
outside of the page allocator, create it as a trivial wrapper for
__free_frozen_pages(..., FPI_TRYLOCK).

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/internal.h   |  1 +
 mm/page_alloc.c |  5 +++++
 mm/slab.h       |  8 +-------
 mm/slub.c       | 56 ++++++++++++++++++++------------------------------------
 4 files changed, 27 insertions(+), 43 deletions(-)

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
index e77260720994..4efec41b6445 100644
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
index b08e775dc4cb..33f218c0e8d6 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3260,7 +3260,7 @@ static struct slab *new_slab(struct kmem_cache *s, gfp_t flags, int node)
 		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
 }
 
-static void __free_slab(struct kmem_cache *s, struct slab *slab)
+static void __free_slab(struct kmem_cache *s, struct slab *slab, bool allow_spin)
 {
 	struct page *page = slab_page(slab);
 	int order = compound_order(page);
@@ -3271,14 +3271,26 @@ static void __free_slab(struct kmem_cache *s, struct slab *slab)
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
@@ -3294,7 +3306,7 @@ static void free_slab(struct kmem_cache *s, struct slab *slab)
 	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		call_rcu(&slab->rcu_head, rcu_free_slab);
 	else
-		__free_slab(s, slab);
+		__free_slab(s, slab, true);
 }
 
 static void discard_slab(struct kmem_cache *s, struct slab *slab)
@@ -3387,8 +3399,6 @@ static void *alloc_single_from_partial(struct kmem_cache *s,
 	return object;
 }
 
-static void defer_deactivate_slab(struct slab *slab, void *flush_freelist);
-
 /*
  * Called only for kmem_cache_debug() caches to allocate from a freshly
  * allocated slab. Allocate a single object instead of whole freelist
@@ -3404,8 +3414,8 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
 	void *object;
 
 	if (!allow_spin && !spin_trylock_irqsave(&n->list_lock, flags)) {
-		/* Unlucky, discard newly allocated slab */
-		defer_deactivate_slab(slab, NULL);
+		/* Unlucky, discard newly allocated slab. */
+		free_new_slab_nolock(s, slab);
 		return NULL;
 	}
 
@@ -4276,7 +4286,7 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
 
 		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
 			/* Unlucky, discard newly allocated slab */
-			defer_deactivate_slab(slab, NULL);
+			free_new_slab_nolock(s, slab);
 			return 0;
 		}
 	}
@@ -6033,7 +6043,6 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 
 struct defer_free {
 	struct llist_head objects;
-	struct llist_head slabs;
 	struct irq_work work;
 };
 
@@ -6041,7 +6050,6 @@ static void free_deferred_objects(struct irq_work *work);
 
 static DEFINE_PER_CPU(struct defer_free, defer_free_objects) = {
 	.objects = LLIST_HEAD_INIT(objects),
-	.slabs = LLIST_HEAD_INIT(slabs),
 	.work = IRQ_WORK_INIT(free_deferred_objects),
 };
 
@@ -6054,10 +6062,9 @@ static void free_deferred_objects(struct irq_work *work)
 {
 	struct defer_free *df = container_of(work, struct defer_free, work);
 	struct llist_head *objs = &df->objects;
-	struct llist_head *slabs = &df->slabs;
 	struct llist_node *llnode, *pos, *t;
 
-	if (llist_empty(objs) && llist_empty(slabs))
+	if (llist_empty(objs))
 		return;
 
 	llnode = llist_del_all(objs);
@@ -6081,16 +6088,6 @@ static void free_deferred_objects(struct irq_work *work)
 
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
@@ -6106,19 +6103,6 @@ static void defer_free(struct kmem_cache *s, void *head)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-13-5595cb000772%40suse.cz.
