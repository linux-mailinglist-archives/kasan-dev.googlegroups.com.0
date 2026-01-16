Return-Path: <kasan-dev+bncBDXYDPH3S4OBBAE4VHFQMGQE2NBXFSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9814ED32C7F
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:41:05 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-64cfbb4c464sf2118967a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:41:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574465; cv=pass;
        d=google.com; s=arc-20240605;
        b=TgG4fFEMNcuGHmupKKjBfqiF2hmr0goMIUnlwexMIJslfz4YjiKf+SZqGiSOZD8A5u
         Xh02xi96vLh6EI1Lp/aXb+6B3jYmHbx9BKK+cyj2zRTkVK64JH5a2UN/g3Gq+fOpuySL
         nW2p2PwAPt7b2FNHWgxOOjwcPq/KahG0mpqBiwt+foQkg++53KOPrNlyMtR56ZzSk3tt
         1aWJTURR7bl+4vPR2v2lZPudTWc4rKp2lbSNWvw9apEFJ5YMIhOkrJuvihZsNyCEUEf7
         LdC/QOBwGKOIySonf9clFwfvoGkMCPQ0dTd6Tti8hx+pZNqoq+dCQFVnfeUBeGe+Dx8n
         YxyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=O9CPn/XWoU1PJV0R4eWhXBBDnCCnpGieHRS1Wbqm4os=;
        fh=ahANJgHJ5OTCypEWmBQaiSRkdOo0tKMD1NriNTpZ09A=;
        b=f2MJ/sI5AKutoHHF4/x1QfJE0hF9I9KHLmtjsoV5GtK875AKqLd85zODni+9jDOX4u
         cS2UKsaDd5fMJcR0qwXgw7iIsaxSxN/QDBzCLF8W4GFzujyA82cAhM0zlTptpqMfcdzy
         mA+s6+UfUUDNaLQxQ942OqgKKfZN2N+YYPFNjlBX4+e+14Wneg06WKb63QDH0jFN2XtO
         2rE/3AqhycCD1a2GF7FTLS1lJuVW4MszmwauvwCh4GwSg1SiHRMS8Otfg+/bqgL9FiwX
         F5CrqR41jSI/k8zhNxTHuKNCk0u1suu7RZ/FgcIuwyZM8eju9iicLqtrwtwXxAZdljNG
         3zag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NqKnKi9p;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NqKnKi9p;
       dkim=neutral (no key) header.i=@suse.cz header.b="/uAKyVaD";
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574465; x=1769179265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O9CPn/XWoU1PJV0R4eWhXBBDnCCnpGieHRS1Wbqm4os=;
        b=RjCevSk9prtrWYxufwmp+TSjjVRZ/6J/AOSzXEGJMbYcqEjEq7vy1FLxFNi3/heK2H
         rppT/5eAnA0TxMaP4r0FB1zl5oEeZrdCvIzazRH2LoJLGAR8kRaH33/NoVL8wP9DdPiy
         wckXWfkwtMEM3pFaCkKWWQq8HTxhTKN/8Fja/4cFcIuTMZv3Tfz8a9tGMuwEmr2FIveS
         wdUgTSv4/UOfV8NYIKxIPYnmtSJ6iZb91N8CHpKwr+TWiwC7WWtqXWXHCyr6RxGQbN5h
         Br/xtS97C7Hq0aLdGMlrzgr/3DNNAp8SNBx8hKUUgOmtDEJRuhtswtCIgbJxApzN8Hxz
         +V9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574465; x=1769179265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O9CPn/XWoU1PJV0R4eWhXBBDnCCnpGieHRS1Wbqm4os=;
        b=cjZx2q9XWRP8Izlz1bByuj49YdSYDyrDA8TvIFIeG6JqoEYP6T3nEsQ6gdjI3N1tsL
         orWnS0Mo8lnsKufsA9rFv+WeHs2/cyAXQ997xPUMH8BjTGDoB04H/g8W4JA/NxbCNWha
         p3UrfUjhBd4HO+aPP6lhTNyP/UcVURcWHrbzi7xsvhFb7B6YDCSzgXhrMBuxPn5J5SNN
         Y1rRLb/9tKBvbgVhyCLO4XoYE0QjhQFo/iQQhJ0FM+DiF+esYyiwKG8QTebEYJH0TrjQ
         Psr38CnMFSi8HiS6uQuXSLEiyZn0Lmjd8n+4pkXxnrYrG1DuJ+7oZUlIVWa3Jgf2fLSs
         KQPg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPMwWBKn2Ka/EP4QIrdVQpnIrKS4euL3tp9RfFlzUCHa/Wm9OrBe45aajrBeKRKGT74sFjmg==@lfdr.de
X-Gm-Message-State: AOJu0Yzuvknfl1fwk//tFiFXcy9Is/GtDFX5CAXpM6u619YiENIEKbCM
	dH78JTR0MjvFWlDoVQCVrgU5l48FfvtRlOG4McJ6BFEXSIiXKZhWeyXH
X-Received: by 2002:a05:6402:3596:b0:64d:57a8:1ff3 with SMTP id 4fb4d7f45d1cf-654524d44e2mr2267332a12.4.1768574464835;
        Fri, 16 Jan 2026 06:41:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FpRv80MU9vtWJYcxK8umaGKXoaWX9ElZIQ/J4gxbWs5Q=="
Received: by 2002:a50:9ec4:0:b0:64b:7641:af54 with SMTP id 4fb4d7f45d1cf-6541c6d8088ls1562309a12.2.-pod-prod-02-eu;
 Fri, 16 Jan 2026 06:41:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFzDt+ON//6hzaBL+w5nxu3+muqrxTBY41HEXhcwtm1fGcmCkNJS1+5UmFsPcHkN2mExYlKxbqCHM=@googlegroups.com
X-Received: by 2002:a05:6402:3647:b0:64f:cfa0:900a with SMTP id 4fb4d7f45d1cf-654524d46a8mr1620789a12.1.1768574462265;
        Fri, 16 Jan 2026 06:41:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574462; cv=none;
        d=google.com; s=arc-20240605;
        b=bKd3HlK/v2981Abynn7qF/jbxBbQ7n5USFjbD2FntPUjgdMhqtA3I5ODzM6ryZUEzY
         vSSXtUVR4DaJdzSRNJnbw1hOYMb5jQPgL786CSLq6NhQpKobYwzIl2615p8/WehlPYYn
         5cve7RQMU92ihAtb2JY5zvlIVe+bEmyQsNKYHSYhdmWFFFk+0WKGl3OD3uDKDa8VWI+a
         EamQNMW1ScUJM4d8jHYasT3xV1llB+eTVkxqPeSgdbCdjIdTDsGkTuBd6YWPqwxF1cmA
         FoUUYE3KDJ1LrfDgWEmx/BnCaWSsGtoBVtgls7fDLNzxnEyeHOdmY9bX9l7Tue1PKO55
         gbrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=yWv/6dge7GPnKkYfY68/8ppGyOUqB4oP1/FkN30jYlE=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=NaY/14JQHkZsBOsItKBApsWx0ZkLTgLUm1PDnw5p5L2Mhyz/QT85bw3RT10jjVK/bJ
         49ekFwEoZPANPgZQrwIdUDYPKBhfLYD+8+jRyll0zTTOFfHuzt17ajOXOqee1/LBToyk
         ZNJP5y7tARu0shr0tzmTKryk7TrEvXLmqDDoIJofI4Lk7DUVaOD8Pm4a79EHxknBPXEG
         5rBqxytwG+MSboHK8JA6HrZj7EPDOqHIxrXWCUSUj3Vx1ptOXdnRY/EPZol4hJsWUo6R
         iMSg7f5oty+OlHnMHCuIKSVSMh56wqh6XAS4M7U4o55tCCreMWZzY/bto0GZOLX9FNY7
         0WPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NqKnKi9p;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NqKnKi9p;
       dkim=neutral (no key) header.i=@suse.cz header.b="/uAKyVaD";
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532d75d9si65695a12.8.2026.01.16.06.41.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:41:02 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0AF9B5BE96;
	Fri, 16 Jan 2026 14:40:39 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E080B3EA63;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id IGiCNuZNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:41 +0100
Subject: [PATCH v3 21/21] mm/slub: cleanup and repurpose some stat items
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-21-5595cb000772@suse.cz>
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
	R_RATELIMIT(0.00)[to(RL941jgdop1fyjkq8h4),to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: 0AF9B5BE96
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NqKnKi9p;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=NqKnKi9p;       dkim=neutral (no key)
 header.i=@suse.cz header.b="/uAKyVaD";       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

A number of stat items related to cpu slabs became unused, remove them.

Two of those were ALLOC_FASTPATH and FREE_FASTPATH. But instead of
removing those, use them instead of ALLOC_PCS and FREE_PCS, since
sheaves are the new (and only) fastpaths, Remove the recently added
_PCS variants instead.

Change where FREE_SLOWPATH is counted so that it only counts freeing of
objects by slab users that (for whatever reason) do not go to a percpu
sheaf, and not all (including internal) callers of __slab_free(). Thus
flushing sheaves (counted by SHEAF_FLUSH) no longer also increments
FREE_SLOWPATH. This matches how ALLOC_SLOWPATH doesn't count sheaf
refills (counted by SHEAF_REFILL).

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 77 +++++++++++++++++----------------------------------------------
 1 file changed, 21 insertions(+), 56 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index c12e90cb2fca..d73ad44fa046 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -330,33 +330,19 @@ enum add_mode {
 };
 
 enum stat_item {
-	ALLOC_PCS,		/* Allocation from percpu sheaf */
-	ALLOC_FASTPATH,		/* Allocation from cpu slab */
-	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
-	FREE_PCS,		/* Free to percpu sheaf */
+	ALLOC_FASTPATH,		/* Allocation from percpu sheaves */
+	ALLOC_SLOWPATH,		/* Allocation from partial or new slab */
 	FREE_RCU_SHEAF,		/* Free to rcu_free sheaf */
 	FREE_RCU_SHEAF_FAIL,	/* Failed to free to a rcu_free sheaf */
-	FREE_FASTPATH,		/* Free to cpu slab */
-	FREE_SLOWPATH,		/* Freeing not to cpu slab */
+	FREE_FASTPATH,		/* Free to percpu sheaves */
+	FREE_SLOWPATH,		/* Free to a slab */
 	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
 	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
-	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
-	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
-	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
-	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
+	ALLOC_SLAB,		/* New slab acquired from page allocator */
+	ALLOC_NODE_MISMATCH,	/* Requested node different from cpu sheaf */
 	FREE_SLAB,		/* Slab freed to the page allocator */
-	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
-	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
-	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
-	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
-	DEACTIVATE_BYPASS,	/* Implicit deactivation */
 	ORDER_FALLBACK,		/* Number of times fallback was necessary */
-	CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
 	CMPXCHG_DOUBLE_FAIL,	/* Failures of slab freelist update */
-	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
-	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
-	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
-	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
 	SHEAF_FLUSH,		/* Objects flushed from a sheaf */
 	SHEAF_REFILL,		/* Objects refilled to a sheaf */
 	SHEAF_ALLOC,		/* Allocation of an empty sheaf */
@@ -4347,8 +4333,10 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 	 * We assume the percpu sheaves contain only local objects although it's
 	 * not completely guaranteed, so we verify later.
 	 */
-	if (unlikely(node_requested && node != numa_mem_id()))
+	if (unlikely(node_requested && node != numa_mem_id())) {
+		stat(s, ALLOC_NODE_MISMATCH);
 		return NULL;
+	}
 
 	if (!local_trylock(&s->cpu_sheaves->lock))
 		return NULL;
@@ -4371,6 +4359,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 		 */
 		if (page_to_nid(virt_to_page(object)) != node) {
 			local_unlock(&s->cpu_sheaves->lock);
+			stat(s, ALLOC_NODE_MISMATCH);
 			return NULL;
 		}
 	}
@@ -4379,7 +4368,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat(s, ALLOC_PCS);
+	stat(s, ALLOC_FASTPATH);
 
 	return object;
 }
@@ -4451,7 +4440,7 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat_add(s, ALLOC_PCS, batch);
+	stat_add(s, ALLOC_FASTPATH, batch);
 
 	allocated += batch;
 
@@ -5111,8 +5100,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 	unsigned long flags;
 	bool on_node_partial;
 
-	stat(s, FREE_SLOWPATH);
-
 	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
 		free_to_partial_list(s, slab, head, tail, cnt, addr);
 		return;
@@ -5416,7 +5403,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat(s, FREE_PCS);
+	stat(s, FREE_FASTPATH);
 
 	return true;
 }
@@ -5664,7 +5651,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 
 	local_unlock(&s->cpu_sheaves->lock);
 
-	stat_add(s, FREE_PCS, batch);
+	stat_add(s, FREE_FASTPATH, batch);
 
 	if (batch < size) {
 		p += batch;
@@ -5686,10 +5673,12 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 	 */
 fallback:
 	__kmem_cache_free_bulk(s, size, p);
+	stat_add(s, FREE_SLOWPATH, size);
 
 flush_remote:
 	if (remote_nr) {
 		__kmem_cache_free_bulk(s, remote_nr, &remote_objects[0]);
+		stat_add(s, FREE_SLOWPATH, remote_nr);
 		if (i < size) {
 			remote_nr = 0;
 			goto next_remote_batch;
@@ -5784,6 +5773,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	}
 
 	__slab_free(s, slab, object, object, 1, addr);
+	stat(s, FREE_SLOWPATH);
 }
 
 #ifdef CONFIG_MEMCG
@@ -5806,8 +5796,10 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
 	 * to remove objects, whose reuse must be delayed.
 	 */
-	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
+	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt))) {
 		__slab_free(s, slab, head, tail, cnt, addr);
+		stat_add(s, FREE_SLOWPATH, cnt);
+	}
 }
 
 #ifdef CONFIG_SLUB_RCU_DEBUG
@@ -6705,6 +6697,7 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 		i = refill_objects(s, p, flags, size, size);
 		if (i < size)
 			goto error;
+		stat_add(s, ALLOC_SLOWPATH, i);
 	}
 
 	return i;
@@ -8704,33 +8697,19 @@ static ssize_t text##_store(struct kmem_cache *s,		\
 }								\
 SLAB_ATTR(text);						\
 
-STAT_ATTR(ALLOC_PCS, alloc_cpu_sheaf);
 STAT_ATTR(ALLOC_FASTPATH, alloc_fastpath);
 STAT_ATTR(ALLOC_SLOWPATH, alloc_slowpath);
-STAT_ATTR(FREE_PCS, free_cpu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
 STAT_ATTR(FREE_FASTPATH, free_fastpath);
 STAT_ATTR(FREE_SLOWPATH, free_slowpath);
 STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
 STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
-STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
 STAT_ATTR(ALLOC_SLAB, alloc_slab);
-STAT_ATTR(ALLOC_REFILL, alloc_refill);
 STAT_ATTR(ALLOC_NODE_MISMATCH, alloc_node_mismatch);
 STAT_ATTR(FREE_SLAB, free_slab);
-STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
-STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
-STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
-STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
-STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
 STAT_ATTR(ORDER_FALLBACK, order_fallback);
-STAT_ATTR(CMPXCHG_DOUBLE_CPU_FAIL, cmpxchg_double_cpu_fail);
 STAT_ATTR(CMPXCHG_DOUBLE_FAIL, cmpxchg_double_fail);
-STAT_ATTR(CPU_PARTIAL_ALLOC, cpu_partial_alloc);
-STAT_ATTR(CPU_PARTIAL_FREE, cpu_partial_free);
-STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
-STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
 STAT_ATTR(SHEAF_FLUSH, sheaf_flush);
 STAT_ATTR(SHEAF_REFILL, sheaf_refill);
 STAT_ATTR(SHEAF_ALLOC, sheaf_alloc);
@@ -8806,33 +8785,19 @@ static struct attribute *slab_attrs[] = {
 	&remote_node_defrag_ratio_attr.attr,
 #endif
 #ifdef CONFIG_SLUB_STATS
-	&alloc_cpu_sheaf_attr.attr,
 	&alloc_fastpath_attr.attr,
 	&alloc_slowpath_attr.attr,
-	&free_cpu_sheaf_attr.attr,
 	&free_rcu_sheaf_attr.attr,
 	&free_rcu_sheaf_fail_attr.attr,
 	&free_fastpath_attr.attr,
 	&free_slowpath_attr.attr,
 	&free_add_partial_attr.attr,
 	&free_remove_partial_attr.attr,
-	&alloc_from_partial_attr.attr,
 	&alloc_slab_attr.attr,
-	&alloc_refill_attr.attr,
 	&alloc_node_mismatch_attr.attr,
 	&free_slab_attr.attr,
-	&cpuslab_flush_attr.attr,
-	&deactivate_full_attr.attr,
-	&deactivate_empty_attr.attr,
-	&deactivate_remote_frees_attr.attr,
-	&deactivate_bypass_attr.attr,
 	&order_fallback_attr.attr,
 	&cmpxchg_double_fail_attr.attr,
-	&cmpxchg_double_cpu_fail_attr.attr,
-	&cpu_partial_alloc_attr.attr,
-	&cpu_partial_free_attr.attr,
-	&cpu_partial_node_attr.attr,
-	&cpu_partial_drain_attr.attr,
 	&sheaf_flush_attr.attr,
 	&sheaf_refill_attr.attr,
 	&sheaf_alloc_attr.attr,

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-21-5595cb000772%40suse.cz.
