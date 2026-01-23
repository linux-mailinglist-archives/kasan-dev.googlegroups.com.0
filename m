Return-Path: <kasan-dev+bncBDXYDPH3S4OBB3VVZTFQMGQEXWCOMBY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SKxwBPAac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB3VVZTFQMGQEXWCOMBY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C3B6A71322
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:35 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-59b6ab3cceesf1457980e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151215; cv=pass;
        d=google.com; s=arc-20240605;
        b=fTLV7716PcQv/4jvYzLc98aQtaiFmBFTt5zWw/Lv7LbAYoVNGeMaPgAZsU1eji4C+5
         Y1rv142olPjlAuq1iWj6f+g3hiFvdwM65S+T/hbc2ntcfejhSftkYR7UBXSKox0mSQis
         R30zndCXKL+iwpYNO2BjPaQjfkVW1d5t4RcrNsummtnaE9IsxSafMhFnPe2AfrYULPry
         uV5VnR/QWKggLrHmxTV7EwAIE69OLIQaGNzq/UOxYyD+SHW9bOfhM5e1idlUPz7btRQ0
         6fxK66yQytTDpGflwniDhR/UlHPLsJRoDGdNLwl5awhABPYaHey+GmKTdjQ50BLJY223
         j4Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=onk/yXwf5amqDJTB6gSmeefa1/MzWrcOqKcpAvSqB4o=;
        fh=8FEXkj0aR52qzkNgcgcG2TVR0zbXbAmhroj/GkFKr2A=;
        b=JB+Of9nQnH+PpdLH/T1YiI3X2Zgn+z8JiHOPJbcecvYzQfmSlYukSfAl14vh3wblrT
         P5V6NKZgMEh/Q7s0nDIyuRyXdBzD9TO1aBVzN7tlKc4LBk93jmX+tuA2FcR5HEZzaQNk
         7s88/YRRgfGdOrixubGyydZ+J109qL2K+G8aN2GAyqlZWETSxUVkgplODIq3kAxMJtkh
         eMbd+QagmahOxuD55QAh1ysdgwySI4gJfml+WFZJe6aBVt3+OXllLl7D4ZE7woHmRAIG
         msXwo5xcxEoDvNTh9VpkgO4oHMMsfFqZZQo/MruV0sPp8Cos/rQIM5ti5P4gpJHxXQCW
         jxaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Z2g9m/rc";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Z2g9m/rc";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151215; x=1769756015; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=onk/yXwf5amqDJTB6gSmeefa1/MzWrcOqKcpAvSqB4o=;
        b=SDC0JnjyQzY7Q7jGLe4K8tU2zp6uAIlR2+zh6NyHMJc69h5NRVPPlfM6k3JjwK06Dd
         97XLrxqsczim+DmTYayk1PvOS6hLUSRBpZW6yB0f9S7PiLkOFP3OaF6DlS7mD1JzNYDN
         Qjms1A9pQdNbxtHMpJ0Y2WPp/weqtR8tsmRiJU31YKKJslaabXn/71AfgVRYxX842suU
         TFQ/EH12oD0Jpa3VOTRcQkdh+B55kQKVuALkQpOR/Jt0TxnVKKY77+CqAc8GFqn83dcP
         QXMTMotTwAsCFu82P1UXCUenv/skCpts6ZLYoLFKHEOazD6JHz37/n1Qbt2wp3sbg0pK
         fiMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151215; x=1769756015;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=onk/yXwf5amqDJTB6gSmeefa1/MzWrcOqKcpAvSqB4o=;
        b=V+mUDF46lzEpkoU+7mhdNYnSYlidiYBZxaWQSN1XYzQ+9eBT/1wXKNuIs1wOh3VhPt
         7OwouF9ytSIU4N+Ro8yZOcy1fEazAN5HY43IxHLnr0a4QtXRsNTnFyhjnvhIXYlbkg+j
         W8q7FhxB5260ER37xaCSsIFQw5PA4hWMwORM5ZO9TL000HMoQcxe3PVPgWWv1JwSQnqq
         ZLt+qDssoVIQDizdLWNH4prpXYSjUvQnb1SBp7rrRmOn/aB4YGJc7NpTin8xfSjXcjjh
         IEiUwBRdGBtCo1RqJOG4TVYhIRlDZGcbRCNv28M8mi0N6rcNdNUNFY7fsA26wIGugxKM
         2DBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW5k4A18wnOJ1uTS14OTtI+n/oeieMEApLUsGHJRCt6H/uNBvIXC7iZqBzufrVYycgrFmziMw==@lfdr.de
X-Gm-Message-State: AOJu0YzwV5Ng20my2Do14UpvJfwDbyY8TuilomqMg3l0S/up3Dnp8g5C
	EDf/pW40vZLjeGZU2gCbEJd3yZdjDMnWHu411F8DGC6VdH3imwi0bcM8
X-Received: by 2002:a05:6512:108c:b0:59d:d64e:b3d7 with SMTP id 2adb3069b0e04-59de492be2amr548967e87.46.1769151214809;
        Thu, 22 Jan 2026 22:53:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E1Ap65DSHlr0t84kSoFGPC1HXOBW71JakA6KX6fdsyYQ=="
Received: by 2002:a05:6512:1242:b0:59b:7324:a12c with SMTP id
 2adb3069b0e04-59dd79861b2ls534942e87.2.-pod-prod-07-eu; Thu, 22 Jan 2026
 22:53:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXAcF4m8GkpW2WL0JLasJZqsA1AtFxmg4wouSbagJjpnDCOZWTHpdgzamiu7vAlfcnliMhs7GyJRgY=@googlegroups.com
X-Received: by 2002:a2e:beab:0:b0:37c:d689:7e1c with SMTP id 38308e7fff4ca-385da028e64mr5899221fa.23.1769151212041;
        Thu, 22 Jan 2026 22:53:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151212; cv=none;
        d=google.com; s=arc-20240605;
        b=G2RdzVM+FHY/AptawhR/BD9kz5LvV1rPhNZS/qUuRTPQf/dNoyr0Tm0CcJjxc98Ei4
         29MpVliyqgalB8XgGGdie2ewHDEZ53HREeB3SIc67vFzdB+eYxDCq3p5/Z2dkpjBUq50
         lIW0uHd+DdVFBCnfgN7YsDdTiH615Hqb7A++28xMHYZ1FdWmwS5qPOtk0zuygBHZOPcb
         fdiFPO35LlAn0AlfD5zcS13YALakokZm0Mihgt/26zDCsXb8chcuPGSOQMPMm+S8N96s
         uzBp90tufJAhMegFl9FoNlWA6gPm1IdO05N+6Fqaxc4NhONWCdY36KgkbuttLzvN5qSl
         k5iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=Lz6+CfboTVUMod3u7B664uLDJDmXudIqpgLE6OkuCxw=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=PZ+cg3bswaAw836GOSQGyBIS6kosklnFfMrOv3JEUQpvIFyipqxUxGJaVGwl5w+m6i
         UToeR8U2cLA/hy8t0OYZrPgMNs/lO+IDi6qZLgkwQ4V0C5hCZwHJSu6s6706iNgqZ+eb
         P4zQqJJ5/meeyg9mJeOC0yN4rs1ySDtNPZT+RMVedZn3nn5Sc/p/fW01ShOjNqrhyV9t
         pidLA+7xufLGfdhuOWN8XFGVaAId9Y3aGVyQpzoGJIfruHpVB1MQuIoEpSSFI5BgmT69
         NbsVipEwMS23Rsyh00IQOm8E9Z2LWG+8R0qmn9GjCR1J/k9G81vcyVMBPlCvh3mZCofE
         kFow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Z2g9m/rc";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Z2g9m/rc";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385d9e542a4si304551fa.0.2026.01.22.22.53.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:32 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C9F8033772;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7C249139F7;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 2McKHtYac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:51 +0100
Subject: [PATCH v4 13/22] slab: remove the do_slab_free() fastpath
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-13-041323d506f7@suse.cz>
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
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Z2g9m/rc";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Z2g9m/rc";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB3VVZTFQMGQEXWCOMBY];
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
	NEURAL_HAM(-0.00)[-0.974];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,oracle.com:email,mail-lf1-x13a.google.com:helo,mail-lf1-x13a.google.com:rdns]
X-Rspamd-Queue-Id: C3B6A71322
X-Rspamd-Action: no action

We have removed cpu slab usage from allocation paths. Now remove
do_slab_free() which was freeing objects to the cpu slab when
the object belonged to it. Instead call __slab_free() directly,
which was previously the fallback.

This simplifies kfree_nolock() - when freeing to percpu sheaf
fails, we can call defer_free() directly.

Also remove functions that became unused.

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Reviewed-by: Hao Li <hao.li@linux.dev>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 149 ++++++--------------------------------------------------------
 1 file changed, 13 insertions(+), 136 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 914b51aedb25..a63a0eed2c55 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3678,29 +3678,6 @@ static inline unsigned int init_tid(int cpu)
 	return cpu;
 }
 
-static inline void note_cmpxchg_failure(const char *n,
-		const struct kmem_cache *s, unsigned long tid)
-{
-#ifdef SLUB_DEBUG_CMPXCHG
-	unsigned long actual_tid = __this_cpu_read(s->cpu_slab->tid);
-
-	pr_info("%s %s: cmpxchg redo ", n, s->name);
-
-	if (IS_ENABLED(CONFIG_PREEMPTION) &&
-	    tid_to_cpu(tid) != tid_to_cpu(actual_tid)) {
-		pr_warn("due to cpu change %d -> %d\n",
-			tid_to_cpu(tid), tid_to_cpu(actual_tid));
-	} else if (tid_to_event(tid) != tid_to_event(actual_tid)) {
-		pr_warn("due to cpu running other code. Event %ld->%ld\n",
-			tid_to_event(tid), tid_to_event(actual_tid));
-	} else {
-		pr_warn("for unknown reason: actual=%lx was=%lx target=%lx\n",
-			actual_tid, tid, next_tid(tid));
-	}
-#endif
-	stat(s, CMPXCHG_DOUBLE_CPU_FAIL);
-}
-
 static void init_kmem_cache_cpus(struct kmem_cache *s)
 {
 #ifdef CONFIG_PREEMPT_RT
@@ -4239,18 +4216,6 @@ static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags)
 	return true;
 }
 
-static inline bool
-__update_cpu_freelist_fast(struct kmem_cache *s,
-			   void *freelist_old, void *freelist_new,
-			   unsigned long tid)
-{
-	struct freelist_tid old = { .freelist = freelist_old, .tid = tid };
-	struct freelist_tid new = { .freelist = freelist_new, .tid = next_tid(tid) };
-
-	return this_cpu_try_cmpxchg_freelist(s->cpu_slab->freelist_tid,
-					     &old.freelist_tid, new.freelist_tid);
-}
-
 /*
  * Get the slab's freelist and do not freeze it.
  *
@@ -6185,99 +6150,6 @@ void defer_free_barrier(void)
 		irq_work_sync(&per_cpu_ptr(&defer_free_objects, cpu)->work);
 }
 
-/*
- * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
- * can perform fastpath freeing without additional function calls.
- *
- * The fastpath is only possible if we are freeing to the current cpu slab
- * of this processor. This typically the case if we have just allocated
- * the item before.
- *
- * If fastpath is not possible then fall back to __slab_free where we deal
- * with all sorts of special processing.
- *
- * Bulk free of a freelist with several objects (all pointing to the
- * same slab) possible by specifying head and tail ptr, plus objects
- * count (cnt). Bulk free indicated by tail pointer being set.
- */
-static __always_inline void do_slab_free(struct kmem_cache *s,
-				struct slab *slab, void *head, void *tail,
-				int cnt, unsigned long addr)
-{
-	/* cnt == 0 signals that it's called from kfree_nolock() */
-	bool allow_spin = cnt;
-	struct kmem_cache_cpu *c;
-	unsigned long tid;
-	void **freelist;
-
-redo:
-	/*
-	 * Determine the currently cpus per cpu slab.
-	 * The cpu may change afterward. However that does not matter since
-	 * data is retrieved via this pointer. If we are on the same cpu
-	 * during the cmpxchg then the free will succeed.
-	 */
-	c = raw_cpu_ptr(s->cpu_slab);
-	tid = READ_ONCE(c->tid);
-
-	/* Same with comment on barrier() in __slab_alloc_node() */
-	barrier();
-
-	if (unlikely(slab != c->slab)) {
-		if (unlikely(!allow_spin)) {
-			/*
-			 * __slab_free() can locklessly cmpxchg16 into a slab,
-			 * but then it might need to take spin_lock
-			 * for further processing.
-			 * Avoid the complexity and simply add to a deferred list.
-			 */
-			defer_free(s, head);
-		} else {
-			__slab_free(s, slab, head, tail, cnt, addr);
-		}
-		return;
-	}
-
-	if (unlikely(!allow_spin)) {
-		if ((in_nmi() || !USE_LOCKLESS_FAST_PATH()) &&
-		    local_lock_is_locked(&s->cpu_slab->lock)) {
-			defer_free(s, head);
-			return;
-		}
-		cnt = 1; /* restore cnt. kfree_nolock() frees one object at a time */
-	}
-
-	if (USE_LOCKLESS_FAST_PATH()) {
-		freelist = READ_ONCE(c->freelist);
-
-		set_freepointer(s, tail, freelist);
-
-		if (unlikely(!__update_cpu_freelist_fast(s, freelist, head, tid))) {
-			note_cmpxchg_failure("slab_free", s, tid);
-			goto redo;
-		}
-	} else {
-		__maybe_unused unsigned long flags = 0;
-
-		/* Update the free list under the local lock */
-		local_lock_cpu_slab(s, flags);
-		c = this_cpu_ptr(s->cpu_slab);
-		if (unlikely(slab != c->slab)) {
-			local_unlock_cpu_slab(s, flags);
-			goto redo;
-		}
-		tid = c->tid;
-		freelist = c->freelist;
-
-		set_freepointer(s, tail, freelist);
-		c->freelist = head;
-		c->tid = next_tid(tid);
-
-		local_unlock_cpu_slab(s, flags);
-	}
-	stat_add(s, FREE_FASTPATH, cnt);
-}
-
 static __fastpath_inline
 void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	       unsigned long addr)
@@ -6294,7 +6166,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 			return;
 	}
 
-	do_slab_free(s, slab, object, object, 1, addr);
+	__slab_free(s, slab, object, object, 1, addr);
 }
 
 #ifdef CONFIG_MEMCG
@@ -6303,7 +6175,7 @@ static noinline
 void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
 {
 	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
-		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
+		__slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
 }
 #endif
 
@@ -6318,7 +6190,7 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
 	 * to remove objects, whose reuse must be delayed.
 	 */
 	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
-		do_slab_free(s, slab, head, tail, cnt, addr);
+		__slab_free(s, slab, head, tail, cnt, addr);
 }
 
 #ifdef CONFIG_SLUB_RCU_DEBUG
@@ -6344,14 +6216,14 @@ static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
 
 	/* resume freeing */
 	if (slab_free_hook(s, object, slab_want_init_on_free(s), true))
-		do_slab_free(s, slab, object, object, 1, _THIS_IP_);
+		__slab_free(s, slab, object, object, 1, _THIS_IP_);
 }
 #endif /* CONFIG_SLUB_RCU_DEBUG */
 
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
-	do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
+	__slab_free(cache, virt_to_slab(x), x, x, 1, addr);
 }
 #endif
 
@@ -6557,7 +6429,12 @@ void kfree_nolock(const void *object)
 			return;
 	}
 
-	do_slab_free(s, slab, x, x, 0, _RET_IP_);
+	/*
+	 * __slab_free() can locklessly cmpxchg16 into a slab, but then it might
+	 * need to take spin_lock for further processing.
+	 * Avoid the complexity and simply add to a deferred list.
+	 */
+	defer_free(s, x);
 }
 EXPORT_SYMBOL_GPL(kfree_nolock);
 
@@ -6983,7 +6860,7 @@ static void __kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
 		if (kfence_free(df.freelist))
 			continue;
 
-		do_slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
+		__slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
 			     _RET_IP_);
 	} while (likely(size));
 }
@@ -7069,7 +6946,7 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
 				cnt++;
 				object = get_freepointer(s, object);
 			} while (object);
-			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
+			__slab_free(s, slab, head, tail, cnt, _RET_IP_);
 		}
 
 		if (refilled >= max)

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-13-041323d506f7%40suse.cz.
