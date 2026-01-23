Return-Path: <kasan-dev+bncBDXYDPH3S4OBB25VZTFQMGQEZ3TCJ5Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SKWELuwac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB25VZTFQMGQEZ3TCJ5Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4857371307
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:32 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4801e9e7159sf16072815e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151211; cv=pass;
        d=google.com; s=arc-20240605;
        b=lBWwruGidcyZsZnT3J10OHCRCsUmOUJ040LbhA2qAqWZ6OYihXpCWsQuYAeU6Y09KW
         VhrMQN5locUfbhTmojsPaPu5r/7qNkdKXslBbCD2Jza1D2pNd1kB0wixew5SfTETsuzu
         jcsfws8T9JcKFCbVvYzSd6qszxFJ+nKz3RcmYANafA4VGP1VSoUQ+fggs+Y8CnOSwJiK
         zdLseiBYZ5G3JZQwVB9qrVIK0C7p7Udiv6AsTrsn9jvZ5BgTc6V9vlHIGbUiqrSV8D1T
         goO4SCr7wx6AnhrJkXQmQxm5Jzou3ovbgNvf51FIDUGLQQ/Z8UU9f666+tPmSrI1KlB3
         NrmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=6yLTm5OSUKT3hpSSYc8Vxulzxn34XmUfINL+1KdGORY=;
        fh=EOUiFbVxc7xOJo+24098OjnZB6GDbKWQ5JG6B4N6Ct8=;
        b=dUp49E17zZK3AACLkheu+RNn/dc5kP3QhYHIBoEBX8QLP970Bs6n2FiiU2sS8VW7tL
         knyr1Z8vdRJ2G/9lXmbiCIe3Xt+iH2WL8is6OCpcub0+xvMQ8Fav8MtiBXvWKQ/YcUlO
         TceCR/KeOjFi/4S1Tuc0Uzj4/YrN6K0EdRfqVweSWhZ4+lvCQiBgt2PoCEE6f/Xjq4jJ
         uzLMYlIK4FOK/Cdawmcgdhcs4OUcigBKqNnlyjTG5J8HPCfVOZSFE3sCpuIbTUI7sCI6
         cjnBd6w050SQpwvwOmyBJo6CbaegNPjUJlWxLZYWkdSPEs1Z/QUWcvpK7ykcta4NCixv
         z9lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pcUtnIn8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pcUtnIn8;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151211; x=1769756011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6yLTm5OSUKT3hpSSYc8Vxulzxn34XmUfINL+1KdGORY=;
        b=pHpTwd2VaDemy/qsJDDSG4G4ovojZJm0qlGUdPx2x4rIJHi85OQ5LQAJP8BcbFwlRF
         iQyqVZrRm1I8k3SWtIZTLx+hDKvcqLWL1/UNbeWzflpY6mqDIxnC9jUVi7bkXprdh3bW
         bBGkpd4WpWqRX1kqyAqYjtyLHRYcAzOvDiyYJnPellk+iFQV8XwAX2ZxFP0nnZp3A4lC
         FmdrEjwDbIDtfrShQi9XuCKCa5j9kLHSDbXxnmvEtFJrHf10j+0fKUa/4SzX77d9XEDp
         lXgN0fW+9ELj0NOCpqvQIqOkbVb1nQ0wqoCFq6oASdfQN/Xz/xOk1P4VVAyac2KN6gxC
         DhYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151211; x=1769756011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6yLTm5OSUKT3hpSSYc8Vxulzxn34XmUfINL+1KdGORY=;
        b=xCkVFmakW31FLh3Mi3AXPNU6XzVI6vpn3E962YpaHyTgAZUcRVARNsy8GDJ2SJ9K2F
         FfnrIinFFlGU0AcwUR/t5V0n+EWS/D4t91IfPnRiVTlkNQrzegSKV2ZkiDOyjA0rpWOp
         s8TARIIqGHzahKpaIo9+Sg1qqO6jxPXhA3RrcPZZ2RIHze4OEUSXcs6+2jgnf5VpGNF6
         F7OqLpSA8Z8cuH40KZpSBCi/KfBGo+QxxS88PMq+SZb9hWV4Fu3kLWVFGBhcUzbznlIb
         FG0n/8A8IapWdj6XJMIPWez1euXiWhtJ4wsQLPeDqjd9khMQ7MEKZCCY9nfKVJ9w1MtT
         0keg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmjX+6WwxOr0HewK11q7t772WNeyK4PKfywTbGaVlV5Ej6OZrFhDA2/tLBA7Zjm6MdlwBRPw==@lfdr.de
X-Gm-Message-State: AOJu0Yw1tcIrdMiJqkUkTJCOkO6Y1tT9AzKTvABBcMrLlkEV+Dsh22el
	wK19gF2CCQ3E7Za1HNSahV8I/ly6VCw/rvB2qRsmEziintwWz4Xz5N2b
X-Received: by 2002:a05:600c:8589:b0:480:4d76:daf0 with SMTP id 5b1f17b1804b1-4804d76dc44mr16401755e9.37.1769151211625;
        Thu, 22 Jan 2026 22:53:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EAgP7Xbw4zJNOVdLvsjPPriv7/57FDa0q8O4cGQDe6/A=="
Received: by 2002:a05:600c:3150:b0:47e:c74a:d836 with SMTP id
 5b1f17b1804b1-48046fc7343ls15154775e9.2.-pod-prod-08-eu; Thu, 22 Jan 2026
 22:53:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKTDA5eovEMgNgcHM9HKZoHqLF1/tVHadYNdTD7HMWEZo5Vxs/6Kq5LDEUjt4RuWnRGHW5ioFD4fQ=@googlegroups.com
X-Received: by 2002:a05:600c:8289:b0:480:3ad0:93c0 with SMTP id 5b1f17b1804b1-4804c9aead2mr29180005e9.23.1769151209282;
        Thu, 22 Jan 2026 22:53:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151209; cv=none;
        d=google.com; s=arc-20240605;
        b=QcsMErDw/0W7UVcLrxEEXSNDkR9ZW4zG0DD0dHSzbnVZXS0agQEgcEylDexgu0FRmr
         royZLby/4nmNXvwHrv0TYlpL6WR+x2R9J5iXEF1yGns84+pQSG5BvGaztRDUBJdddk2F
         +WBy7njMvWn2ITLdvLvsrFJBtzE3mp46RAikXsJGJxRMNJTt2yA5H6Vxf/nIubbdZd9M
         cv6AxNQc/OyMjh27BsnjFy3bGUa83zZCRAyoT+9X7xTf0sUe2iiNwSzb/xlBMFg3t204
         WRXEAtL/WmfGZT/0bUI5lb7v5v/ASC1xpHCvMpwtO+UkLX60W8I6bnd7HAwM0G4LJSSp
         TrFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=FwnfOtyNNX1UiOQaNmveWBNxfRACVrp0A1Nv9nB3IOs=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=k7XJGFKq3MCzvoEshPAV67+Bohvb1nPl24CAra3xqI5UJTL3QmKnatt2/BUTKEWzV+
         q1bgzh9CbixJXTvtHo+haP/ztoLbLs9rD+mlAUcmSwF7vvmsVjJmExYZdSnqjXFeyb0+
         kIwJ6DTOjPCCkPxPiUQi2nXJSAH5BPUWk0nAA1/cHGgj6emL0xOEFrYinFCfNjiJ4FWl
         hnjQWl5Iw+dNi4rP5shKUG+ntSC3eBlMTvBzy8eIL2l1QNbY5lrUD4Ta5YzQSS+UcZvc
         rkNPRLIV74N28Pm2qluVOZZkVPAxgafJoW89adSasWMfwOcDxVY8bZJgW2nwVRh0OOSZ
         hRag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pcUtnIn8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pcUtnIn8;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4804d3b0840si154715e9.0.2026.01.22.22.53.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:29 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D62C05BCD2;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AFC871395E;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id aEakKtYac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:53 +0100
Subject: [PATCH v4 15/22] slab: simplify kmalloc_nolock()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-15-041323d506f7@suse.cz>
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
 header.i=@suse.cz header.s=susede2_rsa header.b=pcUtnIn8;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=pcUtnIn8;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB25VZTFQMGQEZ3TCJ5Q];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,suse.cz:mid,suse.cz:email]
X-Rspamd-Queue-Id: 4857371307
X-Rspamd-Action: no action

The kmalloc_nolock() implementation has several complications and
restrictions due to SLUB's cpu slab locking, lockless fastpath and
PREEMPT_RT differences. With cpu slab usage removed, we can simplify
things:

- relax the PREEMPT_RT context checks as they were before commit
  99a3e3a1cfc9 ("slab: fix kmalloc_nolock() context check for
  PREEMPT_RT") and also reference the explanation comment in the page
  allocator

- the local_lock_cpu_slab() macros became unused, remove them

- we no longer need to set up lockdep classes on PREEMPT_RT

- we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
  since there's no lockless cpu freelist manipulation anymore

- __slab_alloc_node() can be called from kmalloc_nolock_noprof()
  unconditionally. It can also no longer return EBUSY. But trylock
  failures can still happen so retry with the larger bucket if the
  allocation fails for any reason.

Note that we still need __CMPXCHG_DOUBLE, because while it was removed
we don't use cmpxchg16b on cpu freelist anymore, we still use it on
slab freelist, and the alternative is slab_lock() which can be
interrupted by a nmi. Clarify the comment to mention it specifically.

Acked-by: Alexei Starovoitov <ast@kernel.org>
Reviewed-by: Hao Li <hao.li@linux.dev>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   1 -
 mm/slub.c | 144 +++++++++++++-------------------------------------------------
 2 files changed, 29 insertions(+), 116 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 37090a7dffb6..47ca9e2cd3be 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -190,7 +190,6 @@ struct kmem_cache_order_objects {
  */
 struct kmem_cache {
 	struct kmem_cache_cpu __percpu *cpu_slab;
-	struct lock_class_key lock_key;
 	struct slub_percpu_sheaves __percpu *cpu_sheaves;
 	/* Used for retrieving partial slabs, etc. */
 	slab_flags_t flags;
diff --git a/mm/slub.c b/mm/slub.c
index 82950c2bc26d..92e75aeeb89b 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3690,29 +3690,12 @@ static inline unsigned int init_tid(int cpu)
 
 static void init_kmem_cache_cpus(struct kmem_cache *s)
 {
-#ifdef CONFIG_PREEMPT_RT
-	/*
-	 * Register lockdep key for non-boot kmem caches to avoid
-	 * WARN_ON_ONCE(static_obj(key))) in lockdep_register_key()
-	 */
-	bool finegrain_lockdep = !init_section_contains(s, 1);
-#else
-	/*
-	 * Don't bother with different lockdep classes for each
-	 * kmem_cache, since we only use local_trylock_irqsave().
-	 */
-	bool finegrain_lockdep = false;
-#endif
 	int cpu;
 	struct kmem_cache_cpu *c;
 
-	if (finegrain_lockdep)
-		lockdep_register_key(&s->lock_key);
 	for_each_possible_cpu(cpu) {
 		c = per_cpu_ptr(s->cpu_slab, cpu);
 		local_trylock_init(&c->lock);
-		if (finegrain_lockdep)
-			lockdep_set_class(&c->lock, &s->lock_key);
 		c->tid = init_tid(cpu);
 	}
 }
@@ -3799,47 +3782,6 @@ static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
 	}
 }
 
-/*
- * ___slab_alloc()'s caller is supposed to check if kmem_cache::kmem_cache_cpu::lock
- * can be acquired without a deadlock before invoking the function.
- *
- * Without LOCKDEP we trust the code to be correct. kmalloc_nolock() is
- * using local_lock_is_locked() properly before calling local_lock_cpu_slab(),
- * and kmalloc() is not used in an unsupported context.
- *
- * With LOCKDEP, on PREEMPT_RT lockdep does its checking in local_lock_irqsave().
- * On !PREEMPT_RT we use trylock to avoid false positives in NMI, but
- * lockdep_assert() will catch a bug in case:
- * #1
- * kmalloc() -> ___slab_alloc() -> irqsave -> NMI -> bpf -> kmalloc_nolock()
- * or
- * #2
- * kmalloc() -> ___slab_alloc() -> irqsave -> tracepoint/kprobe -> bpf -> kmalloc_nolock()
- *
- * On PREEMPT_RT an invocation is not possible from IRQ-off or preempt
- * disabled context. The lock will always be acquired and if needed it
- * block and sleep until the lock is available.
- * #1 is possible in !PREEMPT_RT only.
- * #2 is possible in both with a twist that irqsave is replaced with rt_spinlock:
- * kmalloc() -> ___slab_alloc() -> rt_spin_lock(kmem_cache_A) ->
- *    tracepoint/kprobe -> bpf -> kmalloc_nolock() -> rt_spin_lock(kmem_cache_B)
- *
- * local_lock_is_locked() prevents the case kmem_cache_A == kmem_cache_B
- */
-#if defined(CONFIG_PREEMPT_RT) || !defined(CONFIG_LOCKDEP)
-#define local_lock_cpu_slab(s, flags)	\
-	local_lock_irqsave(&(s)->cpu_slab->lock, flags)
-#else
-#define local_lock_cpu_slab(s, flags)					       \
-	do {								       \
-		bool __l = local_trylock_irqsave(&(s)->cpu_slab->lock, flags); \
-		lockdep_assert(__l);					       \
-	} while (0)
-#endif
-
-#define local_unlock_cpu_slab(s, flags)	\
-	local_unlock_irqrestore(&(s)->cpu_slab->lock, flags)
-
 static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
 {
 	unsigned long flags;
@@ -4405,20 +4347,6 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	return object;
 }
 
-/*
- * We disallow kprobes in ___slab_alloc() to prevent reentrance
- *
- * kmalloc() -> ___slab_alloc() -> local_lock_cpu_slab() protected part of
- * ___slab_alloc() manipulating c->freelist -> kprobe -> bpf ->
- * kmalloc_nolock() or kfree_nolock() -> __update_cpu_freelist_fast()
- * manipulating c->freelist without lock.
- *
- * This does not prevent kprobe in functions called from ___slab_alloc() such as
- * local_lock_irqsave() itself, and that is fine, we only need to protect the
- * c->freelist manipulation in ___slab_alloc() itself.
- */
-NOKPROBE_SYMBOL(___slab_alloc);
-
 static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
 		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
 {
@@ -5259,13 +5187,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	if (unlikely(!size))
 		return ZERO_SIZE_PTR;
 
-	if (IS_ENABLED(CONFIG_PREEMPT_RT) && !preemptible())
-		/*
-		 * kmalloc_nolock() in PREEMPT_RT is not supported from
-		 * non-preemptible context because local_lock becomes a
-		 * sleeping lock on RT.
-		 */
+	/*
+	 * See the comment for the same check in
+	 * alloc_frozen_pages_nolock_noprof()
+	 */
+	if (IS_ENABLED(CONFIG_PREEMPT_RT) && (in_nmi() || in_hardirq()))
 		return NULL;
+
 retry:
 	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
 		return NULL;
@@ -5274,10 +5202,11 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	if (!(s->flags & __CMPXCHG_DOUBLE) && !kmem_cache_debug(s))
 		/*
 		 * kmalloc_nolock() is not supported on architectures that
-		 * don't implement cmpxchg16b, but debug caches don't use
-		 * per-cpu slab and per-cpu partial slabs. They rely on
-		 * kmem_cache_node->list_lock, so kmalloc_nolock() can
-		 * attempt to allocate from debug caches by
+		 * don't implement cmpxchg16b and thus need slab_lock()
+		 * which could be preempted by a nmi.
+		 * But debug caches don't use that and only rely on
+		 * kmem_cache_node->list_lock, so kmalloc_nolock() can attempt
+		 * to allocate from debug caches by
 		 * spin_trylock_irqsave(&n->list_lock, ...)
 		 */
 		return NULL;
@@ -5286,42 +5215,31 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
 	if (ret)
 		goto success;
 
-	ret = ERR_PTR(-EBUSY);
-
 	/*
 	 * Do not call slab_alloc_node(), since trylock mode isn't
 	 * compatible with slab_pre_alloc_hook/should_failslab and
 	 * kfence_alloc. Hence call __slab_alloc_node() (at most twice)
 	 * and slab_post_alloc_hook() directly.
-	 *
-	 * In !PREEMPT_RT ___slab_alloc() manipulates (freelist,tid) pair
-	 * in irq saved region. It assumes that the same cpu will not
-	 * __update_cpu_freelist_fast() into the same (freelist,tid) pair.
-	 * Therefore use in_nmi() to check whether particular bucket is in
-	 * irq protected section.
-	 *
-	 * If in_nmi() && local_lock_is_locked(s->cpu_slab) then it means that
-	 * this cpu was interrupted somewhere inside ___slab_alloc() after
-	 * it did local_lock_irqsave(&s->cpu_slab->lock, flags).
-	 * In this case fast path with __update_cpu_freelist_fast() is not safe.
 	 */
-	if (!in_nmi() || !local_lock_is_locked(&s->cpu_slab->lock))
-		ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
+	ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
 
-	if (PTR_ERR(ret) == -EBUSY) {
-		if (can_retry) {
-			/* pick the next kmalloc bucket */
-			size = s->object_size + 1;
-			/*
-			 * Another alternative is to
-			 * if (memcg) alloc_gfp &= ~__GFP_ACCOUNT;
-			 * else if (!memcg) alloc_gfp |= __GFP_ACCOUNT;
-			 * to retry from bucket of the same size.
-			 */
-			can_retry = false;
-			goto retry;
-		}
-		ret = NULL;
+	/*
+	 * It's possible we failed due to trylock as we preempted someone with
+	 * the sheaves locked, and the list_lock is also held by another cpu.
+	 * But it should be rare that multiple kmalloc buckets would have
+	 * sheaves locked, so try a larger one.
+	 */
+	if (!ret && can_retry) {
+		/* pick the next kmalloc bucket */
+		size = s->object_size + 1;
+		/*
+		 * Another alternative is to
+		 * if (memcg) alloc_gfp &= ~__GFP_ACCOUNT;
+		 * else if (!memcg) alloc_gfp |= __GFP_ACCOUNT;
+		 * to retry from bucket of the same size.
+		 */
+		can_retry = false;
+		goto retry;
 	}
 
 success:
@@ -7361,10 +7279,6 @@ void __kmem_cache_release(struct kmem_cache *s)
 {
 	cache_random_seq_destroy(s);
 	pcs_destroy(s);
-#ifdef CONFIG_PREEMPT_RT
-	if (s->cpu_slab)
-		lockdep_unregister_key(&s->lock_key);
-#endif
 	free_percpu(s->cpu_slab);
 	free_kmem_cache_nodes(s);
 }

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-15-041323d506f7%40suse.cz.
