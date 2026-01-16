Return-Path: <kasan-dev+bncBDXYDPH3S4OBB743VHFQMGQEXVF36HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A6B4D32C7E
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:41:05 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-38317963123sf12996831fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:41:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574465; cv=pass;
        d=google.com; s=arc-20240605;
        b=MtAp3LtHdAdG97Fr5evs6Au/bQ4UOtn5otKM02peU1tF7sKT+wGFdV+N9PGYcbDi9B
         9PeX2npfP2wx9Q3mZKOKdnmxneDmTI+W2CBpwM0E+MyDJA2KikmnC7YEfeXFiykJ1kva
         9M0EwKf1BmzaEZEYGR9RIPQME+nP9aW1deWvrV9oH8qTa/9xXA1hOQfvlSMSOT9YRqJX
         3eL/va/pYaD1dKEW4F9AWHMB0d/EHcaxx5Cjyp+TVjo87X02ies8ezbc606jTVne47FY
         BbifYQ/cdPSiCqUwYbNVJKJ3eajlIvd5FDGT2wdjH3cEfQfHNwTnChTQt+PQxutqZcSq
         CcDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=CwTHlkHNs6KuVrVST7MoOddrgAG9o8RFhEDO+q0o6Fg=;
        fh=/dAB12y3GXdHbQu31uc6k6q1v5hPnv5RAv42MJ4QMfg=;
        b=PArVbEUS8H9H8/cM6EnrbxmseMx6yRCBJacnlXZ2WFYyS7DBjjNDWEMtCKKsZhD+wW
         1996pPp1A2zrAvnmi0e/TnXjlgYKTFqZJ/gSgt8k/Bhdn+VMclk3s5n/MlYIz3wjvbo+
         1+zZW+21UsGAOn+TyFoOXANJXiHr0Ua2XyI5CsfgS4IxpwphoQsvNMujLb+Ye7eaoCqr
         MPar4DX5shDuH+ex/+w+xB08XAkL1TsOKqFtiKjmwlMUDF67awZ23dlNcba/U5zuDFPs
         U4sQQqhrnY0SKSCZGulmLBjsol+DmjJ6nXrsCTxBD+GivRbUuFhktxEo4viYk7/UJmgD
         LDzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YIg7LUNR;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YIg7LUNR;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574465; x=1769179265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CwTHlkHNs6KuVrVST7MoOddrgAG9o8RFhEDO+q0o6Fg=;
        b=XPZv/jeykjxSIrgjIbiTj/+VkeWbupTjFg2rLVCmBl7AkCbiXstgciEVRzpGBRYCoh
         DzEcqwStW6ttD8UdL3+GYXNlwCtOmPqaEY2+nmZDVWT+aBqpEhAUyIiWlJoZVtxegnDK
         cPla18pfePwRDso86n1eFy3M7RjbRbEv2P8dxbsOktwQLiaIM5c1SnPBmFBIRZLFQmRw
         t0abk+pHNvOAp83BUahPZK4rnPPrKQjmGdspCnWzT7g7UPJ+qEkzR9sw93aUlGEtn28Z
         LtJkLdpbPde39PDohqGS0Bqhq/DVLy088+ZSHY4F3uZIeWV0g6w/633XKPks97pAWJR5
         BEww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574465; x=1769179265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CwTHlkHNs6KuVrVST7MoOddrgAG9o8RFhEDO+q0o6Fg=;
        b=IWrFnbD9TLlFHVjnj7XWJQb+2tm5gLY1dALs/q4uPK37FvrU1n/pYf/PkVjRrTR/SI
         nHv4Ikjrbd5aqKvfHZzg9Efm81fNfZL8wjD0nFCttgyu6fQQLoUiLRAU1OE5JZqbX8XY
         +H3QgYp3iCyaQ5nLtF8r9N81PzSn/IFuHQtApcMees/OGhBYiKsOmX3/hny/QmxZeiLi
         +/7j4Smyev22We4rcXMLzEfIeWFAsG7E3eI8TxLidzQZSxeD6vpAjQqdrKrkk9xHgiOZ
         o5OZ/3/Jzi1Hi3VutU3Cx0/YfaZmB9G4o7QLNGGgkL2gTuGgOxG/zEtfhCbTGB2ygZgg
         RYBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0l8ZYrx2f+nNnDYgI/EKOAaR/gd2xSnJw4ZL1DaBfuRhjfUgUB40kfpICJTaqk9j4Fd8Q+A==@lfdr.de
X-Gm-Message-State: AOJu0Yy/8I2xueJuozooLrfX985TkcCCs4aoI98fX1ash67YgDmxA9q3
	cXB0T7E9Zo6vYixKCE4tSYyH61vYpsC/9IWcwd7pTBtVPeIkj5foSwM7
X-Received: by 2002:a05:651c:c91:b0:356:7e6f:c66b with SMTP id 38308e7fff4ca-38384311fb8mr11136231fa.38.1768574464498;
        Fri, 16 Jan 2026 06:41:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HZXdE6WGeVczNN6FLbKXAN3+HK+3CMy/1rKSOT1sxmIg=="
Received: by 2002:a2e:854f:0:b0:383:10b5:939e with SMTP id 38308e7fff4ca-3836ee7fad2ls3963321fa.1.-pod-prod-03-eu;
 Fri, 16 Jan 2026 06:41:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVQgRabHYWIBDVpd2tzfKjLR1naxLJJoWRkhjioowVR4DpVunUkaLCl0En1GOFnHHJtHadteSCuHCQ=@googlegroups.com
X-Received: by 2002:a05:651c:a07:b0:383:1d66:c1fa with SMTP id 38308e7fff4ca-38384178824mr11095351fa.10.1768574461662;
        Fri, 16 Jan 2026 06:41:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574461; cv=none;
        d=google.com; s=arc-20240605;
        b=lF95pJT9jQrJeWvORWgXLxIYojacA7F2KanxibkHRwnjPQJmldjROA6o0eqEKlSECD
         3cIzmHMSK0KS6SFKKcNlVhQTSYmYsofbFb02kn3ZgxT9ku9P3JDdbIwd4iNV6ggSBbKz
         yz2ahrYrW2Fhyt4bU9qDZ2/zxXlBP3fJXsVPG3vK33SHO7bKbO3vBbiUPlVMJWVqzzaX
         MVkBocUXzMMpL+Z2D1eDDzgC4pLIz2xrbkIqAkzdEWy07TBi4ceG4kLQ6UnOSJEm1NBp
         BayMMr5OuHt5F4zUMk/VXlDE7OxhokSGUgJsSXjaH3bXXM0xjhTT/JcoHrh4xgmjXro/
         MNag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=7lW8Ood/bwUVgrzq8dslY//7lpLYcu/ZEOKOtqQvI2s=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=DqK5u/LPCLuXIS8fQYLLWMNqrCH8VzFVviHpHcFx4hPCLITcrBE4vojJC8QVxY6Q2R
         2+Y5j/REyyJJCAmzR1S/1myQdAkAC6kwgekFa/17Fp31KvqbopD7elYW2QBCgwhnUZiO
         qtnyauHXUmAVlJAhDREJgATa1JOgFIYtuyCbjkcADyRvF+MVSQzXVRkyte9kuBYRl6s3
         uugGggvJ65W08cHneI1LSs0OG6zDstvaF5+czR3dpvhWPhzDLINAgtTbRzaSfTNXD+ZT
         hIw7dqbafZOJUqmmOE7DePELVfMHzrIHwszb28TVb5phLgiiogE6Ncn1DBnNSeSLaPNu
         RQeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YIg7LUNR;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YIg7LUNR;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d0ff47si558451fa.1.2026.01.16.06.41.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:41:01 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 34C6C337CD;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 16EB53EA65;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id wChTBeZNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:34 +0100
Subject: [PATCH v3 14/21] slab: simplify kmalloc_nolock()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-14-5595cb000772@suse.cz>
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
X-Spam-Score: -4.51
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
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq),to(RL941jgdop1fyjkq8h4)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 34C6C337CD
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YIg7LUNR;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=YIg7LUNR;       dkim=neutral (no key)
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

The kmalloc_nolock() implementation has several complications and
restrictions due to SLUB's cpu slab locking, lockless fastpath and
PREEMPT_RT differences. With cpu slab usage removed, we can simplify
things:

- relax the PREEMPT_RT context checks as they were before commit
  a4ae75d1b6a2 ("slab: fix kmalloc_nolock() context check for
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

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h |   1 -
 mm/slub.c | 144 +++++++++++++-------------------------------------------------
 2 files changed, 29 insertions(+), 116 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 4efec41b6445..e9a0738133ed 100644
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
index 33f218c0e8d6..8746d9d3f3a3 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3694,29 +3694,12 @@ static inline unsigned int init_tid(int cpu)
 
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
@@ -3803,47 +3786,6 @@ static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
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
@@ -4402,20 +4344,6 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	return freelist;
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
@@ -5253,13 +5181,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
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
@@ -5268,10 +5196,11 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
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
@@ -5280,42 +5209,31 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
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
@@ -7334,10 +7252,6 @@ void __kmem_cache_release(struct kmem_cache *s)
 	cache_random_seq_destroy(s);
 	if (s->cpu_sheaves)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-14-5595cb000772%40suse.cz.
