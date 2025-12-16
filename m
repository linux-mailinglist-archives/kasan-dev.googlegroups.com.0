Return-Path: <kasan-dev+bncBAABBCELQPFAMGQEZ7HKH7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 48232CC09C4
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 03:35:54 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-3800a9b1d12sf351361fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 18:35:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765852553; cv=pass;
        d=google.com; s=arc-20240605;
        b=M90AIjeFZkOVsQwV59JlU3anzlumeMkQelSj6rBB1aB/EawhrB1szURx2dum14LG5q
         fAOwE9qnH8pltFEIpKDBfcqyn/ANQeDf7s3CuomOc4f3T9zXL+nYxgjlxpiQEPOOtWcD
         IKI80bL/hPFPTtTkQ6rpLVHSM79IAmXSXWnvcbxebjcE6HvjHZublPs+1FyKo9Y84vap
         td28FetCU+qtV/A5QZmexFG7yaZS3u2VmxUvQhllT2XhYe0z19svwL4LU9sYhMZUjg+g
         V94WC3kfKoZVifp5ASDLkOp4VPaT5WrnJONQh4OF/LIOflS/ubZEc8KGh6ojMWaygl8Q
         sgzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/DH/6Hgq1Uz5vrBZkneKmTZTzT7GlhFqPKUU99cq7N4=;
        fh=Iy5kpIwyLmvo2sRIkKHfFgsxz4g8Vx/jC2aPXtOwAuU=;
        b=L2XmSeu1ZOYqSSKLm/39Qrx7nbJVfEg2XXaTwedMpGgmMG8hHTD5DK8XIJJ8wlP0+K
         lymQiY+fhglDOqelrGwTVdoOxb0BIeQQ1zftfvjWMB6eaGZuTsBRacEKRQPcDo2qJnFR
         nY+G1BMaVJDHw01I26rkAz3/parAKA+xBa54Ga6X922yMiCrfJzCSYh5LYj6FbFU8eqN
         IcRkFwUZZbKVo6DwgkqG0QuryM8FdClZkBczCZRJeoQBJxmU9p7ixKMcoMvBHCh2RUkI
         e40P7If0UlTv/4O6f0Q+0YZN7EO1fJPfUT8WcPvjXwmLYNtBXccfrGJnYrMcfuPe4tNh
         8d9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="TxI7E3/S";
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765852553; x=1766457353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/DH/6Hgq1Uz5vrBZkneKmTZTzT7GlhFqPKUU99cq7N4=;
        b=LZ1cTYrV+Wwl38coaPcDz4kG1EoQso17862iDTKGcQ79GV9OdDcAl/2eNSwTnsAjh3
         EdApYNuffp/Bd7rLO0JcQvr8lGe1XgNBRRLMeDZ8lvd6iyS8Fz3gT7RDN9xbQHLr0lbz
         OCQY4n/cY55gDyuHcLNnZD15paXWu11kyMQl86zWPAJqmBlO9cS9S+DPx8vIrt9Xxq+4
         bv4Oos95r2pxiVNLa7onwEoaJKCAieEKZ3fHK5OPRTeUsKPl+HAPtfmqd/+BDAEm1E/C
         xCTLQs5ftfebK/C3t8Ti0xBhH/bwsn/JnJyEltE4CUcffd2UFSoHOWdh3xHSk5g+ioKB
         5bbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765852553; x=1766457353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/DH/6Hgq1Uz5vrBZkneKmTZTzT7GlhFqPKUU99cq7N4=;
        b=QBaJxd3+2qtZOSz9jVR8g14Zt6wWUZbzOliDEQUc2y/gn9WLUuO8CB9cuZDvND+v3Y
         dzqfIJC56F0TR0/tj4rgH4iEMtFQYzgxe241C7vOOgVBK54QaPIP+/7jfILT7Ifhh8+v
         qnQdVQbBFZi+wrikaJmKBS2GBUWuswVWBeH9E+uAssHw3Iqq/6koYu5RTN6eQeA2iKlM
         dxLx4kqFKDIJ3w1uFDZfi91Xor2O4YobE2gXz+Pa84L1DdW5hLCpZlpPUA4s+OuVTzp+
         Q2P6hRmud5V405CP+/IfK5GRbqQkVtAppm8Tp2NOamWWg2I0cMyBCP7JIdzlyS+j03Jp
         UOaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVFJ8dpADaZOcGeJqM/s7x1wbY8mtB/bTkWOQssh0ZTDdgjs2ATms7Cw35VB/fBW9rR/NcbAw==@lfdr.de
X-Gm-Message-State: AOJu0YwdPP+huGlm7goSMlTot1ocg4te31Mz14tdRoByEiWvWBnb/Oif
	BPSyV+iZRaoxWHs13RqKBCUX9wA4T8FQSHCsH9PwsgEKpyFKD1W23svn
X-Google-Smtp-Source: AGHT+IFNsU3+F2lYtByC+Ubyn+cQrJnonHa4OL9dDONVcgCrv6y/0wEzRSyUoKTu0+XjL+3H8R3Gfw==
X-Received: by 2002:a2e:9a04:0:b0:37b:b00b:799d with SMTP id 38308e7fff4ca-37fd0874e13mr36855351fa.24.1765852553319;
        Mon, 15 Dec 2025 18:35:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ7av08Wo2kGYpT607HhHEGLyvpX03YnkIyZbpfeRSt3g=="
Received: by 2002:a05:651c:483:b0:37f:b4e0:a50c with SMTP id
 38308e7fff4ca-37fcef199b9ls2943371fa.0.-pod-prod-03-eu; Mon, 15 Dec 2025
 18:35:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVjiQED0ciK7viSv0dCznTYkeQBEN7RUX6u8TFyd75nuugvbfBhrrGPpU+KqJXdMbVHep0TytsSVUU=@googlegroups.com
X-Received: by 2002:a2e:bcc5:0:b0:37a:d2e:4c07 with SMTP id 38308e7fff4ca-37fd0874e82mr40875201fa.20.1765852551096;
        Mon, 15 Dec 2025 18:35:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765852551; cv=none;
        d=google.com; s=arc-20240605;
        b=PMcG2AOpQwrxs8S0Coafj9zL+dJdRqZNT9OQRrZ6+yppTtAChKCQB5I0p+Rphd2U2+
         tj7PbL7NCv/FvCHdSBjS57FQxtaW1R9+4SvrBKYjWzBzCCLtQVsF9TGx+bctOA2pAIYs
         kCvvJxj2imOhgxwgj+JaYPBStKn0j6CQmtowjJZC24M8pkVS+KDMhwhe4iUz/IMnAR7o
         d05bjvsxNZjgGpnVRvBGrANPLn0rNmlYGNw1rciiQKxrPS4OgL3THDJIqpgHAC81AITL
         aU1+rBOJ0Do3xVrnnMtwWDuy84gbVIgrJsK1oqN+CTWAn0LEqk0u5YcD7wnJ5zO0rKlm
         Oduw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=14Qnu6glJrs2grpIMzCNPU4lzsGBr4BJiAY7oS1kvoU=;
        fh=UxK0f7Sg+Kvncwz8/Gj/XfKMLaSYI6WylwLy90nXgxM=;
        b=MBsECTuo089Yra12BXFZlFtTvFInsPd4NIoDOZc2F8f+o1PsWFjGT59/pXrbzJ3GUL
         AI/5XbcbJ/Axvl9jOH3ChU/Y5TxOzjF+hPCDYINvDr2+1Z3ZaqOTSNd9ck/jOeRSNPhU
         kLt6tqziJ+8y0lgKM0OIPCQurpW09sYrVTdlmchW/hOlPS7iLA0y8XgY+Ffc/K43IHUR
         oandaWvyKn7w7zAAqcPHY1/FryrreLfxFf9XSipMpv1yvcikL30cOEW8EQIa5qdGE3t8
         akCfpEaJ4iqpjTKZyu3D9eQy695k0RMqZVAVLlV6CXdBE+UAn99f0Jebwzqtg6CF1AjM
         RAnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="TxI7E3/S";
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta1.migadu.com (out-183.mta1.migadu.com. [2001:41d0:203:375::b7])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37fded0c6fbsi1247191fa.4.2025.12.15.18.35.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 18:35:51 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b7 as permitted sender) client-ip=2001:41d0:203:375::b7;
Date: Tue, 16 Dec 2025 10:35:33 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC 14/19] slab: simplify kmalloc_nolock()
Message-ID: <4ukrk3ziayvxrcfxm2izwrwt3qrmr4fcsefl4n7oodc4t2hxgt@ijk63r4f3rkr>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-14-6ffa2c9941c0@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251023-sheaves-for-all-v1-14-6ffa2c9941c0@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="TxI7E3/S";       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b7 as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Oct 23, 2025 at 03:52:36PM +0200, Vlastimil Babka wrote:
> The kmalloc_nolock() implementation has several complications and
> restrictions due to SLUB's cpu slab locking, lockless fastpath and
> PREEMPT_RT differences. With cpu slab usage removed, we can simplify
> things:
> 
> - the local_lock_cpu_slab() macros became unused, remove them
> 
> - we no longer need to set up lockdep classes on PREEMPT_RT
> 
> - we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
>   since there's no lockless cpu freelist manipulation anymore
> 
> - __slab_alloc_node() can be called from kmalloc_nolock_noprof()
>   unconditionally
> 
> Note that we still need __CMPXCHG_DOUBLE, because while it was removed
> we don't use cmpxchg16b on cpu freelist anymore, we still use it on
> slab freelist, and the alternative is slab_lock() which can be
> interrupted by a nmi. Clarify the comment to mention it specifically.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h |   1 -
>  mm/slub.c | 100 ++++----------------------------------------------------------
>  2 files changed, 6 insertions(+), 95 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index b2663cc594f3..7dde0b56a7b0 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -208,7 +208,6 @@ struct kmem_cache_order_objects {
>   */
>  struct kmem_cache {
>  	struct kmem_cache_cpu __percpu *cpu_slab;
> -	struct lock_class_key lock_key;
>  	struct slub_percpu_sheaves __percpu *cpu_sheaves;
>  	/* Used for retrieving partial slabs, etc. */
>  	slab_flags_t flags;
> diff --git a/mm/slub.c b/mm/slub.c
> index 6f5ca26bbb00..6dd7fd153391 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3679,29 +3679,12 @@ static inline unsigned int init_tid(int cpu)
>  
>  static void init_kmem_cache_cpus(struct kmem_cache *s)
>  {
> -#ifdef CONFIG_PREEMPT_RT
> -	/*
> -	 * Register lockdep key for non-boot kmem caches to avoid
> -	 * WARN_ON_ONCE(static_obj(key))) in lockdep_register_key()
> -	 */
> -	bool finegrain_lockdep = !init_section_contains(s, 1);
> -#else
> -	/*
> -	 * Don't bother with different lockdep classes for each
> -	 * kmem_cache, since we only use local_trylock_irqsave().
> -	 */
> -	bool finegrain_lockdep = false;
> -#endif
>  	int cpu;
>  	struct kmem_cache_cpu *c;
>  
> -	if (finegrain_lockdep)
> -		lockdep_register_key(&s->lock_key);
>  	for_each_possible_cpu(cpu) {
>  		c = per_cpu_ptr(s->cpu_slab, cpu);
>  		local_trylock_init(&c->lock);
> -		if (finegrain_lockdep)
> -			lockdep_set_class(&c->lock, &s->lock_key);
>  		c->tid = init_tid(cpu);
>  	}
>  }
> @@ -3792,47 +3775,6 @@ static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
>  	}
>  }
>  
> -/*
> - * ___slab_alloc()'s caller is supposed to check if kmem_cache::kmem_cache_cpu::lock
> - * can be acquired without a deadlock before invoking the function.
> - *
> - * Without LOCKDEP we trust the code to be correct. kmalloc_nolock() is
> - * using local_lock_is_locked() properly before calling local_lock_cpu_slab(),
> - * and kmalloc() is not used in an unsupported context.
> - *
> - * With LOCKDEP, on PREEMPT_RT lockdep does its checking in local_lock_irqsave().
> - * On !PREEMPT_RT we use trylock to avoid false positives in NMI, but
> - * lockdep_assert() will catch a bug in case:
> - * #1
> - * kmalloc() -> ___slab_alloc() -> irqsave -> NMI -> bpf -> kmalloc_nolock()
> - * or
> - * #2
> - * kmalloc() -> ___slab_alloc() -> irqsave -> tracepoint/kprobe -> bpf -> kmalloc_nolock()
> - *
> - * On PREEMPT_RT an invocation is not possible from IRQ-off or preempt
> - * disabled context. The lock will always be acquired and if needed it
> - * block and sleep until the lock is available.
> - * #1 is possible in !PREEMPT_RT only.
> - * #2 is possible in both with a twist that irqsave is replaced with rt_spinlock:
> - * kmalloc() -> ___slab_alloc() -> rt_spin_lock(kmem_cache_A) ->
> - *    tracepoint/kprobe -> bpf -> kmalloc_nolock() -> rt_spin_lock(kmem_cache_B)
> - *
> - * local_lock_is_locked() prevents the case kmem_cache_A == kmem_cache_B
> - */
> -#if defined(CONFIG_PREEMPT_RT) || !defined(CONFIG_LOCKDEP)
> -#define local_lock_cpu_slab(s, flags)	\
> -	local_lock_irqsave(&(s)->cpu_slab->lock, flags)
> -#else
> -#define local_lock_cpu_slab(s, flags)					       \
> -	do {								       \
> -		bool __l = local_trylock_irqsave(&(s)->cpu_slab->lock, flags); \
> -		lockdep_assert(__l);					       \
> -	} while (0)
> -#endif
> -
> -#define local_unlock_cpu_slab(s, flags)	\
> -	local_unlock_irqrestore(&(s)->cpu_slab->lock, flags)
> -
>  static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
>  {
>  	unsigned long flags;
> @@ -4320,19 +4262,6 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>  
>  	return freelist;
>  }
> -/*
> - * We disallow kprobes in ___slab_alloc() to prevent reentrance
> - *
> - * kmalloc() -> ___slab_alloc() -> local_lock_cpu_slab() protected part of
> - * ___slab_alloc() manipulating c->freelist -> kprobe -> bpf ->
> - * kmalloc_nolock() or kfree_nolock() -> __update_cpu_freelist_fast()
> - * manipulating c->freelist without lock.
> - *
> - * This does not prevent kprobe in functions called from ___slab_alloc() such as
> - * local_lock_irqsave() itself, and that is fine, we only need to protect the
> - * c->freelist manipulation in ___slab_alloc() itself.
> - */
> -NOKPROBE_SYMBOL(___slab_alloc);
>  
>  static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
>  		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
> @@ -5201,10 +5130,11 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  	if (!(s->flags & __CMPXCHG_DOUBLE) && !kmem_cache_debug(s))
>  		/*
>  		 * kmalloc_nolock() is not supported on architectures that
> -		 * don't implement cmpxchg16b, but debug caches don't use
> -		 * per-cpu slab and per-cpu partial slabs. They rely on
> -		 * kmem_cache_node->list_lock, so kmalloc_nolock() can
> -		 * attempt to allocate from debug caches by
> +		 * don't implement cmpxchg16b and thus need slab_lock()
> +		 * which could be preempted by a nmi.
> +		 * But debug caches don't use that and only rely on
> +		 * kmem_cache_node->list_lock, so kmalloc_nolock() can attempt
> +		 * to allocate from debug caches by
>  		 * spin_trylock_irqsave(&n->list_lock, ...)
>  		 */
>  		return NULL;
> @@ -5214,27 +5144,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  	if (ret)
>  		goto success;
>  
> -	ret = ERR_PTR(-EBUSY);
> -
>  	/*
>  	 * Do not call slab_alloc_node(), since trylock mode isn't
>  	 * compatible with slab_pre_alloc_hook/should_failslab and
>  	 * kfence_alloc. Hence call __slab_alloc_node() (at most twice)
>  	 * and slab_post_alloc_hook() directly.
> -	 *
> -	 * In !PREEMPT_RT ___slab_alloc() manipulates (freelist,tid) pair
> -	 * in irq saved region. It assumes that the same cpu will not
> -	 * __update_cpu_freelist_fast() into the same (freelist,tid) pair.
> -	 * Therefore use in_nmi() to check whether particular bucket is in
> -	 * irq protected section.
> -	 *
> -	 * If in_nmi() && local_lock_is_locked(s->cpu_slab) then it means that
> -	 * this cpu was interrupted somewhere inside ___slab_alloc() after
> -	 * it did local_lock_irqsave(&s->cpu_slab->lock, flags).
> -	 * In this case fast path with __update_cpu_freelist_fast() is not safe.
>  	 */
> -	if (!in_nmi() || !local_lock_is_locked(&s->cpu_slab->lock))
> -		ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
> +	ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
>  
>  	if (PTR_ERR(ret) == -EBUSY) {

After Patch 10 is applied, the logic that returns `EBUSY` has been
removed along with the `s->cpu_slab` logic. As a result, it appears that
`__slab_alloc_node` will no longer return `EBUSY`.

>  		if (can_retry) {
> @@ -7250,10 +7166,6 @@ void __kmem_cache_release(struct kmem_cache *s)
>  {
>  	cache_random_seq_destroy(s);
>  	pcs_destroy(s);
> -#ifdef CONFIG_PREEMPT_RT
> -	if (s->cpu_slab)
> -		lockdep_unregister_key(&s->lock_key);
> -#endif
>  	free_percpu(s->cpu_slab);
>  	free_kmem_cache_nodes(s);
>  }
> 
> -- 
> 2.51.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4ukrk3ziayvxrcfxm2izwrwt3qrmr4fcsefl4n7oodc4t2hxgt%40ijk63r4f3rkr.
