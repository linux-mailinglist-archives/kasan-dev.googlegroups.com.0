Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCVITSVQMGQEBGYQWCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 26A8D7FD45A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 11:35:56 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-41cb4d6744bsf80539181cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 02:35:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701254155; cv=pass;
        d=google.com; s=arc-20160816;
        b=rhKlCkdDgqllwls2Av4JdQzY2RFDT2wUJxhQN60fs+r1MmdWLNkihc8lTon3yYwRB7
         zBosTZ0IXsb5ls51PFmBma77tBE6F4I4xvQWRQeVhXZJAGPpvJ4EtsKnezOM5CjKSLnq
         L0+5ad6DbyuHKhZR+UIlfsMdZ8tkxqy7YGuryyHcKWeyRCOpVW49nBbTla/VTwsV3Ciu
         icRFlVv+L/yZz4aoCcP+xyuf135u1LNfPFZkD64MHniLBlugIq867Z82h4wA+mMnMB6q
         zbpAnDqeNycUweoLTctfLrMHMKSWt8FI7kBnw57VREPAKWLDvxqA5OTz3x419mrcysW0
         /npA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Al1gl/VVVKmFG7OJk60lMThW5W7hSA1n3WpWGyNjl70=;
        fh=BCNYuPqol1vLzLo/yJnM/ouRZane89kp7ezRxw3G5Zc=;
        b=XkVyDo6WTuHqS9IkhIdnyfsYNY7+r5XFWCJuYzU5pHil8A73aKmIenNrMESb3pLPux
         Sz/rCLtsEbw/9LEbJSkeE1mvFXi249HxS4DYvwcEzdYn6w0XcNvYvhnRBTQG95JaykcH
         Kn4T/mxcbbrixUYtTzMO0cdMwN46ppbr7IYB483MQ3/ICeLru5rB45mEcGarn0OBHzCG
         fcD7jVy0SEWLLnlcWiehcz2nTnhwMwsRZSmNe3uintSfwjC4R0QZS8AEDOZHIOvjYczt
         /7d20AcCS4KisUd+MITVdURLyF4p+Qcpkd+/xeE0bfmMduXCn44ERI8U6CWRb2IKDWNR
         wHyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Lp/+o5/S";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701254155; x=1701858955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Al1gl/VVVKmFG7OJk60lMThW5W7hSA1n3WpWGyNjl70=;
        b=xtP8TUmSrOw8zrp4mOrAsPs64PLghLgzaJX1QlTL5Qm1q/TTpljSvD2DbYTbwZeBvS
         kPsuYERJmSTI78zUjcKBXiW45eYoAzlitJjkbYluanKg/8L+3gKOYxDEiJZrhq24FJjY
         Ek3/ldcidFAQKPaTDEaS4vqhn2lLhV6Z9emfSJK2LlhNNE/rt+I4qiO9YAV5cp74rY5V
         k7uWwCMR/1Na2+8Ce9ku1riEYuC5VkyV/wKJc8W9bN3N4xAOWdfBxsXtq7v7vcpBD5KL
         cs4PRX6pZE2Pdu6soF3w3bGT8VlDtIY9+nC6DFtv0kEf72CQKP/4tTCKusGT77oA98Xb
         Rn1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701254155; x=1701858955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Al1gl/VVVKmFG7OJk60lMThW5W7hSA1n3WpWGyNjl70=;
        b=rCProuEtYi7hOiGxZjhLfsAMuGvzDXw96yw4LZVi5v4iPptocvzA7XmZYu4ME8VNph
         2PJjrzK2CGp/wqO+TcyjNH4vatYNDM9lOZ+CWHHDeZU8D/7CrD6JwFNkhO9dvw+G32+x
         BqYBeXGx1ZH+nxBR8vZKKFSucnbDV0BcqqHSmL3V3htuSyeKfoK+kT+EQemoa5pHIMod
         rI2ecuDsYCYdyaepyENSHdabYFwvVkBPB8XSG+6XPyY8Uo5W8Gn5KZ8arcgFUs8K/wEc
         qQV8gIIFO+e+2ejCo0WMdf4HuHEROhReKrvfet+TSZGc1rp+V2HW+wWcHzC5SCvbUjuy
         w57A==
X-Gm-Message-State: AOJu0YxADi2DNAyuwDy20SYhkPbIsKf1LATzEmsAUWhbrKQcQyCvgwfk
	uZS9QL+VqeKQlUSD20Pc6I0=
X-Google-Smtp-Source: AGHT+IH92PEhVA5t9TzcFVb2dus0OXlp2Hse8YYPoLH+NnZ/C0CI/NrIDVk0LQGQLuVUGM1cFxL8qQ==
X-Received: by 2002:a05:622a:1214:b0:412:206b:92e6 with SMTP id y20-20020a05622a121400b00412206b92e6mr21630835qtx.16.1701254155020;
        Wed, 29 Nov 2023 02:35:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:17cc:b0:423:a0d4:8c4a with SMTP id
 u12-20020a05622a17cc00b00423a0d48c4als1018469qtk.0.-pod-prod-03-us; Wed, 29
 Nov 2023 02:35:54 -0800 (PST)
X-Received: by 2002:a05:620a:10b5:b0:77d:776b:528d with SMTP id h21-20020a05620a10b500b0077d776b528dmr17814935qkk.44.1701254154260;
        Wed, 29 Nov 2023 02:35:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701254154; cv=none;
        d=google.com; s=arc-20160816;
        b=KVoPx5UjjP7H3nWsJKL6/6hPvQ27QoRFZzVX4vlzZE/LprU6G/OBTtRRiX6Ymq7nvF
         isoOQrdt1xuLDiyoJ9IW7enoRw5sClnYMvtQz0r/Tlo83TVrzpIE3uZk5L/RR6OSnkCo
         mjrApCXi9wp2/hJkJ1Nku9KdG8/x7mK3CAL4kVjVGRnTa5f1/md6PSCISnq5pX3ba1a9
         fXzY0bYzsOp9OUtgxOZiQr29vB23kLztDNHMv9sXmOy+63SLWLW0W9HsooqM2lgkB/t6
         60USRGwcOOVWZ9gZbffPoNC4yP+5Bdj1H6qw/QznW/fxdqFavK7oArQ9vTriAeN/SIrh
         0xVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iMrQed01JJcN4xQKdeWzhemwVY/MGHkgvTWPoO+Z2wQ=;
        fh=BCNYuPqol1vLzLo/yJnM/ouRZane89kp7ezRxw3G5Zc=;
        b=O/NnyGywUxchH1Ivrg8/AmOd5nMLFHSxlP3I+4hzllt8xuGT8h1hvOuEaJ5+3aEmOk
         q2FZl5OkPkEEfLo8tuUDm4iJPpd4LSKxmKFGTRwdpdJwncKE9geveOAKJh0EH+INAmtP
         YQfltK5Ba1x1iuzbXj9z1FgqueFXGjD+qnHxw3sSTzOEMJc0pb9nfJ7D3gqhFfYVqNdx
         id9x34ZEPS1wH7Jrb43NUkbltEEtGEfdYaHgs6iul2MBOqeRppqiSH3BUv5WagWnhff+
         qdaR2asdmOGpDOhed8ezvnoESqyXj/vwSBaGXiPfOtMYAsTl88nmGixJvRaYMeTwFmjf
         eB3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Lp/+o5/S";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2b.google.com (mail-vs1-xe2b.google.com. [2607:f8b0:4864:20::e2b])
        by gmr-mx.google.com with ESMTPS id r11-20020a05620a298b00b0077576de1665si1214886qkp.3.2023.11.29.02.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Nov 2023 02:35:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) client-ip=2607:f8b0:4864:20::e2b;
Received: by mail-vs1-xe2b.google.com with SMTP id ada2fe7eead31-462a978c470so1342608137.2
        for <kasan-dev@googlegroups.com>; Wed, 29 Nov 2023 02:35:54 -0800 (PST)
X-Received: by 2002:a67:fb15:0:b0:464:408a:5d87 with SMTP id
 d21-20020a67fb15000000b00464408a5d87mr3293331vsr.33.1701254153678; Wed, 29
 Nov 2023 02:35:53 -0800 (PST)
MIME-Version: 1.0
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz> <20231129-slub-percpu-caches-v3-5-6bcf536772bc@suse.cz>
In-Reply-To: <20231129-slub-percpu-caches-v3-5-6bcf536772bc@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 Nov 2023 11:35:15 +0100
Message-ID: <CANpmjNNOUozLuop+QddSdNd462J6CysPVcTbS9jP+aswKS9XHg@mail.gmail.com>
Subject: Re: [PATCH RFC v3 5/9] mm/slub: add opt-in percpu array cache of objects
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	maple-tree@lists.infradead.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Lp/+o5/S";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 29 Nov 2023 at 10:53, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> kmem_cache_setup_percpu_array() will allocate a per-cpu array for
> caching alloc/free objects of given size for the cache. The cache
> has to be created with SLAB_NO_MERGE flag.
>
> When empty, half of the array is filled by an internal bulk alloc
> operation. When full, half of the array is flushed by an internal bulk
> free operation.
>
> The array does not distinguish NUMA locality of the cached objects. If
> an allocation is requested with kmem_cache_alloc_node() with numa node
> not equal to NUMA_NO_NODE, the array is bypassed.
>
> The bulk operations exposed to slab users also try to utilize the array
> when possible, but leave the array empty or full and use the bulk
> alloc/free only to finish the operation itself. If kmemcg is enabled and
> active, bulk freeing skips the array completely as it would be less
> efficient to use it.
>
> The locking scheme is copied from the page allocator's pcplists, based
> on embedded spin locks. Interrupts are not disabled, only preemption
> (cpu migration on RT). Trylock is attempted to avoid deadlock due to an
> interrupt; trylock failure means the array is bypassed.
>
> Sysfs stat counters alloc_cpu_cache and free_cpu_cache count objects
> allocated or freed using the percpu array; counters cpu_cache_refill and
> cpu_cache_flush count objects refilled or flushed form the array.
>
> kmem_cache_prefill_percpu_array() can be called to ensure the array on
> the current cpu to at least the given number of objects. However this is
> only opportunistic as there's no cpu pinning between the prefill and
> usage, and trylocks may fail when the usage is in an irq handler.
> Therefore allocations cannot rely on the array for success even after
> the prefill. But misses should be rare enough that e.g. GFP_ATOMIC
> allocations should be acceptable after the refill.
>
> When slub_debug is enabled for a cache with percpu array, the objects in
> the array are considered as allocated from the slub_debug perspective,
> and the alloc/free debugging hooks occur when moving the objects between
> the array and slab pages. This means that e.g. an use-after-free that
> occurs for an object cached in the array is undetected. Collected
> alloc/free stacktraces might also be less useful. This limitation could
> be changed in the future.
>
> On the other hand, KASAN, kmemcg and other hooks are executed on actual
> allocations and frees by kmem_cache users even if those use the array,
> so their debugging or accounting accuracy should be unaffected.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/slab.h     |   4 +
>  include/linux/slub_def.h |  12 ++
>  mm/Kconfig               |   1 +
>  mm/slub.c                | 457 ++++++++++++++++++++++++++++++++++++++++++++++-
>  4 files changed, 468 insertions(+), 6 deletions(-)
>
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index d6d6ffeeb9a2..fe0c0981be59 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -197,6 +197,8 @@ struct kmem_cache *kmem_cache_create_usercopy(const char *name,
>  void kmem_cache_destroy(struct kmem_cache *s);
>  int kmem_cache_shrink(struct kmem_cache *s);
>
> +int kmem_cache_setup_percpu_array(struct kmem_cache *s, unsigned int count);
> +
>  /*
>   * Please use this macro to create slab caches. Simply specify the
>   * name of the structure and maybe some flags that are listed above.
> @@ -512,6 +514,8 @@ void kmem_cache_free(struct kmem_cache *s, void *objp);
>  void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p);
>  int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size, void **p);
>
> +int kmem_cache_prefill_percpu_array(struct kmem_cache *s, unsigned int count, gfp_t gfp);
> +
>  static __always_inline void kfree_bulk(size_t size, void **p)
>  {
>         kmem_cache_free_bulk(NULL, size, p);
> diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
> index deb90cf4bffb..2083aa849766 100644
> --- a/include/linux/slub_def.h
> +++ b/include/linux/slub_def.h
> @@ -13,8 +13,10 @@
>  #include <linux/local_lock.h>
>
>  enum stat_item {
> +       ALLOC_PCA,              /* Allocation from percpu array cache */
>         ALLOC_FASTPATH,         /* Allocation from cpu slab */
>         ALLOC_SLOWPATH,         /* Allocation by getting a new cpu slab */
> +       FREE_PCA,               /* Free to percpu array cache */
>         FREE_FASTPATH,          /* Free to cpu slab */
>         FREE_SLOWPATH,          /* Freeing not to cpu slab */
>         FREE_FROZEN,            /* Freeing to frozen slab */
> @@ -39,6 +41,8 @@ enum stat_item {
>         CPU_PARTIAL_FREE,       /* Refill cpu partial on free */
>         CPU_PARTIAL_NODE,       /* Refill cpu partial from node partial */
>         CPU_PARTIAL_DRAIN,      /* Drain cpu partial to node partial */
> +       PCA_REFILL,             /* Refilling empty percpu array cache */
> +       PCA_FLUSH,              /* Flushing full percpu array cache */
>         NR_SLUB_STAT_ITEMS
>  };
>
> @@ -66,6 +70,13 @@ struct kmem_cache_cpu {
>  };
>  #endif /* CONFIG_SLUB_TINY */
>
> +struct slub_percpu_array {
> +       spinlock_t lock;
> +       unsigned int count;
> +       unsigned int used;
> +       void * objects[];

checkpatch complains: "foo * bar" should be "foo *bar"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNOUozLuop%2BQddSdNd462J6CysPVcTbS9jP%2BaswKS9XHg%40mail.gmail.com.
