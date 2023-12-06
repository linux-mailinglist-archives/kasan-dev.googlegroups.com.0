Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB6PSYCVQMGQEKIROVFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1489F806A4D
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 10:06:03 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-5d1ed4b268dsf108581357b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 01:06:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701853562; cv=pass;
        d=google.com; s=arc-20160816;
        b=oDqxTbAb2JQ9ArDhXFmxaKPKDT9o/wQ81r0mXH6Nq1sTC63nGVwpO0EDKRrpu9sxrz
         Lqnn7+tFCT8DgfnlWHvv74CY0ZFeVUDEtZG3UVzKWz1NRt6F8bi2yEEcVxvRFu7XVyvC
         5s+DP9YoZcG6AjwyPyNnIcduAr8ayOytp1w6BN7thHXQ1PVY8zdPtHW3ZtWTkV8wglQa
         h22Q8gZUNvc1xxZIheNSD+3ESJP0x+iW8hOK29ZrDZ6EyrA4HDXsefsQiSL8RsfTjm9P
         n+JMa77Ub2D8CJL09o6HC4HNcCAlSBQrvei+AL48kLW/FmPBnAyllQPyrV8OeVuS1W6z
         lIYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=0+HUZ+cvEzGBcWxyO/I8rXdPgfq5NjysXewurnjPH+Q=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=MWFcV/lI6o42U7dcToQCfOQSKaQY/XLfSFRViy5957GSU45/gjJzgKkbKkUfeKyV+s
         sk1nIx6Ujysiq483DB8nk4mZYq/Fnqp44UT4VoKDznqI91pIs4K2OQIdFFV50WfI+dHZ
         kNX+VcKRMnlMKYRpRDi2SVesRTmVI1/BGaKCH0rmncka5qw634YBdppflTV85StO94FQ
         12dP701PfvVMtbn1ykij5oJXwhZ5VXrNGdRMAndOALkAKg6tdCxV++onP+JKVWWIq7NC
         ftMx5grvHGQMdoXLkzJmCR4yaZtHfWjzHNL/FFDtFiYmYEGROm0PK94D7cjyAoqE+CWR
         BwRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CbXdQjQa;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701853562; x=1702458362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0+HUZ+cvEzGBcWxyO/I8rXdPgfq5NjysXewurnjPH+Q=;
        b=pz66L3GuKKTdUNH5AVVaizmu/GLKWs/9S9ANSnD0u9nTcoCmzThAaqg66jrRNNgCC+
         ed0u2oQIHqaEwzq9gmFbhYVLhVcedShF+DyYw6AUaEG7riMxmPin8/Ng19Ie+LgRsrmI
         HidGA64sRVQmDA+Y5PPAaXfyo+6R0aIrSTmh98iLr/NGAX1ntt1iKPvLXPro1SB2RSsG
         OP4IEHMgehU64qGMc6LTBi516fH5VqOzaduPmdAztKcdwigGrLC0kqguERDfaHwobfkN
         QxtXKwoypvl0Fbpc5xyCx2JCRPzLquB+uZNLfqGWqb+C5sFWIxWU4Fz/kxWIFYHMHl2R
         8ZBg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701853562; x=1702458362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0+HUZ+cvEzGBcWxyO/I8rXdPgfq5NjysXewurnjPH+Q=;
        b=RPF8PTb0pcJSycissBUl/uAiUvCnk+J4etWn/WGNVko/aKeqK9hyseKG7JpI+kZs2V
         UFPDJNF4MXKlgtV2Rf2n9YZ/ryd/czisav0SnEE5tTSNzxCt0PnfvczWbioxH0tFv9zk
         ZvSQ6NM3IYG/fwhKdilVvaYMbVbIsQ4MlHaN4dA7LMJstLVg6q13WkVr+dq3JOprOpvs
         3Dgm4c/TsyWiRebwFHW5dy9SBajSmChxc/hFEdgC5R8uHv4Bpvn/FMNSZATZ2qorwbZ+
         yJEUzoVbU5aquooTROiZ9JnK0omScry4EbXg2Uo2tfvhg8X4C5UKBoJHpZIHR2l3PF+o
         A9mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701853562; x=1702458362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0+HUZ+cvEzGBcWxyO/I8rXdPgfq5NjysXewurnjPH+Q=;
        b=WpREdsVcmgH06Jv2txN7fPm8fMH3VtkGWlxbHAxKb81SwTVervoWxOqX47dKs1ZjUx
         dcqzCAAWKG2dxbQL9JcEDQ24gL8RMh/7InCXQ6ppm3UOghlhX0QIKlhAdil5+Ogi1USu
         VyCEtMdKfexdje+xkZ5bWNdWQnD4/WliBBZ7nLXbbf3PbO1RS5E46EcfkIaYRXNMAy7+
         1uykrKYLaQA2k87ao+QVag0p8Qxzn3dLtDbCennjW9g20qnsKu9+zgputmlrBc65hCXe
         /uCINWtZMQCkx58cc/VgWvsgCZyu2zr3e45wz47T+0/soyUcNbLUBQvQWwqI+UOuJKYT
         x49Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxjQqpOI1GiDFYENft7xuFn5YVVpVoSX8r6Ep8HWdg2gCG3/dE6
	JM2fLGImzwIOm33L/4psxmE=
X-Google-Smtp-Source: AGHT+IHfYGDde8SXOIgOjs8oY9G80NsFh2RCG6AhaAIX+woOgGsALN1J7wY94y2FzEixQieuLo6pwA==
X-Received: by 2002:a25:8701:0:b0:db5:4fcd:21f3 with SMTP id a1-20020a258701000000b00db54fcd21f3mr403140ybl.51.1701853561771;
        Wed, 06 Dec 2023 01:06:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7e44:0:b0:daf:6c11:349e with SMTP id z65-20020a257e44000000b00daf6c11349els1438365ybc.2.-pod-prod-07-us;
 Wed, 06 Dec 2023 01:06:01 -0800 (PST)
X-Received: by 2002:a05:690c:fc1:b0:5d8:6ce7:e4 with SMTP id dg1-20020a05690c0fc100b005d86ce700e4mr404008ywb.1.1701853560855;
        Wed, 06 Dec 2023 01:06:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701853560; cv=none;
        d=google.com; s=arc-20160816;
        b=Ljl9xCLmFIghMtP3fDsibt4qE+nV+B0DVTjo+FSrBQnIVf135JavrR3rJVRhdiXKeE
         iRkqXSaWMYQ719fekMzALcCXv6lAXL2p8L1A6ke004ZmHmHY7L/CsUPne3IqB5SnyEF+
         zIu9F+SCN9Bk0R0wnBiCaIDM0TMUbJO32xWLRrpkxWV8CIpZiyo4lNhQYDbk354/0+LZ
         i27mRutft3Yte/Lsb6ewJSYqJzmVxILNJBFqAfQkEEhwALdhKWSphpruht1zXgvqtN9a
         NH29RR147cSf3VU/M1lf/o9BOX3zj6QtZgnjLaJk1QgqkiAidsUgK6tTc5gYzQGxh/d/
         wJzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=b2GGM7bFYDaqOGYAduet1T5T8Hq7xfXB9hdrnTRRI+g=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=dwFj9lkh5u56AZF8o+aLVRAFdSiHeUxYJqUs1Mh3SGOwcrrha4i2Uhnn4hX0WUe7En
         evfM/RpVmfuZLvWAH7vHNVDoRAdsCMKc5WIFYzxRT+eDlB9IZG88WGwWBF+izMR04KAB
         9J1q1nnEUgPMXb+ypMg0m9fc3axWVPdDP7VU0Hk92k2eeJbTVUO1zOt9kr6PEWt++j8d
         UjF6vEm2FEqSOpmzgyk8MYRFR2ZMDQ6Vlk11g35P6k+G2VO209xsF+8FmKQccWIFi5NX
         lkd+oDJhRnRsRLbowPDJmtY0NX0wSTGYcRXzqVhRQbbHlRAbwrgrstjhZQ+PbA8iMMWI
         0zQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CbXdQjQa;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id g23-20020a81ae57000000b005acdb94d61dsi1692003ywk.0.2023.12.06.01.06.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 01:06:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1d069b1d127so26856825ad.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 01:06:00 -0800 (PST)
X-Received: by 2002:a17:902:c411:b0:1d0:6ffd:f1f8 with SMTP id k17-20020a170902c41100b001d06ffdf1f8mr465248plk.78.1701853559768;
        Wed, 06 Dec 2023 01:05:59 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id j20-20020a170902759400b001c74df14e6fsm11559003pll.284.2023.12.06.01.05.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 01:05:58 -0800 (PST)
Date: Wed, 6 Dec 2023 18:05:38 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 07/21] mm/slab: remove CONFIG_SLAB code from slab
 common code
Message-ID: <ZXA5YqZGAfNUQiIC@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-7-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-7-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CbXdQjQa;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 20, 2023 at 07:34:18PM +0100, Vlastimil Babka wrote:
> In slab_common.c and slab.h headers, we can now remove all code behind
> CONFIG_SLAB and CONFIG_DEBUG_SLAB ifdefs, and remove all CONFIG_SLUB
> ifdefs.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/slab.h | 14 ++---------
>  mm/slab.h            | 69 ++++------------------------------------------------
>  mm/slab_common.c     | 22 ++---------------
>  3 files changed, 9 insertions(+), 96 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 34e43cddc520..b2015d0e01ad 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -24,7 +24,7 @@
>  
>  /*
>   * Flags to pass to kmem_cache_create().
> - * The ones marked DEBUG are only valid if CONFIG_DEBUG_SLAB is set.
> + * The ones marked DEBUG need CONFIG_SLUB_DEBUG enabled, otherwise are no-op
>   */
>  /* DEBUG: Perform (expensive) checks on alloc/free */
>  #define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
> @@ -302,25 +302,15 @@ static inline unsigned int arch_slab_minalign(void)
>   * Kmalloc array related definitions
>   */
>  
> -#ifdef CONFIG_SLAB
>  /*
> - * SLAB and SLUB directly allocates requests fitting in to an order-1 page
> + * SLUB directly allocates requests fitting in to an order-1 page
>   * (PAGE_SIZE*2).  Larger requests are passed to the page allocator.
>   */
>  #define KMALLOC_SHIFT_HIGH	(PAGE_SHIFT + 1)
>  #define KMALLOC_SHIFT_MAX	(MAX_ORDER + PAGE_SHIFT)
>  #ifndef KMALLOC_SHIFT_LOW
> -#define KMALLOC_SHIFT_LOW	5
> -#endif
> -#endif
> -
> -#ifdef CONFIG_SLUB
> -#define KMALLOC_SHIFT_HIGH	(PAGE_SHIFT + 1)
> -#define KMALLOC_SHIFT_MAX	(MAX_ORDER + PAGE_SHIFT)
> -#ifndef KMALLOC_SHIFT_LOW
>  #define KMALLOC_SHIFT_LOW	3
>  #endif
> -#endif
>  
>  /* Maximum allocatable size */
>  #define KMALLOC_MAX_SIZE	(1UL << KMALLOC_SHIFT_MAX)
> diff --git a/mm/slab.h b/mm/slab.h
> index 3d07fb428393..014c36ea51fa 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -42,21 +42,6 @@ typedef union {
>  struct slab {
>  	unsigned long __page_flags;
>  
> -#if defined(CONFIG_SLAB)
> -
> -	struct kmem_cache *slab_cache;
> -	union {
> -		struct {
> -			struct list_head slab_list;
> -			void *freelist;	/* array of free object indexes */
> -			void *s_mem;	/* first object */
> -		};
> -		struct rcu_head rcu_head;
> -	};
> -	unsigned int active;
> -
> -#elif defined(CONFIG_SLUB)
> -
>  	struct kmem_cache *slab_cache;
>  	union {
>  		struct {
> @@ -91,10 +76,6 @@ struct slab {
>  	};
>  	unsigned int __unused;
>  
> -#else
> -#error "Unexpected slab allocator configured"
> -#endif
> -
>  	atomic_t __page_refcount;
>  #ifdef CONFIG_MEMCG
>  	unsigned long memcg_data;
> @@ -111,7 +92,7 @@ SLAB_MATCH(memcg_data, memcg_data);
>  #endif
>  #undef SLAB_MATCH
>  static_assert(sizeof(struct slab) <= sizeof(struct page));
> -#if defined(system_has_freelist_aba) && defined(CONFIG_SLUB)
> +#if defined(system_has_freelist_aba)
>  static_assert(IS_ALIGNED(offsetof(struct slab, freelist), sizeof(freelist_aba_t)));
>  #endif
>  
> @@ -228,13 +209,7 @@ static inline size_t slab_size(const struct slab *slab)
>  	return PAGE_SIZE << slab_order(slab);
>  }
>  
> -#ifdef CONFIG_SLAB
> -#include <linux/slab_def.h>
> -#endif
> -
> -#ifdef CONFIG_SLUB
>  #include <linux/slub_def.h>
> -#endif
>  
>  #include <linux/memcontrol.h>
>  #include <linux/fault-inject.h>
> @@ -320,26 +295,16 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
>  			 SLAB_CACHE_DMA32 | SLAB_PANIC | \
>  			 SLAB_TYPESAFE_BY_RCU | SLAB_DEBUG_OBJECTS )
>  
> -#if defined(CONFIG_DEBUG_SLAB)
> -#define SLAB_DEBUG_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER)
> -#elif defined(CONFIG_SLUB_DEBUG)
> +#ifdef CONFIG_SLUB_DEBUG
>  #define SLAB_DEBUG_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
>  			  SLAB_TRACE | SLAB_CONSISTENCY_CHECKS)
>  #else
>  #define SLAB_DEBUG_FLAGS (0)
>  #endif
>  
> -#if defined(CONFIG_SLAB)
> -#define SLAB_CACHE_FLAGS (SLAB_MEM_SPREAD | SLAB_NOLEAKTRACE | \
> -			  SLAB_RECLAIM_ACCOUNT | SLAB_TEMPORARY | \
> -			  SLAB_ACCOUNT | SLAB_NO_MERGE)
> -#elif defined(CONFIG_SLUB)
>  #define SLAB_CACHE_FLAGS (SLAB_NOLEAKTRACE | SLAB_RECLAIM_ACCOUNT | \
>  			  SLAB_TEMPORARY | SLAB_ACCOUNT | \
>  			  SLAB_NO_USER_FLAGS | SLAB_KMALLOC | SLAB_NO_MERGE)
> -#else
> -#define SLAB_CACHE_FLAGS (SLAB_NOLEAKTRACE)
> -#endif
>  
>  /* Common flags available with current configuration */
>  #define CACHE_CREATE_MASK (SLAB_CORE_FLAGS | SLAB_DEBUG_FLAGS | SLAB_CACHE_FLAGS)
> @@ -672,18 +637,14 @@ size_t __ksize(const void *objp);
>  
>  static inline size_t slab_ksize(const struct kmem_cache *s)
>  {
> -#ifndef CONFIG_SLUB
> -	return s->object_size;
> -
> -#else /* CONFIG_SLUB */
> -# ifdef CONFIG_SLUB_DEBUG
> +#ifdef CONFIG_SLUB_DEBUG
>  	/*
>  	 * Debugging requires use of the padding between object
>  	 * and whatever may come after it.
>  	 */
>  	if (s->flags & (SLAB_RED_ZONE | SLAB_POISON))
>  		return s->object_size;
> -# endif
> +#endif
>  	if (s->flags & SLAB_KASAN)
>  		return s->object_size;
>  	/*
> @@ -697,7 +658,6 @@ static inline size_t slab_ksize(const struct kmem_cache *s)
>  	 * Else we can use all the padding etc for the allocation
>  	 */
>  	return s->size;
> -#endif
>  }
>  
>  static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
> @@ -775,23 +735,6 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>   * The slab lists for all objects.
>   */
>  struct kmem_cache_node {
> -#ifdef CONFIG_SLAB
> -	raw_spinlock_t list_lock;
> -	struct list_head slabs_partial;	/* partial list first, better asm code */
> -	struct list_head slabs_full;
> -	struct list_head slabs_free;
> -	unsigned long total_slabs;	/* length of all slab lists */
> -	unsigned long free_slabs;	/* length of free slab list only */
> -	unsigned long free_objects;
> -	unsigned int free_limit;
> -	unsigned int colour_next;	/* Per-node cache coloring */
> -	struct array_cache *shared;	/* shared per node */
> -	struct alien_cache **alien;	/* on other nodes */
> -	unsigned long next_reap;	/* updated without locking */
> -	int free_touched;		/* updated without locking */
> -#endif
> -
> -#ifdef CONFIG_SLUB
>  	spinlock_t list_lock;
>  	unsigned long nr_partial;
>  	struct list_head partial;
> @@ -800,8 +743,6 @@ struct kmem_cache_node {
>  	atomic_long_t total_objects;
>  	struct list_head full;
>  #endif
> -#endif
> -
>  };
>  
>  static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
> @@ -818,7 +759,7 @@ static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
>  		 if ((__n = get_node(__s, __node)))
>  
>  
> -#if defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG)
> +#ifdef CONFIG_SLUB_DEBUG
>  void dump_unreclaimable_slab(void);
>  #else
>  static inline void dump_unreclaimable_slab(void)
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 8d431193c273..63b8411db7ce 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -71,10 +71,8 @@ static int __init setup_slab_merge(char *str)
>  	return 1;
>  }
>  
> -#ifdef CONFIG_SLUB
>  __setup_param("slub_nomerge", slub_nomerge, setup_slab_nomerge, 0);
>  __setup_param("slub_merge", slub_merge, setup_slab_merge, 0);
> -#endif
>  
>  __setup("slab_nomerge", setup_slab_nomerge);
>  __setup("slab_merge", setup_slab_merge);
> @@ -197,10 +195,6 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
>  		if (s->size - size >= sizeof(void *))
>  			continue;
>  
> -		if (IS_ENABLED(CONFIG_SLAB) && align &&
> -			(align > s->align || s->align % align))
> -			continue;
> -
>  		return s;
>  	}
>  	return NULL;
> @@ -1222,12 +1216,8 @@ void cache_random_seq_destroy(struct kmem_cache *cachep)
>  }
>  #endif /* CONFIG_SLAB_FREELIST_RANDOM */
>  
> -#if defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG)
> -#ifdef CONFIG_SLAB
> -#define SLABINFO_RIGHTS (0600)
> -#else
> +#ifdef CONFIG_SLUB_DEBUG
>  #define SLABINFO_RIGHTS (0400)
> -#endif
>  
>  static void print_slabinfo_header(struct seq_file *m)
>  {
> @@ -1235,18 +1225,10 @@ static void print_slabinfo_header(struct seq_file *m)
>  	 * Output format version, so at least we can change it
>  	 * without _too_ many complaints.
>  	 */
> -#ifdef CONFIG_DEBUG_SLAB
> -	seq_puts(m, "slabinfo - version: 2.1 (statistics)\n");
> -#else
>  	seq_puts(m, "slabinfo - version: 2.1\n");
> -#endif
>  	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>");
>  	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
>  	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
> -#ifdef CONFIG_DEBUG_SLAB
> -	seq_puts(m, " : globalstat <listallocs> <maxobjs> <grown> <reaped> <error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
> -	seq_puts(m, " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
> -#endif
>  	seq_putc(m, '\n');
>  }
>  
> @@ -1370,7 +1352,7 @@ static int __init slab_proc_init(void)
>  }
>  module_init(slab_proc_init);
>  
> -#endif /* CONFIG_SLAB || CONFIG_SLUB_DEBUG */
> +#endif /* CONFIG_SLUB_DEBUG */
>  
>  static __always_inline __realloc_size(2) void *
>  __do_krealloc(const void *p, size_t new_size, gfp_t flags)
> 
> -- 

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXA5YqZGAfNUQiIC%40localhost.localdomain.
