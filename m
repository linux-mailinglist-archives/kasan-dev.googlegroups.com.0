Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBOMFYGVQMGQEB6XXO3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id DC3C5806AF8
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 10:45:31 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-42541bff239sf13643861cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 01:45:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701855930; cv=pass;
        d=google.com; s=arc-20160816;
        b=CpsDfe6FQp2g3oygXMWD8qshoeuxknv5EXeDtvoK4CNvS9vzP1XeGzg5DdrkuBp1Ic
         /LUPnG8M9lkCitBGWG4zIvw7/FkLmvoEL4bW6dVqBQr5hysMuwb9zmCEgYpqRV5mNxU6
         kHICJgtV2ZrhFHHWl/gO12Rxh2P+bMaiK1+S15ig5UDLftf+D59lXELxOQAjOVSBTFyz
         gPEiU4GP+Sx7aP7BSRygz2Lo/J6dsglMs74wWvFjd3q6Uz4oqfhQTG09q5/UcH2suXJv
         Lgddr5XKvf/l8IJ7qfzK4gG6PAV/LBI3HmZSKJic7ikOKAMDayb/PiLEqZwOkiTvoefA
         RF1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=St4tnJkPmP6IulWuQAOEbaHUeG5ih9PgOfyrXXZ3Yig=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=XYoTlzzaDwhZWklSc1vmFFfcbxjzU6TH2iOAjaoUyzJ58j9LyICECFj+k5sIdprg/j
         rOkG/CpJF+JdRO1DZ8kCiogoqqmgvBa/shFVSwanAhkvJLLUHvpX/RL3FQiNI5xF0Y7d
         v6SP6PfpgNkHMyS2JsrAG1hVRC/TtzA655Lrcs3LWIEHgOiWdAT8d3ZpDJs7UhHdV5ay
         KddNsPxlk3WaP+NF598+D9kB8ut9UP/Emspy2Tj375JJS1azIgcHl7X7FFdpX5+ka7xr
         CWX1/VKGcCtFlTzAAXzPP7nXXjWRQhdXC4DaEqL0LgThgWmC4sRFzHIlDihuoTAM8M1p
         iOTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=D6B11Dfv;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701855930; x=1702460730; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=St4tnJkPmP6IulWuQAOEbaHUeG5ih9PgOfyrXXZ3Yig=;
        b=emRJAWnpJgbkxdJIpGMoc/m5ywgv5Pc7NkcgcV/sIxNjD7VutWWcNQoJYiFhxfW6ad
         dPQmUkNozW+lXUohwpV3k2RQPsqXAO+bq7KJX0BAtLwt/JKfkprJqgxL77x8Fx7TAfLW
         EQY/CmkQWRl1zdMfdGeZfJh27rsLiJVPYodo3FzInCDawkOX9uE8iQehk6JH4govj8TR
         MFGLCLJHhpwCdZbJOU808yz4IHPNsuHI4Mt1i1o5rbiK7Rp9hlvUeo1J4m/Suwr8bj3E
         2D8bZlwjrF+EPEM0l5z6xOlGTErEqvZm1xsGmmG5w9IEmZKL09LLyoTj/C4TZq6rI4st
         E4Zg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701855930; x=1702460730; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=St4tnJkPmP6IulWuQAOEbaHUeG5ih9PgOfyrXXZ3Yig=;
        b=mGXx2fMJlIAtnYrMiMQzV+hPi/lS50XKpEtD8dbwh60/+8meTjm5YlnBHpiScCs8mw
         OprThR1opOyWed1YKf37olmkoEUppSi0VBuFcdE2bR33QkSJ3TrzdYqM7uAoPzzl8qjt
         wu6E6KLU6FgBgu/5T0YjiEojTmhn/f5uFWYau8u82dsSToFSSQeuT2AlgXV6q+/5qBg6
         /ogNyxGlKezlukrT+XCttXZaoxsWevcclcyh99oWm3dlMV18frwica+3KihNkTN5qHOk
         pfzwp/LminzCsu7gKGEASB+V0ZZiLrWg0RBOtZ5fyZBwYaY7o6NhuMX3m8BqZu4EDBGY
         e5vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701855930; x=1702460730;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=St4tnJkPmP6IulWuQAOEbaHUeG5ih9PgOfyrXXZ3Yig=;
        b=MBa8HVAIfRPgX/pOfeHNFl+X0we02cpJzkNL5kJMzeO1VtOjcAIeYnkS1/xoAxhZHI
         1QAOt/NlKx4sgLrLg0Q5HaBOoZlUaDJDjBFDe7KyPk+pUq8hEsX36NPUjgYFDfq5RM/9
         yw8FMFO+onphqxVTbbg+HamrUE/Pq/s1csRyeEvf9ROkqHpDbeKdQxn4zGLVPiWebv/W
         YmN74RyAEqx6Wo1vlBHIPJNEaiR8fLlv1Hinf0DGl+GrOJgHnPWtXbI2UZbzFot5Nyat
         AbBbvShFcHZJbMjrjrsiZkHbTmXJiXMXgc0zDg8zQywXCJBygx4H7M14DEfKLm2F3ae/
         plzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywc39w4IQlF2oPhW1dD8GAN5CPcLmqGc3DqvzMbWqIJ1EVr2VY6
	kYmROwHQyd5sMmVwT4Pyma4=
X-Google-Smtp-Source: AGHT+IFjcwPrVtnEy+25HxlQ2g+sMOKG4u+XjjxNADdKdkSi5tx8oUTGrfzW2hDjZhGFcMEYe2ASWQ==
X-Received: by 2002:a0c:f90c:0:b0:67a:ceb6:26c1 with SMTP id v12-20020a0cf90c000000b0067aceb626c1mr1045153qvn.2.1701855930049;
        Wed, 06 Dec 2023 01:45:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4428:0:b0:67a:dd5b:643c with SMTP id e8-20020ad44428000000b0067add5b643cls1286149qvt.0.-pod-prod-03-us;
 Wed, 06 Dec 2023 01:45:29 -0800 (PST)
X-Received: by 2002:a05:6122:50c:b0:4b2:83ab:7ebd with SMTP id x12-20020a056122050c00b004b283ab7ebdmr272395vko.11.1701855929110;
        Wed, 06 Dec 2023 01:45:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701855929; cv=none;
        d=google.com; s=arc-20160816;
        b=FftHt5X5uTU42DEoQLtRtpmBNux9d4REicI+GhKJc8tdHHAmUeSjuTJ51MnLgjW0eO
         BLG32jeRIi/JY3qRRGJlQzgVz/ynvcx5E5gyzGXiCmkktxo1h4gO4sU2qh9XyZJSK+SM
         X+4PC3lLlz3hCkQJWq69S/TE3dwcIs93cLRFy3Xz2DJ+jkFwbE6Fz2EiSm8J24RC64Jo
         8b118dtCnQlcKw81z7ZhCrxZz8KIaMQIt3Q/wdlVn/EKJKTDAh962jYUfxWW164oVqi8
         Z7uhnNtafhFB02eHaW1TiSsBhwPgInkziEheiIMcyB7W2Iz+Fd7VvK3lzI8zRyFCg6ny
         ktUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cDd5Zi7vCvO2ycBR8Ub2HRlOTkCLIJYdUeR29MHQbio=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=tkI9O9JcB2QTwVDIQyNzMcYZCuLM+exdZXiSCea3xIo2EVY3cxZjz2Wphv9IZwN3Vq
         f6w3xpWbALg2HVlDgwhnILHC2H/N35ZhePqN5h00VbALp8yWX+L6qVdXRb9ksoqo/+9d
         9NlwHux7PHUQlQr0dBSP3RjGxOOeAq/VUF+xO6xGvn4GfUNapzAm9jAuhvvbAhUNX/zY
         52d5JRA78sNU1svwXABukG5ae89/M8AHQlrdNO+7QnoSMlqL95jJ3ySbeGzP5ar/Zd48
         +Zhl5vWEETDXzE9eV84/vjaLqeOgMsWJ1Cyyd+Dhh1gvn+er/nH9CsUztasnHxY/Uoqt
         i0NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=D6B11Dfv;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id d3-20020a05612212c300b004b2c71cd532si896268vkp.5.2023.12.06.01.45.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 01:45:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-28694702c18so3492701a91.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 01:45:29 -0800 (PST)
X-Received: by 2002:a17:90b:1298:b0:286:6cc0:cac2 with SMTP id fw24-20020a17090b129800b002866cc0cac2mr546651pjb.57.1701855927932;
        Wed, 06 Dec 2023 01:45:27 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id ms10-20020a17090b234a00b0028679f2ee38sm938188pjb.0.2023.12.06.01.45.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 01:45:27 -0800 (PST)
Date: Wed, 6 Dec 2023 18:45:19 +0900
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
Subject: Re: [PATCH v2 11/21] mm/slab: move the rest of slub_def.h to
 mm/slab.h
Message-ID: <ZXBCr2n9m/jfXxFw@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-11-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-11-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=D6B11Dfv;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::102d
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

On Mon, Nov 20, 2023 at 07:34:22PM +0100, Vlastimil Babka wrote:
> mm/slab.h is the only place to include include/linux/slub_def.h which
> has allowed switching between SLAB and SLUB. Now we can simply move the
> contents over and remove slub_def.h.
> 
> Use this opportunity to fix up some whitespace (alignment) issues.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/slub_def.h | 150 -----------------------------------------------
>  mm/slab.h                | 138 ++++++++++++++++++++++++++++++++++++++++++-
>  2 files changed, 137 insertions(+), 151 deletions(-)
> 
> diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
> deleted file mode 100644
> index a0229ea42977..000000000000
> --- a/include/linux/slub_def.h
> +++ /dev/null
> @@ -1,150 +0,0 @@
> -/* SPDX-License-Identifier: GPL-2.0 */
> -#ifndef _LINUX_SLUB_DEF_H
> -#define _LINUX_SLUB_DEF_H
> -
> -/*
> - * SLUB : A Slab allocator without object queues.
> - *
> - * (C) 2007 SGI, Christoph Lameter
> - */
> -#include <linux/kfence.h>
> -#include <linux/kobject.h>
> -#include <linux/reciprocal_div.h>
> -#include <linux/local_lock.h>
> -
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -#define slub_percpu_partial(c)		((c)->partial)
> -
> -#define slub_set_percpu_partial(c, p)		\
> -({						\
> -	slub_percpu_partial(c) = (p)->next;	\
> -})
> -
> -#define slub_percpu_partial_read_once(c)     READ_ONCE(slub_percpu_partial(c))
> -#else
> -#define slub_percpu_partial(c)			NULL
> -
> -#define slub_set_percpu_partial(c, p)
> -
> -#define slub_percpu_partial_read_once(c)	NULL
> -#endif // CONFIG_SLUB_CPU_PARTIAL
> -
> -/*
> - * Word size structure that can be atomically updated or read and that
> - * contains both the order and the number of objects that a slab of the
> - * given order would contain.
> - */
> -struct kmem_cache_order_objects {
> -	unsigned int x;
> -};
> -
> -/*
> - * Slab cache management.
> - */
> -struct kmem_cache {
> -#ifndef CONFIG_SLUB_TINY
> -	struct kmem_cache_cpu __percpu *cpu_slab;
> -#endif
> -	/* Used for retrieving partial slabs, etc. */
> -	slab_flags_t flags;
> -	unsigned long min_partial;
> -	unsigned int size;	/* The size of an object including metadata */
> -	unsigned int object_size;/* The size of an object without metadata */
> -	struct reciprocal_value reciprocal_size;
> -	unsigned int offset;	/* Free pointer offset */
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -	/* Number of per cpu partial objects to keep around */
> -	unsigned int cpu_partial;
> -	/* Number of per cpu partial slabs to keep around */
> -	unsigned int cpu_partial_slabs;
> -#endif
> -	struct kmem_cache_order_objects oo;
> -
> -	/* Allocation and freeing of slabs */
> -	struct kmem_cache_order_objects min;
> -	gfp_t allocflags;	/* gfp flags to use on each alloc */
> -	int refcount;		/* Refcount for slab cache destroy */
> -	void (*ctor)(void *);
> -	unsigned int inuse;		/* Offset to metadata */
> -	unsigned int align;		/* Alignment */
> -	unsigned int red_left_pad;	/* Left redzone padding size */
> -	const char *name;	/* Name (only for display!) */
> -	struct list_head list;	/* List of slab caches */
> -#ifdef CONFIG_SYSFS
> -	struct kobject kobj;	/* For sysfs */
> -#endif
> -#ifdef CONFIG_SLAB_FREELIST_HARDENED
> -	unsigned long random;
> -#endif
> -
> -#ifdef CONFIG_NUMA
> -	/*
> -	 * Defragmentation by allocating from a remote node.
> -	 */
> -	unsigned int remote_node_defrag_ratio;
> -#endif
> -
> -#ifdef CONFIG_SLAB_FREELIST_RANDOM
> -	unsigned int *random_seq;
> -#endif
> -
> -#ifdef CONFIG_KASAN_GENERIC
> -	struct kasan_cache kasan_info;
> -#endif
> -
> -#ifdef CONFIG_HARDENED_USERCOPY
> -	unsigned int useroffset;	/* Usercopy region offset */
> -	unsigned int usersize;		/* Usercopy region size */
> -#endif
> -
> -	struct kmem_cache_node *node[MAX_NUMNODES];
> -};
> -
> -#if defined(CONFIG_SYSFS) && !defined(CONFIG_SLUB_TINY)
> -#define SLAB_SUPPORTS_SYSFS
> -void sysfs_slab_unlink(struct kmem_cache *);
> -void sysfs_slab_release(struct kmem_cache *);
> -#else
> -static inline void sysfs_slab_unlink(struct kmem_cache *s)
> -{
> -}
> -static inline void sysfs_slab_release(struct kmem_cache *s)
> -{
> -}
> -#endif
> -
> -void *fixup_red_left(struct kmem_cache *s, void *p);
> -
> -static inline void *nearest_obj(struct kmem_cache *cache, const struct slab *slab,
> -				void *x) {
> -	void *object = x - (x - slab_address(slab)) % cache->size;
> -	void *last_object = slab_address(slab) +
> -		(slab->objects - 1) * cache->size;
> -	void *result = (unlikely(object > last_object)) ? last_object : object;
> -
> -	result = fixup_red_left(cache, result);
> -	return result;
> -}
> -
> -/* Determine object index from a given position */
> -static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
> -					  void *addr, void *obj)
> -{
> -	return reciprocal_divide(kasan_reset_tag(obj) - addr,
> -				 cache->reciprocal_size);
> -}
> -
> -static inline unsigned int obj_to_index(const struct kmem_cache *cache,
> -					const struct slab *slab, void *obj)
> -{
> -	if (is_kfence_address(obj))
> -		return 0;
> -	return __obj_to_index(cache, slab_address(slab), obj);
> -}
> -
> -static inline int objs_per_slab(const struct kmem_cache *cache,
> -				     const struct slab *slab)
> -{
> -	return slab->objects;
> -}
> -#endif /* _LINUX_SLUB_DEF_H */
> diff --git a/mm/slab.h b/mm/slab.h
> index 014c36ea51fa..3a8d13c099fa 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -209,7 +209,143 @@ static inline size_t slab_size(const struct slab *slab)
>  	return PAGE_SIZE << slab_order(slab);
>  }
>  
> -#include <linux/slub_def.h>
> +#include <linux/kfence.h>
> +#include <linux/kobject.h>
> +#include <linux/reciprocal_div.h>
> +#include <linux/local_lock.h>
> +
> +#ifdef CONFIG_SLUB_CPU_PARTIAL
> +#define slub_percpu_partial(c)			((c)->partial)
> +
> +#define slub_set_percpu_partial(c, p)		\
> +({						\
> +	slub_percpu_partial(c) = (p)->next;	\
> +})
> +
> +#define slub_percpu_partial_read_once(c)	READ_ONCE(slub_percpu_partial(c))
> +#else
> +#define slub_percpu_partial(c)			NULL
> +
> +#define slub_set_percpu_partial(c, p)
> +
> +#define slub_percpu_partial_read_once(c)	NULL
> +#endif // CONFIG_SLUB_CPU_PARTIAL
> +
> +/*
> + * Word size structure that can be atomically updated or read and that
> + * contains both the order and the number of objects that a slab of the
> + * given order would contain.
> + */
> +struct kmem_cache_order_objects {
> +	unsigned int x;
> +};
> +
> +/*
> + * Slab cache management.
> + */
> +struct kmem_cache {
> +#ifndef CONFIG_SLUB_TINY
> +	struct kmem_cache_cpu __percpu *cpu_slab;
> +#endif
> +	/* Used for retrieving partial slabs, etc. */
> +	slab_flags_t flags;
> +	unsigned long min_partial;
> +	unsigned int size;		/* Object size including metadata */
> +	unsigned int object_size;	/* Object size without metadata */
> +	struct reciprocal_value reciprocal_size;
> +	unsigned int offset;		/* Free pointer offset */
> +#ifdef CONFIG_SLUB_CPU_PARTIAL
> +	/* Number of per cpu partial objects to keep around */
> +	unsigned int cpu_partial;
> +	/* Number of per cpu partial slabs to keep around */
> +	unsigned int cpu_partial_slabs;
> +#endif
> +	struct kmem_cache_order_objects oo;
> +
> +	/* Allocation and freeing of slabs */
> +	struct kmem_cache_order_objects min;
> +	gfp_t allocflags;		/* gfp flags to use on each alloc */
> +	int refcount;			/* Refcount for slab cache destroy */
> +	void (*ctor)(void *object);	/* Object constructor */
> +	unsigned int inuse;		/* Offset to metadata */
> +	unsigned int align;		/* Alignment */
> +	unsigned int red_left_pad;	/* Left redzone padding size */
> +	const char *name;		/* Name (only for display!) */
> +	struct list_head list;		/* List of slab caches */
> +#ifdef CONFIG_SYSFS
> +	struct kobject kobj;		/* For sysfs */
> +#endif
> +#ifdef CONFIG_SLAB_FREELIST_HARDENED
> +	unsigned long random;
> +#endif
> +
> +#ifdef CONFIG_NUMA
> +	/*
> +	 * Defragmentation by allocating from a remote node.
> +	 */
> +	unsigned int remote_node_defrag_ratio;
> +#endif
> +
> +#ifdef CONFIG_SLAB_FREELIST_RANDOM
> +	unsigned int *random_seq;
> +#endif
> +
> +#ifdef CONFIG_KASAN_GENERIC
> +	struct kasan_cache kasan_info;
> +#endif
> +
> +#ifdef CONFIG_HARDENED_USERCOPY
> +	unsigned int useroffset;	/* Usercopy region offset */
> +	unsigned int usersize;		/* Usercopy region size */
> +#endif
> +
> +	struct kmem_cache_node *node[MAX_NUMNODES];
> +};
> +
> +#if defined(CONFIG_SYSFS) && !defined(CONFIG_SLUB_TINY)
> +#define SLAB_SUPPORTS_SYSFS
> +void sysfs_slab_unlink(struct kmem_cache *s);
> +void sysfs_slab_release(struct kmem_cache *s);
> +#else
> +static inline void sysfs_slab_unlink(struct kmem_cache *s) { }
> +static inline void sysfs_slab_release(struct kmem_cache *s) { }
> +#endif
> +
> +void *fixup_red_left(struct kmem_cache *s, void *p);
> +
> +static inline void *nearest_obj(struct kmem_cache *cache,
> +				const struct slab *slab, void *x)
> +{
> +	void *object = x - (x - slab_address(slab)) % cache->size;
> +	void *last_object = slab_address(slab) +
> +		(slab->objects - 1) * cache->size;
> +	void *result = (unlikely(object > last_object)) ? last_object : object;
> +
> +	result = fixup_red_left(cache, result);
> +	return result;
> +}
> +
> +/* Determine object index from a given position */
> +static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
> +					  void *addr, void *obj)
> +{
> +	return reciprocal_divide(kasan_reset_tag(obj) - addr,
> +				 cache->reciprocal_size);
> +}
> +
> +static inline unsigned int obj_to_index(const struct kmem_cache *cache,
> +					const struct slab *slab, void *obj)
> +{
> +	if (is_kfence_address(obj))
> +		return 0;
> +	return __obj_to_index(cache, slab_address(slab), obj);
> +}
> +
> +static inline int objs_per_slab(const struct kmem_cache *cache,
> +				const struct slab *slab)
> +{
> +	return slab->objects;
> +}
>  
>  #include <linux/memcontrol.h>
>  #include <linux/fault-inject.h>

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 
> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXBCr2n9m/jfXxFw%40localhost.localdomain.
