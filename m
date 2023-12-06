Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB54AYGVQMGQEKTUVLMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 85C78806AC8
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 10:35:54 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-58db2015327sf8641625eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 01:35:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701855352; cv=pass;
        d=google.com; s=arc-20160816;
        b=QpLBa9KOi3GNnp5ikc6US6stym9y4PJT+B+XU9Z5wKNV4yY7Z/iWQ7GTNODTGoZr93
         RXswwPZmKW/xeio6UqvR2hqZKa/5kaOgEzeQx4to0ASRa6mpFhKArrSj8KQDJRChllgL
         q+sZlEpa835KARgtdVWSR1m2Yn4V51Xtykp1qcg/Bujzh4p6HhksT7ixE4b2e6PtKOFS
         H97HE+h0I5tpSzeMFtWwp65vZqrxhJjiVWOOKduTaK798/LlT5A9JHLdZKNTbXCRwoYB
         kvEZ3/ONw1+3c+7WZ0uEseg1hm5Wh0KgrHmrQ7giaUGSXyqxVST7iI4Fm3e7BKg1dAvj
         VYDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=7iHmH5K7+iTFEOFbd7njvS9Etzbw3I05y0jrxTHVLeg=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=Cj0OWFVhvs8SQAfnnxSs8XGipLT463fnjSRie7pvH659QjzIrjYeO3TD0lbDaVcfRu
         eMTAQOykpCDh6AgYazynP7pdg8ZAPLLRUkc8+j7iEGL8nVnXXWyNeVO+WvikOHjlVlck
         lHRIwgXaqBM7tspzErUiaOr0yt/hPwzTbozP/GWSvLre4FcNwdXDYfFO+3FwDz3OzKPR
         kin0Vo7tNRGbZYSzXmZVxZD8YGY1JwEERdwetNxE0ju3PfPybPNd9ShYU3bXtLUtVrol
         rEHRWuEvAaP8CEQqbZjbKBiELHS72Wm+V2mFbdGYJLbEiWqzGNjJbo9SXgjJWjB0Jdnl
         BTXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=e0rZzjky;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701855352; x=1702460152; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7iHmH5K7+iTFEOFbd7njvS9Etzbw3I05y0jrxTHVLeg=;
        b=DtqclbIWbMRHDINv7efpizC2e0PBxBtrkxyNN+rIsimA8aI2h6NodIkHuSvGmEp/KM
         kzBgRIB2Fnsqlx5Btxtqcbf2U3bSsoC/0gJheJVPtzSfi6tV9edrInjmCmpPWdMf1C56
         5qr1LI9Mqh0xO9fIz+ZePtptM0et64U0sj8KZ6OB6ZGcgyZo0Ze2tBfB1bwKFv3BsVGv
         WQ8LPeY3Bu/WRwGQwbhDpRjCW5KPy4DgGi9+JL0JwARazJSBMG2qrFEqYk455gOHb7St
         lXkhWDe1cnuJmEpic7oz5O/smdJ16hac7jFD2kUCT7GiVzMjQ2F5ZGv3wP8Fro7BfBSx
         CU7Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701855352; x=1702460152; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=7iHmH5K7+iTFEOFbd7njvS9Etzbw3I05y0jrxTHVLeg=;
        b=kq9zkLaasmVF6fB54TYTjcpE5sOa0YXhJnpHF8Eqals+XuD58o2SoFNF2qMgRBrZbh
         R2qxpga960svSomNk7i51Y4GLn+XkwEPZucXOOKumAw3khjwMFEh3mWdlS/UYa05qGFh
         t+kDCpjeAV/7LJzsyh9mFZlsTTqzVAJ2UaBuLmraUdbk2nRM2sI+4ekeqLxsOe4u3H6F
         l5xX/nJmo4ULGfkNoY3sFtvT/+tvvitvk1Wr5/FsWURXp1ipn3A2b4YFJhtA1ClrDTHu
         rsij2f/I5/C03qa4DgCKsOTnqbEkbbC8YX2YuFudz8TBh39nrbJ5jkGJs++0S1ZahApJ
         3hPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701855352; x=1702460152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7iHmH5K7+iTFEOFbd7njvS9Etzbw3I05y0jrxTHVLeg=;
        b=bXR0zjDQLhvSzwH1T/DNqAEKn+emg0ufVmiOfMA8Yl4Bejr5CxCZzDOLsGoi5+1ae0
         NiB5wJ0ZoUSANcHRRFXRH1XSuea7M/wBfGC+BBswmOG/pGNCqYIkcM1D6+XIUV1uKto8
         RTvJEOZKowCeJ/dPyTMKR1PF2AMbn2ZXs9azHLzAbQPyzybRHRNlcpj/Fo6Z0Bjnu1lk
         vToAYkA5QtpwU8FdJremnLSOGwE5/bDsRLfMY3sP5aH6F2zr04Wh2yEOQmApYhTYFW5j
         QosKZbYfIb0brciGbhnd5QlggsTpz5zCz1jf0crzaWrItVURQYd1+PM+axdBpHU8vbgN
         RwPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxfX+zKXpjVqCwE0wew+XmrJnv4v3lmXRB4uz05W04Dv6lin8/R
	6Y/cFLtxFtdMnXoQYvlWIqc=
X-Google-Smtp-Source: AGHT+IGTHMNNi71VYqAA1OKJMtOr2LnqaNUriMadNfDQvVFLYPUcQpnbGBpsygwzP1rJVRXTkEqvsA==
X-Received: by 2002:a4a:925a:0:b0:58e:1c48:39a7 with SMTP id g26-20020a4a925a000000b0058e1c4839a7mr485430ooh.13.1701855352039;
        Wed, 06 Dec 2023 01:35:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2216:b0:58d:9e35:a9fe with SMTP id
 cj22-20020a056820221600b0058d9e35a9fels8856464oob.1.-pod-prod-08-us; Wed, 06
 Dec 2023 01:35:51 -0800 (PST)
X-Received: by 2002:a4a:761c:0:b0:58e:1c48:39ac with SMTP id t28-20020a4a761c000000b0058e1c4839acmr420822ooc.18.1701855351149;
        Wed, 06 Dec 2023 01:35:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701855351; cv=none;
        d=google.com; s=arc-20160816;
        b=eLEWiFjK9yz7QrnZnlPYsujnprzffNiC9AqPhXzZKVSFRG7hlI/sEWmeu8eUH5EyeX
         +MmeA7iQtYvrY0Bz/3g6tnXYLLBZcBb55zrniztx/tSoUdBYUko2RhkEdCFfJ5xgIRsx
         pj/Ba+jAdmHak4aPrkn0exngK4NhVnbe0nIqCORBgT5ABNGrhBnZKITSul2uhz8TZt1f
         BXo8ffLvA4ppQP/2PcpFBtIQms+nMSuWz1ngnYOWy5WJ8WXR6zrf0OtkgA952ev0DDg/
         7s8a4ZlbZp93sIGxXb95Dzh0Xtnnfxkh40DTrRpS10d3VZDljxEo+eGylGdkbWq5yUJs
         EyVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yma25+fKs5uOP5FQ6tfNto8zkRZRxKoDlNbBVbZifwI=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=vdyqSe+UV5pH0xSbyGtGLHBPDXqEDrJ0O/wavIw+ou4cyT5Q92IplZ6bqr1K7krZyW
         Dm+gsv0kUqH+lWVHIc5OqOqF/yjRhrzxD8sqV37kyBR3dliGEl4pP6AsrkMGaKmbeJXd
         zj9b91xbDJmHf6PQxlxVrhc3MIkiTmGXyoDRn9Zv4gr1kYKOvFApyZi2oXIay9DQobL9
         hnawrWkvlO7o6/7q82oepxfPnRjHQYtdlsDd7OW9hElGKAU7VMSt+R6DszOXKreypWaj
         qt98/3gzMCChBKC7f0EVWg5Z2lybyL3aZs3NMWJ8Ci3EJCPVnlEc7hZNiOLCeD7F4Fur
         +Slw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=e0rZzjky;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id o17-20020a056820041100b0058e2b7a8d82si602723oou.0.2023.12.06.01.35.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 01:35:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1d05e4a94c3so45606995ad.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 01:35:51 -0800 (PST)
X-Received: by 2002:a17:902:ce92:b0:1d0:7ed3:ea7c with SMTP id f18-20020a170902ce9200b001d07ed3ea7cmr647263plg.29.1701855350258;
        Wed, 06 Dec 2023 01:35:50 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id d9-20020a170902aa8900b001c9db5e2929sm11663481plr.93.2023.12.06.01.35.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 01:35:49 -0800 (PST)
Date: Wed, 6 Dec 2023 18:35:42 +0900
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
Subject: Re: [PATCH v2 10/21] mm/slab: move struct kmem_cache_cpu declaration
 to slub.c
Message-ID: <ZXBAbu7pR4o7JIa5@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-10-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-10-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=e0rZzjky;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::631
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

On Mon, Nov 20, 2023 at 07:34:21PM +0100, Vlastimil Babka wrote:
> Nothing outside SLUB itself accesses the struct kmem_cache_cpu fields so
> it does not need to be declared in slub_def.h. This allows also to move
> enum stat_item.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/slub_def.h | 54 ------------------------------------------------
>  mm/slub.c                | 54 ++++++++++++++++++++++++++++++++++++++++++++++++
>  2 files changed, 54 insertions(+), 54 deletions(-)
> 
> diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
> index deb90cf4bffb..a0229ea42977 100644
> --- a/include/linux/slub_def.h
> +++ b/include/linux/slub_def.h
> @@ -12,60 +12,6 @@
>  #include <linux/reciprocal_div.h>
>  #include <linux/local_lock.h>
>  
> -enum stat_item {
> -	ALLOC_FASTPATH,		/* Allocation from cpu slab */
> -	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
> -	FREE_FASTPATH,		/* Free to cpu slab */
> -	FREE_SLOWPATH,		/* Freeing not to cpu slab */
> -	FREE_FROZEN,		/* Freeing to frozen slab */
> -	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
> -	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
> -	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
> -	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
> -	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
> -	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
> -	FREE_SLAB,		/* Slab freed to the page allocator */
> -	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
> -	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
> -	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
> -	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
> -	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
> -	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
> -	DEACTIVATE_BYPASS,	/* Implicit deactivation */
> -	ORDER_FALLBACK,		/* Number of times fallback was necessary */
> -	CMPXCHG_DOUBLE_CPU_FAIL,/* Failure of this_cpu_cmpxchg_double */
> -	CMPXCHG_DOUBLE_FAIL,	/* Number of times that cmpxchg double did not match */
> -	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
> -	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
> -	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
> -	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
> -	NR_SLUB_STAT_ITEMS
> -};
> -
> -#ifndef CONFIG_SLUB_TINY
> -/*
> - * When changing the layout, make sure freelist and tid are still compatible
> - * with this_cpu_cmpxchg_double() alignment requirements.
> - */
> -struct kmem_cache_cpu {
> -	union {
> -		struct {
> -			void **freelist;	/* Pointer to next available object */
> -			unsigned long tid;	/* Globally unique transaction id */
> -		};
> -		freelist_aba_t freelist_tid;
> -	};
> -	struct slab *slab;	/* The slab from which we are allocating */
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -	struct slab *partial;	/* Partially allocated frozen slabs */
> -#endif
> -	local_lock_t lock;	/* Protects the fields above */
> -#ifdef CONFIG_SLUB_STATS
> -	unsigned stat[NR_SLUB_STAT_ITEMS];
> -#endif
> -};
> -#endif /* CONFIG_SLUB_TINY */
> -
>  #ifdef CONFIG_SLUB_CPU_PARTIAL
>  #define slub_percpu_partial(c)		((c)->partial)
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index 3e01731783df..979932d046fd 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -330,6 +330,60 @@ static void debugfs_slab_add(struct kmem_cache *);
>  static inline void debugfs_slab_add(struct kmem_cache *s) { }
>  #endif
>  
> +enum stat_item {
> +	ALLOC_FASTPATH,		/* Allocation from cpu slab */
> +	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
> +	FREE_FASTPATH,		/* Free to cpu slab */
> +	FREE_SLOWPATH,		/* Freeing not to cpu slab */
> +	FREE_FROZEN,		/* Freeing to frozen slab */
> +	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
> +	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
> +	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
> +	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
> +	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
> +	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
> +	FREE_SLAB,		/* Slab freed to the page allocator */
> +	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
> +	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
> +	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
> +	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
> +	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
> +	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
> +	DEACTIVATE_BYPASS,	/* Implicit deactivation */
> +	ORDER_FALLBACK,		/* Number of times fallback was necessary */
> +	CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
> +	CMPXCHG_DOUBLE_FAIL,	/* Failures of slab freelist update */
> +	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
> +	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
> +	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
> +	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
> +	NR_SLUB_STAT_ITEMS
> +};
> +
> +#ifndef CONFIG_SLUB_TINY
> +/*
> + * When changing the layout, make sure freelist and tid are still compatible
> + * with this_cpu_cmpxchg_double() alignment requirements.
> + */
> +struct kmem_cache_cpu {
> +	union {
> +		struct {
> +			void **freelist;	/* Pointer to next available object */
> +			unsigned long tid;	/* Globally unique transaction id */
> +		};
> +		freelist_aba_t freelist_tid;
> +	};
> +	struct slab *slab;	/* The slab from which we are allocating */
> +#ifdef CONFIG_SLUB_CPU_PARTIAL
> +	struct slab *partial;	/* Partially allocated frozen slabs */
> +#endif
> +	local_lock_t lock;	/* Protects the fields above */
> +#ifdef CONFIG_SLUB_STATS
> +	unsigned int stat[NR_SLUB_STAT_ITEMS];
> +#endif
> +};
> +#endif /* CONFIG_SLUB_TINY */
> +
>  static inline void stat(const struct kmem_cache *s, enum stat_item si)
>  {
>  #ifdef CONFIG_SLUB_STATS

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXBAbu7pR4o7JIa5%40localhost.localdomain.
