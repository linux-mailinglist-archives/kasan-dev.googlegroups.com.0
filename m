Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBKFEYSVQMGQEF5QCB5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C4E10807D3F
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 01:30:33 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-67aa0c94343sf27871496d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 16:30:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701909032; cv=pass;
        d=google.com; s=arc-20160816;
        b=S0Pnzq+D/ZUoZtvVY7dcy0I4A6Z1SVjhrZ6XUgTPRQ+e9jp7xRlsjkxJUkCobZaFWJ
         A7Xr3wZLOZw2aJeCIzXgptsVauOfE5XsapNvdPT643cg4jU7+4erSScmmHXCfDFMcz50
         XjpmeL5tKP7m2XW9HEhskI3pYZ9sPzDzpybDqg8q4YfO+2rhwzbVd2B7LiiKTk/uIkWl
         b7FrCzrUg5xDanGs7dNN5FNXsJNJDhmSYwezXULpZ6CSeq/c26xZaN6/6sE9c/3gzhQV
         ak93EDk+UwxGy9PfV0LoO1FPLGaJzID/RhABWUaacQem+HktEItCnD+4gECcHIEztPsr
         4UfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=0lLiZXZDkFU4wfZpfjrlIWsoQO/Wt+PkKjRp+GbOulI=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=taEQ9/I4BP1Skf32JJXNSLyL5ZC5g6W+ozf8k2IJjIthXa5dCzdMjUINMbY29G5qxy
         ZrLJLT26SbcW+uUlSkKW9ySWQuIKz8NoRy6onLsx/FxGIrDb5GzhF08T9rhcMjp+Nw5g
         e11VCZG3UcYw2j34t1Om3tkFC33BwJIFn1sssAkn62gDbD13Z2LLTqFnmM5+DP/cEQaM
         GDycPSAYlgz+8RkCflLNFxFdM0P+GAiH7BoHVV8x+cRSaKdILLaYJxPCIysz2257gIbe
         +Ye86RDrU5wb+LZ9iH0vv7ZA85f5/MYjHWRUkMRApTEx7f78rqSTg7cW1uKtSRbnoNHI
         NHlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jaLieCTn;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701909032; x=1702513832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0lLiZXZDkFU4wfZpfjrlIWsoQO/Wt+PkKjRp+GbOulI=;
        b=TVxc7rNlpKsPaMZaHZDi9ZzD0YRuZ658vwwLpg1qPQXh5tDunQyp0kz1QTytARkoRS
         bJA51JVD5aD3ilytPVfv1tCXrU0D7z3Ak4WWRNezfG96b7HprujLhiRkWUd385mAfIdt
         PYfmjfUE5T19LRc1uqg52QdihvIa2MwouZp3wLTp8VCbq5/V76EBMrkcKvuEEgTTnxcl
         3pWjtAFVErVY2LTRWwLutTrH6yTLwgH0ToT1wWlGlJ3v6Wm5xRgXEQndBhDpZPq22R/P
         uk4tS56X0yMCTCH0KEOjjcXguRiofAr5YKFwKPnXb3XylP9roDL6QRfTlIYww+q12GBq
         u1LA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701909032; x=1702513832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0lLiZXZDkFU4wfZpfjrlIWsoQO/Wt+PkKjRp+GbOulI=;
        b=LgDj9QCjVx0QiOowd4+PftjXFMt1B4q2M1koqoVinD5rPwTLBmwhtbyEs+vHy0KC76
         C/DwKqyCrTVMSvbUsi+G/02rS6HIhGpFQFIM2ht6g1PL3KAiB+2tTQOHSv9AGnvEPzKB
         d/RWmvtF0Bqf6Lw+Ea6EdFRtbmHW8cZ+0VdtID1NLcQgdgrUe132PZjCEYjYlYrxdEIa
         +588IypTNnRIxN2jNdnkzmQuOh1dePePwTDNvGRinqqruMQahDDU6F3QTnWznWpeqt12
         VlGKMepStYq38YtG1rhKkQL6UuzoA0X18fBrVviVs9Dv9s0zv5/djuAqn6iGtHRpXTyf
         lVCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701909032; x=1702513832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0lLiZXZDkFU4wfZpfjrlIWsoQO/Wt+PkKjRp+GbOulI=;
        b=Ge05W7vaVoMQgouzVI/dKqZFvjfLgfk7BkM1YeODLKlfmqH6jpndV9hl5AEIUcVFEb
         omYemQwJqgu9dc9PzxQysOd5DnMRM9w/NPI+GNlJZThAB5FvcVDzawViTysf+eUbeqzW
         aWkVzUu64Q2Razu0VackJjqIAKW8DtsZtiYBqIM42SwBz8QZcmnIWbLEho3xscG5KhL9
         Bnfvb7HKuoVulaD7/VhMYSQWx7VWgHZPMJ717x4/gQhXBDtbEzSVf6aKI1vjjktkByQs
         UwakChGj8oa9sOVSeR1Wubvs6Lgcx5SKwY4WjLBH7XkmoKDL6IzA/J4baZJ/5sDaVrMW
         B8ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwuH0ssNUfTmRVnSoE3FMu14e7npSl2s0g+yqHgicxjcJIkr4Nd
	RikjWQsR1DGj/UVzTvfBRBs=
X-Google-Smtp-Source: AGHT+IGDywcARkSPr6BzyHQBc0wZm1BZ8LkrN0NSo8NAwD3gwkjFe+s73CIgACNG+IlDQex+SVh7LQ==
X-Received: by 2002:a0c:fec4:0:b0:67c:cfba:5098 with SMTP id z4-20020a0cfec4000000b0067ccfba5098mr958693qvs.43.1701909032429;
        Wed, 06 Dec 2023 16:30:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:bec6:0:b0:67a:9173:54f9 with SMTP id f6-20020a0cbec6000000b0067a917354f9ls362046qvj.1.-pod-prod-00-us;
 Wed, 06 Dec 2023 16:30:31 -0800 (PST)
X-Received: by 2002:a0c:b559:0:b0:67a:5be3:f0f8 with SMTP id w25-20020a0cb559000000b0067a5be3f0f8mr3700677qvd.19.1701909031517;
        Wed, 06 Dec 2023 16:30:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701909031; cv=none;
        d=google.com; s=arc-20160816;
        b=g4NLrutbhaHSwMzJIMjaHfGjS7Gyj40Z2mIWcEOZ16fhXhi0FSdB3sdbApn70JinV5
         2XUYYJ+GRJfemmv3OwNOmop8IbqDB+waHKgNIJxra1NhWY/KUhvw7fx4WMl1q6B9E/av
         lYB4QVh0meRKsyAHssnHJq99dBXnCtJVzzmdPmlfjgHfbsKg7YoCJfY7/b+BrNjNxAZH
         +Su+GgFAtmqLch3L34OcrbuxKy6RWn6/CaAaa4JvwdKSt8yX7Jkm8W1QsMb4BwScv9yM
         Q14evDx409SRgO15HD9pEnqoOcdHdcAMlBaMEP4D+BPgnrSfh+d8rxwXMERJq6qjbvw8
         JHbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pUILdXO0fAmIum4i0LjaIhGHTq4M4euUAAZGlBJTfMI=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=xye6IfZNohLpvVVVQPnTfrVOnMzCcN8r0gqXcb9qYYfwJZEmAT0qYIw2s3um5o2ocS
         YsFZAFPbPn59HnZdcEYJoV4xPG5OQG0MsDKbwCtS2g7OxkVikqm2IqsxQfFsBH28vBQ3
         uJyFCjN24U/B1UKuA/6w0Dr54vFz+JRP/Cj/sutTv1tj9q6+dAplR86BXbGqflVYRGRR
         UiFyuXHe3AY7TvkJa4niU0tan6d44ryh5gNkhtIUOeEge9H+pnRSKjr4YTPP1wdwCqXp
         EPgsgGkWDie5otj+kvq+zS8Pxdw+eVHmApF+I9NyOfdldMiZ3nwRHpRPGWnhSUiZAhAJ
         dt4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jaLieCTn;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id ev7-20020a0562140a8700b0067a9e5ac0c4si10203qvb.8.2023.12.06.16.30.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 16:30:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-6cb55001124so85375b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 16:30:31 -0800 (PST)
X-Received: by 2002:a05:6a00:3a1a:b0:68f:a92a:8509 with SMTP id fj26-20020a056a003a1a00b0068fa92a8509mr4897945pfb.7.1701909030344;
        Wed, 06 Dec 2023 16:30:30 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id n19-20020aa78a53000000b006ce7d0d2590sm120723pfa.0.2023.12.06.16.30.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 16:30:29 -0800 (PST)
Date: Thu, 7 Dec 2023 09:30:15 +0900
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
Subject: Re: [PATCH v2 12/21] mm/slab: consolidate includes in the internal
 mm/slab.h
Message-ID: <ZXESF2kgL93SjEgl@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-12-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-12-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jaLieCTn;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::430
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

On Mon, Nov 20, 2023 at 07:34:23PM +0100, Vlastimil Babka wrote:
> The #include's are scattered at several places of the file, but it does
> not seem this is needed to prevent any include loops (anymore?) so
> consolidate them at the top. Also move the misplaced kmem_cache_init()
> declaration away from the top.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h | 28 ++++++++++++++--------------
>  1 file changed, 14 insertions(+), 14 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 3a8d13c099fa..1ac3a2f8d4c0 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -1,10 +1,22 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
>  #ifndef MM_SLAB_H
>  #define MM_SLAB_H
> +
> +#include <linux/reciprocal_div.h>
> +#include <linux/list_lru.h>
> +#include <linux/local_lock.h>
> +#include <linux/random.h>
> +#include <linux/kobject.h>
> +#include <linux/sched/mm.h>
> +#include <linux/memcontrol.h>
> +#include <linux/fault-inject.h>
> +#include <linux/kmemleak.h>
> +#include <linux/kfence.h>
> +#include <linux/kasan.h>
> +
>  /*
>   * Internal slab definitions
>   */
> -void __init kmem_cache_init(void);
>  
>  #ifdef CONFIG_64BIT
>  # ifdef system_has_cmpxchg128
> @@ -209,11 +221,6 @@ static inline size_t slab_size(const struct slab *slab)
>  	return PAGE_SIZE << slab_order(slab);
>  }
>  
> -#include <linux/kfence.h>
> -#include <linux/kobject.h>
> -#include <linux/reciprocal_div.h>
> -#include <linux/local_lock.h>
> -
>  #ifdef CONFIG_SLUB_CPU_PARTIAL
>  #define slub_percpu_partial(c)			((c)->partial)
>  
> @@ -347,14 +354,6 @@ static inline int objs_per_slab(const struct kmem_cache *cache,
>  	return slab->objects;
>  }
>  
> -#include <linux/memcontrol.h>
> -#include <linux/fault-inject.h>
> -#include <linux/kasan.h>
> -#include <linux/kmemleak.h>
> -#include <linux/random.h>
> -#include <linux/sched/mm.h>
> -#include <linux/list_lru.h>
> -
>  /*
>   * State of the slab allocator.
>   *
> @@ -405,6 +404,7 @@ gfp_t kmalloc_fix_flags(gfp_t flags);
>  /* Functions provided by the slab allocators */
>  int __kmem_cache_create(struct kmem_cache *, slab_flags_t flags);
>  
> +void __init kmem_cache_init(void);
>  void __init new_kmalloc_cache(int idx, enum kmalloc_cache_type type,
>  			      slab_flags_t flags);
>  extern void create_boot_cache(struct kmem_cache *, const char *name,

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXESF2kgL93SjEgl%40localhost.localdomain.
