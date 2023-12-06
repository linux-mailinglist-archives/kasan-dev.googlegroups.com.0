Return-Path: <kasan-dev+bncBCKLZ4GJSELRBO4CX6VQMGQEO7KMKLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 439A9806375
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 01:33:02 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c9eca8abe5sf35862261fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 16:33:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701822781; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZFz9oTIItWkV+xwTtcMj+c4T7Xk55QQ+B7W+1x+HGDJAsRcODx5cb8kWEx7yrLGtua
         jIacgyjNHt28EK0rgoVtpLs1jxniO85TDuW/NcUyT5IIytJDcZUIAYGLgPcprtioVAnC
         9voaunmXELZnaCUlcn0Vr0G14z3mwpjSNmyY20CyjlAkROaAIDdVpAK68SBCKGeZyEni
         4z4PCgt+znUncIlVLRdQpxERQydWbcKV6QJEjU2ZnGwRNJotme+nSp4c76vTTlDDIYj8
         +sVNx+3yeE8B+7d8a/e+9qntc9waDdAiM/T6gmROcLitMm6bx2sdldGhMPChmvGoEVl5
         zW7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=qhqlkMHc59zvGpYYue5Q27E2cX79rmBdrD/707awL3c=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=cE3xNAGZOBh6uipMt66TKn/xAIlUs1PdPLUHLnfXkGOS4sTdNhT3WrXFzycJkRcO1K
         MDeThKq1irNyV+ge1vtaNjPlXrnLGDYrFMT+41Y0evcjUihsRKC9zB/MhCb4fs/owip8
         x8tDYdrdbWE7WA6TcQXJ8Ep3JMNlHgFy4GSlQpUdr95hbqX462fvXTmludT9YQqYcL5L
         UEvJqHsXuMhmXa/l6Ij24Ts8zLgYNUHJlZb4Pz4YB0vTwGHLVfoGnuvV1qZNnbdRNYmP
         JFJtgN5fi9sQYZsMazQPLVYzN62770hEM7xo5XqHvtDB35I29kTvpS/8KKGflphrlQTM
         YX1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fw9nU65c;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.187 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701822781; x=1702427581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=qhqlkMHc59zvGpYYue5Q27E2cX79rmBdrD/707awL3c=;
        b=m11WmNWx6CodAySR2TNz0M+EhQimP1t8M0Zk7d2tabQbTmvrrwkiPgBmZYly1I8Rvp
         wXTI+KRHdCSsKM/8gsR7H2zae2XVGOkjX4sdI4fTo00apyd+CAl0tOr4z7WZGGT7Wr7F
         160AdddrHHEDb9+U1uxwIvf2CqDPJRedCzQ4w28lLtF3MBzfTmDt0DGiu2a1jHHOkVVE
         fxVK/ugmc8bsvfXB6h/eUWbN/Ez74R9QEGsdO/442SDaWX6+ycU9LQo5TjdTgLAZ8aff
         NFWYw03n4AIrDYUSfYDhvzeT8LeTmvQWNMhHTYl+BvpfZMvCCer0kqzGf93YQumICm7y
         iCkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701822781; x=1702427581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=qhqlkMHc59zvGpYYue5Q27E2cX79rmBdrD/707awL3c=;
        b=ijYogBL/ajZm33fjKce/Mb3F37qM8IRrjDn5pOwIVoMVKnFhm9caSigBVbuLe3apJW
         pWtbiTHC/+2ZiZOjcEyGZm6fE6cd2+ww5gVUvJTQC9SWsG7tX/5F/sMSNidee1BTQP6R
         U/FQeB/uhKFqtazXaCJFFbZGaJl3RDLU3RkDBsajecBpiT/oAzj5PdCTq774/8Eilqqj
         S/ASaL14VkuxRU7n3t/dNdy4v3Jndo3agPwe2i5QnXwctStKq0m9Qw3vhAi0h7q9F1s2
         QX4Kj7vXsPE0MRyXzqjhK2o4a3oWC4zFc8/H7u4V9PVYj3LBggRO23Y32B9gpZ7q692I
         5PcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywee3L5bSB82/cB+NqV5n2/s7IdNZif/1/xRRrV7AQ59I5W6Ubi
	Aetm71B9es8xzuCct469rVY=
X-Google-Smtp-Source: AGHT+IFhEM1LSBi7oGAmkbbM0AsexMBEZ0M4qJyqKncvgDW9v2O5jYMl80DH+CZQCJr2gYYSuflEqg==
X-Received: by 2002:a2e:7a14:0:b0:2ca:cb:4273 with SMTP id v20-20020a2e7a14000000b002ca00cb4273mr57593ljc.24.1701822780160;
        Tue, 05 Dec 2023 16:33:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:19a6:b0:2ca:1c74:c45c with SMTP id
 bx38-20020a05651c19a600b002ca1c74c45cls466772ljb.2.-pod-prod-04-eu; Tue, 05
 Dec 2023 16:32:58 -0800 (PST)
X-Received: by 2002:a2e:7e10:0:b0:2ca:1082:3b30 with SMTP id z16-20020a2e7e10000000b002ca10823b30mr60519ljc.95.1701822777931;
        Tue, 05 Dec 2023 16:32:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701822777; cv=none;
        d=google.com; s=arc-20160816;
        b=yms3oMqeW1OKmhz5O9ugkEk57cxQ85J+rqzp0AnKVcYWRqUBmqsR+3KkkVK1yJHFSY
         Hq3jvfhklmnezgpCN/JQ4X/S0oQIGWkvofZPz0Vj2fLpaYfcD+RwdPzknZtUigGufwxq
         gtm9QaTc971N5Pqwy7CKnPWO/vk2pK5hQn9Uu6/el7s25vo46gBAIQM/Tj3l9umDHNH9
         +eJ57F1XsnpVy5cOXLKk2yKjTIT5z4zmBssnHsMEi7q+/BL7KmFMVMhe5uyTErs7eXjM
         RTUzTBHSrfzQwHquAkyLmrim12xTN1wL0HdFHBTHhwAc1rydehTzkDdnMSDzbV39fs5W
         SmsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=3SnfDF8plKJgpWd+lzxgl5v07A2wnaRHIaQlR7xVpG0=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=p7kztALsI1TnJTIuJwJ1jvb+4s1XA8pe+8sLzDWoh5Re5MSDPywZ4qveY8/2KpR18u
         lhmFG+it8BpbqBjSIpakQ0H7Yql3gpVuS6g/CyxMntyJbZaq/qkT4BDlBrNEaH9fINIc
         lpVHBYzWNKrGQD6YUm2/Xy5vAzBsASlI9MLY037kaIxRkFNw3ZDUSSn5aGmE82ydOvdb
         ZaVqbLNROrUvw9fZtybCEn/hLgyHh1zJUf25lFbNMmzLrkKrqR/A3p9uLIB4kG8SANaO
         AaPmHh231A29ubNsNTtDrwi6ghrP/S6CmFMBPNkSRLZfX1dzrsqFt0c6sj9G41LNy4R0
         U1iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fw9nU65c;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.187 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta0.migadu.com (out-187.mta0.migadu.com. [91.218.175.187])
        by gmr-mx.google.com with ESMTPS id v23-20020a2e9f57000000b002c9f6a36a65si432935ljk.1.2023.12.05.16.32.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Dec 2023 16:32:57 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.187 as permitted sender) client-ip=91.218.175.187;
Message-ID: <836818de-73ca-4233-830a-71a80dcc1c6c@linux.dev>
Date: Wed, 6 Dec 2023 08:31:45 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 2/4] mm/slub: introduce __kmem_cache_free_bulk() without
 free hooks
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-2-88b65f7cd9d5@suse.cz>
 <30f88452-740b-441f-bb4f-a2d946e35cf5@linux.dev>
 <25eb93ee-e71a-c257-ef4b-9fbb3b694faf@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <25eb93ee-e71a-c257-ef4b-9fbb3b694faf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fw9nU65c;       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.187 as
 permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2023/12/6 03:57, Vlastimil Babka wrote:
> On 12/5/23 09:19, Chengming Zhou wrote:
>> On 2023/12/5 03:34, Vlastimil Babka wrote:
>>> Currently, when __kmem_cache_alloc_bulk() fails, it frees back the
>>> objects that were allocated before the failure, using
>>> kmem_cache_free_bulk(). Because kmem_cache_free_bulk() calls the free
>>> hooks (KASAN etc.) and those expect objects that were processed by the
>>> post alloc hooks, slab_post_alloc_hook() is called before
>>> kmem_cache_free_bulk().
>>>
>>> This is wasteful, although not a big concern in practice for the rare
>>> error path. But in order to efficiently handle percpu array batch refill
>>> and free in the near future, we will also need a variant of
>>> kmem_cache_free_bulk() that avoids the free hooks. So introduce it now
>>> and use it for the failure path.
>>>
>>> As a consequence, __kmem_cache_alloc_bulk() no longer needs the objcg
>>> parameter, remove it.
>>
>> The objects may have been charged before, but it seems __kmem_cache_alloc_bulk()
>> forget to uncharge them? I can't find "uncharge" in do_slab_free(), or maybe
>> the bulk interface won't be used on chargeable slab?
> 
> You're right! I missed that the memcg_pre_alloc_hook() already does the
> charging, so we need to uncharge. How does this look? Thanks for noticing!
> 
> ----8<----
> From 52f8e77fdfeabffffdce6b761ba5508e940df3be Mon Sep 17 00:00:00 2001
> From: Vlastimil Babka <vbabka@suse.cz>
> Date: Thu, 2 Nov 2023 16:34:39 +0100
> Subject: [PATCH 2/4] mm/slub: introduce __kmem_cache_free_bulk() without free
>  hooks
> 
> Currently, when __kmem_cache_alloc_bulk() fails, it frees back the
> objects that were allocated before the failure, using
> kmem_cache_free_bulk(). Because kmem_cache_free_bulk() calls the free
> hooks (KASAN etc.) and those expect objects that were processed by the
> post alloc hooks, slab_post_alloc_hook() is called before
> kmem_cache_free_bulk().
> 
> This is wasteful, although not a big concern in practice for the rare
> error path. But in order to efficiently handle percpu array batch refill
> and free in the near future, we will also need a variant of
> kmem_cache_free_bulk() that avoids the free hooks. So introduce it now
> and use it for the failure path.
> 
> In case of failure we however still need to perform memcg uncharge so
> handle that in a new memcg_slab_alloc_error_hook(). Thanks to Chengming
> Zhou for noticing the missing uncharge.
> 
> As a consequence, __kmem_cache_alloc_bulk() no longer needs the objcg
> parameter, remove it.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Looks good to me!

Reviewed-by: Chengming Zhou <zhouchengming@bytedance.com>

Thanks!

> ---
>  mm/slub.c | 56 ++++++++++++++++++++++++++++++++++++++++++++++---------
>  1 file changed, 47 insertions(+), 9 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index d7b0ca6012e0..0a9e4bd0dd68 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2003,6 +2003,14 @@ void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
>  
>  	__memcg_slab_free_hook(s, slab, p, objects, objcgs);
>  }
> +
> +static inline
> +void memcg_slab_alloc_error_hook(struct kmem_cache *s, int objects,
> +			   struct obj_cgroup *objcg)
> +{
> +	if (objcg)
> +		obj_cgroup_uncharge(objcg, objects * obj_full_size(s));
> +}
>  #else /* CONFIG_MEMCG_KMEM */
>  static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
>  {
> @@ -2032,6 +2040,12 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>  					void **p, int objects)
>  {
>  }
> +
> +static inline
> +void memcg_slab_alloc_error_hook(struct kmem_cache *s, int objects,
> +				 struct obj_cgroup *objcg)
> +{
> +}
>  #endif /* CONFIG_MEMCG_KMEM */
>  
>  /*
> @@ -4478,6 +4492,27 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
>  	return same;
>  }
>  
> +/*
> + * Internal bulk free of objects that were not initialised by the post alloc
> + * hooks and thus should not be processed by the free hooks
> + */
> +static void __kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
> +{
> +	if (!size)
> +		return;
> +
> +	do {
> +		struct detached_freelist df;
> +
> +		size = build_detached_freelist(s, size, p, &df);
> +		if (!df.slab)
> +			continue;
> +
> +		do_slab_free(df.s, df.slab, df.freelist, df.tail, df.cnt,
> +			     _RET_IP_);
> +	} while (likely(size));
> +}
> +
>  /* Note that interrupts must be enabled when calling this function. */
>  void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>  {
> @@ -4498,8 +4533,9 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>  EXPORT_SYMBOL(kmem_cache_free_bulk);
>  
>  #ifndef CONFIG_SLUB_TINY
> -static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> -			size_t size, void **p, struct obj_cgroup *objcg)
> +static inline
> +int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
> +			    void **p)
>  {
>  	struct kmem_cache_cpu *c;
>  	unsigned long irqflags;
> @@ -4563,14 +4599,13 @@ static inline int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
>  
>  error:
>  	slub_put_cpu_ptr(s->cpu_slab);
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
> -	kmem_cache_free_bulk(s, i, p);
> +	__kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  
>  }
>  #else /* CONFIG_SLUB_TINY */
>  static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> -			size_t size, void **p, struct obj_cgroup *objcg)
> +				   size_t size, void **p)
>  {
>  	int i;
>  
> @@ -4593,8 +4628,7 @@ static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
>  	return i;
>  
>  error:
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
> -	kmem_cache_free_bulk(s, i, p);
> +	__kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }
>  #endif /* CONFIG_SLUB_TINY */
> @@ -4614,15 +4648,19 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	if (unlikely(!s))
>  		return 0;
>  
> -	i = __kmem_cache_alloc_bulk(s, flags, size, p, objcg);
> +	i = __kmem_cache_alloc_bulk(s, flags, size, p);
>  
>  	/*
>  	 * memcg and kmem_cache debug support and memory initialization.
>  	 * Done outside of the IRQ disabled fastpath loop.
>  	 */
> -	if (i != 0)
> +	if (likely(i != 0)) {
>  		slab_post_alloc_hook(s, objcg, flags, size, p,
>  			slab_want_init_on_alloc(flags, s), s->object_size);
> +	} else {
> +		memcg_slab_alloc_error_hook(s, size, objcg);
> +	}
> +
>  	return i;
>  }
>  EXPORT_SYMBOL(kmem_cache_alloc_bulk);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/836818de-73ca-4233-830a-71a80dcc1c6c%40linux.dev.
