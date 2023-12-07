Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBD7BYSVQMGQEX7ASODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F3C5807EB8
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 03:40:17 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1faef8466f9sf842779fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 18:40:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701916816; cv=pass;
        d=google.com; s=arc-20160816;
        b=q7eESGBP8OZDbyTKXn5qDYPeyV4WYjIj8DT9ODTegsDG5GuWlLTTIWlT+BxT9A42ws
         EEU0fFv4WOHSxrWZpmwbcKtE/F0D0ddL+w5rw8hsTbiSdcEEbrZIz7p4c0wLWhYeYcz6
         P9eeyPJSUq8bvU7YP+D46qZ1bGHc4TVmLctfTSv7792De4os/ADmeuTwDsY3pLmLEhr/
         8xaliWHGBLwJOlDP/7wD76lXOGkqm/wvXbByMToYx+2hw/WLg5bKy4HD79OiufG+4alV
         tNu1z8iqqOZhGTU6MTFTUF4k+xrTTyRmguWhGCH5ksNQNVK3+PQ7qACujDqx3wYynqco
         NtVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=EE/CWEquZXw/Hs2pXTzUOge1o3R7nD0cPF6AOX8fNPI=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=s9Cfgc/w+vfJAIxfOQqVUUsQG5rOgAZfX/3Pg34g+wHAoWnmQTdJQJ4qwjLgsp43Nv
         rv8HZu6HClZnhlfeLqXroFJQVBL4BiMFTGUhPyANeAA/gAXAgS/QA8yLhFtVUVkXmoXr
         DhYP5kgJvUbqKLDZm8GuN9Z0HS8Ld4XPaf7+pE5CL11qMpiKX+mlMcpOeJN1zRuxHA+F
         DLCy3IxuhNXRjQa4mt9Oj4CPwLosRnLXHRUPTjvznOdHzklzJUDWCTJRXCTQx7U3sHEp
         aDhI3LLJi6+XDmxkUev61dB8ZKPR76vffgL2u+Wk4ZE12T8Xzn6zh5VHjKXtu3751FcJ
         ynSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fL0bVQJ8;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701916816; x=1702521616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EE/CWEquZXw/Hs2pXTzUOge1o3R7nD0cPF6AOX8fNPI=;
        b=BfXYuuqdRldqUyaZSoTkUPUL2BEeXUEAUwRbb+f5stgtBFxik9Au4cCcMMxvCbYKSU
         1lFs+kSCuT060m0pKy37iTqn5IZkT9O/lBSfaJH4pzsfuslRZMf+pgraXd6jytsy8WJo
         wMwqfA4UUHjodfZ+FEUtKCL7bI4SXSJvp5QOvAcNdZZEsDlUySobGH+D9VaSwXrMHyIM
         y7UIeVEDq/ntLL0kHqGHIJb03mIpacbQc2IFtwgXAkT4s4lytji+/uGcVeDbgLeG5kXQ
         soHg7ln39FuaP33WUltfvDOxeYo8t4wXKFLcGz2SBm4I+a/W1Vzss5akvfdyMMB0Q5E8
         im0A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701916816; x=1702521616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=EE/CWEquZXw/Hs2pXTzUOge1o3R7nD0cPF6AOX8fNPI=;
        b=D4VCE8II71VZs5MNFor0ujfLIVsMlSQRVsmv/QViph99HZWG6vPW5FU/yswN1USjtx
         mkMAAUVRPQhz0E6hUG2Nk2zdRDhXvFbZlpKSObdHJCxqLKMlEptL8p144fa0OtEWmCU7
         xt+KLHMAYhjrdJ/O5/aumgAOJMfkSnJTgFq1L1YbMBeFzHpvLN97msNVKJ/0rWBwR8bz
         PnPLzdUTMBLeWiBzK5NdwZoP/KKNH7T4Ts+Sb0g+mFC9MkDzjItet9IVnst9+LUqRLOw
         CavH7YtyyvP8J7JESIUCwKnxRRhIA/pNYaXgj7VE3DPDh/sg2OGUQ2EKAR6QrEtVM43R
         edDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701916816; x=1702521616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EE/CWEquZXw/Hs2pXTzUOge1o3R7nD0cPF6AOX8fNPI=;
        b=DlB9e2PAM3sNHL/BsrEwzMh7JVWu+12s9TchSj971J73zJaCFLMwZ8qb0jtD4z2LJU
         7yJRqAkVPlXW3XCCqB1vR9I7hiiTGpPGsNoCWgkm6aJ6tRV1+iKHgOcDBT2zgY5/k7U9
         afS6pqRmg3wbZ3fe4V7FYR/M397m4XFw9oTxn0J2Nb9dfxAah9pi6OQuIqQiS0+YOU5e
         HMWLaC2Vk2P9m9K6+kTXdUmu52pv7lbCf4bzFDK9x7uYO9QdaxkYeD7cCUZxvVkloqeZ
         3K8UyKMA70VnXydtEhjIlsZWY60OHxPeViMYbu8OybVOmDt9hV9hceRLw0sVpBGgTi+7
         EboQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy+BJaoJhAK745dhaUd2oHldPN5x6O1jnyYeRy/mNe4+Ex6vQUU
	VjONTVUfhEy69bivWnQisvY=
X-Google-Smtp-Source: AGHT+IFQA9hg/rVXmRXK5tM37eLHfbZju6LPFnHC76vbbaf02TsmxaKRTNHyte0gmUIj4H0cTz1Q8w==
X-Received: by 2002:a05:6870:a2c6:b0:1fb:75a:6d1e with SMTP id w6-20020a056870a2c600b001fb075a6d1emr2129937oak.69.1701916815841;
        Wed, 06 Dec 2023 18:40:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d14a:b0:1fb:358b:7c2d with SMTP id
 f10-20020a056870d14a00b001fb358b7c2dls740933oac.2.-pod-prod-01-us; Wed, 06
 Dec 2023 18:40:15 -0800 (PST)
X-Received: by 2002:a05:6808:178a:b0:3b8:bb95:9763 with SMTP id bg10-20020a056808178a00b003b8bb959763mr2338276oib.34.1701916815198;
        Wed, 06 Dec 2023 18:40:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701916815; cv=none;
        d=google.com; s=arc-20160816;
        b=gJgRqsH+a+i3VGqxK71hhN1OVNMeP+hjzKVQd93nlVBPyDFlclFboGP0I/Nt3Vcwe5
         8EjqGp3ypLdPgIRr84jQmiY+gKVMIFyP68RwR031pdtTeoTr4tFYQi0Nt0QiAfh80F2M
         fxQIMUmh9d4Ou+T5d34ecXVecHzb86wuIVLxRGK96oEF7h5f2bV3Lh+7y6BZ6S1U4LGi
         Idk2FjYSylRylp0yYDoAuiUcY48z7VGeNo4zp6I4ugUzMsYgMjuaJQV4OyUfOYUZvjXD
         3RU5yls47vdOGY+rVIH7VzVAIdEXtwIhRHmWHG0H/D4kEdHPsVWxb8nZucmChVXk4sMI
         ELYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CjGR+gix1XQRxaJ5p7IMY1S7CLbhofOgFFoOucSld8k=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=LD8KNWwbTy86Kuoce4RBWTpkV+K8PU+dDH+QIgBnmqK5isK7Cdp3j3vH4+QnbZVbKC
         y/Cw5HGkwm8Z2t4JibcnloIpePr7HvkWiRpcLt5kc2hnsa1DnxfDM7eDSHGML7ZqINe5
         NequmKAYJ2AYktXtYF0vNufiG80VGzyyYaWNW+Q7VdfwOgsEBrgf+solEOAjCAuLOJin
         wOrCf67fCO86fJH3CRwRqUi7TqVeUjoo6H5JyXKCIuIuJLm0YvcVxEN6bT42LgnYEoZd
         4ooeQxHfjcar5qmV//edZ96JwlLiGTnSm34bURWrvD1IBnGVEWaOIMY8RI3IXJGqLtit
         hU3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fL0bVQJ8;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id bi1-20020a056808188100b003ae413f2b6esi27457oib.5.2023.12.06.18.40.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 18:40:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-6ce9c8c45a7so160236b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 18:40:15 -0800 (PST)
X-Received: by 2002:a05:6a20:1593:b0:18f:97c:4f3b with SMTP id h19-20020a056a20159300b0018f097c4f3bmr1673961pzj.71.1701916814237;
        Wed, 06 Dec 2023 18:40:14 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id pl16-20020a17090b269000b0028652f98978sm121526pjb.8.2023.12.06.18.40.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 18:40:13 -0800 (PST)
Date: Thu, 7 Dec 2023 11:40:05 +0900
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
Subject: Re: [PATCH v2 21/21] mm/slub: optimize free fast path code layout
Message-ID: <ZXEwhbDgESjPs/vh@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-21-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-21-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fL0bVQJ8;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42e
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

On Mon, Nov 20, 2023 at 07:34:32PM +0100, Vlastimil Babka wrote:
> Inspection of kmem_cache_free() disassembly showed we could make the
> fast path smaller by providing few more hints to the compiler, and
> splitting the memcg_slab_free_hook() into an inline part that only
> checks if there's work to do, and an out of line part doing the actual
> uncharge.
> 
> bloat-o-meter results:
> add/remove: 2/0 grow/shrink: 0/3 up/down: 286/-554 (-268)
> Function                                     old     new   delta
> __memcg_slab_free_hook                         -     270    +270
> __pfx___memcg_slab_free_hook                   -      16     +16
> kfree                                        828     665    -163
> kmem_cache_free                             1116     948    -168
> kmem_cache_free_bulk.part                   1701    1478    -223
> 
> Checking kmem_cache_free() disassembly now shows the non-fastpath
> cases are handled out of line, which should reduce instruction cache
> usage.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 40 ++++++++++++++++++++++++----------------
>  1 file changed, 24 insertions(+), 16 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 77d259f3d592..3f8b95757106 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1959,20 +1959,11 @@ void memcg_slab_post_alloc_hook(struct kmem_cache *s, struct obj_cgroup *objcg,
>  	return __memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
>  }
>  
> -static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> -					void **p, int objects)
> +static void __memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> +				   void **p, int objects,
> +				   struct obj_cgroup **objcgs)
>  {
> -	struct obj_cgroup **objcgs;
> -	int i;
> -
> -	if (!memcg_kmem_online())
> -		return;
> -
> -	objcgs = slab_objcgs(slab);
> -	if (!objcgs)
> -		return;
> -
> -	for (i = 0; i < objects; i++) {
> +	for (int i = 0; i < objects; i++) {
>  		struct obj_cgroup *objcg;
>  		unsigned int off;
>  
> @@ -1988,6 +1979,22 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>  		obj_cgroup_put(objcg);
>  	}
>  }
> +
> +static __fastpath_inline
> +void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab, void **p,
> +			  int objects)
> +{
> +	struct obj_cgroup **objcgs;
> +
> +	if (!memcg_kmem_online())
> +		return;
> +
> +	objcgs = slab_objcgs(slab);
> +	if (likely(!objcgs))
> +		return;
> +
> +	__memcg_slab_free_hook(s, slab, p, objects, objcgs);
> +}
>  #else /* CONFIG_MEMCG_KMEM */
>  static inline struct mem_cgroup *memcg_from_slab_obj(void *ptr)
>  {
> @@ -2047,7 +2054,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
>  	 * The initialization memset's clear the object and the metadata,
>  	 * but don't touch the SLAB redzone.
>  	 */
> -	if (init) {
> +	if (unlikely(init)) {
>  		int rsize;
>  
>  		if (!kasan_has_integrated_init())
> @@ -2083,7 +2090,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  		next = get_freepointer(s, object);
>  
>  		/* If object's reuse doesn't have to be delayed */
> -		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
> +		if (likely(!slab_free_hook(s, object,
> +					   slab_want_init_on_free(s)))) {
>  			/* Move object to the new freelist */
>  			set_freepointer(s, object, *head);
>  			*head = object;
> @@ -4282,7 +4290,7 @@ static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
>  	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
>  	 * to remove objects, whose reuse must be delayed.
>  	 */
> -	if (slab_free_freelist_hook(s, &head, &tail, &cnt))
> +	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
>  		do_slab_free(s, slab, head, tail, cnt, addr);
>  }
>  
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEwhbDgESjPs/vh%40localhost.localdomain.
