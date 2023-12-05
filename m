Return-Path: <kasan-dev+bncBCKLZ4GJSELRBSGKXSVQMGQEL5ECIUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 95D6A8055E0
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 14:27:38 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50bf00775ecsf2653274e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 05:27:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701782858; cv=pass;
        d=google.com; s=arc-20160816;
        b=keeNZAE+WE1vHsJDLUwg5mZ1iTQ3VXCt7S7crPz6opxVB0H+ZImgicQyUOC6NMYR0j
         R/96c28Vqg9xvx5EIwb4sOlDHNCBfm4oMQd3x3AB2Y2Po3talIOMlE9WxjgWc91ut5f+
         ufh1ZehivcgyM5VJRkySJBZEdL27cyMDMKpdIpnuV5oztyBTzoA27hkH2r+t08VLmZ8q
         FEtQXkBkGauASgKHdDx4U9/ZTCn9E5oI96bI2xJcm2HyynfF2MUFTVNhACdh/DVGq0/F
         BSR0cIFOdGozTcQLtST/lQ5isOdeMTU41EiSyPzyrpPwoWZUXf25n/Y9FuDbCXKWawDH
         +ApQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=mT+dXphvapQ6bOVrg5Ew+P9q48qJlo+Qt/doSj3Ch3w=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=nwAsZefps5yuJE5M980e/o3wLyFRyAdQRTWKGYnOG3oryx0sqNgoztmoNymWYeEDS2
         MltTWyttueAORl7yBRQQKBb2xGRkpegLZ4OzPGdxH1zWRlSoJWe/gsBUFJtq0WTGiwyW
         SMJtJQgQ5zjN3PKjr1RviNUUtj4GDhkHVeWJCKelgPv3vcVnUkrQqZYXVk+rbXc/LMXN
         CS37s1yWOAfuHu9NfpUIroWkQnwaoQV3vFEyTZHFtOERbOaqGvxXMNYUEC8b+zdVIlkQ
         A9UqvWODnd1VNc5XSl4DISG3inzeoITsQE5A6lB0NLmQY9l51pWCXZ1s4A1kn5sIOeOj
         Nc0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FQUkcXNP;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701782858; x=1702387658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=mT+dXphvapQ6bOVrg5Ew+P9q48qJlo+Qt/doSj3Ch3w=;
        b=s3A3TG1agG8OALrYgRLvCv4+JM2MTdUymgT49sLbDYOUa2eISXAmfaVWayMOegrAJg
         WsuSOTVUdBsN94fjLDh+0K7d+UjyW1P59vNvLVG5A0Pz6Cnvvn/7dytN6o0UDxbQCgyn
         Z9cm9zVP1izwml3XghrvwenLKiLKBYErxU8l0xBMiWjsy4nUe5r6URfXto6t9yZ4aO5b
         aO9Wd/idpjORz/Anpb/0A52CXrr8EdTMU4VV8XmSqwFWsQEZFuZMpiCDk2zvZ+65Vtod
         Mvzz7Fq9l6i2Hta0vvjaWyBHwevfy/15FWQKG4+qjfodRtBV49t/ho1KpTPbG+Cj4Ott
         Jfbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701782858; x=1702387658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mT+dXphvapQ6bOVrg5Ew+P9q48qJlo+Qt/doSj3Ch3w=;
        b=M6YSZeZ9fuR+svF4GiUye5zRzN68uABuxEsVUFThzUNbOsJtxxGdm5MG3jr3+kKeJC
         diilSO7uTcR7ctc4h5+UBVJBn3VZnOnHqM/UU7cVvYdhLDMmy1xwtvz5bokZhhzucGCt
         Nm0xaS2tw2uKexyo0jr3yzOVFWuTWllG59wkVEnlRjblx4GioI5V9zcfRZRImiKiM2Ln
         qAyijEhyU96eWkqY/AdBdlcH4xLA5H5JwYGhSm+5KBsr7PJu3+B/c7EsEz8KOyHo5kc+
         ymYTeoiYzEd7fnRVII+tCZLaPoWKmnMS8m0VslFh5XXRLXHTiXjdrLINkAdpEH+F7UTb
         Xo2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzsu56fB8m4AO9CzN65Tp558aoaBQbYDLGla+KFGZhyQNqJgBj8
	wGh1BCWjsRAkw+hDUtjc98o=
X-Google-Smtp-Source: AGHT+IF1aULk3AtZGyG/OCSYv33EcDOM8tKV0lYAZPZUqXck7WlFK3lYyyfq5uQDv2Or0zsnlQzkWw==
X-Received: by 2002:a05:6512:15a0:b0:50b:f4f9:75cf with SMTP id bp32-20020a05651215a000b0050bf4f975cfmr2355885lfb.9.1701782856617;
        Tue, 05 Dec 2023 05:27:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10c5:b0:50b:f53e:922e with SMTP id
 k5-20020a05651210c500b0050bf53e922els844848lfg.1.-pod-prod-09-eu; Tue, 05 Dec
 2023 05:27:34 -0800 (PST)
X-Received: by 2002:a05:6512:1093:b0:50c:bbb:e3cf with SMTP id j19-20020a056512109300b0050c0bbbe3cfmr543831lfg.89.1701782854583;
        Tue, 05 Dec 2023 05:27:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701782854; cv=none;
        d=google.com; s=arc-20160816;
        b=N5nzBva7ljrX0e/VqcmP0eTiGIc/XdVkekyIMsOwtqSNh9Ent+Xf1cMm8DhtlyJuAd
         GL4sAisAxHMRJ5hvtNJbjVlDAtmLKxL9zHNGPspcZG5kH5r5Xc7TkY382pep6OA8ZheF
         2rrcjW1iP7yx9aYdDArKx5yyL+TsVM1ECF5naz05iWGK8pvg3I/KacV7fvMUKQRAoOgE
         70QGt9QG9ralBTnMQkgs9XGi2md/bAzT+BgilzdULM+cFedAtxw7nCXgnb+eb2ntA0Hd
         6+FS4kDL0W/KdDpgZgIkCCHZSCaqJPnWxTW2hifRfdRUdpOKgBtysC0jltmlrmkJVEZn
         f1bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=dSQSwpmn7M/CrcHDOooBYuyEVhVwNmvfJ9+Pn01yWSY=;
        fh=zuD9N5pN5mzGyGYPnd9z08QWmYn9dfavasdtweZowiE=;
        b=KKHd+aSdC5ca6VRCi6x0d13HYX/KdO6Yi4B92CAXk/6SLREcca/i+oOLsbG8pEFVKm
         lf1TQ89dVbswzCozFJRfAnjdUK7jSNjszlPenRnLSa4tibj0zoPWy6qvTDfHGwNR9BE5
         AM4fcIVYlV7jCJP4mACWkodPg5DpZYxkclTY/PbYV8DYTSOg/vxtMVMkp8mWrLgzPlrR
         n4xrc0YeD4EOAiTyUjxbQ2O368wyg9m2CNGBWzumVB1VJHUZJDpnqwbX3wmZb7hd9FKq
         LVQXz4882ax0RliYN0fK3HtUI0MChQSVoXTS3RkNElvex4U5CSi5LnWMWAKKhTJUrR7M
         HbfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FQUkcXNP;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta1.migadu.com (out-187.mta1.migadu.com. [2001:41d0:203:375::bb])
        by gmr-mx.google.com with ESMTPS id o20-20020ac24bd4000000b0050c0beaba3esi55130lfq.1.2023.12.05.05.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Dec 2023 05:27:34 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:203:375::bb as permitted sender) client-ip=2001:41d0:203:375::bb;
Message-ID: <44421a37-4343-46d0-9e5c-17c2cd038cf2@linux.dev>
Date: Tue, 5 Dec 2023 21:27:27 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 4/4] mm/slub: free KFENCE objects in slab_free_hook()
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
 <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FQUkcXNP;       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates
 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2023/12/5 03:34, Vlastimil Babka wrote:
> When freeing an object that was allocated from KFENCE, we do that in the
> slowpath __slab_free(), relying on the fact that KFENCE "slab" cannot be
> the cpu slab, so the fastpath has to fallback to the slowpath.
> 
> This optimization doesn't help much though, because is_kfence_address()
> is checked earlier anyway during the free hook processing or detached
> freelist building. Thus we can simplify the code by making the
> slab_free_hook() free the KFENCE object immediately, similarly to KASAN
> quarantine.
> 
> In slab_free_hook() we can place kfence_free() above init processing, as
> callers have been making sure to set init to false for KFENCE objects.
> This simplifies slab_free(). This places it also above kasan_slab_free()
> which is ok as that skips KFENCE objects anyway.
> 
> While at it also determine the init value in slab_free_freelist_hook()
> outside of the loop.
> 
> This change will also make introducing per cpu array caches easier.
> 
> Tested-by: Marco Elver <elver@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 22 ++++++++++------------
>  1 file changed, 10 insertions(+), 12 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index ed2fa92e914c..e38c2b712f6c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2039,7 +2039,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>   * production configuration these hooks all should produce no code at all.
>   *
>   * Returns true if freeing of the object can proceed, false if its reuse
> - * was delayed by KASAN quarantine.
> + * was delayed by KASAN quarantine, or it was returned to KFENCE.
>   */
>  static __always_inline
>  bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
> @@ -2057,6 +2057,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>  		__kcsan_check_access(x, s->object_size,
>  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>  
> +	if (kfence_free(kasan_reset_tag(x)))

I'm wondering if "kasan_reset_tag()" is needed here?

The patch looks good to me!

Reviewed-by: Chengming Zhou <zhouchengming@bytedance.com>

Thanks.

> +		return false;
> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_slab_free and initialization memset's must be
> @@ -2086,23 +2089,25 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  	void *object;
>  	void *next = *head;
>  	void *old_tail = *tail;
> +	bool init;
>  
>  	if (is_kfence_address(next)) {
>  		slab_free_hook(s, next, false);
> -		return true;
> +		return false;
>  	}
>  
>  	/* Head and tail of the reconstructed freelist */
>  	*head = NULL;
>  	*tail = NULL;
>  
> +	init = slab_want_init_on_free(s);
> +
>  	do {
>  		object = next;
>  		next = get_freepointer(s, object);
>  
>  		/* If object's reuse doesn't have to be delayed */
> -		if (likely(slab_free_hook(s, object,
> -					  slab_want_init_on_free(s)))) {
> +		if (likely(slab_free_hook(s, object, init))) {
>  			/* Move object to the new freelist */
>  			set_freepointer(s, object, *head);
>  			*head = object;
> @@ -4103,9 +4108,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
>  
>  	stat(s, FREE_SLOWPATH);
>  
> -	if (kfence_free(head))
> -		return;
> -
>  	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>  		free_to_partial_list(s, slab, head, tail, cnt, addr);
>  		return;
> @@ -4290,13 +4292,9 @@ static __fastpath_inline
>  void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  	       unsigned long addr)
>  {
> -	bool init;
> -
>  	memcg_slab_free_hook(s, slab, &object, 1);
>  
> -	init = !is_kfence_address(object) && slab_want_init_on_free(s);
> -
> -	if (likely(slab_free_hook(s, object, init)))
> +	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
>  		do_slab_free(s, slab, object, object, 1, addr);
>  }
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/44421a37-4343-46d0-9e5c-17c2cd038cf2%40linux.dev.
