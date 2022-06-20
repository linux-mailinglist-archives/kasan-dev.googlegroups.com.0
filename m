Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVMHYGKQMGQEBJPAOKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id BE48D5514F2
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 11:54:29 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id i10-20020a5d55ca000000b002103d76ffcasf2333537wrw.17
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 02:54:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655718869; cv=pass;
        d=google.com; s=arc-20160816;
        b=CdRgz6j5rXHmjHLFfZutHe4zTWUbYfzJae89NcgPtKoNPB3J8RzjpCIFsW7MH6sze3
         zbxMTnw+K29DZAUYbjWZi0pf3/rh4VU3150i7ftIdbxEb4G/SS3yJiX9TVdQKiY/3o1J
         iLYZ7gEzG/b3d2wx6wECaC4Z1wJfJ0JTiCE1KMZXjD6zZO2VTKL3xNhVbFccLkvrgAVo
         FSMJDZuY8NtAWf1nZovlrOBXvQqOQJ4o2NgwABoy5wzmYWkiVy8H4oXgmjcPKV/SyHEL
         Sm4B2xYMiLhzJ++iuyN8qafqpyy4JwDJ667lD0MdN42CPCM8/GYMCMQGYWcX5msT2tbb
         lAMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=XYHxXrBMOr8YxWZcnU+a75+fQyukYOgQt1gpzLGb9M0=;
        b=cb4djgNzP9XV9dC19sx/TeOJJ8TRWXgcXsR44ydaFmzMqDZxrk3BcGHkRDa/eV2e9g
         mBrriZvfvVDExrBJiN/lCVSk3pIMKCMK1+rDtDGH9LQ1e6w4QLm6Ce0R/+faiv09b7GO
         8DN8e+BTmN9A4v4kIi4ehStI/wQp78K5XCf8WrAaDlyoUQCHVNlgLDrARIjvKa0ayi9f
         j6Dm+ibGOW44VCU7F6uHLgfbv/XEJhfDNkR+gtCBQIj0g8EEv3AL+nXkKtX8jsKsdyGl
         p1N+e6Oyn5br8YaN9Ao2VxNR7IFUil6oodwRFUplI5UD19jEUG1Lv2Dp8JkUoiOdenbx
         g+0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HeTIwbsd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XYHxXrBMOr8YxWZcnU+a75+fQyukYOgQt1gpzLGb9M0=;
        b=AXrOm/xJO4uIYDe1EfFtqVNDEjTnBToX7aW8Scfegg7Tig/mRWCTjk3ePgCmikcU8r
         EhO4gl9DgyToguraMMIV7CLP2nxdZZRg14UNtQNXDAlOPa3jSgXPW6iSpbGAZ5aJaEOj
         nKRR9wHbgt2JZYM7E3hbVuStGycqIxHV7Cjv/kZrDY53TB2N9WjIVZV2OmO/H3WZCj48
         lU9GcllMbrGDvDOOTnj6WvWbPyPWIfCSF9r2uP5eKTFhKrCqhMwH/AruLMNzV8S/jLxV
         oQlNkz89nJ1Muq2XVxZ6vFr829Vwo9phn9SIFA5zAbc74JqnxcFmoZwMrADfd5AWy1Wv
         DqKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XYHxXrBMOr8YxWZcnU+a75+fQyukYOgQt1gpzLGb9M0=;
        b=nXLQ5DgHqy0cJmZorY50U3xXm/gw4ZvGstTIAfuzToTRrn2XzEENLiNoP4geqBzOqc
         1Y+vwq6xHX7KpKj1gXpSWP2my6i5cztXz5geIjZflmknjWkVheaF47Itd6ieIWCEe8Sj
         3N0wnTVFJ11BRB3NEbMBgThDStjPs86VI/OKUd01QfGCmSQdhGhkAehYbZUNjYLtnrJB
         tAcsk2vDBhdOhCxavDqL/AE5JoY+bFIsxYz6FUrs8J14b71/WpRpMQuUxyXJEZW4rucd
         Ox99pW87bFyMdt9RzPRdMdHYMI4sfe1anTKmQk5Uku8XunDcsuiaJXLi9AIEJ3KNmQYk
         +W1Q==
X-Gm-Message-State: AJIora+qb2uMMChttI9xRGyiLS/9Ka4kjNC4mg2jgxiUEpAmGIjVklEY
	Q0E7HvZKFuTCm5NCvWyXiLg=
X-Google-Smtp-Source: AGRyM1s0Ykprdq0ZQtcvBXqowMc9gz88RTfjXv9Q9X8XPwnvwRLVXTwvmBreH4P5H5ixc6Nq9i3vNg==
X-Received: by 2002:a05:600c:5008:b0:39c:54a7:5664 with SMTP id n8-20020a05600c500800b0039c54a75664mr24277636wmr.35.1655718869274;
        Mon, 20 Jun 2022 02:54:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:648e:0:b0:217:c8b4:52e3 with SMTP id o14-20020a5d648e000000b00217c8b452e3ls12616401wri.1.gmail;
 Mon, 20 Jun 2022 02:54:28 -0700 (PDT)
X-Received: by 2002:a05:6000:701:b0:21b:8df9:2dde with SMTP id bs1-20020a056000070100b0021b8df92ddemr5432396wrb.29.1655718868007;
        Mon, 20 Jun 2022 02:54:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655718868; cv=none;
        d=google.com; s=arc-20160816;
        b=ULzaqaD1M34k8uKp/Ct5F+onUZnmGWnEFbrZbHAu7acvb+de2eg2TyFBhv+peCX3/Y
         rGK/Y0nC4+4RcP3vnzGxTzPE7pU/qEDWT8qPnq2LMzUm6ordhrjdm7VTdAmEOH5h28FK
         cyG851+Zv0lb9FSv4OjyxEjfhkmaijYtQnNqeIkO1/mgvs/VRt3zu/EjDDeAxecZ3A0U
         TO0z5155nqKcqyppkMFIFvMJa5MUK5yyXxkbi8+BJXka4YVdpsED+qxr2p1KLrU2T2Us
         1C9LzCssv3acwz388fHwLhTqFBUBSZ8lGbMeH/pEAI+evDOVOTI6es4sKibvY3RUx7ox
         oK7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/5XQWxUT78CJ9q4IKK57xGusAoxHrjt7w5b5bQek9HA=;
        b=TUCrwY0i7U3vOrqqz7hCNYbWsukXJTbQbAYyeIxTd/B2sHhl6E9bbVwTbGC8Ic/H+z
         KGAkKj4at8p8R/Vzl+elF+cbnV3m23ilHCkt0Fv3SEj5ylQx1f9+WyjLAh6PY0/RInaW
         Mf4D1Dk9DDmADjG0f8cgWuKf9AFH4Eg8+IwX56PR7iTUEe2KMVAgV0Y7pBK5DNtnU/PN
         Dx29X0wmNygLZJ7zloU6fs2iQizD3V5G6qj/LKwFdipFbOPqDgMxisrQCKzLRFUxLYdO
         1TXQ3lrL3LjUvAPNq3toClPtWzzSmy9323cCI+VC7d21gaHxHyZFY9Wttu4jZDDRLYf/
         e0Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HeTIwbsd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id w9-20020adfcd09000000b0021b947060b9si2633wrm.6.2022.06.20.02.54.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 02:54:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id g4so13855605wrh.11
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 02:54:27 -0700 (PDT)
X-Received: by 2002:a5d:47a7:0:b0:218:5a5d:6c55 with SMTP id 7-20020a5d47a7000000b002185a5d6c55mr22074873wrb.192.1655718867517;
        Mon, 20 Jun 2022 02:54:27 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3746:a989:7595:e29f])
        by smtp.gmail.com with ESMTPSA id z6-20020a5d4d06000000b0021a3dd1c5d5sm10312787wrt.96.2022.06.20.02.54.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Jun 2022 02:54:26 -0700 (PDT)
Date: Mon, 20 Jun 2022 11:54:20 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 19/32] kasan: pass tagged pointers to
 kasan_save_alloc/free_info
Message-ID: <YrBDzKTZMnWztGIQ@elver.google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
 <9363b16202fb04a3223de714e70b7a6b72c4367e.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9363b16202fb04a3223de714e70b7a6b72c4367e.1655150842.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.3 (2022-04-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HeTIwbsd;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
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

On Mon, Jun 13, 2022 at 10:14PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Pass tagged pointers to kasan_save_alloc/free_info().
> 
> This is a preparatory patch to simplify other changes in the series.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/common.c  | 4 ++--
>  mm/kasan/generic.c | 3 +--
>  mm/kasan/kasan.h   | 2 +-
>  mm/kasan/tags.c    | 3 +--
>  4 files changed, 5 insertions(+), 7 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index f937b6c9e86a..519fd0b3040b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -227,7 +227,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  		return false;
>  
>  	if (kasan_stack_collection_enabled())
> -		kasan_save_free_info(cache, object, tag);
> +		kasan_save_free_info(cache, tagged_object);
>  

Variable 'tag' becomes unused in this function after this patch.

>  	return kasan_quarantine_put(cache, object);
>  }
> @@ -316,7 +316,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>  
>  	/* Save alloc info (if possible) for non-kmalloc() allocations. */
>  	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
> -		kasan_save_alloc_info(cache, (void *)object, flags);
> +		kasan_save_alloc_info(cache, tagged_object, flags);
>  
>  	return tagged_object;
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index f6bef347de87..aff39af3c532 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -500,8 +500,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  		kasan_set_track(&alloc_meta->alloc_track, flags);
>  }
>  
> -void kasan_save_free_info(struct kmem_cache *cache,
> -				void *object, u8 tag)
> +void kasan_save_free_info(struct kmem_cache *cache, void *object)
>  {
>  	struct kasan_free_meta *free_meta;
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 30ec9ebf52c3..e8329935fbfb 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -308,7 +308,7 @@ static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
>  void kasan_set_track(struct kasan_track *track, gfp_t flags);
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
> -void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
> +void kasan_save_free_info(struct kmem_cache *cache, void *object);
>  struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
>  						void *object);
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 4f24669085e9..fd11d10a4ffc 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -21,8 +21,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
>  }
>  
> -void kasan_save_free_info(struct kmem_cache *cache,
> -				void *object, u8 tag)
> +void kasan_save_free_info(struct kmem_cache *cache, void *object)
>  {
>  }
>  
> -- 
> 2.25.1
> 
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9363b16202fb04a3223de714e70b7a6b72c4367e.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YrBDzKTZMnWztGIQ%40elver.google.com.
