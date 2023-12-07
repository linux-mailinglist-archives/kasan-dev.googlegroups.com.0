Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBRO5YSVQMGQEXZTZ57Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E36B8807E87
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 03:32:38 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-58d527787absf256616eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 18:32:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701916357; cv=pass;
        d=google.com; s=arc-20160816;
        b=sVxZXo0eN21OZpnmGst3eNaCejAlIDG+ojoO56z9Yk6+6qoYKqZdT/aLY8ljZagCyk
         mVnUyXBdmBSClZpvMZNDRT5T1VF4fl1aPmM21zgAj3lH6mV5L2VnogG9BVeYW6VUUugs
         HXG9tK7KlQ1OqLv3PD+9HjMzFwfY11fqRZ9mBkpTGEdg4Qv+YEGTD3F++nwl7F42wkHg
         OWPlwPfG5TtFd8N9MlL+9j2pNoZdAEvTL169BC5AAwN9WWMd0TJO2yFvcQ+WGLaHlUvt
         AqnIhWWu3vRdbo8uGeb8g6IO8IQNGfMp/VwVu2WX1NfCKvvMIoZ+A5RFu4L8EECLeip5
         67jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=pWyAhW7XdHVcDp52FWnScY/1Ry5W9uy2+uYM+8zNuL4=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=pYye62M9iAPpl/iZ+udegYfSnmGC3UcSpU0XVApsfuG+D5k/e+5L4XYVQZDJRABWwV
         ZxB3v1El4VcR6PbvFxkq9B0u/L0d3XPc0k81Dfrk+b5imNXjkqtyukuPTzQTMiPnCO+n
         Fuy49B1SOd+sYdX9Zq4k18ZI/u8CgyZsJwAMN7hJhgOk1pZ/FxTUq1ulZgDAMVgPOr8c
         3o6e2BmtShN50pYPrp0sassxQ7mhNWYwBkfUkXgo1U6PqXjt8eaZtZQl0h51xHHv6NtT
         kPWmxZ0SWpLyDaOzUfBOeWL3mhTHfZG586wQ38Buy3Y3zOjJ7AnVjFAEnF6aBTh1STGZ
         wCWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="GatItkj/";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701916357; x=1702521157; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pWyAhW7XdHVcDp52FWnScY/1Ry5W9uy2+uYM+8zNuL4=;
        b=hAhaOt0auh/I3HutugBAhO6cQ7PKAmDE5hzcs1a0CeB2WfjQoMJ0MsvUca2qTbtaeW
         zyf1srQ0P2we96l3qxauP06763Is4QR0eR6tE4BKKsrQnMylj6ZHoJMLC9luqdq+Tc/Z
         xjB/Hsw8ffzpi0jsyjAEfycx7YIlTpZCaE2DASGRUt3uA0CooGEyerpJJNZEbug/N55F
         Zu6wbbqEAR8FLUkeyF6+pkOM+4ItiacNZ0j0utLIizlLtqZDDL+t/Knl4iUN7bwpuysQ
         gXyOKPnObcCU9+AT8WpVJ+qDrC7HJQEfF8NP+EKpejVGK6BEGmhus8mvTvJpvMniOCk1
         t2Pw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701916357; x=1702521157; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=pWyAhW7XdHVcDp52FWnScY/1Ry5W9uy2+uYM+8zNuL4=;
        b=MoWMv3e6+Aj20W6uIjSZ6kgQfloqxVXZ1wZccty6xdQkvNknfqH+L2z814j+4P3dKb
         6xPgk7zJM2Uf80+tz8WfnNGGHWR5ALDdzghgbVeakZ+ADTPQVvxKar9Ua3umo3nrE4tc
         Tgc19yUfnUcjiUzGpmNJmv0n0xGn+4OV5DbMVBvA6atDgOZIBxa8aZreKHW91oTySnQz
         vp0eLnECGv9931pYl7B7js7xMY9dGzKRONird3uuAstQQpqRHeAnHTHHRzFvWbPdoMMR
         eSzeiSyX5AdSKesl12/J0vMHD77m0fGpUtLrI6eaUGQ1ryBObyl3PWSCZ/0H8yBmj8kX
         e3VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701916357; x=1702521157;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pWyAhW7XdHVcDp52FWnScY/1Ry5W9uy2+uYM+8zNuL4=;
        b=hIcn6GlVdEAe2NBLloYgv1AGgf6XcQsK45VhPTcsKFjmYbj9SICc2SzHn2kROWe15/
         XUM4Gy4Me/DtDHECgR8zUgJ7XHK+j/MqpBupkB6ui235k0b3ArwGPp834A+08C0KccMZ
         zpQL69KmBCRCGFRcsIHEpXQuqXfC/M0mw2jyO40b+1J3s3tUQlGIyHmP2xsvYegsg24b
         84sdA+3aJ8pkJHZ5F5qldArnaX6mPaw2czIftykJrPpLoCeDuUrs2Xk6Y0LLeazvpTIW
         YGWM4S1cho55G0zv//lEYqYPjKlgDqIDQxceyuRTZ0gssD3/IV1nc2Y4+mrHn06y0axt
         /ZOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyBtiyWgUSssl3SMAgM1MwpVaxmOq/t6/XrnFz8/tFgzH2IU2ks
	omXXVdzQusoxAeFNQEpIYAo=
X-Google-Smtp-Source: AGHT+IH/uxVhE/x4jd80IcPgQM1wFzPQSSj1wr/dcr9nJKjVZGtJfZbiQ6oTxvBEpqFDRsvdwMvODg==
X-Received: by 2002:a05:6820:1c9d:b0:58d:974b:504b with SMTP id ct29-20020a0568201c9d00b0058d974b504bmr2125913oob.7.1701916357607;
        Wed, 06 Dec 2023 18:32:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:602:b0:58f:7a18:580 with SMTP id
 e2-20020a056820060200b0058f7a180580ls654203oow.0.-pod-prod-07-us; Wed, 06 Dec
 2023 18:32:37 -0800 (PST)
X-Received: by 2002:a05:6808:17a7:b0:3b9:de62:3738 with SMTP id bg39-20020a05680817a700b003b9de623738mr255590oib.26.1701916356845;
        Wed, 06 Dec 2023 18:32:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701916356; cv=none;
        d=google.com; s=arc-20160816;
        b=k1UZxZX+eiSO23p4PmnRJsBnOSHHtHG1oHWhWFOF9kuva2iq9jVZtGqpcZwwikOzB9
         ErAeYnr5TKOvve9VLZpzrivBpOE90E3JXElPkA1k6xeDwo9Lv7xsYX3hDjbYI89MG6A+
         qXtMSVkGLDGvQwI4XuVYa0l+ywFiI5BYhcmYDgTCDAM/zZfgq8v4BZEaY8CoMLtctgF+
         ylxL4lnHHD+exfdi0sa8K/Mx3boJ1pmfxwqO0xJbzjm5vx15xw761wD0U4RCS3kPczRK
         NKh4JSq4ZdrWSENHESs49XgkCAXGxKOSS2KTiuzWAP4W+KbxMqyIhXjJ7UAutVLaaiQS
         YwjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ETvtz3rEq8y5ZHvBBRevwO8n4qMHcpeDzavyr8b+04g=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=uYQQyDYCL66fRyaqbRSi7PI/5qZMBC7+A1YyZoRyQbaeS8FtRDp87BM2jLFkzmiYYm
         7ybkzG1FGCheVDIpoS3VbM+T7FFkPuj7jmAbfkoqNwOAfXFYADlx0HZ6yKtSY97qtWRL
         1V6ps6rdcwsm5sfiNd/7HW+aFKD9+f5Ca1KLqNsPPTDhaK42ptxb14qEXmmkCX+y1F1Y
         W78KFdwjy0fKDNHYU29RaKCXaeY2ckBOcbodIXCrfmhEEOJtA1Fhaer+50ihrrCQeWio
         tKbkLDbwdUFyktzpelXEeBjI09jWo4OMTsQa1IsXYYE8kzY8C5O7rNRmAWPoSg8/j+oH
         dyKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="GatItkj/";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id bd29-20020a056808221d00b003aef18f3442si25181oib.0.2023.12.06.18.32.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 18:32:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id 46e09a7af769-6d7e56f6845so312327a34.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 18:32:36 -0800 (PST)
X-Received: by 2002:a05:6870:d93:b0:1fb:75b:2fd1 with SMTP id mj19-20020a0568700d9300b001fb075b2fd1mr2039607oab.104.1701916356157;
        Wed, 06 Dec 2023 18:32:36 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id c192-20020a6335c9000000b005c60ad6c4absm168730pga.4.2023.12.06.18.32.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 18:32:35 -0800 (PST)
Date: Thu, 7 Dec 2023 11:32:12 +0900
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
Subject: Re: [PATCH v2 20/21] mm/slub: optimize alloc fastpath code layout
Message-ID: <ZXEurG+jk62uNgRK@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-20-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-20-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="GatItkj/";       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::32d
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

On Mon, Nov 20, 2023 at 07:34:31PM +0100, Vlastimil Babka wrote:
> With allocation fastpaths no longer divided between two .c files, we
> have better inlining, however checking the disassembly of
> kmem_cache_alloc() reveals we can do better to make the fastpaths
> smaller and move the less common situations out of line or to separate
> functions, to reduce instruction cache pressure.
> 
> - split memcg pre/post alloc hooks to inlined checks that use likely()
>   to assume there will be no objcg handling necessary, and non-inline
>   functions doing the actual handling
> 
> - add some more likely/unlikely() to pre/post alloc hooks to indicate
>   which scenarios should be out of line
> 
> - change gfp_allowed_mask handling in slab_post_alloc_hook() so the
>   code can be optimized away when kasan/kmsan/kmemleak is configured out
> 
> bloat-o-meter shows:
> add/remove: 4/2 grow/shrink: 1/8 up/down: 521/-2924 (-2403)
> Function                                     old     new   delta
> __memcg_slab_post_alloc_hook                   -     461    +461
> kmem_cache_alloc_bulk                        775     791     +16
> __pfx_should_failslab.constprop                -      16     +16
> __pfx___memcg_slab_post_alloc_hook             -      16     +16
> should_failslab.constprop                      -      12     +12
> __pfx_memcg_slab_post_alloc_hook              16       -     -16
> kmem_cache_alloc_lru                        1295    1023    -272
> kmem_cache_alloc_node                       1118     817    -301
> kmem_cache_alloc                            1076     772    -304
> kmalloc_node_trace                          1149     838    -311
> kmalloc_trace                               1102     789    -313
> __kmalloc_node_track_caller                 1393    1080    -313
> __kmalloc_node                              1397    1082    -315
> __kmalloc                                   1374    1059    -315
> memcg_slab_post_alloc_hook                   464       -    -464
> 
> Note that gcc still decided to inline __memcg_pre_alloc_hook(), but the
> code is out of line. Forcing noinline did not improve the results. As a
> result the fastpaths are shorter and overal code size is reduced.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 89 ++++++++++++++++++++++++++++++++++++++-------------------------
>  1 file changed, 54 insertions(+), 35 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 5683f1d02e4f..77d259f3d592 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1866,25 +1866,17 @@ static inline size_t obj_full_size(struct kmem_cache *s)
>  /*
>   * Returns false if the allocation should fail.
>   */
> -static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
> -					     struct list_lru *lru,
> -					     struct obj_cgroup **objcgp,
> -					     size_t objects, gfp_t flags)
> +static bool __memcg_slab_pre_alloc_hook(struct kmem_cache *s,
> +					struct list_lru *lru,
> +					struct obj_cgroup **objcgp,
> +					size_t objects, gfp_t flags)
>  {
> -	struct obj_cgroup *objcg;
> -
> -	if (!memcg_kmem_online())
> -		return true;
> -
> -	if (!(flags & __GFP_ACCOUNT) && !(s->flags & SLAB_ACCOUNT))
> -		return true;
> -
>  	/*
>  	 * The obtained objcg pointer is safe to use within the current scope,
>  	 * defined by current task or set_active_memcg() pair.
>  	 * obj_cgroup_get() is used to get a permanent reference.
>  	 */
> -	objcg = current_obj_cgroup();
> +	struct obj_cgroup *objcg = current_obj_cgroup();
>  	if (!objcg)
>  		return true;
>  
> @@ -1907,17 +1899,34 @@ static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
>  	return true;
>  }
>  
> -static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
> -					      struct obj_cgroup *objcg,
> -					      gfp_t flags, size_t size,
> -					      void **p)
> +/*
> + * Returns false if the allocation should fail.
> + */
> +static __fastpath_inline
> +bool memcg_slab_pre_alloc_hook(struct kmem_cache *s, struct list_lru *lru,
> +			       struct obj_cgroup **objcgp, size_t objects,
> +			       gfp_t flags)
> +{
> +	if (!memcg_kmem_online())
> +		return true;
> +
> +	if (likely(!(flags & __GFP_ACCOUNT) && !(s->flags & SLAB_ACCOUNT)))
> +		return true;
> +
> +	return likely(__memcg_slab_pre_alloc_hook(s, lru, objcgp, objects,
> +						  flags));
> +}
> +
> +static void __memcg_slab_post_alloc_hook(struct kmem_cache *s,
> +					 struct obj_cgroup *objcg,
> +					 gfp_t flags, size_t size,
> +					 void **p)
>  {
>  	struct slab *slab;
>  	unsigned long off;
>  	size_t i;
>  
> -	if (!memcg_kmem_online() || !objcg)
> -		return;
> +	flags &= gfp_allowed_mask;
>  
>  	for (i = 0; i < size; i++) {
>  		if (likely(p[i])) {
> @@ -1940,6 +1949,16 @@ static inline void memcg_slab_post_alloc_hook(struct kmem_cache *s,
>  	}
>  }
>  
> +static __fastpath_inline
> +void memcg_slab_post_alloc_hook(struct kmem_cache *s, struct obj_cgroup *objcg,
> +				gfp_t flags, size_t size, void **p)
> +{
> +	if (likely(!memcg_kmem_online() || !objcg))
> +		return;
> +
> +	return __memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> +}
> +
>  static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>  					void **p, int objects)
>  {
> @@ -3709,34 +3728,34 @@ noinline int should_failslab(struct kmem_cache *s, gfp_t gfpflags)
>  }
>  ALLOW_ERROR_INJECTION(should_failslab, ERRNO);
>  
> -static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
> -						     struct list_lru *lru,
> -						     struct obj_cgroup **objcgp,
> -						     size_t size, gfp_t flags)
> +static __fastpath_inline
> +struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
> +				       struct list_lru *lru,
> +				       struct obj_cgroup **objcgp,
> +				       size_t size, gfp_t flags)
>  {
>  	flags &= gfp_allowed_mask;
>  
>  	might_alloc(flags);
>  
> -	if (should_failslab(s, flags))
> +	if (unlikely(should_failslab(s, flags)))
>  		return NULL;
>  
> -	if (!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags))
> +	if (unlikely(!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags)))
>  		return NULL;
>  
>  	return s;
>  }
>  
> -static inline void slab_post_alloc_hook(struct kmem_cache *s,
> -					struct obj_cgroup *objcg, gfp_t flags,
> -					size_t size, void **p, bool init,
> -					unsigned int orig_size)
> +static __fastpath_inline
> +void slab_post_alloc_hook(struct kmem_cache *s,	struct obj_cgroup *objcg,
> +			  gfp_t flags, size_t size, void **p, bool init,
> +			  unsigned int orig_size)
>  {
>  	unsigned int zero_size = s->object_size;
>  	bool kasan_init = init;
>  	size_t i;
> -
> -	flags &= gfp_allowed_mask;
> +	gfp_t init_flags = flags & gfp_allowed_mask;
>  
>  	/*
>  	 * For kmalloc object, the allocated memory size(object_size) is likely
> @@ -3769,13 +3788,13 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>  	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
>  	 */
>  	for (i = 0; i < size; i++) {
> -		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
> +		p[i] = kasan_slab_alloc(s, p[i], init_flags, kasan_init);
>  		if (p[i] && init && (!kasan_init ||
>  				     !kasan_has_integrated_init()))
>  			memset(p[i], 0, zero_size);
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
> -					 s->flags, flags);
> -		kmsan_slab_alloc(s, p[i], flags);
> +					 s->flags, init_flags);
> +		kmsan_slab_alloc(s, p[i], init_flags);
>  	}
>  
>  	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> @@ -3799,7 +3818,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
>  	bool init = false;
>  
>  	s = slab_pre_alloc_hook(s, lru, &objcg, 1, gfpflags);
> -	if (!s)
> +	if (unlikely(!s))
>  		return NULL;
>  
>  	object = kfence_alloc(s, orig_size, gfpflags);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEurG%2Bjk62uNgRK%40localhost.localdomain.
