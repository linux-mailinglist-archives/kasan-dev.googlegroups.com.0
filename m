Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBH5V3KNAMGQE7PCK2MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 6089660AC00
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Oct 2022 16:01:06 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id j21-20020a17090a7e9500b00212b3905d87sf3023794pjl.9
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Oct 2022 07:01:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666620065; cv=pass;
        d=google.com; s=arc-20160816;
        b=ugpA0gQgZKrdn19wO32sksV/7//LNDdxu9r3XHiH/gpW7IPYJXlKaAo8nM3+2DRzvy
         M064LLLyeWKoC1t3nFqCJuqwX6WfhUZwKS8XFG16E6y6wGytZZD5lzRHfQctGQ7/pCjU
         L8pdVtS5Ugy5xFWDVUvuTc9QrYvJ+k6TqZXakGlnSpdP8bYqdZ/h1rIVnEvbNK9CzAWx
         LQnf3lfylVpFED3EVl+cjGVSQ08yu/1QEbNSPyYlOi2PyF9gwV5tHdTe86a0v9PElksV
         Ova+dgJVSJBQKOQkg2AJd6cerfQjz197077wxgQSKBDjaZItamliM9RZGRipRSsZzVYk
         dyng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=BatkbnCJp8WX5bHcMeevX/of3G03ND0jMo6bY/ypXqw=;
        b=F2iVmvrChtCyfwcWHl31M9zeuWPfLID/rTu3k35rRX4J0XcDDeQrirUXzTS5H2DIeI
         QROMhKlq1H9a2suAU+Ry25vhJnLIWVCTYQ1HovBXFPFgaJehXejqlKbBFAeWRqziPs5n
         uL+9eVwD2Byjg5a/VeFjYZPHrJLlb6NXkxPpAXrKc2t6P/zF4yDTZIR7EDMNilAI/Xj8
         XUIjVffPcKHcpWCrNoltwmvdotEKziAqRwBUKJj9jhXyyU/dn8N0Wg67VP71McuxY1HJ
         KPZW1Fr80c/323QpJEjn3yg6wqscWc9DzF9fc3kq8Vg95g9/qWBFKlF48JNqT2mcxXcU
         zETw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=P1UXV1aQ;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BatkbnCJp8WX5bHcMeevX/of3G03ND0jMo6bY/ypXqw=;
        b=qcMVouwnqha1ENVXOdoG8E8vzBqbueql/HFfbr5KAA2jSSXQ99EXWZlfBqRj+Ea+Ft
         iVTBPDhMmrCNB3BSuEXIsq9SFws+LoI9nqYdfNOoQDov9iEGSUgP1LwCZW5z61/AYQIs
         nqXgw7G+5bghn9m/M9CVl3/XMrPXgFvmfFXcfdufW/8HyFQfUvtrVDGN3gzAqF6zd59C
         4UqWEKNiXiPXkPeVkVYYhZK0xi2dgoGldPkDc1Q3nyf03/QJeLsEw4T7ivmnYiu1GXzr
         16OCjVJI5LpMyrkAun0688AQRCdSsqHkzk/Dkbj/Xcs5105TwrU0NFYwNz9j7RsM5p/a
         Nudw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=BatkbnCJp8WX5bHcMeevX/of3G03ND0jMo6bY/ypXqw=;
        b=QjYQnfTUs2iHKqOBqu9q4zc1wLoCBXWtZoZcV7QuCOtfZAk1+mg4iQKy1VMos5ptRE
         F6IiP29OD8DpcnSFe+ZGY5sUdQStXXHHCBNpd+9wMxqi6jD8BRRqIG3EJ6AAat1kslfa
         /1qaswu4B5blYYe/40nAxEIUHE3rQlCuJge2FaNcvUD7EVKNgyX9efm1e0XxcDlslZYX
         +MymXxEYwj4gP5Pxd1c1dhc7MP2iYQShLBcFEzBphk2rdRo5ID0UTWL45j5QwHsTALSO
         tYUn6SX3dx3uxLxvjPR4jDaYqbHxaMm/yXhx6LvTWbNMGjHNQGs5qUlqdjqNFRxd+2oh
         arew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BatkbnCJp8WX5bHcMeevX/of3G03ND0jMo6bY/ypXqw=;
        b=SlDTFMMyExaczzzHkWT1W4V+F21T1OxgKv5W2wuvTG2sCLucsUMJWPQWbA1ePXTJnV
         kFIjooaBw1ynH7weT4XdM75p9gLRI4Ozxqn3VJ4LyhZCap/BotDwBGfX8UuG8ippGSIg
         EWvEZH1UozyskX/3PfxmL3IzE2zSA2l7JCZDU18SDdpmOXiGkNeKoUUC6Bv9Ioj7AafD
         gAFYKF1mfuOZ/XC43H3K8cslJ5dK0Pon41t+bix/7lkHJCJPGCjqMjIq5KIute7dnlCc
         an2gGgWEkokT+IQLhE+khsJDe0otVL5aD5nInHCpFRzIV10PbfK5lpokrHkc6CTvwO2r
         QsHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf39MEFrMndiC8ZWCRtriJNwznj0+cqnXKqFIMtCVfvU0/hN4YPw
	l0PRqd9t67K9WuCqm5dmVL4=
X-Google-Smtp-Source: AMsMyM5uveuYLNipUeN/MYl95KDciewUvcjVq3xL63S6rNR7xz4gf4F4WscRel6aUFAU7ZbqfDV1Hw==
X-Received: by 2002:a17:902:d38d:b0:186:9fc5:6c13 with SMTP id e13-20020a170902d38d00b001869fc56c13mr7344715pld.73.1666620063763;
        Mon, 24 Oct 2022 07:01:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c153:b0:186:8125:ce7f with SMTP id
 19-20020a170902c15300b001868125ce7fls5672784plj.5.-pod-prod-gmail; Mon, 24
 Oct 2022 07:01:02 -0700 (PDT)
X-Received: by 2002:a17:90a:d14a:b0:203:7b4b:6010 with SMTP id t10-20020a17090ad14a00b002037b4b6010mr74627948pjw.237.1666620062766;
        Mon, 24 Oct 2022 07:01:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666620062; cv=none;
        d=google.com; s=arc-20160816;
        b=sFU0+5Lsav7P6cUxl0kuNFu9L9gvt6AR4YjH7qHCLpbl88/k13z9Iz2uwpSPbb/Lxg
         vnZInJ+UHaY8dYHFH8P4TftpUmS9ZZhw8KurCaK3dd8tNj4oGcgNbwdy8G9iLByy3hYv
         khU7nE9jC3Ps85CIytmIjM+ipnPdTC5LBZCmwKPOTjkueOb5YFof1kTILprajaS4IWfm
         G/CIKKSkYhUYh8McrGV8//YAj4U0ND06QPGTLxeyzsL+jcOOunjTanBUmeVLnr5usjS7
         ElXuTlVkco/3Rkqxdfp8s6t3fgcrlq8Hi5mVgT3/qiuYdHo3gyp8Saq1A5C6cVJ/MyWT
         GA4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=54kX8KDXQhkF+Q470pyPNzIGi7dKEvffdL2ryBeituk=;
        b=lHG/lSn9GqGLV1PR4xjnyjqU3ozyFBjYJJenFvqLU5/Si0GHj88BYM9FR5IlfTO8ky
         /gdqShMkHyCAn6lU3IrnO+enkjchrvIUz/W1vD0rCqd34U8A904AXsGtDVRrIfmZ2viZ
         qRcAkgxkpnFUMpAoKckQ5l+zHVTK5lzIJ9pCStMTNzboBRz0n00zSB8JWpZmWrKBECP7
         BIDnSEkB4T76SmY6MOUKmZtnbImsGWxHGwGuvIodUes6vKk259fFieeNFz9Qd7e/n/pl
         JtalMlE7gq4TeYxITNcKA2RKJqX1SvYiyFcFLl2IyWPrEj2wR8dY/UCCYhz2GcmHYvAq
         dAqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=P1UXV1aQ;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id e4-20020a17090301c400b0017829f95c9asi1302359plh.3.2022.10.24.07.01.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Oct 2022 07:01:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id f23so8517839plr.6
        for <kasan-dev@googlegroups.com>; Mon, 24 Oct 2022 07:01:02 -0700 (PDT)
X-Received: by 2002:a17:903:18c:b0:186:994c:51b8 with SMTP id z12-20020a170903018c00b00186994c51b8mr9260281plg.44.1666620062372;
        Mon, 24 Oct 2022 07:01:02 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id v7-20020a17090abb8700b001faf7a88138sm5712448pjr.42.2022.10.24.07.00.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Oct 2022 07:01:01 -0700 (PDT)
Date: Mon, 24 Oct 2022 23:00:55 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Kees Cook <keescook@chromium.org>,
	Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v7 1/3] mm/slub: only zero requested size of buffer for
 kzalloc when debug enabled
Message-ID: <Y1aal/VXQZRBwSgq@hyeyoo>
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <20221021032405.1825078-2-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221021032405.1825078-2-feng.tang@intel.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=P1UXV1aQ;       spf=pass
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

On Fri, Oct 21, 2022 at 11:24:03AM +0800, Feng Tang wrote:
> kzalloc/kmalloc will round up the request size to a fixed size
> (mostly power of 2), so the allocated memory could be more than
> requested. Currently kzalloc family APIs will zero all the
> allocated memory.
> 
> To detect out-of-bound usage of the extra allocated memory, only
> zero the requested part, so that redzone sanity check could be
> added to the extra space later.
> 
> For kzalloc users who will call ksize() later and utilize this
> extra space, please be aware that the space is not zeroed any
> more when debug is enabled. (Thanks to Kees Cook's effort to
> sanitize all ksize() user cases [1], this won't be a big issue).
> 
> [1]. https://lore.kernel.org/all/20220922031013.2150682-1-keescook@chromium.org/#r
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab.c |  7 ++++---
>  mm/slab.h | 18 ++++++++++++++++--
>  mm/slub.c | 10 +++++++---
>  3 files changed, 27 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/slab.c b/mm/slab.c
> index a5486ff8362a..4594de0e3d6b 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3253,7 +3253,8 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
>  	init = slab_want_init_on_alloc(flags, cachep);
>  
>  out:
> -	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> +	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
> +				cachep->object_size);
>  	return objp;
>  }
>  
> @@ -3506,13 +3507,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	 * Done outside of the IRQ disabled section.
>  	 */
>  	slab_post_alloc_hook(s, objcg, flags, size, p,
> -				slab_want_init_on_alloc(flags, s));
> +			slab_want_init_on_alloc(flags, s), s->object_size);
>  	/* FIXME: Trace call missing. Christoph would like a bulk variant */
>  	return size;
>  error:
>  	local_irq_enable();
>  	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
>  	kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }
> diff --git a/mm/slab.h b/mm/slab.h
> index 0202a8c2f0d2..8b4ee02fc14a 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -720,12 +720,26 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
>  
>  static inline void slab_post_alloc_hook(struct kmem_cache *s,
>  					struct obj_cgroup *objcg, gfp_t flags,
> -					size_t size, void **p, bool init)
> +					size_t size, void **p, bool init,
> +					unsigned int orig_size)
>  {
> +	unsigned int zero_size = s->object_size;
>  	size_t i;
>  
>  	flags &= gfp_allowed_mask;
>  
> +	/*
> +	 * For kmalloc object, the allocated memory size(object_size) is likely
> +	 * larger than the requested size(orig_size). If redzone check is
> +	 * enabled for the extra space, don't zero it, as it will be redzoned
> +	 * soon. The redzone operation for this extra space could be seen as a
> +	 * replacement of current poisoning under certain debug option, and
> +	 * won't break other sanity checks.
> +	 */
> +	if (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
> +	    (s->flags & SLAB_KMALLOC))
> +		zero_size = orig_size;
> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_slab_alloc and initialization memset must be
> @@ -736,7 +750,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>  	for (i = 0; i < size; i++) {
>  		p[i] = kasan_slab_alloc(s, p[i], flags, init);
>  		if (p[i] && init && !kasan_has_integrated_init())
> -			memset(p[i], 0, s->object_size);
> +			memset(p[i], 0, zero_size);
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
>  					 s->flags, flags);
>  		kmsan_slab_alloc(s, p[i], flags);
> diff --git a/mm/slub.c b/mm/slub.c
> index 12354fb8d6e4..17292c2d3eee 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3395,7 +3395,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
>  	init = slab_want_init_on_alloc(gfpflags, s);
>  
>  out:
> -	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
> +	/*
> +	 * When init equals 'true', like for kzalloc() family, only
> +	 * @orig_size bytes will be zeroed instead of s->object_size
> +	 */
> +	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
>  
>  	return object;
>  }
> @@ -3852,11 +3856,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	 * Done outside of the IRQ disabled fastpath loop.
>  	 */
>  	slab_post_alloc_hook(s, objcg, flags, size, p,
> -				slab_want_init_on_alloc(flags, s));
> +			slab_want_init_on_alloc(flags, s), s->object_size);
>  	return i;
>  error:
>  	slub_put_cpu_ptr(s->cpu_slab);
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
>  	kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }
> -- 
> 2.34.1

Looks good to me.

Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y1aal/VXQZRBwSgq%40hyeyoo.
