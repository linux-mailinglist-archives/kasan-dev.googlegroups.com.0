Return-Path: <kasan-dev+bncBDW2JDUY5AORBF5X5ONAMGQEJJ7W3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8917B610194
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 21:27:20 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id m200-20020a25d4d1000000b006cb7e26b93csf2414221ybf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 12:27:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666898839; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cx68NZd1aNOF0k/+pxF1WkPx9G8BGyelUXCTLUK39OtwprdYKZCiNAUtFtXSCKdod2
         pVZ0fNml385ZGa8mt6zlFpa+8IVbhwjng4QVHhAM9yjLBDYXYFW3DAjh3JjjhlFFJW4E
         doDZZNyUImUixf8UVU6GQyBVR2RtywSGAiC4F0y0Fp61L+IdiJtfeVCFJ5aVDf2yUlRA
         U8dtwDLDR7LFIMvafK71Okp723wEsblTJMt8WjRB3tEScLvVaUz4haA0hs2e1hmGLedk
         HGSjDVSTcXjXFDM3JsqKDh1S+SbIacSH5GkPzYi4FYBLABhHGWwCO2bHJFVF/VAyrLfB
         Y7jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=J8ZKRCsFSRH1H+ZJNByVdtMLrBzL9KWm3n3lLgHjVOM=;
        b=FzL1bmujMoQxddgxr6oB2k8QaZIvsp926r8jqw52AWSRiOY/4RP1/9FXmiPttPAuaF
         O0PvRSlxmLYHHVF1akFYCLNLjeSe2opgbgcIx4TSjLimp/e+J+ufyWScBx5PkivWh/+E
         9I6/mHhr8KhnMB5GFtQdM7gfifvHOEVRAbP0+MvQujWsQbrNbPfKcud0+hX68TpVcoQO
         vt4wUrIWuYTSV82Uag1/cqz6253fU/3rnjDAlFovZsMPIfAg3IesbZdhywLqoe02mz6h
         imHVf8YGHtZ3Fy1TrzBi50WlhB5N/MKbRTIxlHSD9Fo/bSLDXszWUWTAVPxTE9zeY+xO
         fiqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QcfHLCvL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J8ZKRCsFSRH1H+ZJNByVdtMLrBzL9KWm3n3lLgHjVOM=;
        b=SkfJaMGAHLEY4mTRooOUpDhrkjeV015uD4L2u75R5gz6DkDy03TB7FMBzVaZZ3UXcH
         pSlujc3QCX6GDtXzNKsLWBWEcWe8S7rEhIrc1NeURwyoBa+VvA7l3+23cru0bICw+6ae
         D8er99q3rs+ARbICDWTY+RRIeaZZSPH1pTCf3yG7ASj8HyAmZFjf7ltUy/WojAIdjrPq
         VbrUv6526PCHCvO8thkoi8jTvOue6qpTL5uPAiPBe6YaKhvNTSfF9Ztuq6BidPVgOLbf
         Rx2G508r0fMCWRzLG5CuTflwip0yp6Uaupqi4vS1omB1FWs+koUYP1u+JT7dlKwLzl9T
         DhNA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=J8ZKRCsFSRH1H+ZJNByVdtMLrBzL9KWm3n3lLgHjVOM=;
        b=RWh5W4gE/LfE2oGk659cofMdzbk1DwIJJ763lr5/WUfAgt50hwqymTgg6vtnnTLDN7
         u+RBAdFWi9Qi/Yenvf/+qCYVkkxXlztMb7lDdhsHT+e1Ts4v9vvf/JBji+AiqHRD9vUZ
         wh68Iigx+EF8kD/uqzytSBl6Gj236EHKqdXseu488HOl5kwszrMHvaHcwcP7Y8Fc9o3p
         2+PASN2z3dzHSripnknxDaPAZyy41WHM4yRGbkLZsGkwKtAvIAKg4CRrI2/BkOtG+pd+
         wdC/lt5BKxQ7lqIkUUDWkgNt3CnMjv5CAgqCZ0HMy/3lXcY/Z6MG7/QhA+4NgN8jgmpa
         zdNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J8ZKRCsFSRH1H+ZJNByVdtMLrBzL9KWm3n3lLgHjVOM=;
        b=lSgnTNalVzAscmHeOEcWm3eJ6PJ9K3giCwGJJ6Xi6i8/wuGXi0nSSWp6G5xp4X0DGm
         PyYH6nb6c5t4yQ+9sr9ILpU7WofsRWKv5o3mRQ/kW4Bheu9uH0P8+nsIBvvZ5wrYdI8x
         jyY4sArYzGGYUrGvRsPPPWODJaOsBQ6RYScdDNNjLYF1tM72HahvQG7rfMXtbQH5l6ZA
         9Zet71eRPqevnkQ++5GYnnZ828mmVxf6ovwD934RHIcxdQBV7o4B9pddtZMbUwyz+WEu
         bYpC4HXS0n8fbFkkmsTVYEXmPEr2ONAkeH65HVZT3QgNh8u2gtZgeIOSX+3a09NWNSvn
         m4Dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1VLznar8GYzvqpCMclqh/q+wuJbw/JNRcR07MrXiMODb5BZuXg
	VFYbYNQEKzfuWxcFzZZj/Tw=
X-Google-Smtp-Source: AMsMyM6x2qdlFbXSYtajCxbsQLURZHRpVoTjhikeoFbU6KS4MO+ezy6QY+OivlyXp7Ap+Q7hCgV+1Q==
X-Received: by 2002:a25:e447:0:b0:6c1:c882:a998 with SMTP id b68-20020a25e447000000b006c1c882a998mr45292171ybh.630.1666898839296;
        Thu, 27 Oct 2022 12:27:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:abd3:0:b0:6bc:579b:ebdd with SMTP id v77-20020a25abd3000000b006bc579bebddls124602ybi.8.-pod-prod-gmail;
 Thu, 27 Oct 2022 12:27:18 -0700 (PDT)
X-Received: by 2002:a05:6902:70f:b0:6ca:70b5:f407 with SMTP id k15-20020a056902070f00b006ca70b5f407mr30435564ybt.522.1666898838788;
        Thu, 27 Oct 2022 12:27:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666898838; cv=none;
        d=google.com; s=arc-20160816;
        b=CPwYYlhJCFW5ReSV6GHTwTXCU4KuQIUzpPsmGh0FlcnaO+1YLBkxX7uKHtUFIIOrKt
         gjL3QZ8S+bNVcjroGmgA8Y/L4WrpwqETD0FKtbhV88qcouzU2ut9u0YPNuLZ2Lm6PUnL
         1F1U3iGPEJ4qG0ynfaMAmGiiTiRGX2wGFOeN8ow539AUSyIgewh8X+vokvpJcYowJ0vV
         rrA6EnAa2cvMio/eYgyS97SYEUX8sVQrwEFQzd9tqEFTPixSBRvxMHnOAK2L5/KcGNzK
         hPC76/N28YGX+EOocsgO+fZAqdlJc2WRovmJBV3F2Csro7bpWUr6dOWqesEWbt9IgXLc
         EueQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o482CCSS2t5cpOMDg/QGNflnp9GjmK74VY4pwqBErkk=;
        b=1Ea1XKrNxYqDt7rLFOk0RFLNnCoaJYYB4ny95RWpP5bUIDNoAVfg/ZHZeTgAw6KiCV
         NZCJATttWTQZw3joGFYfwTvpjesFdAodQx5bkJIRtcyPRwt+2HhwmqKVBwtXKc0BV7bS
         S2D9cXe36wReLbmYsW+eFjAV93nU5+neBPPsNGH+1xZJKITv5eseJlUGqUUcr23RPPbX
         kdtPZKhhWKcluIYOS/XtNA0nb5DZay9ddqAieanjF7+BOcwxdrmIKZiqqGS/N8GeRHeN
         z6JSMIbLdnDxgWvaQur0mfwPNFFh+PTzc9BLiSwmnxKTr/T31rnxyK+K3px1HJ73Wdbc
         vRww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QcfHLCvL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id bp19-20020a05690c069300b0036bde06a6b6si82348ywb.3.2022.10.27.12.27.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 12:27:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id p127so3493105oih.9
        for <kasan-dev@googlegroups.com>; Thu, 27 Oct 2022 12:27:18 -0700 (PDT)
X-Received: by 2002:a05:6808:1404:b0:355:4cd4:b10b with SMTP id
 w4-20020a056808140400b003554cd4b10bmr5744997oiv.207.1666898838501; Thu, 27
 Oct 2022 12:27:18 -0700 (PDT)
MIME-Version: 1.0
References: <20221021032405.1825078-1-feng.tang@intel.com> <20221021032405.1825078-2-feng.tang@intel.com>
In-Reply-To: <20221021032405.1825078-2-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 27 Oct 2022 21:27:07 +0200
Message-ID: <CA+fCnZcx4TP7Sn28XMxJL09_K_nzZyZe1xt_Zhoh+61h=5xneQ@mail.gmail.com>
Subject: Re: [PATCH v7 1/3] mm/slub: only zero requested size of buffer for
 kzalloc when debug enabled
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Kees Cook <keescook@chromium.org>, Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QcfHLCvL;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::236
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Oct 21, 2022 at 5:24 AM Feng Tang <feng.tang@intel.com> wrote:
>
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
>         init = slab_want_init_on_alloc(flags, cachep);
>
>  out:
> -       slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> +       slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
> +                               cachep->object_size);
>         return objp;
>  }
>
> @@ -3506,13 +3507,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>          * Done outside of the IRQ disabled section.
>          */
>         slab_post_alloc_hook(s, objcg, flags, size, p,
> -                               slab_want_init_on_alloc(flags, s));
> +                       slab_want_init_on_alloc(flags, s), s->object_size);
>         /* FIXME: Trace call missing. Christoph would like a bulk variant */
>         return size;
>  error:
>         local_irq_enable();
>         cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> -       slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +       slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
>         kmem_cache_free_bulk(s, i, p);
>         return 0;
>  }
> diff --git a/mm/slab.h b/mm/slab.h
> index 0202a8c2f0d2..8b4ee02fc14a 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -720,12 +720,26 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
>
>  static inline void slab_post_alloc_hook(struct kmem_cache *s,
>                                         struct obj_cgroup *objcg, gfp_t flags,
> -                                       size_t size, void **p, bool init)
> +                                       size_t size, void **p, bool init,
> +                                       unsigned int orig_size)
>  {
> +       unsigned int zero_size = s->object_size;
>         size_t i;
>
>         flags &= gfp_allowed_mask;
>
> +       /*
> +        * For kmalloc object, the allocated memory size(object_size) is likely
> +        * larger than the requested size(orig_size). If redzone check is
> +        * enabled for the extra space, don't zero it, as it will be redzoned
> +        * soon. The redzone operation for this extra space could be seen as a
> +        * replacement of current poisoning under certain debug option, and
> +        * won't break other sanity checks.
> +        */
> +       if (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
> +           (s->flags & SLAB_KMALLOC))
> +               zero_size = orig_size;
> +
>         /*
>          * As memory initialization might be integrated into KASAN,
>          * kasan_slab_alloc and initialization memset must be
> @@ -736,7 +750,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>         for (i = 0; i < size; i++) {
>                 p[i] = kasan_slab_alloc(s, p[i], flags, init);
>                 if (p[i] && init && !kasan_has_integrated_init())
> -                       memset(p[i], 0, s->object_size);
> +                       memset(p[i], 0, zero_size);
>                 kmemleak_alloc_recursive(p[i], s->object_size, 1,
>                                          s->flags, flags);
>                 kmsan_slab_alloc(s, p[i], flags);
> diff --git a/mm/slub.c b/mm/slub.c
> index 12354fb8d6e4..17292c2d3eee 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3395,7 +3395,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
>         init = slab_want_init_on_alloc(gfpflags, s);
>
>  out:
> -       slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
> +       /*
> +        * When init equals 'true', like for kzalloc() family, only
> +        * @orig_size bytes will be zeroed instead of s->object_size
> +        */
> +       slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
>
>         return object;
>  }
> @@ -3852,11 +3856,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>          * Done outside of the IRQ disabled fastpath loop.
>          */
>         slab_post_alloc_hook(s, objcg, flags, size, p,
> -                               slab_want_init_on_alloc(flags, s));
> +                       slab_want_init_on_alloc(flags, s), s->object_size);
>         return i;
>  error:
>         slub_put_cpu_ptr(s->cpu_slab);
> -       slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +       slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
>         kmem_cache_free_bulk(s, i, p);
>         return 0;
>  }
> --
> 2.34.1
>

For the KASAN part:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcx4TP7Sn28XMxJL09_K_nzZyZe1xt_Zhoh%2B61h%3D5xneQ%40mail.gmail.com.
